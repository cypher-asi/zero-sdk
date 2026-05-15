//! Real GRID client backed by the upstream `grid-net::NetworkService`.
//!
//! [`RealGridClient::connect`] dials a single Zode at the supplied multiaddr,
//! awaits the libp2p connection-established event, then spawns an event-loop
//! task that:
//!
//! * forwards [`GridClient::publish`] / [`GridClient::subscribe`] /
//!   [`GridClient::unsubscribe`] requests onto the underlying `NetworkService`
//!   via an `mpsc` command channel, and
//! * fans out inbound `NetworkEvent::GossipMessage` payloads to per-topic
//!   `tokio::sync::broadcast` channels surfaced through the `subscribe`
//!   stream.
//!
//! Owning the `NetworkService` inside the event-loop task (rather than behind
//! a shared mutex like `grid-sdk` does) avoids the lock-contention deadlock
//! where `next_event` holds the mutex across an `.await` that may never
//! resolve when the network is idle.

use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_core::Stream;
use grid_net::{
    extract_peer_id, strip_zx_multiaddr, KademliaMode, Multiaddr, NetworkConfig, NetworkEvent,
    NetworkService, ZodeId,
};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::client::{GridClient, SectorBytes};
use crate::error::NetworkError;

/// Buffer per topic. Subscribers that fall further behind than this are
/// reported as a `NetworkError::Other("broadcast lag: ...")` item on their
/// stream and may resume from the next message.
const TOPIC_CHANNEL_CAPACITY: usize = 256;

/// Bound on outstanding control-plane commands. Exceeding this means the
/// caller is producing publishes/subscribes faster than the event loop can
/// drain them, in which case `send` will simply yield until there is room.
const COMMAND_CHANNEL_CAPACITY: usize = 64;

/// How long `connect` will drive the swarm waiting for the dial to either
/// succeed (`PeerConnected`) or fail (`ConnectionFailed`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Local listen address. We bind to an ephemeral UDP port via QUIC v1 so two
/// clients in the same process never fight over a fixed port.
const LISTEN_ADDR: &str = "/ip4/0.0.0.0/udp/0/quic-v1";

type Topics = Arc<Mutex<HashMap<String, broadcast::Sender<SectorBytes>>>>;

/// A GRID client backed by the upstream `grid-net::NetworkService`.
///
/// Construct via [`RealGridClient::connect`]. Dropping the client signals
/// the background event loop to shut down via the `_shutdown` guard.
pub struct RealGridClient {
    multiaddr: String,
    commands: mpsc::Sender<Command>,
    topics: Topics,
    _shutdown: ShutdownGuard,
}

impl RealGridClient {
    /// Dial the GRID node at `multiaddr` and bring up an event loop ready to
    /// pump GossipSub traffic.
    ///
    /// # Errors
    ///
    /// * [`NetworkError::Other`] when the multiaddr is malformed, when the
    ///   underlying `NetworkService` fails to initialise (e.g. the QUIC
    ///   transport cannot be built), or when the upstream reports a dial
    ///   failure for the target peer.
    /// * [`NetworkError::Timeout`] when the libp2p handshake does not
    ///   complete within [`CONNECT_TIMEOUT`].
    pub async fn connect(multiaddr: &str) -> Result<Self, NetworkError> {
        // Strip the display-only `Zx` prefix from the trailing `/p2p/<peer>`
        // segment so libp2p's parser can recover the raw `PeerId`.
        let parsed_str = strip_zx_multiaddr(multiaddr).into_owned();
        let dial_addr = Multiaddr::from_str(&parsed_str)
            .map_err(|e| NetworkError::Other(format!("invalid multiaddr `{multiaddr}`: {e}")))?;
        let target_peer = extract_peer_id(&dial_addr);

        let listen_addr = Multiaddr::from_str(LISTEN_ADDR)
            .expect("static LISTEN_ADDR is a valid multiaddr literal");

        // SDK clients query the DHT but do not serve routes. Allow private
        // (loopback / RFC1918) addresses so dialling a local zode succeeds.
        let mut config = NetworkConfig::new(listen_addr);
        config.bootstrap_peers = vec![dial_addr.clone()];
        config.discovery.kademlia_mode = KademliaMode::Client;
        config.discovery.allow_private_addresses = true;

        let mut service = NetworkService::new(config)
            .await
            .map_err(|e| NetworkError::Other(format!("network init failed: {e}")))?;

        // Drive the swarm until the target peer is connected, the dial
        // explicitly fails, or the timeout fires.
        let dial_result = tokio::time::timeout(
            CONNECT_TIMEOUT,
            await_dial_completion(&mut service, target_peer),
        )
        .await;

        match dial_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(NetworkError::Timeout),
        }

        let topics: Topics = Arc::new(Mutex::new(HashMap::new()));
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let event_topics = Arc::clone(&topics);
        tokio::spawn(async move {
            event_loop(service, cmd_rx, event_topics, shutdown_rx).await;
        });

        Ok(Self {
            multiaddr: multiaddr.to_owned(),
            commands: cmd_tx,
            topics,
            _shutdown: ShutdownGuard {
                tx: Some(shutdown_tx),
            },
        })
    }

    /// The multiaddr originally passed to [`RealGridClient::connect`].
    ///
    /// Returned verbatim (including any `Zx` prefix on the `/p2p/...` tail)
    /// so consumers can round-trip it back into config / UI surfaces without
    /// loss.
    pub fn multiaddr(&self) -> &str {
        &self.multiaddr
    }

    async fn send_command<F>(&self, build: F) -> Result<(), NetworkError>
    where
        F: FnOnce(oneshot::Sender<Result<(), NetworkError>>) -> Command,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(build(reply_tx))
            .await
            .map_err(|_| NetworkError::Other("grid event loop terminated".into()))?;
        reply_rx
            .await
            .map_err(|_| NetworkError::Other("grid event loop dropped command reply".into()))?
    }
}

/// Drains `next_event` until either the target peer connects or a dial
/// failure for that peer is observed.
///
/// `target_peer` is `None` when the dial multiaddr lacked a trailing
/// `/p2p/<peer>` component; in that case the first `PeerConnected` /
/// `ConnectionFailed` event is treated as the result of our dial.
async fn await_dial_completion(
    service: &mut NetworkService,
    target_peer: Option<ZodeId>,
) -> Result<(), NetworkError> {
    loop {
        match service.next_event().await {
            Some(NetworkEvent::PeerConnected(peer)) => {
                if target_peer.is_none() || target_peer == Some(peer) {
                    return Ok(());
                }
            }
            Some(NetworkEvent::ConnectionFailed { peer, error })
                if peer == target_peer || target_peer.is_none() =>
            {
                return Err(NetworkError::Other(format!("dial failed: {error}")));
            }
            Some(_) => {}
            None => {
                return Err(NetworkError::Other(
                    "grid network event stream ended unexpectedly".into(),
                ));
            }
        }
    }
}

/// Long-running task that owns the [`NetworkService`] for the lifetime of a
/// [`RealGridClient`].
async fn event_loop(
    mut service: NetworkService,
    mut cmd_rx: mpsc::Receiver<Command>,
    topics: Topics,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                handle_command(&mut service, cmd);
            }
            event = service.next_event() => {
                let Some(event) = event else { break };
                if let NetworkEvent::GossipMessage { topic, data, .. } = event {
                    let senders = topics.lock().await;
                    if let Some(tx) = senders.get(&topic) {
                        // Send error means no live receivers, which is fine
                        // -- the message is simply dropped on the floor.
                        let _ = tx.send(data);
                    }
                }
            }
        }
    }
}

fn handle_command(service: &mut NetworkService, cmd: Command) {
    match cmd {
        Command::Subscribe(topic, reply) => {
            let res = service
                .subscribe(&topic)
                .map_err(|e| NetworkError::Other(format!("subscribe failed: {e}")));
            let _ = reply.send(res);
        }
        Command::Unsubscribe(topic, reply) => {
            let res = service
                .unsubscribe(&topic)
                .map_err(|e| NetworkError::Other(format!("unsubscribe failed: {e}")));
            let _ = reply.send(res);
        }
        Command::Publish(topic, data, reply) => {
            let res = service
                .publish(&topic, data)
                .map_err(|e| NetworkError::Other(format!("publish failed: {e}")));
            let _ = reply.send(res);
        }
    }
}

/// Control-plane messages from `GridClient` methods to the event loop.
enum Command {
    Subscribe(String, oneshot::Sender<Result<(), NetworkError>>),
    Unsubscribe(String, oneshot::Sender<Result<(), NetworkError>>),
    Publish(String, SectorBytes, oneshot::Sender<Result<(), NetworkError>>),
}

/// RAII guard that signals the background event loop to exit when the
/// owning [`RealGridClient`] is dropped.
struct ShutdownGuard {
    tx: Option<oneshot::Sender<()>>,
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

#[async_trait]
impl GridClient for RealGridClient {
    async fn publish(&self, topic: &str, sector_bytes: SectorBytes) -> Result<(), NetworkError> {
        let topic = topic.to_owned();
        self.send_command(|reply| Command::Publish(topic, sector_bytes, reply))
            .await
    }

    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<SectorBytes, NetworkError>> + Send>>, NetworkError>
    {
        // Insert the broadcast sender BEFORE asking gossipsub to subscribe so
        // the very first inbound message after subscription cannot race past
        // the topic registration.
        let rx = {
            let mut topics = self.topics.lock().await;
            let sender = topics
                .entry(topic.to_owned())
                .or_insert_with(|| broadcast::channel(TOPIC_CHANNEL_CAPACITY).0)
                .clone();
            sender.subscribe()
        };

        let topic_owned = topic.to_owned();
        self.send_command(|reply| Command::Subscribe(topic_owned, reply))
            .await?;

        let stream = BroadcastStream::new(rx)
            .map(|item| item.map_err(|e| NetworkError::Other(format!("broadcast lag: {e}"))));
        Ok(Box::pin(stream))
    }

    async fn unsubscribe(&self, topic: &str) -> Result<(), NetworkError> {
        let topic_owned = topic.to_owned();
        let outcome = self
            .send_command(|reply| Command::Unsubscribe(topic_owned, reply))
            .await;

        // Forget the broadcast sender regardless of upstream error so
        // subsequent `subscribe` calls re-register cleanly.
        self.topics.lock().await.remove(topic);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_grid_client<T: GridClient>() {}

    #[test]
    fn real_grid_client_satisfies_trait_bounds() {
        assert_grid_client::<RealGridClient>();
    }

    #[tokio::test]
    async fn connect_with_invalid_multiaddr_fails() {
        let err = match RealGridClient::connect("not-a-multiaddr").await {
            Ok(_) => panic!("connect should have rejected an unparseable multiaddr"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("invalid multiaddr"),
            "expected parse error, got: {msg}"
        );
    }

    /// The dial path is asynchronous: an unreachable multiaddr should
    /// surface as `NetworkError::Timeout` (or `NetworkError::Other` if
    /// the swarm reports a fast-fail). Either way, `connect` must not
    /// silently succeed.
    ///
    /// We use `192.0.2.1` (TEST-NET-1, RFC 5737) which is guaranteed
    /// non-routable and a randomly-generated peer id so libp2p has a
    /// concrete dial target. The test drives a short timeout to keep
    /// CI snappy.
    #[tokio::test]
    async fn connect_to_unreachable_peer_returns_some_network_error() {
        // Random PeerId derived from a fresh ed25519 keypair so the dial has
        // a structurally-valid `/p2p/<peer>` tail.
        let peer = grid_net::Keypair::generate_ed25519().public().to_peer_id();
        let unreachable = format!("/ip4/192.0.2.1/udp/65530/quic-v1/p2p/{peer}");

        // Use `tokio::time::timeout` with a budget shorter than CONNECT_TIMEOUT
        // so the test fails fast even when libp2p doesn't surface a quick
        // ConnectionFailed for our test address.
        let result =
            tokio::time::timeout(Duration::from_secs(20), RealGridClient::connect(&unreachable))
                .await;

        match result {
            Ok(Err(e)) => {
                // Either a Timeout or an upstream "dial failed" Other --
                // the contract is just that connect did not succeed.
                let _ = e;
            }
            Ok(Ok(_)) => panic!("connect should not succeed for an unreachable test address"),
            Err(_) => panic!("connect outlived its 20s test budget"),
        }
    }
}
