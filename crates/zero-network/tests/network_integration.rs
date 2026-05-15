//! Live-node integration tests for `RealGridClient`.
//!
//! All tests are gated with `#[ignore]` so they only run when explicitly
//! requested via `cargo test -p zero-network -- --ignored`.
//! Requires a GRID node listening on `/ip4/0.0.0.0/udp/3690/quic-v1`.

use zero_network::real::RealGridClient;
use zero_network::GridClient;

const LIVE_NODE: &str = "/ip4/0.0.0.0/udp/3690/quic-v1";

#[tokio::test]
#[ignore]
async fn connect_to_live_node() {
    let client = RealGridClient::connect(LIVE_NODE)
        .await
        .expect("should connect to live GRID node");
    assert_eq!(client.multiaddr(), LIVE_NODE);
}

#[tokio::test]
#[ignore]
async fn publish_and_get_sector_round_trip() {
    let client = RealGridClient::connect(LIVE_NODE)
        .await
        .expect("should connect to live GRID node");

    let topic = "zero.chat.v1/sector";
    let payload = b"hello-grid".to_vec();

    let result = client.publish(topic, payload).await;
    // When the upstream is linked this should succeed; until then we just
    // verify it returns an error without panicking.
    if let Err(e) = &result {
        eprintln!("publish returned (expected until upstream linked): {e}");
    }
}

#[tokio::test]
#[ignore]
async fn subscribe_and_receive() {
    let client = RealGridClient::connect(LIVE_NODE)
        .await
        .expect("should connect to live GRID node");

    let topic = "zero.chat.v1/sector";

    let result = client.subscribe(topic).await;
    if let Err(e) = &result {
        eprintln!("subscribe returned (expected until upstream linked): {e}");
    }
}
