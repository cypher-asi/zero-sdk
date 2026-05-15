//! In-memory GRID broker and mock client for testing.
//!
//! [`InMemoryGridBroker`] holds shared state; call [`InMemoryGridBroker::client`]
//! to obtain [`MockGridClient`] handles that implement [`GridClient`].
//! Supports fault injection (drop, duplicate, delay) per topic.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_core::Stream;
use tokio::sync::broadcast;

use crate::client::{GridClient, SectorBytes};
use crate::error::NetworkError;

/// Fault to inject on a per-topic basis during [`MockGridClient::publish`].
#[derive(Debug, Clone)]
pub enum Fault {
    /// Silently drop the message (do not deliver to subscribers).
    Drop,
    /// Deliver the message twice to every subscriber.
    Duplicate,
    /// Delay delivery by the specified duration.
    Delay(Duration),
}

/// Shared mutable state backing the broker.
struct BrokerState {
    /// All published sector bytes, in order.
    published: Vec<(String, SectorBytes)>,
    /// Per-topic broadcast senders.
    topics: HashMap<String, broadcast::Sender<SectorBytes>>,
    /// Per-topic fault injection rules.
    faults: HashMap<String, Vec<Fault>>,
}

impl BrokerState {
    fn get_or_create_sender(&mut self, topic: &str) -> broadcast::Sender<SectorBytes> {
        self.topics
            .entry(topic.to_owned())
            .or_insert_with(|| broadcast::channel(256).0)
            .clone()
    }
}

/// Shared in-memory broker. Clone-friendly via internal `Arc`.
#[derive(Clone)]
pub struct InMemoryGridBroker {
    state: Arc<Mutex<BrokerState>>,
}

impl InMemoryGridBroker {
    /// Create a new empty broker.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(BrokerState {
                published: Vec::new(),
                topics: HashMap::new(),
                faults: HashMap::new(),
            })),
        }
    }

    /// Obtain a [`MockGridClient`] handle attached to this broker.
    pub fn client(&self) -> MockGridClient {
        MockGridClient {
            state: Arc::clone(&self.state),
        }
    }

    /// Number of sectors currently stored in the broker.
    pub fn sector_count(&self) -> usize {
        self.state.lock().unwrap().published.len()
    }

    /// Drain all published sectors (for test assertions).
    pub fn drain_published(&self) -> Vec<(String, SectorBytes)> {
        self.state.lock().unwrap().published.drain(..).collect()
    }

    /// Add a fault injection rule for the given topic.
    pub fn inject_fault(&self, topic: &str, fault: Fault) {
        self.state
            .lock()
            .unwrap()
            .faults
            .entry(topic.to_owned())
            .or_default()
            .push(fault);
    }

    /// Clear all fault injection rules for every topic.
    pub fn clear_faults(&self) {
        self.state.lock().unwrap().faults.clear();
    }
}

impl Default for InMemoryGridBroker {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock client handle backed by an [`InMemoryGridBroker`].
pub struct MockGridClient {
    state: Arc<Mutex<BrokerState>>,
}

#[async_trait]
impl GridClient for MockGridClient {
    async fn publish(&self, topic: &str, sector_bytes: SectorBytes) -> Result<(), NetworkError> {
        let (sender, faults) = {
            let mut st = self.state.lock().unwrap();
            st.published.push((topic.to_owned(), sector_bytes.clone()));
            let sender = st.get_or_create_sender(topic);
            let faults = st.faults.get(topic).cloned().unwrap_or_default();
            (sender, faults)
        };

        let mut should_drop = false;
        let mut duplicate_count: usize = 1;
        let mut delay = None;

        for fault in &faults {
            match fault {
                Fault::Drop => should_drop = true,
                Fault::Duplicate => duplicate_count += 1,
                Fault::Delay(d) => delay = Some(*d),
            }
        }

        if should_drop {
            return Ok(());
        }

        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }

        for _ in 0..duplicate_count {
            // Ignore send errors (no active receivers is fine).
            let _ = sender.send(sector_bytes.clone());
        }

        Ok(())
    }

    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<SectorBytes, NetworkError>> + Send>>, NetworkError>
    {
        let rx = {
            let mut st = self.state.lock().unwrap();
            let sender = st.get_or_create_sender(topic);
            sender.subscribe()
        };
        Ok(Box::pin(BroadcastStream { rx }))
    }

    async fn unsubscribe(&self, topic: &str) -> Result<(), NetworkError> {
        let mut st = self.state.lock().unwrap();
        st.topics.remove(topic);
        Ok(())
    }
}

/// Wraps a `broadcast::Receiver` as a `Stream`.
struct BroadcastStream {
    rx: broadcast::Receiver<SectorBytes>,
}

impl Stream for BroadcastStream {
    type Item = Result<SectorBytes, NetworkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.try_recv() {
            Ok(bytes) => Poll::Ready(Some(Ok(bytes))),
            Err(broadcast::error::TryRecvError::Empty) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                // Skip lagged messages, log would go here in production.
                let _ = n;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(broadcast::error::TryRecvError::Closed) => {
                Poll::Ready(Some(Err(NetworkError::SubscriptionClosed)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn multi_subscriber_pub_sub() {
        let broker = InMemoryGridBroker::new();
        let client_a = broker.client();
        let client_b = broker.client();

        let mut stream_a = client_a.subscribe("topic.test").await.unwrap();
        let mut stream_b = client_b.subscribe("topic.test").await.unwrap();

        let publisher = broker.client();
        publisher
            .publish("topic.test", b"hello".to_vec())
            .await
            .unwrap();

        let item_a = tokio::time::timeout(Duration::from_millis(500), stream_a.next())
            .await
            .expect("stream_a timed out")
            .expect("stream_a ended")
            .expect("stream_a error");
        assert_eq!(item_a, b"hello");

        let item_b = tokio::time::timeout(Duration::from_millis(500), stream_b.next())
            .await
            .expect("stream_b timed out")
            .expect("stream_b ended")
            .expect("stream_b error");
        assert_eq!(item_b, b"hello");

        assert_eq!(broker.sector_count(), 1);
    }

    #[tokio::test]
    async fn injected_duplicate_delivered_twice() {
        let broker = InMemoryGridBroker::new();
        broker.inject_fault("dup.topic", Fault::Duplicate);

        let client = broker.client();
        let mut stream = client.subscribe("dup.topic").await.unwrap();

        client
            .publish("dup.topic", b"dup-msg".to_vec())
            .await
            .unwrap();

        let first = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout first")
            .expect("stream ended")
            .expect("error");
        assert_eq!(first, b"dup-msg");

        let second = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout second")
            .expect("stream ended")
            .expect("error");
        assert_eq!(second, b"dup-msg");
    }

    #[tokio::test]
    async fn injected_drop_suppresses_delivery() {
        let broker = InMemoryGridBroker::new();
        broker.inject_fault("drop.topic", Fault::Drop);

        let client = broker.client();
        let mut stream = client.subscribe("drop.topic").await.unwrap();

        client
            .publish("drop.topic", b"gone".to_vec())
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_millis(200), stream.next()).await;
        assert!(result.is_err(), "should have timed out (message dropped)");

        // The message is still recorded in published store.
        assert_eq!(broker.sector_count(), 1);
    }

    #[tokio::test]
    async fn scan_and_drain_published() {
        let broker = InMemoryGridBroker::new();
        let client = broker.client();

        client.publish("t1", b"a".to_vec()).await.unwrap();
        client.publish("t2", b"b".to_vec()).await.unwrap();
        client.publish("t1", b"c".to_vec()).await.unwrap();

        assert_eq!(broker.sector_count(), 3);

        let drained = broker.drain_published();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].0, "t1");
        assert_eq!(drained[1].0, "t2");
        assert_eq!(drained[2].0, "t1");

        assert_eq!(broker.sector_count(), 0);
    }

    #[tokio::test]
    async fn unsubscribe_removes_topic() {
        let broker = InMemoryGridBroker::new();
        let client = broker.client();

        let _stream = client.subscribe("unsub.topic").await.unwrap();
        client.unsubscribe("unsub.topic").await.unwrap();

        {
            let st = broker.state.lock().unwrap();
            assert!(!st.topics.contains_key("unsub.topic"));
        }
    }

    #[tokio::test]
    async fn different_topics_isolated() {
        let broker = InMemoryGridBroker::new();
        let client = broker.client();

        let mut stream_a = client.subscribe("topic.a").await.unwrap();

        client.publish("topic.b", b"wrong".to_vec()).await.unwrap();

        let result = tokio::time::timeout(Duration::from_millis(200), stream_a.next()).await;
        assert!(
            result.is_err(),
            "should not receive messages from a different topic"
        );
    }
}
