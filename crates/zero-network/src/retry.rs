//! Outbox pump with exponential backoff retry logic.
//!
//! [`RetryPump`] drives a background loop that polls an [`OutboxHandle`] for
//! due entries, publishes them via any [`GridClient`], and reschedules
//! failures with exponential backoff (500 ms initial, x2, cap 30 s, full
//! jitter in [0.5x, 1.0x]). After [`RETRY_MAX_ATTEMPTS`] failures an entry
//! is removed and a [`RetryExhausted`] event is emitted.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::client::{GridClient, SectorBytes};

// ── Retry policy constants ────────────────────────────────────────────────────

/// Initial delay before the first retry, in milliseconds.
pub const RETRY_INITIAL_DELAY_MS: u64 = 500;

/// Multiplicative backoff factor applied on each consecutive failure.
pub const RETRY_BACKOFF_MULTIPLIER: u64 = 2;

/// Maximum number of publish attempts before the entry is abandoned.
pub const RETRY_MAX_ATTEMPTS: u8 = 5;

/// Upper cap on computed backoff delay, in milliseconds.
pub const RETRY_CAP_MS: u64 = 30_000;

/// How often the pump polls the outbox for due entries, in milliseconds.
pub const PUMP_POLL_INTERVAL_MS: u64 = 250;

// ── Event emitted on exhaustion ───────────────────────────────────────────────

/// Emitted when an outbox entry has been retried [`RETRY_MAX_ATTEMPTS`] times
/// without success and is being permanently abandoned.
#[derive(Debug, Clone)]
pub struct RetryExhausted {
    /// Topic the sector was intended for.
    pub topic: String,
    /// Total number of attempts made.
    pub attempts: u8,
}

// ── Outbox abstraction ────────────────────────────────────────────────────────

/// A single entry returned from the outbox that is due for (re)delivery.
#[derive(Debug, Clone)]
pub struct OutboxEntryHandle {
    /// Routing topic (e.g. a GRID multiaddr or channel name).
    pub topic: String,
    /// Raw sector payload to publish.
    pub payload: SectorBytes,
    /// Number of delivery attempts already recorded (0 on first try).
    pub attempts: u8,
}

/// Minimal async interface over an outbox store, used by [`RetryPump`].
///
/// A blanket impl is provided for `Arc<T: OutboxHandle>`.  The in-memory
/// implementation used by tests lives in this module as
/// [`InMemoryOutboxHandle`].
#[async_trait::async_trait]
pub trait OutboxHandle: Send + Sync + 'static {
    /// Return every entry whose next-attempt timestamp is <= `now_ms`.
    async fn due_entries(&self, now_ms: u64) -> Vec<OutboxEntryHandle>;

    /// Mark an entry as successfully delivered; removes it from the outbox.
    async fn ack(&self, topic: &str);

    /// Record a failed delivery attempt and schedule the next retry at
    /// `next_attempt_ms` (absolute Unix ms timestamp).
    async fn record_failure(&self, topic: &str, next_attempt_ms: u64);

    /// Permanently remove an entry that has exceeded the retry budget.
    async fn remove(&self, topic: &str);
}

// ── RetryPump ─────────────────────────────────────────────────────────────────

/// Drives background publish retries for all due outbox entries.
pub struct RetryPump<C: GridClient, O: OutboxHandle> {
    client: Arc<C>,
    outbox: Arc<O>,
    exhausted_tx: Option<mpsc::UnboundedSender<RetryExhausted>>,
}

impl<C: GridClient, O: OutboxHandle> RetryPump<C, O> {
    /// Create a new pump without an exhaustion event channel.
    pub fn new(client: Arc<C>, outbox: Arc<O>) -> Self {
        Self {
            client,
            outbox,
            exhausted_tx: None,
        }
    }

    /// Attach an unbounded channel that receives [`RetryExhausted`] events.
    pub fn with_exhaustion_channel(mut self, tx: mpsc::UnboundedSender<RetryExhausted>) -> Self {
        self.exhausted_tx = Some(tx);
        self
    }

    /// Spawn a background tokio task running the pump loop.
    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(pump_loop(self.client, self.outbox, self.exhausted_tx))
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns the current time in milliseconds.
///
/// Uses `tokio::time::Instant` so that tests using `start_paused = true` and
/// `tokio::time::advance` see consistent virtual time inside the pump loop.
fn now_ms() -> u64 {
    use std::sync::OnceLock;
    use tokio::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    Instant::now()
        .checked_duration_since(*epoch)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Compute the next backoff delay in ms using full jitter.
///
/// Formula: `jitter(min(cap, initial * multiplier^attempts))` where jitter
/// picks uniformly in `[0.5 * delay, 1.0 * delay]`.
fn compute_backoff_ms(attempts: u8) -> u64 {
    let exp = (attempts as u32).saturating_sub(1);
    let base = RETRY_INITIAL_DELAY_MS.saturating_mul(RETRY_BACKOFF_MULTIPLIER.saturating_pow(exp));
    let capped = base.min(RETRY_CAP_MS);
    // Full jitter in [0.5 * capped, 1.0 * capped]
    let half = capped / 2;
    let frac = {
        // Use a simple deterministic spread based on current ns timestamp.
        use std::time::{SystemTime, UNIX_EPOCH};
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        ns % (half.max(1))
    };
    half + frac
}

/// Background loop: poll outbox every `PUMP_POLL_INTERVAL_MS`, publish due
/// entries, ack successes, schedule retries on failure, abandon after
/// `RETRY_MAX_ATTEMPTS`.
async fn pump_loop<C: GridClient, O: OutboxHandle>(
    client: Arc<C>,
    outbox: Arc<O>,
    exhausted_tx: Option<mpsc::UnboundedSender<RetryExhausted>>,
) {
    let interval = std::time::Duration::from_millis(PUMP_POLL_INTERVAL_MS);
    loop {
        let due = outbox.due_entries(now_ms()).await;
        for entry in due {
            let next_attempts = entry.attempts + 1;
            match client.publish(&entry.topic, entry.payload.clone()).await {
                Ok(()) => {
                    outbox.ack(&entry.topic).await;
                }
                Err(_) => {
                    if next_attempts >= RETRY_MAX_ATTEMPTS {
                        outbox.remove(&entry.topic).await;
                        if let Some(tx) = &exhausted_tx {
                            let _ = tx.send(RetryExhausted {
                                topic: entry.topic.clone(),
                                attempts: next_attempts,
                            });
                        }
                    } else {
                        let delay = compute_backoff_ms(next_attempts);
                        outbox.record_failure(&entry.topic, now_ms() + delay).await;
                    }
                }
            }
        }
        tokio::time::sleep(interval).await;
    }
}

// ── In-memory outbox for tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NetworkError;
    use futures_core::Stream;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Mutex;

    // ── InMemoryOutboxHandle ──────────────────────────────────────────────────

    #[derive(Default)]
    struct OutboxEntry {
        topic: String,
        payload: SectorBytes,
        attempts: u8,
        next_attempt_ms: u64,
    }

    #[derive(Default)]
    struct OutboxState {
        entries: HashMap<String, OutboxEntry>,
    }

    struct InMemoryOutboxHandle {
        state: Mutex<OutboxState>,
    }

    impl InMemoryOutboxHandle {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(OutboxState::default()),
            })
        }

        fn enqueue(&self, topic: &str, payload: SectorBytes) {
            let mut state = self.state.lock().unwrap();
            state.entries.insert(
                topic.to_string(),
                OutboxEntry {
                    topic: topic.to_string(),
                    payload,
                    attempts: 0,
                    next_attempt_ms: 0,
                },
            );
        }

        fn contains(&self, topic: &str) -> bool {
            self.state.lock().unwrap().entries.contains_key(topic)
        }

        fn len(&self) -> usize {
            self.state.lock().unwrap().entries.len()
        }
    }

    #[async_trait::async_trait]
    impl OutboxHandle for InMemoryOutboxHandle {
        async fn due_entries(&self, now_ms: u64) -> Vec<OutboxEntryHandle> {
            let state = self.state.lock().unwrap();
            state
                .entries
                .values()
                .filter(|e| e.next_attempt_ms <= now_ms)
                .map(|e| OutboxEntryHandle {
                    topic: e.topic.clone(),
                    payload: e.payload.clone(),
                    attempts: e.attempts,
                })
                .collect()
        }

        async fn ack(&self, topic: &str) {
            self.state.lock().unwrap().entries.remove(topic);
        }

        async fn record_failure(&self, topic: &str, next_attempt_ms: u64) {
            if let Some(e) = self.state.lock().unwrap().entries.get_mut(topic) {
                e.attempts += 1;
                e.next_attempt_ms = next_attempt_ms;
            }
        }

        async fn remove(&self, topic: &str) {
            self.state.lock().unwrap().entries.remove(topic);
        }
    }

    // ── AlwaysOkClient / AlwaysFailClient ─────────────────────────────────────

    struct AlwaysOkClient;

    #[async_trait::async_trait]
    impl GridClient for AlwaysOkClient {
        async fn publish(&self, _topic: &str, _bytes: SectorBytes) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn subscribe(
            &self,
            _topic: &str,
        ) -> Result<
            Pin<Box<dyn Stream<Item = Result<SectorBytes, NetworkError>> + Send>>,
            NetworkError,
        > {
            Err(NetworkError::Other("not implemented".into()))
        }

        async fn unsubscribe(&self, _topic: &str) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    struct AlwaysFailClient;

    #[async_trait::async_trait]
    impl GridClient for AlwaysFailClient {
        async fn publish(&self, _topic: &str, _bytes: SectorBytes) -> Result<(), NetworkError> {
            Err(NetworkError::Other("simulated failure".into()))
        }

        async fn subscribe(
            &self,
            _topic: &str,
        ) -> Result<
            Pin<Box<dyn Stream<Item = Result<SectorBytes, NetworkError>> + Send>>,
            NetworkError,
        > {
            Err(NetworkError::Other("not implemented".into()))
        }

        async fn unsubscribe(&self, _topic: &str) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn backoff_stays_within_jitter_bounds_expected() {
        // For attempts=1 the base is 500ms, capped at 500ms.
        // Jitter must be in [250, 500].
        for _ in 0..50 {
            let delay = compute_backoff_ms(1);
            assert!(
                (250..=500).contains(&delay),
                "delay {delay} out of [250, 500]"
            );
        }
        // For attempts=5 the base is 500 * 2^4 = 8000ms; capped at 30000.
        // Jitter must be in [4000, 8000].
        for _ in 0..50 {
            let delay = compute_backoff_ms(5);
            assert!(
                (4_000..=8_000).contains(&delay),
                "delay {delay} out of [4000, 8000]"
            );
        }
        // For very high attempts the cap is 30000; jitter in [15000, 30000].
        for _ in 0..50 {
            let delay = compute_backoff_ms(20);
            assert!(
                (15_000..=30_000).contains(&delay),
                "delay {delay} out of [15000, 30000]"
            );
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn pump_publishes_due_entries() {
        let outbox = InMemoryOutboxHandle::new();
        outbox.enqueue("topic/a", b"payload-a".to_vec());
        outbox.enqueue("topic/b", b"payload-b".to_vec());
        outbox.enqueue("topic/c", b"payload-c".to_vec());

        let client = Arc::new(AlwaysOkClient);
        let pump = RetryPump::new(client, Arc::clone(&outbox));
        let handle = pump.start();

        // Advance time past the poll interval so entries become due.
        tokio::time::advance(std::time::Duration::from_millis(PUMP_POLL_INTERVAL_MS + 10)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_millis(10)).await;
        tokio::task::yield_now().await;

        handle.abort();
        assert_eq!(outbox.len(), 0, "all entries should have been acked");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn exhaustion_after_max_attempts() {
        let outbox = InMemoryOutboxHandle::new();
        outbox.enqueue("topic/fail", b"data".to_vec());

        let client = Arc::new(AlwaysFailClient);
        let (tx, mut rx) = mpsc::unbounded_channel::<RetryExhausted>();
        let pump = RetryPump::new(client, Arc::clone(&outbox)).with_exhaustion_channel(tx);
        let handle = pump.start();

        // Drive through RETRY_MAX_ATTEMPTS poll cycles.
        // Each cycle: poll interval + small processing time.
        for _ in 0..(RETRY_MAX_ATTEMPTS as u64 + 2) {
            tokio::time::advance(std::time::Duration::from_secs(35)).await;
            tokio::task::yield_now().await;
        }

        handle.abort();

        // Entry must be gone from the outbox.
        assert!(
            !outbox.contains("topic/fail"),
            "entry should be removed after exhaustion"
        );

        // A RetryExhausted event must have been emitted.
        let event = rx.try_recv().expect("RetryExhausted event expected");
        assert_eq!(event.topic, "topic/fail");
        assert_eq!(event.attempts, RETRY_MAX_ATTEMPTS);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn partial_failure_retries_then_succeeds() {
        use std::sync::atomic::{AtomicU8, Ordering};

        struct FailTwiceClient {
            call_count: Arc<AtomicU8>,
        }

        #[async_trait::async_trait]
        impl GridClient for FailTwiceClient {
            async fn publish(&self, _topic: &str, _bytes: SectorBytes) -> Result<(), NetworkError> {
                let n = self.call_count.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(NetworkError::Other("fail".into()))
                } else {
                    Ok(())
                }
            }

            async fn subscribe(
                &self,
                _topic: &str,
            ) -> Result<
                Pin<Box<dyn Stream<Item = Result<SectorBytes, NetworkError>> + Send>>,
                NetworkError,
            > {
                Err(NetworkError::Other("not implemented".into()))
            }

            async fn unsubscribe(&self, _topic: &str) -> Result<(), NetworkError> {
                Ok(())
            }
        }

        let outbox = InMemoryOutboxHandle::new();
        outbox.enqueue("topic/partial", b"data".to_vec());

        let counter = Arc::new(AtomicU8::new(0));
        let client = Arc::new(FailTwiceClient {
            call_count: Arc::clone(&counter),
        });
        let pump = RetryPump::new(client, Arc::clone(&outbox));
        let handle = pump.start();

        // Drive several cycles — enough for 2 failures + 1 success.
        for _ in 0..6 {
            tokio::time::advance(std::time::Duration::from_secs(35)).await;
            tokio::task::yield_now().await;
        }

        handle.abort();

        assert_eq!(
            outbox.len(),
            0,
            "entry should be acked after eventual success"
        );
        assert!(
            counter.load(Ordering::SeqCst) >= 3,
            "should have tried at least 3 times"
        );
    }
}
