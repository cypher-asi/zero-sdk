//! Bounded LRU dedupe cache keyed on [`SectorId`].
//!
//! `DedupeCache` is `Send + Sync` so it can be shared across the network layer.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

use crate::sector::SectorId;

/// Default maximum number of entries before LRU eviction kicks in.
pub const DEFAULT_DEDUPE_CAPACITY: usize = 8192;

/// Thread-safe bounded LRU cache for sector deduplication.
///
/// `mark` inserts (or promotes) a `SectorId`; `seen` checks membership
/// without altering eviction order.
#[derive(Debug, Clone)]
pub struct DedupeCache {
    inner: Arc<Mutex<LruCache<SectorId, ()>>>,
}

impl DedupeCache {
    /// Create a new cache that holds at most `capacity` entries.
    ///
    /// # Panics
    /// Panics if `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).expect("DedupeCache capacity must be > 0");
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(cap))),
        }
    }

    /// Returns `true` if `id` is already in the cache. Does **not** alter
    /// eviction order (uses `peek`).
    pub fn seen(&self, id: SectorId) -> bool {
        let cache = self.inner.lock().expect("dedupe lock poisoned");
        cache.peek(&id).is_some()
    }

    /// Insert (or promote) `id` in the cache. If the cache is at capacity
    /// the least-recently-used entry is evicted.
    pub fn mark(&self, id: SectorId) {
        let mut cache = self.inner.lock().expect("dedupe lock poisoned");
        cache.put(id, ());
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        let cache = self.inner.lock().expect("dedupe lock poisoned");
        cache.len()
    }

    /// Returns `true` when the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync + 'static>() {}

    #[test]
    fn send_sync() {
        assert_send_sync::<DedupeCache>();
    }

    #[test]
    fn unseen_returns_false() {
        let cache = DedupeCache::new(16);
        let id = SectorId::new();
        assert!(!cache.seen(id));
    }

    #[test]
    fn mark_then_seen() {
        let cache = DedupeCache::new(16);
        let id = SectorId::new();
        cache.mark(id);
        assert!(cache.seen(id));
    }

    #[test]
    fn eviction_at_capacity() {
        let cap = 4;
        let cache = DedupeCache::new(cap);

        let ids: Vec<SectorId> = (0..cap + 1)
            .map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(1));
                SectorId::new()
            })
            .collect();

        for id in &ids[..cap] {
            cache.mark(*id);
        }
        assert_eq!(cache.len(), cap);

        // Insert one more -- the oldest (ids[0]) should be evicted.
        cache.mark(ids[cap]);
        assert_eq!(cache.len(), cap);
        assert!(!cache.seen(ids[0]), "oldest entry should have been evicted");
        assert!(cache.seen(ids[cap]), "newest entry should be present");
        // ids[1] through ids[cap-1] should still be present.
        for id in &ids[1..cap] {
            assert!(cache.seen(*id));
        }
    }

    #[test]
    fn mark_is_idempotent() {
        let cache = DedupeCache::new(16);
        let id = SectorId::new();
        cache.mark(id);
        cache.mark(id);
        assert_eq!(cache.len(), 1);
        assert!(cache.seen(id));
    }

    #[test]
    fn default_capacity() {
        let cache = DedupeCache::new(DEFAULT_DEDUPE_CAPACITY);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_panics() {
        let _cache = DedupeCache::new(0);
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(DedupeCache::new(1024));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let id = SectorId::new();
                    c.mark(id);
                    let _ = c.seen(id);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert!(cache.len() <= 1024);
    }
}
