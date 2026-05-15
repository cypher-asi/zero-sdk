//! Persistent outbox queue for retryable outbound sector deliveries.
//!
//! Entries are stored in `CF_OUTBOX` keyed by `SectorId` (16 bytes).
//! The queue is bounded; attempts to enqueue beyond capacity return
//! `StorageError::OutboxFull`.

use serde::{Deserialize, Serialize};

use crate::db::{ZeroDb, CF_OUTBOX};
use crate::error::StorageError;
use crate::sector::SectorId;

pub const DEFAULT_OUTBOX_CAPACITY: usize = 1_000;

/// A single outbox entry persisted in RocksDB.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub sector_id: SectorId,
    pub payload: Vec<u8>,
    pub attempt_count: u8,
    pub next_attempt_ms: u64,
    pub created_at_ms: u64,
}

/// Persistent bounded outbox queue backed by `CF_OUTBOX`.
pub struct Outbox<'db> {
    db: &'db ZeroDb,
    capacity: usize,
}

impl<'db> Outbox<'db> {
    pub fn new(db: &'db ZeroDb) -> Self {
        Self {
            db,
            capacity: DEFAULT_OUTBOX_CAPACITY,
        }
    }

    pub fn with_capacity(db: &'db ZeroDb, capacity: usize) -> Self {
        Self { db, capacity }
    }

    /// Enqueue a sector for delivery. Idempotent by `SectorId`: if the entry
    /// already exists, this is a no-op. Returns `OutboxFull` when the queue
    /// is at capacity and the entry is new.
    pub fn enqueue(&self, entry: OutboxEntry) -> Result<(), StorageError> {
        let key = entry.sector_id.as_bytes().as_slice();

        if self.db.get_raw(CF_OUTBOX, key)?.is_some() {
            return Ok(());
        }

        let count = self.count()?;
        if count >= self.capacity {
            return Err(StorageError::OutboxFull);
        }

        let value = postcard::to_stdvec(&entry).map_err(StorageError::from)?;
        self.db.put_raw(CF_OUTBOX, key, &value)?;
        Ok(())
    }

    /// Return all entries whose `next_attempt_ms <= now_ms`, ordered by
    /// `next_attempt_ms` ascending (FIFO by scheduled time).
    pub fn dequeue_due(&self, now_ms: u64) -> Result<Vec<OutboxEntry>, StorageError> {
        let all = self.scan_all()?;
        let mut due: Vec<OutboxEntry> = all
            .into_iter()
            .filter(|e| e.next_attempt_ms <= now_ms)
            .collect();
        due.sort_by_key(|e| e.next_attempt_ms);
        Ok(due)
    }

    /// Update `attempt_count` and `next_attempt_ms` after a failed delivery.
    pub fn mark_attempted(&self, id: SectorId, next_attempt_ms: u64) -> Result<(), StorageError> {
        let key = id.as_bytes().as_slice();
        let raw = self
            .db
            .get_raw(CF_OUTBOX, key)?
            .ok_or(StorageError::SectorNotFound(id))?;
        let mut entry: OutboxEntry = postcard::from_bytes(&raw).map_err(StorageError::from)?;
        entry.attempt_count = entry.attempt_count.saturating_add(1);
        entry.next_attempt_ms = next_attempt_ms;
        let value = postcard::to_stdvec(&entry).map_err(StorageError::from)?;
        self.db.put_raw(CF_OUTBOX, key, &value)?;
        Ok(())
    }

    /// Remove an entry (acknowledge successful delivery).
    pub fn remove(&self, id: SectorId) -> Result<(), StorageError> {
        self.db.delete_raw(CF_OUTBOX, id.as_bytes().as_slice())
    }

    /// Count entries currently in the outbox.
    fn count(&self) -> Result<usize, StorageError> {
        let cf = self.db.cf_handle(CF_OUTBOX)?;
        let iter = self
            .db
            .inner()
            .iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut n = 0usize;
        for item in iter {
            let _kv = item?;
            n += 1;
        }
        Ok(n)
    }

    /// Scan all entries in CF_OUTBOX.
    fn scan_all(&self) -> Result<Vec<OutboxEntry>, StorageError> {
        let cf = self.db.cf_handle(CF_OUTBOX)?;
        let iter = self
            .db
            .inner()
            .iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut entries = Vec::new();
        for item in iter {
            let (_k, v) = item?;
            let entry: OutboxEntry = postcard::from_bytes(&v).map_err(StorageError::from)?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_db() -> (TempDir, ZeroDb) {
        let tmp = TempDir::new().unwrap();
        let db = ZeroDb::open(tmp.path()).unwrap();
        (tmp, db)
    }

    fn make_entry(next_ms: u64) -> OutboxEntry {
        OutboxEntry {
            sector_id: SectorId::new(),
            payload: vec![1, 2, 3],
            attempt_count: 0,
            next_attempt_ms: next_ms,
            created_at_ms: next_ms.saturating_sub(100),
        }
    }

    #[test]
    fn enqueue_and_dequeue_due() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::new(&db);

        let entry = make_entry(1000);
        let sid = entry.sector_id;
        outbox.enqueue(entry.clone()).unwrap();

        let due = outbox.dequeue_due(1000).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].sector_id, sid);
    }

    #[test]
    fn dequeue_due_before_time_returns_empty() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::new(&db);

        outbox.enqueue(make_entry(5000)).unwrap();
        let due = outbox.dequeue_due(4999).unwrap();
        assert!(due.is_empty());
    }

    #[test]
    fn dequeue_due_fifo_ordering_by_next_attempt() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::new(&db);

        let e1 = make_entry(3000);
        let e2 = make_entry(1000);
        let e3 = make_entry(2000);

        outbox.enqueue(e1.clone()).unwrap();
        outbox.enqueue(e2.clone()).unwrap();
        outbox.enqueue(e3.clone()).unwrap();

        let due = outbox.dequeue_due(5000).unwrap();
        assert_eq!(due.len(), 3);
        assert_eq!(due[0].sector_id, e2.sector_id);
        assert_eq!(due[1].sector_id, e3.sector_id);
        assert_eq!(due[2].sector_id, e1.sector_id);
    }

    #[test]
    fn remove_deletes_entry() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::new(&db);

        let entry = make_entry(1000);
        let sid = entry.sector_id;
        outbox.enqueue(entry).unwrap();

        outbox.remove(sid).unwrap();
        let due = outbox.dequeue_due(u64::MAX).unwrap();
        assert!(due.is_empty());
    }

    #[test]
    fn enqueue_idempotent_same_sector_id() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::new(&db);

        let entry = make_entry(1000);
        outbox.enqueue(entry.clone()).unwrap();
        outbox.enqueue(entry).unwrap();

        let due = outbox.dequeue_due(u64::MAX).unwrap();
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn mark_attempted_updates_entry() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::new(&db);

        let entry = make_entry(1000);
        let sid = entry.sector_id;
        outbox.enqueue(entry).unwrap();

        outbox.mark_attempted(sid, 5000).unwrap();

        let due = outbox.dequeue_due(1000).unwrap();
        assert!(due.is_empty(), "should not be due yet after reschedule");

        let due = outbox.dequeue_due(5000).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempt_count, 1);
        assert_eq!(due[0].next_attempt_ms, 5000);
    }

    #[test]
    fn mark_attempted_missing_returns_error() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::new(&db);

        let result = outbox.mark_attempted(SectorId::new(), 5000);
        assert!(result.is_err());
    }

    #[test]
    fn capacity_bound_enforced() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::with_capacity(&db, 3);

        outbox.enqueue(make_entry(1000)).unwrap();
        outbox.enqueue(make_entry(2000)).unwrap();
        outbox.enqueue(make_entry(3000)).unwrap();

        let result = outbox.enqueue(make_entry(4000));
        match result {
            Err(StorageError::OutboxFull) => {}
            other => panic!("expected OutboxFull, got: {other:?}"),
        }
    }

    #[test]
    fn capacity_bound_allows_idempotent_insert_at_limit() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::with_capacity(&db, 2);

        let entry = make_entry(1000);
        outbox.enqueue(entry.clone()).unwrap();
        outbox.enqueue(make_entry(2000)).unwrap();

        // Re-enqueue existing entry should succeed even at capacity
        outbox.enqueue(entry).unwrap();
    }

    #[test]
    fn durable_across_reopen() {
        let tmp = TempDir::new().unwrap();

        let entry = make_entry(1000);
        let sid = entry.sector_id;

        {
            let db = ZeroDb::open(tmp.path()).unwrap();
            let outbox = Outbox::new(&db);
            outbox.enqueue(entry.clone()).unwrap();
        }

        {
            let db = ZeroDb::open(tmp.path()).unwrap();
            let outbox = Outbox::new(&db);
            let due = outbox.dequeue_due(u64::MAX).unwrap();
            assert_eq!(due.len(), 1);
            assert_eq!(due[0].sector_id, sid);
            assert_eq!(due[0].payload, vec![1, 2, 3]);
        }
    }

    #[test]
    fn remove_then_capacity_frees_slot() {
        let (_tmp, db) = open_db();
        let outbox = Outbox::with_capacity(&db, 2);

        let e1 = make_entry(1000);
        let sid1 = e1.sector_id;
        outbox.enqueue(e1).unwrap();
        outbox.enqueue(make_entry(2000)).unwrap();

        // At capacity
        assert!(outbox.enqueue(make_entry(3000)).is_err());

        // Remove one -> slot freed
        outbox.remove(sid1).unwrap();
        outbox.enqueue(make_entry(3000)).unwrap();
    }
}
