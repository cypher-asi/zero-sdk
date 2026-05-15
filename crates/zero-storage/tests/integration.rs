//! Full storage lifecycle integration test.
//!
//! Opens a DB on a temp dir, puts 100 sectors across 3 machine-ids,
//! iterates chains per scope, verifies dedupe rejects replayed sectors,
//! exercises the outbox, then reopens the DB and confirms durability.

use std::thread;
use std::time::Duration;

use tempfile::TempDir;
use zero_storage::{DedupeCache, Outbox, OutboxEntry, Sector, SectorId, ZeroDb};

fn make_sector(identity_id: &str, machine_id: &str, prev: Option<SectorId>) -> Sector {
    // Small sleep so UUIDv7 timestamps differ and ordering is deterministic.
    thread::sleep(Duration::from_millis(1));
    Sector {
        id: SectorId::new(),
        kind: "test.sector.v1".to_string(),
        identity_id: identity_id.to_string(),
        machine_id: machine_id.to_string(),
        created_at: 0,
        payload: vec![0xAB; 32],
        prev,
    }
}

#[test]
fn full_lifecycle() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().to_path_buf();

    let machine_ids = ["machine-a", "machine-b", "machine-c"];
    let identity_id = "identity-1";

    // Track inserted sector IDs per machine for later verification.
    let mut ids_per_machine: [Vec<SectorId>; 3] = [Vec::new(), Vec::new(), Vec::new()];

    // -- Phase 1: Insert 100 sectors (round-robin across 3 machines) ----------
    {
        let db = ZeroDb::open(&db_path).unwrap();

        for i in 0..100u32 {
            let machine_idx = (i % 3) as usize;
            let machine_id = machine_ids[machine_idx];
            let prev = ids_per_machine[machine_idx].last().copied();

            let sector = make_sector(identity_id, machine_id, prev);
            let sid = sector.id;

            db.put_sector(&sector).unwrap();
            ids_per_machine[machine_idx].push(sid);
        }

        // -- Phase 2: Iterate chain per scope and verify counts ---------------
        // machine-a gets indices 0,3,6,...,99 => 34 sectors
        // machine-b gets indices 1,4,7,...,97 => 33 sectors
        // machine-c gets indices 2,5,8,...,98 => 33 sectors
        let expected_counts = [34usize, 33, 33];

        for (idx, machine_id) in machine_ids.iter().enumerate() {
            let chain = db.iter_chain(identity_id, machine_id).unwrap();
            assert_eq!(
                chain.len(),
                expected_counts[idx],
                "chain length mismatch for {machine_id}"
            );

            // Verify chronological ordering (UUIDv7 sorts ascending).
            for window in chain.windows(2) {
                assert!(
                    window[0].id < window[1].id,
                    "sectors should be in ascending order for {machine_id}"
                );
            }

            // Verify the IDs match what we inserted.
            let chain_ids: Vec<SectorId> = chain.iter().map(|s| s.id).collect();
            assert_eq!(chain_ids, ids_per_machine[idx]);
        }

        // -- Phase 3: get_sector round-trip -----------------------------------
        for (idx, machine_id) in machine_ids.iter().enumerate() {
            for sid in &ids_per_machine[idx] {
                let fetched = db.get_sector(identity_id, machine_id, sid).unwrap();
                assert!(fetched.is_some(), "sector {sid} should exist");
                let fetched = fetched.unwrap();
                assert_eq!(fetched.id, *sid);
                assert_eq!(fetched.machine_id, *machine_id);
                assert_eq!(fetched.identity_id, identity_id);
            }
        }

        // -- Phase 4: Dedupe cache rejects replayed sector --------------------
        let dedupe = DedupeCache::new(256);
        let first_id = ids_per_machine[0][0];

        assert!(!dedupe.seen(first_id), "first check should report unseen");
        dedupe.mark(first_id);
        assert!(dedupe.seen(first_id), "second check should report seen");

        // Mark all 100 IDs, then re-check the first one is still seen.
        for ids in &ids_per_machine {
            for sid in ids {
                dedupe.mark(*sid);
            }
        }
        assert!(
            dedupe.seen(first_id),
            "first_id should still be cached (capacity=256 > 100)"
        );

        // -- Phase 5: Outbox enqueue / dequeue / ack --------------------------
        let outbox = Outbox::new(&db);
        let outbox_sid = ids_per_machine[1][0];
        let entry = OutboxEntry {
            sector_id: outbox_sid,
            payload: vec![0xCD; 16],
            attempt_count: 0,
            next_attempt_ms: 1000,
            created_at_ms: 500,
        };

        outbox.enqueue(entry.clone()).unwrap();

        // Not yet due at t=999
        let due = outbox.dequeue_due(999).unwrap();
        assert!(
            due.is_empty(),
            "entry should not be due before next_attempt_ms"
        );

        // Due at t=1000
        let due = outbox.dequeue_due(1000).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].sector_id, outbox_sid);

        // Idempotent enqueue
        outbox.enqueue(entry).unwrap();
        let due = outbox.dequeue_due(1000).unwrap();
        assert_eq!(
            due.len(),
            1,
            "idempotent enqueue should not create a duplicate"
        );

        // mark_attempted bumps attempt_count
        outbox.mark_attempted(outbox_sid, 2000).unwrap();
        let due = outbox.dequeue_due(1500).unwrap();
        assert!(
            due.is_empty(),
            "entry rescheduled to 2000 should not be due at 1500"
        );
        let due = outbox.dequeue_due(2000).unwrap();
        assert_eq!(due[0].attempt_count, 1);

        // ack (remove)
        outbox.remove(outbox_sid).unwrap();
        let due = outbox.dequeue_due(u64::MAX).unwrap();
        assert!(due.is_empty(), "removed entry should be gone");
    }

    // -- Phase 6: Reopen DB and confirm durability ----------------------------
    {
        let db = ZeroDb::open(&db_path).unwrap();

        // All 100 sectors should survive the reopen.
        for (idx, machine_id) in machine_ids.iter().enumerate() {
            let chain = db.iter_chain(identity_id, machine_id).unwrap();
            let expected_count = ids_per_machine[idx].len();
            assert_eq!(
                chain.len(),
                expected_count,
                "after reopen: chain length mismatch for {machine_id}"
            );

            let chain_ids: Vec<SectorId> = chain.iter().map(|s| s.id).collect();
            assert_eq!(
                chain_ids, ids_per_machine[idx],
                "after reopen: sector IDs should match for {machine_id}"
            );
        }

        // Spot-check a single sector's payload survived.
        let spot_id = ids_per_machine[2][5];
        let sector = db
            .get_sector(identity_id, machine_ids[2], &spot_id)
            .unwrap()
            .expect("spot-check sector should exist after reopen");
        assert_eq!(sector.payload, vec![0xAB; 32]);

        // Outbox entry was removed before close, so it should remain gone.
        let outbox = Outbox::new(&db);
        let due = outbox.dequeue_due(u64::MAX).unwrap();
        assert!(
            due.is_empty(),
            "outbox should be empty after reopen (entry was acked)"
        );

        // Delete a sector and verify it is gone.
        let del_id = ids_per_machine[0][0];
        db.delete_sector(identity_id, machine_ids[0], &del_id)
            .unwrap();
        let gone = db.get_sector(identity_id, machine_ids[0], &del_id).unwrap();
        assert!(gone.is_none(), "deleted sector should return None");
    }
}
