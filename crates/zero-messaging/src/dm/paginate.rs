//! Cursor-based pagination for DM conversation history.
//!
//! [`paginate_messages`] performs the RocksDB scan used by
//! [`super::service::DmService::history`].

use rocksdb::{Direction, IteratorMode};
use zero_storage::db::ZeroDb;
use zero_storage::CF_CHAINS;

use super::types::{ConversationId, Message, MessageId};
use super::DmError;

const MSG_KEY_PREFIX: &[u8] = b"dm_msg:";

fn make_msg_prefix(conversation_id: &ConversationId) -> Vec<u8> {
    let mut key = Vec::with_capacity(MSG_KEY_PREFIX.len() + 32);
    key.extend_from_slice(MSG_KEY_PREFIX);
    key.extend_from_slice(&conversation_id.0);
    key
}

fn make_msg_key(conversation_id: &ConversationId, message_id: &MessageId) -> Vec<u8> {
    let mut key = make_msg_prefix(conversation_id);
    key.extend_from_slice(&message_id.0);
    key
}

/// Increment the last non-0xff byte so the result is the smallest key greater
/// than every key sharing the original prefix.
fn increment_bytes(v: &mut Vec<u8>) {
    for byte in v.iter_mut().rev() {
        if *byte < 0xff {
            *byte += 1;
            return;
        }
        *byte = 0;
    }
    // All bytes were 0xff; push an extra byte (prefix is already beyond range).
    v.push(1);
}

/// Standalone paginator used independently of [`super::service::DmService`].
///
/// Returns up to `limit` messages for `conversation_id` in **descending**
/// `created_at_ms` order. `before` is an exclusive upper bound; pass `None`
/// to start from the latest message.
pub fn paginate_messages(
    db: &ZeroDb,
    conversation_id: ConversationId,
    before: Option<MessageId>,
    limit: usize,
) -> Result<Vec<Message>, DmError> {
    if limit == 0 {
        return Ok(vec![]);
    }

    let cf = db.cf_handle(CF_CHAINS)?;
    let prefix = make_msg_prefix(&conversation_id);

    let seek_key: Vec<u8>;
    let mode = match before {
        Some(ref id) => {
            seek_key = make_msg_key(&conversation_id, id);
            IteratorMode::From(&seek_key, Direction::Reverse)
        }
        None => {
            seek_key = {
                let mut upper = prefix.clone();
                increment_bytes(&mut upper);
                upper
            };
            IteratorMode::From(&seek_key, Direction::Reverse)
        }
    };

    let iter = db.inner().iterator_cf(cf, mode);
    let mut results = Vec::with_capacity(limit);

    for item in iter {
        let (k, v) = item.map_err(|e| DmError::Codec(e.to_string()))?;
        if !k.starts_with(&prefix) {
            break;
        }
        // Exclude the seek key itself when using a `before` cursor.
        if before.is_some() && k.as_ref() == seek_key.as_slice() {
            continue;
        }
        let msg: Message = postcard::from_bytes(&v).map_err(|e| DmError::Codec(e.to_string()))?;
        results.push(msg);
        if results.len() >= limit {
            break;
        }
    }

    Ok(results)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use proptest::prelude::*;
    use tempfile::TempDir;
    use zero_crypto::aad::{IdentityId, MachineId};
    use zero_storage::db::ZeroDb;

    use super::super::service::DmService;
    use super::super::types::{ConversationId, Message, MessageId, MessageStatus};
    use crate::contacts::store::ContactStore;
    use crate::contacts::types::Contact;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn open_db() -> (TempDir, Arc<ZeroDb>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(ZeroDb::open(dir.path()).unwrap());
        (dir, db)
    }

    fn alice_id() -> IdentityId {
        IdentityId([1u8; 16])
    }

    fn bob_id() -> IdentityId {
        IdentityId([2u8; 16])
    }

    fn machine_id() -> MachineId {
        MachineId([0u8; 16])
    }

    fn make_service(db: Arc<ZeroDb>) -> (DmService, IdentityId, IdentityId) {
        let alice = alice_id();
        let bob = bob_id();
        let machine = machine_id();
        let contacts = Arc::new(ContactStore::new(Arc::clone(&db), alice));
        contacts
            .add_contact(Contact {
                identity_id: bob,
                label: "Bob".to_string(),
                machine_keys: vec![],
                last_seen_epoch: None,
                added_at_ms: 0,
            })
            .unwrap();
        let svc = DmService::new(Arc::clone(&db), alice, machine, contacts);
        (svc, alice, bob)
    }

    /// Build a deterministic `MessageId` from an index. Larger index => larger
    /// key (and therefore newer in the reverse iterator).
    fn msg_id(i: u64) -> MessageId {
        let mut bytes = [0u8; 16];
        bytes[8..16].copy_from_slice(&i.to_be_bytes());
        MessageId(bytes)
    }

    fn make_message(conv_id: ConversationId, i: u64) -> Message {
        Message {
            id: msg_id(i),
            conversation_id: conv_id,
            sender_identity: alice_id(),
            sender_machine: machine_id(),
            text: format!("msg {i}"),
            status: MessageStatus::Queued,
            created_at_ms: i * 1000,
            status_updated_at_ms: i * 1000,
        }
    }

    fn store_n_messages(svc: &DmService, conv_id: ConversationId, n: u64) {
        for i in 0..n {
            svc.store_message(&make_message(conv_id, i)).unwrap();
        }
    }

    // ── unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn paginate_empty_returns_empty() {
        let (_dir, db) = open_db();
        let (svc, _alice, bob) = make_service(db);
        let conv = svc.open_conversation(bob).unwrap();
        let page = svc.history(conv.conversation_id, None, 10).unwrap();
        assert!(page.is_empty());
    }

    #[test]
    fn paginate_returns_descending_order() {
        let (_dir, db) = open_db();
        let (svc, _alice, bob) = make_service(db);
        let conv = svc.open_conversation(bob).unwrap();
        store_n_messages(&svc, conv.conversation_id, 5);

        let page = svc.history(conv.conversation_id, None, 10).unwrap();
        assert_eq!(page.len(), 5);
        // IDs must be strictly decreasing (newest first).
        for w in page.windows(2) {
            assert!(w[0].id.0 > w[1].id.0, "expected descending order");
        }
    }

    #[test]
    fn paginate_respects_limit() {
        let (_dir, db) = open_db();
        let (svc, _alice, bob) = make_service(db);
        let conv = svc.open_conversation(bob).unwrap();
        store_n_messages(&svc, conv.conversation_id, 10);

        let page = svc.history(conv.conversation_id, None, 5).unwrap();
        assert_eq!(page.len(), 5);
        // First page should be the 5 newest: indices 9, 8, 7, 6, 5.
        assert_eq!(page[0].id, msg_id(9));
        assert_eq!(page[4].id, msg_id(5));
    }

    #[test]
    fn paginate_before_cursor_excludes_boundary() {
        let (_dir, db) = open_db();
        let (svc, _alice, bob) = make_service(db);
        let conv = svc.open_conversation(bob).unwrap();
        store_n_messages(&svc, conv.conversation_id, 10);

        // Request page starting strictly before index 5.
        let page = svc
            .history(conv.conversation_id, Some(msg_id(5)), 10)
            .unwrap();
        // Should return indices 4, 3, 2, 1, 0 (5 messages, msg_id(5) excluded).
        assert_eq!(page.len(), 5);
        assert_eq!(page[0].id, msg_id(4));
        assert_eq!(page[4].id, msg_id(0));
        assert!(!page.iter().any(|m| m.id == msg_id(5)));
    }

    #[test]
    fn paginate_successive_pages_cover_full_history() {
        let (_dir, db) = open_db();
        let (svc, _alice, bob) = make_service(db);
        let conv = svc.open_conversation(bob).unwrap();
        store_n_messages(&svc, conv.conversation_id, 10);

        let page_size = 3usize;
        let mut all: Vec<MessageId> = Vec::new();
        let mut cursor: Option<MessageId> = None;

        loop {
            let page = svc
                .history(conv.conversation_id, cursor, page_size)
                .unwrap();
            if page.is_empty() {
                break;
            }
            cursor = Some(page.last().unwrap().id);
            all.extend(page.iter().map(|m| m.id));
        }

        // All 10 messages recovered, in descending order, no duplicates.
        assert_eq!(all.len(), 10);
        let expected: Vec<MessageId> = (0..10u64).rev().map(msg_id).collect();
        assert_eq!(all, expected);
    }

    // ── proptest ──────────────────────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_successive_pages_are_contiguous_descending_nonoverlapping(
            n in 1usize..=20,
            page_size in 1usize..=5,
        ) {
            let dir = TempDir::new().unwrap();
            let db = Arc::new(ZeroDb::open(dir.path()).unwrap());
            let (svc, _alice, bob) = make_service(db);
            let conv = svc.open_conversation(bob).unwrap();

            // Store n messages with deterministic IDs.
            for i in 0..n as u64 {
                svc.store_message(&make_message(conv.conversation_id, i)).unwrap();
            }

            // Collect all pages via cursor chaining.
            let mut all_ids: Vec<MessageId> = Vec::new();
            let mut cursor: Option<MessageId> = None;

            loop {
                let page = svc
                    .history(conv.conversation_id, cursor, page_size)
                    .unwrap();
                if page.is_empty() {
                    break;
                }

                // Each page must be internally descending.
                for w in page.windows(2) {
                    prop_assert!(w[0].id.0 > w[1].id.0,
                        "page not descending: {:?} >= {:?}", w[0].id, w[1].id);
                }

                // The first element of this page must be strictly less than the
                // last element of the previous page (no overlap, no gap).
                if let Some(prev_last) = all_ids.last() {
                    prop_assert!(page[0].id.0 < prev_last.0,
                        "overlap or non-contiguous boundary");
                    // Also verify no ID from this page appeared before.
                    for m in &page {
                        prop_assert!(!all_ids.contains(&m.id),
                            "duplicate message {:?}", m.id);
                    }
                }

                cursor = Some(page.last().unwrap().id);
                all_ids.extend(page.iter().map(|m| m.id));
            }

            // Exactly n messages, newest-first.
            prop_assert_eq!(all_ids.len(), n);
            let expected: Vec<MessageId> = (0..n as u64).rev().map(msg_id).collect();
            prop_assert_eq!(all_ids, expected);
        }
    }
}
