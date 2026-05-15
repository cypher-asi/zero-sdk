//! DmService: open and resume 1:1 conversations.

use std::sync::Arc;

use zero_crypto::aad::{IdentityId, MachineId};
use zero_storage::db::ZeroDb;
use zero_storage::outbox::{Outbox, OutboxEntry};
use zero_storage::sector::SectorId;
use zero_storage::CF_CHAINS;

use crate::contacts::store::ContactStore;

use super::receipt::enqueue_receipt;
use super::types::{
    Conversation, ConversationId, DmSectorPayload, Message, MessageId, MessageStatus,
    ReceiptPayload,
};
use super::DmError;

const MSG_KEY_PREFIX: &[u8] = b"dm_msg:";

fn make_msg_key(conversation_id: &ConversationId, message_id: &MessageId) -> Vec<u8> {
    let mut key = Vec::with_capacity(MSG_KEY_PREFIX.len() + 32 + 16);
    key.extend_from_slice(MSG_KEY_PREFIX);
    key.extend_from_slice(&conversation_id.0);
    key.extend_from_slice(&message_id.0);
    key
}

fn make_msg_prefix(conversation_id: &ConversationId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(MSG_KEY_PREFIX.len() + 32);
    prefix.extend_from_slice(MSG_KEY_PREFIX);
    prefix.extend_from_slice(&conversation_id.0);
    prefix
}

/// Manages 1:1 direct-message conversations.
pub struct DmService {
    db: Arc<ZeroDb>,
    identity: IdentityId,
    machine_id: MachineId,
    contacts: Arc<ContactStore>,
}

impl DmService {
    pub fn new(
        db: Arc<ZeroDb>,
        identity: IdentityId,
        machine_id: MachineId,
        contacts: Arc<ContactStore>,
    ) -> Self {
        Self {
            db,
            identity,
            machine_id,
            contacts,
        }
    }

    /// Open a new conversation with `peer` or return the existing one.
    /// The peer must already exist in the `ContactStore`.
    pub fn open_conversation(&self, peer: IdentityId) -> Result<Conversation, DmError> {
        if self.contacts.get_contact(&peer)?.is_none() {
            return Err(DmError::ContactNotFound(peer));
        }

        let conv_id = ConversationId::derive(self.identity, peer);
        let key = conv_id.storage_key();

        if let Some(bytes) = self.db.get_raw(CF_CHAINS, &key)? {
            let conv: Conversation =
                postcard::from_bytes(&bytes).map_err(|e| DmError::Codec(e.to_string()))?;
            return Ok(conv);
        }

        let conv = Conversation {
            conversation_id: conv_id,
            peer_identity: peer,
            last_sector: None,
        };

        let encoded = postcard::to_allocvec(&conv).map_err(|e| DmError::Codec(e.to_string()))?;
        self.db.put_raw(CF_CHAINS, &key, &encoded)?;

        Ok(conv)
    }

    /// Resume an existing conversation by its `ConversationId`.
    pub fn resume_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Conversation, DmError> {
        let key = conversation_id.storage_key();
        let bytes = self
            .db
            .get_raw(CF_CHAINS, &key)?
            .ok_or(DmError::UnknownConversation(conversation_id))?;
        let conv: Conversation =
            postcard::from_bytes(&bytes).map_err(|e| DmError::Codec(e.to_string()))?;
        Ok(conv)
    }

    /// Persist an updated conversation (e.g. after updating `last_sector`).
    pub fn save_conversation(&self, conv: &Conversation) -> Result<(), DmError> {
        let key = conv.conversation_id.storage_key();
        let encoded = postcard::to_allocvec(conv).map_err(|e| DmError::Codec(e.to_string()))?;
        self.db.put_raw(CF_CHAINS, &key, &encoded)?;
        Ok(())
    }

    /// Persist a `Message` into the message index.
    pub fn store_message(&self, msg: &Message) -> Result<(), DmError> {
        let key = make_msg_key(&msg.conversation_id, &msg.id);
        let encoded = postcard::to_allocvec(msg).map_err(|e| DmError::Codec(e.to_string()))?;
        self.db.put_raw(CF_CHAINS, &key, &encoded)?;
        Ok(())
    }

    /// Cursor-based message history.
    ///
    /// Returns up to `limit` messages for `conversation_id` in **descending**
    /// `created_at_ms` order (newest first). When `before` is `Some(id)` the
    /// returned page starts strictly before that message id (exclusive upper
    /// bound). When `before` is `None` the page starts from the latest message.
    ///
    /// Successive calls where the caller passes the oldest returned message's
    /// id as `before` yield contiguous, non-overlapping windows over the full
    /// conversation history.
    pub fn history(
        &self,
        conversation_id: ConversationId,
        before: Option<MessageId>,
        limit: usize,
    ) -> Result<Vec<Message>, DmError> {
        use rocksdb::{Direction, IteratorMode};

        let cf = self.db.cf_handle(CF_CHAINS)?;
        let prefix = make_msg_prefix(&conversation_id);

        // Build seek key with long enough lifetime for the iterator.
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

        let iter = self.db.inner().iterator_cf(cf, mode);

        let mut results = Vec::with_capacity(limit);
        for item in iter {
            let (k, v) = item.map_err(|e| DmError::Codec(e.to_string()))?;
            // Stop once we leave the conversation prefix.
            if !k.starts_with(&prefix) {
                break;
            }
            // For the `before` case the seek key itself must be excluded.
            if before.is_some() && k.as_ref() == seek_key.as_slice() {
                continue;
            }
            let msg: Message =
                postcard::from_bytes(&v).map_err(|e| DmError::Codec(e.to_string()))?;
            results.push(msg);
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    /// Retrieve a single message by conversation and message ID.
    pub fn get_message(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
    ) -> Result<Option<Message>, DmError> {
        let key = make_msg_key(&conversation_id, &message_id);
        let cf = self.db.cf_handle(CF_CHAINS)?;
        match self.db.inner().get_cf(cf, &key) {
            Ok(Some(bytes)) => {
                let msg: Message =
                    postcard::from_bytes(&bytes).map_err(|e| DmError::Codec(e.to_string()))?;
                Ok(Some(msg))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DmError::Codec(e.to_string())),
        }
    }

    /// Advance a message's status monotonically.
    /// Returns `Err(InvalidStatusTransition)` on backward or equal transitions.
    pub fn update_status(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        new_status: MessageStatus,
    ) -> Result<(), DmError> {
        let msg = self
            .get_message(conversation_id, message_id)?
            .ok_or(DmError::MessageNotFound(message_id))?;

        if !msg.status.is_valid_transition(new_status) {
            return Err(DmError::InvalidStatusTransition {
                from: msg.status,
                to: new_status,
            });
        }

        let updated = Message {
            status: new_status,
            status_updated_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..msg
        };
        self.store_message(&updated)?;
        Ok(())
    }

    /// Process an inbound `zero.receipt.v1` payload.
    /// Updates the local message status to the receipt's status value.
    pub fn process_receipt(&self, receipt: &ReceiptPayload) -> Result<(), DmError> {
        self.update_status(receipt.conversation_id, receipt.message_id, receipt.status)
    }

    /// Mark a message as `Read` locally and return a `ReceiptPayload` to emit.
    pub fn mark_read(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
    ) -> Result<ReceiptPayload, DmError> {
        self.update_status(conversation_id, message_id, MessageStatus::Read)?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(ReceiptPayload {
            message_id,
            conversation_id,
            recipient_identity: self.identity,
            recipient_machine: self.machine_id,
            status: MessageStatus::Read,
            timestamp_ms: now_ms,
        })
    }

    /// Mark a message as `Read` and enqueue the Read receipt in the outbox
    /// so it is published to the sender.
    pub fn mark_read_and_emit(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        outbox: &Outbox<'_>,
    ) -> Result<ReceiptPayload, DmError> {
        let receipt = self.mark_read(conversation_id, message_id)?;
        enqueue_receipt(outbox, &receipt)?;
        Ok(receipt)
    }

    /// Send a plain-text message in an existing conversation.
    ///
    /// Creates a `Message` with status `Queued`, persists it, builds a
    /// `DmSectorPayload` (schema tag `"zero.dm.v1"`), and enqueues the
    /// serialized payload into the `Outbox` for retry-aware delivery.
    /// The conversation's `last_sector` is updated to the new sector id.
    pub fn send_text(
        &self,
        conversation_id: ConversationId,
        text: String,
    ) -> Result<MessageId, DmError> {
        let mut conv = self.resume_conversation(conversation_id)?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let message_id = MessageId::new();
        let sector_id = SectorId::new();

        let msg = Message {
            id: message_id,
            conversation_id,
            sender_identity: self.identity,
            sender_machine: self.machine_id,
            text: text.clone(),
            status: MessageStatus::Queued,
            created_at_ms: now_ms,
            status_updated_at_ms: now_ms,
        };
        self.store_message(&msg)?;

        let sector_payload = DmSectorPayload {
            message_id,
            conversation_id,
            sender_identity: self.identity,
            sender_machine: self.machine_id,
            text,
            created_at_ms: now_ms,
        };

        let payload_bytes =
            postcard::to_allocvec(&sector_payload).map_err(|e| DmError::Codec(e.to_string()))?;

        let entry = OutboxEntry {
            sector_id,
            payload: payload_bytes,
            attempt_count: 0,
            next_attempt_ms: now_ms,
            created_at_ms: now_ms,
        };

        let outbox = Outbox::new(&self.db);
        outbox.enqueue(entry)?;

        conv.last_sector = Some(sector_id);
        self.save_conversation(&conv)?;

        Ok(message_id)
    }

    /// Acknowledge that a message was successfully published by the outbox.
    /// Transitions the message status from `Queued` to `Sent`.
    pub fn acknowledge_sent(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
    ) -> Result<(), DmError> {
        self.update_status(conversation_id, message_id, MessageStatus::Sent)
    }
}

/// Increment a byte vector as a big-endian unsigned integer.
fn increment_bytes(v: &mut Vec<u8>) {
    for byte in v.iter_mut().rev() {
        if *byte < 0xFF {
            *byte += 1;
            return;
        }
        *byte = 0;
    }
    // All bytes were 0xFF; push an extra byte.
    v.insert(0, 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::types::Contact;
    use tempfile::TempDir;
    use zero_storage::sector::SectorId;

    fn setup() -> (
        TempDir,
        Arc<ZeroDb>,
        Arc<ContactStore>,
        IdentityId,
        IdentityId,
    ) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(ZeroDb::open(dir.path()).unwrap());

        let alice = IdentityId([1u8; 16]);
        let bob = IdentityId([2u8; 16]);

        let contacts = Arc::new(ContactStore::new(Arc::clone(&db), alice));

        contacts
            .add_contact(Contact {
                identity_id: bob,
                label: "Bob".to_string(),
                machine_keys: vec![],
                last_seen_epoch: None,
                added_at_ms: 1000,
            })
            .unwrap();

        (dir, db, contacts, alice, bob)
    }

    #[test]
    fn open_conversation_creates_and_returns_same_id() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);

        let c1 = svc.open_conversation(bob).unwrap();
        let c2 = svc.open_conversation(bob).unwrap();

        assert_eq!(c1.conversation_id, c2.conversation_id);
        assert_eq!(c1.peer_identity, bob);
        assert!(c1.last_sector.is_none());
    }

    #[test]
    fn open_conversation_unknown_peer_returns_error() {
        let (_dir, db, contacts, alice, _bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);

        let unknown = IdentityId([99u8; 16]);
        let err = svc.open_conversation(unknown).unwrap_err();
        assert!(matches!(err, DmError::ContactNotFound(_)));
    }

    #[test]
    fn resume_conversation_round_trip() {
        let (_dir, db, contacts, alice, bob) = setup();
        let svc = DmService::new(
            Arc::clone(&db),
            alice,
            MachineId([0xAA; 16]),
            Arc::clone(&contacts),
        );

        let conv = svc.open_conversation(bob).unwrap();
        let resumed = svc.resume_conversation(conv.conversation_id).unwrap();

        assert_eq!(conv.conversation_id, resumed.conversation_id);
        assert_eq!(conv.peer_identity, resumed.peer_identity);
        assert_eq!(conv.last_sector, resumed.last_sector);
    }

    #[test]
    fn resume_unknown_conversation_returns_error() {
        let (_dir, db, contacts, alice, _bob) = setup();
        let svc = DmService::new(db, alice, MachineId([0xAA; 16]), contacts);

        let fake_id = ConversationId([0xABu8; 32]);
        let err = svc.resume_conversation(fake_id).unwrap_err();
        assert!(matches!(err, DmError::UnknownConversation(_)));
    }

    #[test]
    fn save_conversation_updates_last_sector() {
        let (_dir, db, contacts, alice, bob) = setup();
        let svc = DmService::new(db, alice, MachineId([0xAA; 16]), contacts);

        let mut conv = svc.open_conversation(bob).unwrap();
        assert!(conv.last_sector.is_none());

        let sector_id = SectorId::new();
        conv.last_sector = Some(sector_id);
        svc.save_conversation(&conv).unwrap();

        let resumed = svc.resume_conversation(conv.conversation_id).unwrap();
        assert_eq!(resumed.last_sector, Some(sector_id));
    }

    #[test]
    fn conversation_id_is_commutative() {
        let a = IdentityId([1u8; 16]);
        let b = IdentityId([2u8; 16]);
        assert_eq!(ConversationId::derive(a, b), ConversationId::derive(b, a),);
    }

    #[test]
    fn distinct_pairs_produce_distinct_conversation_ids() {
        let a = IdentityId([1u8; 16]);
        let b = IdentityId([2u8; 16]);
        let c = IdentityId([3u8; 16]);
        assert_ne!(ConversationId::derive(a, b), ConversationId::derive(a, c),);
    }

    fn make_test_message(
        conv_id: ConversationId,
        sender: IdentityId,
        machine: MachineId,
        text: &str,
    ) -> Message {
        let id = MessageId(uuid::Uuid::now_v7().into_bytes());
        Message {
            id,
            conversation_id: conv_id,
            sender_identity: sender,
            sender_machine: machine,
            text: text.to_string(),
            status: MessageStatus::Queued,
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            status_updated_at_ms: 0,
        }
    }

    #[test]
    fn get_message_returns_stored_message() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msg = make_test_message(conv.conversation_id, alice, machine, "hello");
        svc.store_message(&msg).unwrap();

        let found = svc.get_message(conv.conversation_id, msg.id).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().text, "hello");
    }

    #[test]
    fn get_message_returns_none_for_missing() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();
        let fake_id = MessageId([0xFFu8; 16]);
        let found = svc.get_message(conv.conversation_id, fake_id).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn update_status_monotonic_forward() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msg = make_test_message(conv.conversation_id, alice, machine, "hi");
        svc.store_message(&msg).unwrap();

        svc.update_status(conv.conversation_id, msg.id, MessageStatus::Sent)
            .unwrap();
        svc.update_status(conv.conversation_id, msg.id, MessageStatus::Delivered)
            .unwrap();
        svc.update_status(conv.conversation_id, msg.id, MessageStatus::Read)
            .unwrap();

        let final_msg = svc
            .get_message(conv.conversation_id, msg.id)
            .unwrap()
            .unwrap();
        assert_eq!(final_msg.status, MessageStatus::Read);
    }

    #[test]
    fn update_status_rejects_backward() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msg = make_test_message(conv.conversation_id, alice, machine, "hi");
        svc.store_message(&msg).unwrap();
        svc.update_status(conv.conversation_id, msg.id, MessageStatus::Delivered)
            .unwrap();

        let err = svc
            .update_status(conv.conversation_id, msg.id, MessageStatus::Sent)
            .unwrap_err();
        assert!(matches!(err, DmError::InvalidStatusTransition { .. }));
    }

    #[test]
    fn update_status_rejects_equal() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msg = make_test_message(conv.conversation_id, alice, machine, "hi");
        svc.store_message(&msg).unwrap();

        let err = svc
            .update_status(conv.conversation_id, msg.id, MessageStatus::Queued)
            .unwrap_err();
        assert!(matches!(err, DmError::InvalidStatusTransition { .. }));
    }

    #[test]
    fn process_receipt_updates_status() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine_a = MachineId([0xAAu8; 16]);
        let machine_b = MachineId([0xBBu8; 16]);
        let svc_a = DmService::new(db, alice, machine_a, contacts);
        let conv = svc_a.open_conversation(bob).unwrap();

        let msg = make_test_message(conv.conversation_id, alice, machine_a, "hello bob");
        svc_a.store_message(&msg).unwrap();
        svc_a
            .update_status(conv.conversation_id, msg.id, MessageStatus::Sent)
            .unwrap();

        let receipt = ReceiptPayload {
            message_id: msg.id,
            conversation_id: conv.conversation_id,
            recipient_identity: bob,
            recipient_machine: machine_b,
            status: MessageStatus::Delivered,
            timestamp_ms: 12345,
        };
        svc_a.process_receipt(&receipt).unwrap();

        let updated = svc_a
            .get_message(conv.conversation_id, msg.id)
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, MessageStatus::Delivered);
    }

    #[test]
    fn mark_read_updates_and_returns_receipt() {
        let (_dir, db, _contacts, alice, bob) = setup();
        let machine_b = MachineId([0xBBu8; 16]);

        let contacts_b = Arc::new(ContactStore::new(Arc::clone(&db), bob));
        contacts_b
            .add_contact(Contact {
                identity_id: alice,
                label: "Alice".to_string(),
                machine_keys: vec![],
                last_seen_epoch: None,
                added_at_ms: 2000,
            })
            .unwrap();

        let svc_b = DmService::new(Arc::clone(&db), bob, machine_b, contacts_b);
        let conv = svc_b.open_conversation(alice).unwrap();

        let msg = make_test_message(
            conv.conversation_id,
            alice,
            MachineId([0xAA; 16]),
            "hi from A",
        );
        svc_b.store_message(&msg).unwrap();
        svc_b
            .update_status(conv.conversation_id, msg.id, MessageStatus::Sent)
            .unwrap();
        svc_b
            .update_status(conv.conversation_id, msg.id, MessageStatus::Delivered)
            .unwrap();

        let receipt = svc_b.mark_read(conv.conversation_id, msg.id).unwrap();

        assert_eq!(receipt.message_id, msg.id);
        assert_eq!(receipt.conversation_id, conv.conversation_id);
        assert_eq!(receipt.status, MessageStatus::Read);
        assert_eq!(receipt.recipient_identity, bob);
        assert_eq!(receipt.recipient_machine, machine_b);

        let final_msg = svc_b
            .get_message(conv.conversation_id, msg.id)
            .unwrap()
            .unwrap();
        assert_eq!(final_msg.status, MessageStatus::Read);
    }

    #[test]
    fn delivered_then_read_round_trip() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine_a = MachineId([0xAAu8; 16]);
        let machine_b = MachineId([0xBBu8; 16]);

        let contacts_b = Arc::new(ContactStore::new(Arc::clone(&db), bob));
        contacts_b
            .add_contact(Contact {
                identity_id: alice,
                label: "Alice".to_string(),
                machine_keys: vec![],
                last_seen_epoch: None,
                added_at_ms: 2000,
            })
            .unwrap();

        let dir_b = tempfile::tempdir().unwrap();
        let db_b = Arc::new(ZeroDb::open(dir_b.path()).unwrap());
        let contacts_b2 = Arc::new(ContactStore::new(Arc::clone(&db_b), bob));
        contacts_b2
            .add_contact(Contact {
                identity_id: alice,
                label: "Alice".to_string(),
                machine_keys: vec![],
                last_seen_epoch: None,
                added_at_ms: 2000,
            })
            .unwrap();

        let svc_a = DmService::new(Arc::clone(&db), alice, machine_a, Arc::clone(&contacts));
        let svc_b = DmService::new(Arc::clone(&db_b), bob, machine_b, contacts_b2);

        let conv = svc_a.open_conversation(bob).unwrap();
        let msg = make_test_message(conv.conversation_id, alice, machine_a, "round trip");
        svc_a.store_message(&msg).unwrap();
        svc_a
            .update_status(conv.conversation_id, msg.id, MessageStatus::Sent)
            .unwrap();

        // B receives -> emits Delivered receipt
        svc_b.open_conversation(alice).unwrap();
        svc_b.store_message(&msg).unwrap();

        let delivered_receipt = ReceiptPayload {
            message_id: msg.id,
            conversation_id: conv.conversation_id,
            recipient_identity: bob,
            recipient_machine: machine_b,
            status: MessageStatus::Delivered,
            timestamp_ms: 1000,
        };

        // A processes Delivered receipt
        svc_a.process_receipt(&delivered_receipt).unwrap();
        let a_msg = svc_a
            .get_message(conv.conversation_id, msg.id)
            .unwrap()
            .unwrap();
        assert_eq!(a_msg.status, MessageStatus::Delivered);

        // B marks read -> emits Read receipt
        let read_receipt = svc_b.mark_read(conv.conversation_id, msg.id).unwrap();
        assert_eq!(read_receipt.status, MessageStatus::Read);

        // A processes Read receipt
        svc_a.process_receipt(&read_receipt).unwrap();
        let a_msg = svc_a
            .get_message(conv.conversation_id, msg.id)
            .unwrap()
            .unwrap();
        assert_eq!(a_msg.status, MessageStatus::Read);
    }

    #[test]
    fn send_text_persists_message_with_queued_status() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msg_id = svc
            .send_text(conv.conversation_id, "hello".to_string())
            .unwrap();

        let msg = svc
            .get_message(conv.conversation_id, msg_id)
            .unwrap()
            .unwrap();
        assert_eq!(msg.id, msg_id);
        assert_eq!(msg.conversation_id, conv.conversation_id);
        assert_eq!(msg.sender_identity, alice);
        assert_eq!(msg.sender_machine, machine);
        assert_eq!(msg.text, "hello");
        assert_eq!(msg.status, MessageStatus::Queued);
    }

    #[test]
    fn send_text_enqueues_outbox_entry() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(Arc::clone(&db), alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        svc.send_text(conv.conversation_id, "outbox test".to_string())
            .unwrap();

        let outbox = Outbox::new(&db);
        let pending = outbox.dequeue_due(u64::MAX).unwrap();
        assert_eq!(pending.len(), 1);

        let payload: DmSectorPayload = postcard::from_bytes(&pending[0].payload).unwrap();
        assert_eq!(payload.text, "outbox test");
        assert_eq!(payload.conversation_id, conv.conversation_id);
    }

    #[test]
    fn send_text_updates_conversation_last_sector() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv_before = svc.open_conversation(bob).unwrap();
        assert!(conv_before.last_sector.is_none());

        svc.send_text(conv_before.conversation_id, "update sector".to_string())
            .unwrap();

        let conv_after = svc
            .resume_conversation(conv_before.conversation_id)
            .unwrap();
        assert!(conv_after.last_sector.is_some());
    }

    #[test]
    fn acknowledge_sent_transitions_queued_to_sent() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msg_id = svc
            .send_text(conv.conversation_id, "ack test".to_string())
            .unwrap();

        let before = svc
            .get_message(conv.conversation_id, msg_id)
            .unwrap()
            .unwrap();
        assert_eq!(before.status, MessageStatus::Queued);

        svc.acknowledge_sent(conv.conversation_id, msg_id).unwrap();

        let after = svc
            .get_message(conv.conversation_id, msg_id)
            .unwrap()
            .unwrap();
        assert_eq!(after.status, MessageStatus::Sent);
        assert!(after.status_updated_at_ms >= before.status_updated_at_ms);
    }

    #[test]
    fn send_text_to_unknown_conversation_fails() {
        let (_dir, db, contacts, alice, _bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);

        let fake_conv = ConversationId([0xFFu8; 32]);
        let err = svc.send_text(fake_conv, "nope".to_string()).unwrap_err();
        assert!(matches!(err, DmError::UnknownConversation(_)));
    }

    // ---- history / pagination tests ----

    fn insert_n_messages(
        svc: &DmService,
        conv_id: ConversationId,
        sender: IdentityId,
        machine: MachineId,
        n: usize,
    ) -> Vec<Message> {
        let mut msgs = Vec::with_capacity(n);
        for i in 0..n {
            let id = MessageId(uuid::Uuid::now_v7().into_bytes());
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let msg = Message {
                id,
                conversation_id: conv_id,
                sender_identity: sender,
                sender_machine: machine,
                text: format!("msg-{i}"),
                status: MessageStatus::Queued,
                created_at_ms: now,
                status_updated_at_ms: 0,
            };
            svc.store_message(&msg).unwrap();
            msgs.push(msg);
            // Small sleep to ensure distinct UUIDv7 timestamps
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        msgs
    }

    #[test]
    fn history_empty_conversation_returns_empty() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let page = svc.history(conv.conversation_id, None, 10).unwrap();
        assert!(page.is_empty());
    }

    #[test]
    fn history_returns_descending_order() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msgs = insert_n_messages(&svc, conv.conversation_id, alice, machine, 5);
        let page = svc.history(conv.conversation_id, None, 10).unwrap();

        assert_eq!(page.len(), 5);
        // Page should be in descending order (newest first)
        for w in page.windows(2) {
            assert!(w[0].id.0 > w[1].id.0);
        }
        // Last inserted message should be first in descending page
        assert_eq!(page[0].id, msgs[4].id);
        assert_eq!(page[4].id, msgs[0].id);
    }

    #[test]
    fn history_respects_limit() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let _msgs = insert_n_messages(&svc, conv.conversation_id, alice, machine, 10);
        let page = svc.history(conv.conversation_id, None, 5).unwrap();

        assert_eq!(page.len(), 5);
    }

    #[test]
    fn history_before_cursor_excludes_boundary() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msgs = insert_n_messages(&svc, conv.conversation_id, alice, machine, 10);

        // Get first page (5 latest)
        let page1 = svc.history(conv.conversation_id, None, 5).unwrap();
        assert_eq!(page1.len(), 5);

        // Use oldest message from page1 as cursor for page2
        let cursor = page1.last().unwrap().id;
        let page2 = svc.history(conv.conversation_id, Some(cursor), 5).unwrap();
        assert_eq!(page2.len(), 5);

        // No overlap between pages
        let page1_ids: Vec<MessageId> = page1.iter().map(|m| m.id).collect();
        let page2_ids: Vec<MessageId> = page2.iter().map(|m| m.id).collect();
        for id in &page2_ids {
            assert!(!page1_ids.contains(id));
        }

        // page2 messages are all older than page1 messages
        let page1_oldest = page1.last().unwrap().id.0;
        let page2_newest = page2.first().unwrap().id.0;
        assert!(page2_newest < page1_oldest);

        // Together they cover all 10 messages
        let mut all_ids: Vec<MessageId> = page1_ids.into_iter().chain(page2_ids).collect();
        all_ids.sort_by(|a, b| a.0.cmp(&b.0));
        let mut expected_ids: Vec<MessageId> = msgs.iter().map(|m| m.id).collect();
        expected_ids.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(all_ids, expected_ids);
    }

    #[test]
    fn history_past_end_returns_empty() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msgs = insert_n_messages(&svc, conv.conversation_id, alice, machine, 3);
        // Use the oldest message as cursor -- nothing before it
        let oldest_id = msgs[0].id;
        let page = svc
            .history(conv.conversation_id, Some(oldest_id), 10)
            .unwrap();
        assert!(page.is_empty());
    }

    #[test]
    fn history_successive_pages_cover_full_history() {
        let (_dir, db, contacts, alice, bob) = setup();
        let machine = MachineId([0xAAu8; 16]);
        let svc = DmService::new(db, alice, machine, contacts);
        let conv = svc.open_conversation(bob).unwrap();

        let msgs = insert_n_messages(&svc, conv.conversation_id, alice, machine, 13);

        let mut all_collected: Vec<MessageId> = Vec::new();
        let mut cursor: Option<MessageId> = None;
        loop {
            let page = svc.history(conv.conversation_id, cursor, 4).unwrap();
            if page.is_empty() {
                break;
            }
            // Each page is descending
            for w in page.windows(2) {
                assert!(w[0].id.0 > w[1].id.0);
            }
            // Contiguous with previous: newest in this page < oldest in prev page
            if let Some(prev_oldest) = all_collected.last() {
                assert!(page.first().unwrap().id.0 < prev_oldest.0);
            }
            cursor = Some(page.last().unwrap().id);
            all_collected.extend(page.iter().map(|m| m.id));
        }

        assert_eq!(all_collected.len(), 13);
        let mut expected: Vec<MessageId> = msgs.iter().map(|m| m.id).collect();
        expected.sort_by(|a, b| b.0.cmp(&a.0)); // descending
        assert_eq!(all_collected, expected);
    }

    mod pagination_proptest {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(proptest::prelude::ProptestConfig::with_cases(20))]
            #[test]
            fn successive_pages_yield_contiguous_nonoverlapping_windows(
                n in 1usize..30,
                page_size in 1usize..10,
            ) {
                let dir = TempDir::new().unwrap();
                let db = Arc::new(ZeroDb::open(dir.path()).unwrap());
                let alice = IdentityId([1u8; 16]);
                let bob = IdentityId([2u8; 16]);
                let machine = MachineId([0xAAu8; 16]);
                let contacts = Arc::new(ContactStore::new(Arc::clone(&db), alice));
                contacts
                    .add_contact(Contact {
                        identity_id: bob,
                        label: "Bob".to_string(),
                        machine_keys: vec![],
                        last_seen_epoch: None,
                        added_at_ms: 1000,
                    })
                    .unwrap();
                let svc = DmService::new(db, alice, machine, contacts);
                let conv = svc.open_conversation(bob).unwrap();

                let msgs = insert_n_messages(&svc, conv.conversation_id, alice, machine, n);

                let mut all_collected: Vec<MessageId> = Vec::new();
                let mut cursor: Option<MessageId> = None;
                let mut page_count = 0usize;

                loop {
                    let page = svc
                        .history(conv.conversation_id, cursor, page_size)
                        .unwrap();
                    if page.is_empty() {
                        break;
                    }
                    page_count += 1;

                    // Each page is strictly descending
                    for w in page.windows(2) {
                        prop_assert!(
                            w[0].id.0 > w[1].id.0,
                            "page {} not descending: {:?} vs {:?}",
                            page_count,
                            w[0].id,
                            w[1].id,
                        );
                    }

                    // Page size respects limit
                    prop_assert!(page.len() <= page_size);

                    // Contiguous: newest in this page < oldest in previous page
                    if let Some(prev_oldest) = all_collected.last() {
                        prop_assert!(
                            page.first().unwrap().id.0 < prev_oldest.0,
                            "page {} not contiguous with previous",
                            page_count,
                        );
                    }

                    // No overlap: none of these ids were seen before
                    for m in &page {
                        prop_assert!(
                            !all_collected.contains(&m.id),
                            "duplicate message id {:?}",
                            m.id,
                        );
                    }

                    cursor = Some(page.last().unwrap().id);
                    all_collected.extend(page.iter().map(|m| m.id));
                }

                // All messages were returned
                prop_assert_eq!(all_collected.len(), n);

                // The collected order matches the full descending sort
                let mut expected: Vec<MessageId> = msgs.iter().map(|m| m.id).collect();
                expected.sort_by(|a, b| b.0.cmp(&a.0));
                prop_assert_eq!(all_collected, expected);
            }
        }
    }
}
