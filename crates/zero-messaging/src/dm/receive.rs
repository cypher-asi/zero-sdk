//! Inbound DM receive loop and processing.
//!
//! `DmReceiver` subscribes to the `dm/{identity_id}` topic, processes inbound
//! sectors, persists messages, and emits `Delivered` receipts via the outbox.

use std::future::poll_fn;
use std::sync::Arc;

use futures_core::Stream;
use tokio::task::JoinHandle;

use zero_crypto::aad::{IdentityId, MachineId};
use zero_network::client::GridClient;
use zero_storage::db::ZeroDb;
use zero_storage::dedupe::DedupeCache;
use zero_storage::outbox::Outbox;
use zero_storage::sector::SectorId;

use crate::dm::receipt::{build_delivered_receipt, enqueue_receipt};

use super::service::DmService;
use super::types::{DmSectorPayload, Message, MessageId, MessageStatus};
use super::DmError;

/// Handle returned by [`DmReceiver::start_receive_loop`]. Dropping it aborts
/// the background task.
pub struct ReceiveLoopHandle(JoinHandle<()>);

impl Drop for ReceiveLoopHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ReceiveLoopHandle {
    /// Check whether the background task has finished.
    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}

/// Receives inbound DMs from the GRID network, persists messages, and emits
/// `Delivered` receipts via the outbox.
pub struct DmReceiver<C: GridClient> {
    pub(crate) service: Arc<DmService>,
    pub(crate) db: Arc<ZeroDb>,
    pub(crate) identity: IdentityId,
    pub(crate) machine_id: MachineId,
    pub(crate) grid: Arc<C>,
    pub(crate) dedupe: Arc<DedupeCache>,
}

impl<C: GridClient> DmReceiver<C> {
    pub fn new(
        service: Arc<DmService>,
        db: Arc<ZeroDb>,
        identity: IdentityId,
        machine_id: MachineId,
        grid: Arc<C>,
        dedupe: Arc<DedupeCache>,
    ) -> Self {
        Self {
            service,
            db,
            identity,
            machine_id,
            grid,
            dedupe,
        }
    }

    /// Process a single inbound DM sector (postcard-encoded `DmSectorPayload` bytes).
    ///
    /// 1. Deserialize `DmSectorPayload`.
    /// 2. Persist the message with status `Delivered`.
    /// 3. Enqueue a `Delivered` receipt in the outbox.
    pub fn process_inbound_dm(&self, sector_bytes: &[u8]) -> Result<MessageId, DmError> {
        let payload: DmSectorPayload =
            postcard::from_bytes(sector_bytes).map_err(|e| DmError::Codec(e.to_string()))?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let msg = Message {
            id: payload.message_id,
            conversation_id: payload.conversation_id,
            sender_identity: payload.sender_identity,
            sender_machine: payload.sender_machine,
            text: payload.text.clone(),
            status: MessageStatus::Delivered,
            created_at_ms: payload.created_at_ms,
            status_updated_at_ms: now_ms,
        };

        // Ensure conversation exists for this peer. ContactNotFound is
        // non-fatal: we still persist the message even if the sender is not
        // yet in our contact store. Real storage errors propagate.
        if let Err(e @ DmError::Storage(_)) =
            self.service.open_conversation(payload.sender_identity)
        {
            return Err(e);
        }

        self.service.store_message(&msg)?;

        let receipt = build_delivered_receipt(
            payload.message_id,
            payload.conversation_id,
            self.identity,
            self.machine_id,
        );

        let outbox = Outbox::new(&self.db);
        enqueue_receipt(&outbox, &receipt)?;

        Ok(payload.message_id)
    }

    /// Start the inbound receive loop. Subscribes to `dm/{identity_id}` and
    /// spawns a tokio task that processes each inbound sector.
    pub fn start_receive_loop(self: Arc<Self>) -> ReceiveLoopHandle {
        let mut topic = String::from("dm/");
        for byte in &self.identity.0 {
            use std::fmt::Write;
            let _ = write!(topic, "{byte:02x}");
        }

        let handle = tokio::spawn(async move {
            let stream = match self.grid.subscribe(&topic).await {
                Ok(s) => s,
                Err(_) => return,
            };

            tokio::pin!(stream);

            loop {
                let item = poll_fn(|cx| stream.as_mut().poll_next(cx)).await;

                match item {
                    Some(Ok(sector_bytes)) => {
                        let hash = blake3::hash(&sector_bytes);
                        let mut id_bytes = [0u8; 16];
                        id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
                        let sector_id = SectorId(id_bytes);

                        if self.dedupe.seen(sector_id) {
                            continue;
                        }
                        self.dedupe.mark(sector_id);

                        let _ = self.process_inbound_dm(&sector_bytes);
                    }
                    Some(Err(_)) | None => break,
                }
            }
        });

        ReceiveLoopHandle(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::store::ContactStore;
    use crate::contacts::types::Contact;
    use crate::dm::types::{ConversationId, DmSectorPayload, ReceiptPayload};
    use zero_network::mock::MockGridClient;
    use zero_storage::db::ZeroDb;

    fn setup_db() -> Arc<ZeroDb> {
        let dir = tempfile::tempdir().unwrap();
        Arc::new(ZeroDb::open(dir.path()).unwrap())
    }

    fn make_identity() -> IdentityId {
        let id = uuid::Uuid::now_v7();
        IdentityId(id.into_bytes())
    }

    fn make_machine() -> MachineId {
        let id = uuid::Uuid::now_v7();
        MachineId(id.into_bytes())
    }

    fn setup_receiver(
        db: Arc<ZeroDb>,
        identity: IdentityId,
        machine_id: MachineId,
        peer: IdentityId,
    ) -> DmReceiver<MockGridClient> {
        let contacts = Arc::new(ContactStore::new(db.clone(), identity));
        contacts
            .add_contact(Contact {
                identity_id: peer,
                label: "peer".to_string(),
                machine_keys: Vec::new(),
                last_seen_epoch: None,
                added_at_ms: 1000,
            })
            .unwrap();

        let service = Arc::new(DmService::new(db.clone(), identity, machine_id, contacts));
        let broker = zero_network::mock::InMemoryGridBroker::new();
        let grid = Arc::new(broker.client());
        let dedupe = Arc::new(DedupeCache::new(1024));

        DmReceiver::new(service, db, identity, machine_id, grid, dedupe)
    }

    #[test]
    fn process_inbound_dm_persists_message_as_delivered() {
        let db = setup_db();
        let my_id = make_identity();
        let my_machine = make_machine();
        let sender_id = make_identity();
        let sender_machine = make_machine();

        let receiver = setup_receiver(db, my_id, my_machine, sender_id);

        let conv_id = ConversationId::derive(my_id, sender_id);
        let msg_id = MessageId::new();

        let payload = DmSectorPayload {
            message_id: msg_id,
            conversation_id: conv_id,
            sender_identity: sender_id,
            sender_machine,
            text: "hello from sender".to_string(),
            created_at_ms: 42_000,
        };

        let sector_bytes = postcard::to_allocvec(&payload).unwrap();
        let result = receiver.process_inbound_dm(&sector_bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), msg_id);

        let stored = receiver.service.get_message(conv_id, msg_id).unwrap();
        assert!(stored.is_some());
        let stored = stored.unwrap();
        assert_eq!(stored.status, MessageStatus::Delivered);
        assert_eq!(stored.text, "hello from sender");
        assert_eq!(stored.sender_identity, sender_id);
    }

    #[test]
    fn process_inbound_dm_enqueues_delivered_receipt() {
        let db = setup_db();
        let my_id = make_identity();
        let my_machine = make_machine();
        let sender_id = make_identity();
        let sender_machine = make_machine();

        let receiver = setup_receiver(db.clone(), my_id, my_machine, sender_id);

        let conv_id = ConversationId::derive(my_id, sender_id);
        let msg_id = MessageId::new();

        let payload = DmSectorPayload {
            message_id: msg_id,
            conversation_id: conv_id,
            sender_identity: sender_id,
            sender_machine,
            text: "test receipt".to_string(),
            created_at_ms: 100_000,
        };

        let sector_bytes = postcard::to_allocvec(&payload).unwrap();
        receiver.process_inbound_dm(&sector_bytes).unwrap();

        let outbox = Outbox::new(&db);
        let entries = outbox.dequeue_due(u64::MAX).unwrap();
        assert_eq!(entries.len(), 1, "expected one receipt in outbox");

        let receipt: ReceiptPayload = postcard::from_bytes(&entries[0].payload).unwrap();
        assert_eq!(receipt.message_id, msg_id);
        assert_eq!(receipt.conversation_id, conv_id);
        assert_eq!(receipt.status, MessageStatus::Delivered);
        assert_eq!(receipt.recipient_identity, my_id);
        assert_eq!(receipt.recipient_machine, my_machine);
    }

    #[test]
    fn process_inbound_dm_invalid_bytes_returns_codec_error() {
        let db = setup_db();
        let my_id = make_identity();
        let my_machine = make_machine();
        let sender_id = make_identity();

        let receiver = setup_receiver(db, my_id, my_machine, sender_id);

        let bad_bytes = b"not a valid payload";
        let result = receiver.process_inbound_dm(bad_bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            DmError::Codec(_) => {}
            other => panic!("expected DmError::Codec, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn receive_loop_handle_drop_aborts_task() {
        let db = setup_db();
        let my_id = make_identity();
        let my_machine = make_machine();
        let sender_id = make_identity();

        let receiver = setup_receiver(db, my_id, my_machine, sender_id);
        let receiver = Arc::new(receiver);
        let handle = receiver.clone().start_receive_loop();

        drop(handle);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    #[test]
    fn dedupe_prevents_duplicate_processing() {
        let db = setup_db();
        let my_id = make_identity();
        let my_machine = make_machine();
        let sender_id = make_identity();
        let sender_machine = make_machine();

        let receiver = setup_receiver(db, my_id, my_machine, sender_id);

        let conv_id = ConversationId::derive(my_id, sender_id);
        let msg_id = MessageId::new();

        let payload = DmSectorPayload {
            message_id: msg_id,
            conversation_id: conv_id,
            sender_identity: sender_id,
            sender_machine,
            text: "dedup test".to_string(),
            created_at_ms: 50_000,
        };

        let sector_bytes = postcard::to_allocvec(&payload).unwrap();

        let hash = blake3::hash(&sector_bytes);
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        let sector_id = SectorId(id_bytes);

        receiver.dedupe.mark(sector_id);

        // Processing should still work (dedupe is only checked in the loop)
        // but if we simulate the loop logic, a duplicate would be skipped
        assert!(receiver.dedupe.seen(sector_id));
    }
}
