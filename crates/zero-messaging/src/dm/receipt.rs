//! Receipt building and emission for `zero.receipt.v1` sectors.

use zero_crypto::aad::{IdentityId, MachineId};
use zero_storage::outbox::{Outbox, OutboxEntry};
use zero_storage::sector::SectorId;

use super::types::{ConversationId, MessageId, MessageStatus, ReceiptPayload};
use super::DmError;

/// Schema tag used for receipt sectors on the wire.
pub const RECEIPT_SCHEMA_TAG: &str = "zero.receipt.v1";

/// Build a `ReceiptPayload` for a delivered message.
pub fn build_delivered_receipt(
    message_id: MessageId,
    conversation_id: ConversationId,
    recipient_identity: IdentityId,
    recipient_machine: MachineId,
) -> ReceiptPayload {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    ReceiptPayload {
        message_id,
        conversation_id,
        recipient_identity,
        recipient_machine,
        status: MessageStatus::Delivered,
        timestamp_ms: now_ms,
    }
}

/// Build a `ReceiptPayload` for a read message.
pub fn build_read_receipt(
    message_id: MessageId,
    conversation_id: ConversationId,
    recipient_identity: IdentityId,
    recipient_machine: MachineId,
) -> ReceiptPayload {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    ReceiptPayload {
        message_id,
        conversation_id,
        recipient_identity,
        recipient_machine,
        status: MessageStatus::Read,
        timestamp_ms: now_ms,
    }
}

/// Validate that a receipt's status is a permitted receipt status (Delivered or Read).
/// Queued and Sent are not valid receipt statuses.
pub fn is_valid_receipt_status(status: MessageStatus) -> bool {
    matches!(status, MessageStatus::Delivered | MessageStatus::Read)
}

/// Deserialize a raw receipt payload from bytes.
pub fn decode_receipt(bytes: &[u8]) -> Result<ReceiptPayload, DmError> {
    postcard::from_bytes(bytes).map_err(|e| DmError::Codec(e.to_string()))
}

/// Serialize a `ReceiptPayload` and enqueue it in the outbox for delivery.
pub fn enqueue_receipt(outbox: &Outbox<'_>, receipt: &ReceiptPayload) -> Result<SectorId, DmError> {
    let payload_bytes =
        postcard::to_allocvec(receipt).map_err(|e| DmError::Codec(e.to_string()))?;

    let sector_id = SectorId::new();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let entry = OutboxEntry {
        sector_id,
        payload: payload_bytes,
        attempt_count: 0,
        next_attempt_ms: now_ms,
        created_at_ms: now_ms,
    };

    outbox.enqueue(entry)?;
    Ok(sector_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ids() -> (MessageId, ConversationId, IdentityId, MachineId) {
        let message_id = MessageId::new();
        let conversation_id = ConversationId([0x42u8; 32]);
        let identity = IdentityId([0x01u8; 16]);
        let machine = MachineId([0x02u8; 16]);
        (message_id, conversation_id, identity, machine)
    }

    #[test]
    fn build_delivered_receipt_has_delivered_status() {
        let (msg_id, conv_id, identity, machine) = test_ids();
        let r = build_delivered_receipt(msg_id, conv_id, identity, machine);
        assert_eq!(r.status, MessageStatus::Delivered);
        assert_eq!(r.message_id, msg_id);
        assert_eq!(r.conversation_id, conv_id);
        assert_eq!(r.recipient_identity, identity);
        assert_eq!(r.recipient_machine, machine);
    }

    #[test]
    fn build_read_receipt_has_read_status() {
        let (msg_id, conv_id, identity, machine) = test_ids();
        let r = build_read_receipt(msg_id, conv_id, identity, machine);
        assert_eq!(r.status, MessageStatus::Read);
        assert_eq!(r.message_id, msg_id);
    }

    #[test]
    fn is_valid_receipt_status_accepts_delivered_and_read() {
        assert!(is_valid_receipt_status(MessageStatus::Delivered));
        assert!(is_valid_receipt_status(MessageStatus::Read));
    }

    #[test]
    fn is_valid_receipt_status_rejects_queued_and_sent() {
        assert!(!is_valid_receipt_status(MessageStatus::Queued));
        assert!(!is_valid_receipt_status(MessageStatus::Sent));
    }

    #[test]
    fn decode_receipt_round_trips() {
        let (msg_id, conv_id, identity, machine) = test_ids();
        let original = build_delivered_receipt(msg_id, conv_id, identity, machine);
        let bytes = postcard::to_allocvec(&original).unwrap();
        let decoded = decode_receipt(&bytes).unwrap();
        assert_eq!(decoded.message_id, original.message_id);
        assert_eq!(decoded.conversation_id, original.conversation_id);
        assert_eq!(decoded.status, original.status);
        assert_eq!(decoded.recipient_identity, original.recipient_identity);
        assert_eq!(decoded.recipient_machine, original.recipient_machine);
    }

    #[test]
    fn decode_receipt_invalid_bytes_returns_error() {
        let result = decode_receipt(b"not valid postcard bytes !!!");
        assert!(result.is_err());
    }

    #[test]
    fn read_receipt_roundtrip_via_decode() {
        let (msg_id, conv_id, identity, machine) = test_ids();
        let original = build_read_receipt(msg_id, conv_id, identity, machine);
        let bytes = postcard::to_allocvec(&original).unwrap();
        let decoded = decode_receipt(&bytes).unwrap();
        assert_eq!(decoded.status, MessageStatus::Read);
    }
}
