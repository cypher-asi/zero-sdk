//! DM types: identifiers, messages, conversations, and receipts.

use serde::{Deserialize, Serialize};
use zero_crypto::aad::{IdentityId, MachineId};
use zero_storage::sector::SectorId;

/// 32-byte conversation identifier derived from two `IdentityId`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationId(pub [u8; 32]);

impl std::fmt::Display for ConversationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl ConversationId {
    /// Derive a deterministic conversation ID from two identity IDs.
    /// The result is commutative: `derive(a, b) == derive(b, a)`.
    /// Build the storage key for persisting conversation metadata.
    #[must_use]
    pub fn storage_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(3 + 32);
        key.extend_from_slice(b"dm:");
        key.extend_from_slice(&self.0);
        key
    }

    pub fn derive(a: IdentityId, b: IdentityId) -> Self {
        let (first, second) = if a.0 <= b.0 { (a.0, b.0) } else { (b.0, a.0) };
        let mut input = [0u8; 32];
        input[..16].copy_from_slice(&first);
        input[16..].copy_from_slice(&second);
        let hash = blake3::hash(&input);
        Self(*hash.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Time-ordered message identifier wrapping a UUIDv7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 16]);

impl MessageId {
    #[must_use]
    pub fn new() -> Self {
        Self(*uuid::Uuid::now_v7().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", uuid::Uuid::from_bytes(self.0))
    }
}

/// Monotonic message delivery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessageStatus {
    Queued,
    Sent,
    Delivered,
    Read,
}

impl MessageStatus {
    /// Returns true iff transitioning from `self` to `to` is valid (strictly forward).
    #[must_use]
    pub fn is_valid_transition(self, to: Self) -> bool {
        to > self
    }
}

/// A single direct message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub conversation_id: ConversationId,
    pub sender_identity: IdentityId,
    pub sender_machine: MachineId,
    pub text: String,
    pub status: MessageStatus,
    pub created_at_ms: u64,
    pub status_updated_at_ms: u64,
}

/// Metadata for a 1:1 conversation, persisted in `CF_CHAINS`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConversationMeta {
    pub conversation_id: ConversationId,
    pub peer_identity: IdentityId,
    pub last_message_at_ms: u64,
    pub last_sector_id: Option<SectorId>,
}

/// A 1:1 conversation handle persisted in `CF_CHAINS`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Conversation {
    pub conversation_id: ConversationId,
    pub peer_identity: IdentityId,
    pub last_sector: Option<SectorId>,
}

/// Serialized DM sector content for outbox entries, schema tag `"zero.dm.v1"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmSectorPayload {
    pub message_id: MessageId,
    pub conversation_id: ConversationId,
    pub sender_identity: IdentityId,
    pub sender_machine: MachineId,
    pub text: String,
    pub created_at_ms: u64,
}

/// Payload for a delivery/read receipt, schema tag `"zero.receipt.v1"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptPayload {
    pub message_id: MessageId,
    pub conversation_id: ConversationId,
    pub recipient_identity: IdentityId,
    pub recipient_machine: MachineId,
    pub status: MessageStatus,
    pub timestamp_ms: u64,
}
