//! Group types: identifiers, messages, manifests, roles, and errors.
//!
//! Group messages use the `zero.group.v1` schema tag and are encrypted with the
//! current MLS epoch secret. Receipts reuse the DM receipt wire format under
//! `zero.receipt.v1`, with forward-only status transitions
//! (Queued -> Sent -> Delivered -> Read).

use serde::{Deserialize, Serialize};
use zero_crypto::aad::{IdentityId, MachineId};

/// Schema tag for group messages.
pub const GROUP_MSG_TAG: &str = "zero.group.v1";
/// Schema tag for group receipts (identical to DM receipts).
pub const GROUP_RECEIPT_TAG: &str = "zero.receipt.v1";

/// 16-byte group identifier (UUIDv7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 16]);

/// 16-byte group message identifier (UUIDv7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupMessageId(pub [u8; 16]);

/// Role within a group, ordered by decreasing privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    Moderator,
    Member,
}

/// Actions that can be performed within a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupAction {
    SendMessage,
    AddMember,
    RemoveMember,
    PromoteDemoteMod,
    PromoteDemoteAdmin,
    DeleteGroup,
}

/// A member entry inside a `GroupManifest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupMember {
    pub identity_id: IdentityId,
    pub machine_id: MachineId,
    pub role: Role,
    pub added_at_ms: u64,
}

/// The authoritative snapshot of group state, persisted after each epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupManifest {
    pub group_id: GroupId,
    pub name: String,
    pub creator: IdentityId,
    pub members: Vec<GroupMember>,
    pub mls_epoch: u64,
    pub mls_state_blob: Vec<u8>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

/// Message delivery status (mirrors DM statuses for receipt compatibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GroupMessageStatus {
    Sent = 0,
    Delivered = 1,
    Read = 2,
}

/// A decrypted group message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    pub id: GroupMessageId,
    pub group_id: GroupId,
    pub sender_identity: IdentityId,
    pub sender_machine: MachineId,
    pub text: String,
    pub mls_epoch: u64,
    pub created_at_ms: u64,
    pub status: GroupMessageStatus,
}

/// Receipt payload for group messages, schema tag `"zero.receipt.v1"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupReceiptPayload {
    pub message_id: GroupMessageId,
    pub group_id: GroupId,
    pub recipient_identity: IdentityId,
    pub recipient_machine: MachineId,
    pub status: GroupMessageStatus,
    pub timestamp_ms: u64,
}

/// Errors produced by group operations.
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("storage error: {0}")]
    Storage(#[from] zero_storage::StorageError),

    #[error("MLS error: {0}")]
    Mls(String),

    #[error("permission denied: {actor:?} cannot {action:?}")]
    PermissionDenied { actor: Role, action: GroupAction },

    #[error("group full ({size} members)")]
    GroupFull { size: usize },

    #[error("not a member: {0:?}")]
    NotAMember(IdentityId),

    #[error("group not found: {0:?}")]
    GroupNotFound(GroupId),

    #[error("manifest conflict")]
    ManifestConflict,

    #[error("invalid manifest update")]
    InvalidManifestUpdate,

    #[error("name too long ({len} chars, max 64)")]
    NameTooLong { len: usize },
}
