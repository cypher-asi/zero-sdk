use serde::{Deserialize, Serialize};
use zero_crypto::aad::{Epoch, IdentityId, MachineId};

/// Public keys associated with a specific machine belonging to a contact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContactMachineKey {
    pub machine_id: MachineId,
    pub x25519_public: [u8; 32],
    pub mlkem_encap_key: Vec<u8>,
    pub ed25519_verifying: [u8; 32],
    pub mldsa_verifying: Vec<u8>,
    pub epoch: Epoch,
}

/// A contact in the address book.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contact {
    pub identity_id: IdentityId,
    pub label: String,
    pub machine_keys: Vec<ContactMachineKey>,
    pub last_seen_epoch: Option<Epoch>,
    pub added_at_ms: u64,
}

/// Errors from the contact store.
#[derive(Debug, thiserror::Error)]
pub enum ContactError {
    #[error("storage error: {0}")]
    Storage(#[from] zero_storage::error::StorageError),

    #[error("contact not found: {0:?}")]
    NotFound(IdentityId),

    #[error("label too long: {len} chars (max 64)")]
    LabelTooLong { len: usize },

    #[error("codec error: {0}")]
    Codec(String),

    #[error("duplicate contact: {0:?}")]
    Duplicate(IdentityId),
}
