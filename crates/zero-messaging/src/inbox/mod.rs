//! Inbox conversation index module (task 7.1).
//!
//! Maintains a `CF_INBOX_INDEX` entry per conversation keyed by
//! `(IdentityId, MachineId, ConversationId)`. Updated on every
//! send, receive, and read operation.

pub mod index;
pub mod service;
pub mod types;

pub use service::InboxService;
pub use types::{ConversationRef, InboxEntry, InboxStats};

use zero_storage::error::StorageError;

/// Errors from the inbox subsystem.
#[derive(Debug, thiserror::Error)]
pub enum InboxError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("codec error: {0}")]
    Codec(String),
}
