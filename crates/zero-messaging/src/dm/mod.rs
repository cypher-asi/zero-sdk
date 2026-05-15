//! Direct messaging (1:1) module.

pub mod paginate;
pub mod receipt;
pub mod receive;
pub mod service;
pub mod types;

pub use receipt::{
    build_delivered_receipt, build_read_receipt, decode_receipt, enqueue_receipt,
    is_valid_receipt_status, RECEIPT_SCHEMA_TAG,
};
pub use receive::{DmReceiver, ReceiveLoopHandle};
pub use service::DmService;
pub use types::{
    Conversation, ConversationId, ConversationMeta, Message, MessageId, MessageStatus,
    ReceiptPayload,
};

use crate::contacts::types::ContactError;
use zero_crypto::aad::IdentityId;
use zero_crypto::error::CryptoError;
use zero_network::error::NetworkError;
use zero_storage::error::StorageError;

/// Errors from the DM subsystem.
#[derive(Debug, thiserror::Error)]
pub enum DmError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    #[error("contact error: {0}")]
    Contact(#[from] ContactError),

    #[error("unknown conversation: {0:?}")]
    UnknownConversation(ConversationId),

    #[error("invalid status transition from {from:?} to {to:?}")]
    InvalidStatusTransition {
        from: MessageStatus,
        to: MessageStatus,
    },

    #[error("contact not found: {0:?}")]
    ContactNotFound(IdentityId),

    #[error("message not found: {0:?}")]
    MessageNotFound(MessageId),

    #[error("codec error: {0}")]
    Codec(String),
}
