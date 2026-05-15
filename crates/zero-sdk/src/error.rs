//! Unified error type for the zero-sdk facade.

use zero_identity::error::IdentityError;
use zero_messaging::contacts::types::ContactError;
use zero_messaging::dm::DmError;
use zero_messaging::group::types::GroupError;
use zero_messaging::inbox::InboxError;
use zero_network::error::NetworkError;
use zero_storage::error::StorageError;

/// Top-level SDK error that wraps every sub-system error.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    #[error("dm error: {0}")]
    Dm(#[from] DmError),

    #[error("group error: {0}")]
    Group(#[from] GroupError),

    #[error("inbox error: {0}")]
    Inbox(#[from] InboxError),

    #[error("contact error: {0}")]
    Contact(#[from] ContactError),

    #[error("build error: {0}")]
    Build(String),
}
