//! `zero-sdk` -- top-level facade for the zero messaging stack.
//!
//! Consumers depend only on `zero-sdk` and use `zero_sdk::*` to access
//! every service, type, and error in the stack.

#![deny(warnings)]
#![forbid(unsafe_code)]

pub mod builder;
pub mod error;

pub use error::SdkError;

// --- Identity re-exports ---
pub use zero_identity::error::IdentityError;
pub use zero_identity::machine_key::{MachineKeyEntry, MachineKeyRecord, MachineKeyStore};
pub use zero_identity::neural_key::{NeuralKey, NeuralKeyShares};

// --- Crypto re-exports ---
pub use zero_crypto::aad::{IdentityId, MachineId};

// --- Storage re-exports ---
pub use zero_storage::ZeroDb;

// --- Network re-exports ---
pub use zero_network::{
    GridClient, InMemoryGridBroker, MockGridClient, NetworkError, RealGridClient,
};

// --- Contacts re-exports ---
pub use zero_messaging::contacts::{Contact, ContactMachineKey, ContactStore};

// --- DM re-exports ---
pub use zero_messaging::dm::{
    ConversationId, ConversationMeta, DmError, DmService, Message, MessageId, MessageStatus,
};

// --- Group re-exports ---
pub use zero_messaging::group::{
    GroupAction, GroupError, GroupId, GroupManifest, GroupMember, GroupMessage, GroupMessageId,
    GroupMessageStatus, Role,
};

// --- Inbox re-exports ---
pub use zero_messaging::inbox::types::ConversationKind;
pub use zero_messaging::inbox::{
    ConversationRef, InboxEntry, InboxError, InboxService, InboxStats,
};

use std::sync::Arc;

/// Top-level facade wiring all zero-sdk services into a single entry point.
pub struct ZeroSdk {
    pub db: Arc<ZeroDb>,
    pub contacts: Arc<ContactStore>,
    pub dm: Arc<DmService>,
    pub inbox: Arc<InboxService>,
    pub identity_id: IdentityId,
    pub machine_id: MachineId,
}

impl ZeroSdk {
    /// List inbox conversations sorted by last-message timestamp DESC.
    pub fn list_inbox(&self, limit: Option<usize>) -> Result<Vec<InboxEntry>, SdkError> {
        Ok(self.inbox.list_conversations(limit)?)
    }

    /// Global unread stats (total unread count + conversation count).
    pub fn inbox_stats(&self) -> Result<InboxStats, SdkError> {
        Ok(self.inbox.stats()?)
    }
}
