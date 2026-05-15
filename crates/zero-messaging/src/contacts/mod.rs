//! Address-book contacts persisted in `cf_contacts`, scoped by the owning
//! `IdentityId`. Each contact stores the remote identity's public keys and an
//! optional human-readable label. CRUD operations enforce uniqueness on
//! `(owner, contact.identity_id)` -- a second `add_contact` with the same
//! identity overwrites the previous entry.

pub mod store;
pub mod types;

pub use store::ContactStore;
pub use types::{Contact, ContactError, ContactMachineKey};
