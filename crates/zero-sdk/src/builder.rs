//! Builder for constructing the `ZeroSdk` facade.

use std::path::PathBuf;
use std::sync::Arc;

use zero_crypto::aad::{IdentityId, MachineId};
use zero_identity::neural_key::NeuralKey;
use zero_messaging::contacts::ContactStore;
use zero_messaging::dm::DmService;
use zero_messaging::inbox::InboxService;
use zero_storage::ZeroDb;

use crate::error::SdkError;
use crate::ZeroSdk;

impl ZeroSdk {
    /// Construct the full wired stack from a database path and a `NeuralKey`.
    ///
    /// Derives `IdentityId` from the key and generates a deterministic
    /// default `MachineId` via BLAKE3 so that the same key always produces
    /// the same local identity.
    pub fn open(path: impl Into<PathBuf>, neural_key: &NeuralKey) -> Result<Self, SdkError> {
        let identity_id = IdentityId(neural_key.identity_id_bytes());
        let machine_id = derive_default_machine_id(&identity_id);
        Self::open_raw(path, identity_id, machine_id)
    }

    /// Lower-level constructor that accepts explicit ids.
    pub fn open_raw(
        path: impl Into<PathBuf>,
        identity_id: IdentityId,
        machine_id: MachineId,
    ) -> Result<Self, SdkError> {
        let path = path.into();
        let db = Arc::new(ZeroDb::open(&path)?);
        let contacts = Arc::new(ContactStore::new(Arc::clone(&db), identity_id));
        let dm = Arc::new(DmService::new(
            Arc::clone(&db),
            identity_id,
            machine_id,
            Arc::clone(&contacts),
        ));
        let inbox = Arc::new(InboxService::new(Arc::clone(&db), identity_id, machine_id));

        Ok(Self {
            db,
            contacts,
            dm,
            inbox,
            identity_id,
            machine_id,
        })
    }
}

/// Derive a deterministic `MachineId` from an `IdentityId` using BLAKE3.
fn derive_default_machine_id(identity_id: &IdentityId) -> MachineId {
    let hash = blake3::keyed_hash(
        blake3::hash(b"zero-sdk:machine-id:v1").as_bytes(),
        &identity_id.0,
    );
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    MachineId(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_machine_id_is_deterministic() {
        let id = IdentityId([0xAA; 16]);
        let a = derive_default_machine_id(&id);
        let b = derive_default_machine_id(&id);
        assert_eq!(a, b);
    }

    #[test]
    fn different_identity_yields_different_machine_id() {
        let a = derive_default_machine_id(&IdentityId([0x01; 16]));
        let b = derive_default_machine_id(&IdentityId([0x02; 16]));
        assert_ne!(a, b);
    }
}
