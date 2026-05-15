//! `machine_key` --- in-memory `MachineKey` store.
//!
//! This module exposes [`MachineKeyEntry`] and [`MachineKeyStore`], an
//! in-memory registry of machine keys generated for a given
//! [`NeuralKey`](crate::neural_key::NeuralKey). Persistence is the subject
//! of later phase-1 tasks; for now the store keeps entries behind a
//! [`std::sync::Mutex`] so it can be shared across `tokio` tasks without
//! pulling in a database.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use zid::keys::machine::{MachineKeyCapabilities, MachineKeyPair};
use zid::types::{IdentityId, MachineId};

use crate::error::IdentityError;
use crate::neural_key::NeuralKey;

/// Public, display-oriented summary of a machine key persisted in a
/// [`MachineKeyStore`].
///
/// All public-key fields are raw byte representations so that callers may
/// hex/base64-encode them as needed without depending on `zid` types.
#[derive(Debug, Clone)]
pub struct MachineKeyEntry {
    /// Stable 128-bit machine identifier.
    pub machine_id: MachineId,
    /// Caller-provided human-readable label (e.g. `"laptop-2024"`).
    pub label: String,
    /// Creation timestamp expressed as seconds since the Unix epoch.
    pub created_at: u64,
    /// Ed25519 verifying key (32 bytes).
    pub ed25519_pub: [u8; 32],
    /// ML-DSA-65 verifying key (1952 bytes).
    pub mldsa65_pub: Vec<u8>,
}

/// In-memory registry of machine keys keyed by their owning identity.
///
/// The store is `Send + Sync` and may be cloned cheaply by wrapping in an
/// [`std::sync::Arc`]. Persistence is intentionally out of scope for this
/// task and lands in later milestones.
#[derive(Debug, Default)]
pub struct MachineKeyStore {
    entries: Mutex<Vec<(IdentityId, MachineKeyEntry)>>,
}

impl MachineKeyStore {
    /// Construct an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a fresh machine key for `identity` and persist a summary
    /// in the store.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Zid`] if the upstream key derivation
    /// rejects the freshly drawn seed material (e.g. ML-DSA key gen
    /// fails internally), or [`IdentityError::SerializationError`] if
    /// the system clock is set before the Unix epoch.
    pub fn generate_machine_key(
        &self,
        identity: &NeuralKey,
        label: impl Into<String>,
    ) -> Result<MachineKeyEntry, IdentityError> {
        let mut rng = OsRng;

        let mut sign_seed = [0u8; 32];
        let mut encrypt_seed = [0u8; 32];
        let mut pq_sign_seed = [0u8; 32];
        let mut pq_encrypt_seed = [0u8; 32];
        rng.fill_bytes(&mut sign_seed);
        rng.fill_bytes(&mut encrypt_seed);
        rng.fill_bytes(&mut pq_sign_seed);
        rng.fill_bytes(&mut pq_encrypt_seed);

        let mut machine_id_bytes = [0u8; 16];
        rng.fill_bytes(&mut machine_id_bytes);
        let machine_id = MachineId::from(machine_id_bytes);

        let pair = MachineKeyPair::from_seeds(
            sign_seed,
            encrypt_seed,
            pq_sign_seed,
            pq_encrypt_seed,
            MachineKeyCapabilities::empty(),
            0,
        )?;
        let public = pair.public_key();

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IdentityError::SerializationError)?
            .as_secs();

        let entry = MachineKeyEntry {
            machine_id,
            label: label.into(),
            created_at,
            ed25519_pub: public.ed25519_bytes(),
            mldsa65_pub: public.ml_dsa_bytes(),
        };

        let identity_id = identity.identity_id();
        self.entries
            .lock()
            .map_err(|_| IdentityError::SerializationError)?
            .push((identity_id, entry.clone()));

        Ok(entry)
    }

    /// List every machine key previously generated for `identity`, in
    /// insertion order.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::SerializationError`] if the internal
    /// mutex has been poisoned by a panic in another thread.
    pub fn list_machine_keys(
        &self,
        identity: &NeuralKey,
    ) -> Result<Vec<MachineKeyEntry>, IdentityError> {
        let target = identity.identity_id();
        let guard = self
            .entries
            .lock()
            .map_err(|_| IdentityError::SerializationError)?;
        Ok(guard
            .iter()
            .filter(|(id, _)| *id == target)
            .map(|(_, entry)| entry.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{MachineKeyEntry, MachineKeyStore};
    use crate::neural_key::NeuralKey;
    use std::collections::HashSet;

    /// ML-DSA-65 verifying-key encoded length in bytes (FIPS 204).
    const MLDSA65_PUB_LEN: usize = 1952;

    #[test]
    fn generate_three_then_list_returns_three_entries() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("generate neural key");

        let mut created: Vec<MachineKeyEntry> = Vec::new();
        for i in 0..3 {
            let entry = store
                .generate_machine_key(&identity, format!("machine-{i}"))
                .expect("generate machine key");
            assert_eq!(entry.ed25519_pub.len(), 32);
            assert_eq!(entry.mldsa65_pub.len(), MLDSA65_PUB_LEN);
            created.push(entry);
        }

        let listed = store
            .list_machine_keys(&identity)
            .expect("list machine keys");
        assert_eq!(listed.len(), 3, "expected exactly 3 entries");

        let listed_ids: HashSet<_> = listed.iter().map(|e| e.machine_id).collect();
        let created_ids: HashSet<_> = created.iter().map(|e| e.machine_id).collect();
        assert_eq!(listed_ids.len(), 3, "machine ids must be distinct");
        assert_eq!(
            listed_ids, created_ids,
            "listed ids must match those returned by generate_machine_key"
        );

        for entry in &listed {
            assert_eq!(entry.ed25519_pub.len(), 32);
            assert_eq!(entry.mldsa65_pub.len(), MLDSA65_PUB_LEN);
        }
    }

    #[test]
    fn list_is_scoped_per_identity() {
        let store = MachineKeyStore::new();
        let alice = NeuralKey::generate().expect("alice");
        let bob = NeuralKey::generate().expect("bob");

        store
            .generate_machine_key(&alice, "alice-laptop")
            .expect("generate alice key");
        store
            .generate_machine_key(&bob, "bob-phone")
            .expect("generate bob key");
        store
            .generate_machine_key(&bob, "bob-laptop")
            .expect("generate bob key");

        let alice_keys = store.list_machine_keys(&alice).expect("list alice");
        let bob_keys = store.list_machine_keys(&bob).expect("list bob");

        assert_eq!(alice_keys.len(), 1);
        assert_eq!(bob_keys.len(), 2);
        assert_eq!(alice_keys[0].label, "alice-laptop");
    }

    /// Task 1.10 acceptance: every key-bearing field of
    /// [`MachineKeyEntry`] has the exact byte length mandated by its
    /// underlying primitive, and [`MachineId`] matches the ZID
    /// 128-bit-identifier spec.
    #[test]
    fn byte_length_invariants() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("generate neural key");
        let entry = store
            .generate_machine_key(&identity, "byte-length-check")
            .expect("generate machine key");

        // Ed25519 verifying key: RFC 8032 fixes the public-key length at
        // 32 bytes.
        assert_eq!(
            entry.ed25519_pub.len(),
            32,
            "Ed25519 verifying key must be exactly 32 bytes"
        );

        // ML-DSA-65 verifying key: FIPS 204 fixes the public-key length
        // at 1952 bytes.
        assert_eq!(
            entry.mldsa65_pub.len(),
            MLDSA65_PUB_LEN,
            "ML-DSA-65 verifying key must be exactly {MLDSA65_PUB_LEN} bytes"
        );

        // MachineId per ZID spec is a 128-bit (16-byte) identifier.
        assert_eq!(
            entry.machine_id.as_bytes().len(),
            16,
            "MachineId must be exactly 16 bytes (128 bits) per ZID spec"
        );
    }

    /// Task 1.6 acceptance: the first `generate_machine_key` call binds a
    /// genesis machine key under a fresh `NeuralKey`, and subsequent
    /// calls produce additional, distinct machine ids that are all
    /// scoped to the same `NeuralKey`.
    #[test]
    fn first_and_subsequent_generates_share_one_neural_key() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("generate neural key");

        let genesis = store
            .generate_machine_key(&identity, "genesis")
            .expect("first generate must succeed");

        let mut ids: HashSet<_> = HashSet::new();
        ids.insert(genesis.machine_id);

        for i in 0..4 {
            let entry = store
                .generate_machine_key(&identity, format!("subsequent-{i}"))
                .expect("subsequent generate must succeed");
            assert!(
                ids.insert(entry.machine_id),
                "machine id collision between generated keys"
            );
        }
        assert_eq!(ids.len(), 5, "expected five distinct machine ids");

        let listed = store
            .list_machine_keys(&identity)
            .expect("list under owning identity");
        assert_eq!(
            listed.len(),
            5,
            "all generated keys must be bound to the originating NeuralKey"
        );
        let listed_ids: HashSet<_> = listed.iter().map(|e| e.machine_id).collect();
        assert_eq!(
            listed_ids, ids,
            "listed ids must exactly match the generated ids"
        );

        let unrelated = NeuralKey::generate().expect("generate unrelated neural key");
        let foreign = store
            .list_machine_keys(&unrelated)
            .expect("list under unrelated identity");
        assert!(
            foreign.is_empty(),
            "no machine keys should leak across NeuralKeys"
        );
    }
}
