//! End-to-end integration test for `zero-identity` (task 1.9).
//!
//! Exercises the full identity lifecycle:
//!   1. Generate a fresh `NeuralKey`.
//!   2. Emit `(threshold = 2, total = 3)` Shamir shares.
//!   3. Recover the `NeuralKey` from a 2-share subset.
//!   4. Bind a first `MachineKey` and then two more under the same identity.
//!   5. Assert that listing returns 3 entries and that the recovered key
//!      produces an identical `IdentityId` to the original.
//!
//! The crate's public API does not expose a seedable RNG, so we rely on the
//! deterministic `IdentityId` derivation (BLAKE3 over the raw key bytes) as
//! the reproducibility anchor required by the acceptance criteria.

use zero_identity::machine_key::MachineKeyStore;
use zero_identity::neural_key::{recover_neural_key, split_neural_key, NeuralKey, ShareConfig};

const ED25519_PUB_LEN: usize = 32;
const MLDSA65_PUB_LEN: usize = 1952;

#[test]
fn full_identity_lifecycle() {
    let original = NeuralKey::generate().expect("generate fresh NeuralKey");
    let original_id = original.identity_id();

    let cfg = ShareConfig {
        threshold: 2,
        total: 3,
    };
    let shares = split_neural_key(&original, cfg).expect("split into (2,3) shares");
    assert_eq!(
        shares.threshold, 2,
        "emitted shares must echo the requested threshold"
    );
    assert_eq!(
        shares.shares.len(),
        3,
        "split must emit exactly `total` shares"
    );

    let subset: Vec<Vec<u8>> = shares.shares.iter().take(2).cloned().collect();
    assert_eq!(subset.len(), 2, "threshold subset must have 2 shares");
    let recovered = recover_neural_key(&subset, shares.threshold)
        .expect("recover NeuralKey from threshold subset");

    assert_eq!(
        recovered.identity_id(),
        original_id,
        "recovered NeuralKey must yield the original IdentityId"
    );

    let store = MachineKeyStore::new();

    let first = store
        .generate_machine_key(&original, "primary-laptop")
        .expect("bind first machine key");
    let second = store
        .generate_machine_key(&original, "secondary-phone")
        .expect("bind second machine key");
    let third = store
        .generate_machine_key(&original, "tertiary-tablet")
        .expect("bind third machine key");

    for entry in [&first, &second, &third] {
        assert_eq!(
            entry.ed25519_pub.len(),
            ED25519_PUB_LEN,
            "Ed25519 verifying key must be {ED25519_PUB_LEN} bytes"
        );
        assert_eq!(
            entry.mldsa65_pub.len(),
            MLDSA65_PUB_LEN,
            "ML-DSA-65 verifying key must be {MLDSA65_PUB_LEN} bytes"
        );
    }

    assert_ne!(
        first.machine_id, second.machine_id,
        "distinct binds must yield distinct MachineIds"
    );
    assert_ne!(
        second.machine_id, third.machine_id,
        "distinct binds must yield distinct MachineIds"
    );
    assert_ne!(
        first.machine_id, third.machine_id,
        "distinct binds must yield distinct MachineIds"
    );

    let listed = store
        .list_machine_keys(&original)
        .expect("list machine keys for the original identity");
    assert_eq!(
        listed.len(),
        3,
        "list_machine_keys must return all three bound entries"
    );

    let listed_ids: Vec<_> = listed.iter().map(|e| e.machine_id).collect();
    assert!(
        listed_ids.contains(&first.machine_id),
        "list must contain the first machine id"
    );
    assert!(
        listed_ids.contains(&second.machine_id),
        "list must contain the second machine id"
    );
    assert!(
        listed_ids.contains(&third.machine_id),
        "list must contain the third machine id"
    );

    // Recovery anchor: the recovered NeuralKey is functionally interchangeable
    // with the original from the store's perspective.
    let listed_via_recovered = store
        .list_machine_keys(&recovered)
        .expect("list under recovered NeuralKey");
    assert_eq!(
        listed_via_recovered.len(),
        3,
        "recovered NeuralKey must list the same machine keys as the original"
    );
}
