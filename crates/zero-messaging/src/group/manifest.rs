//! GroupManifest encoding, decoding, and persistence.

use std::sync::Arc;

use zero_storage::{ZeroDb, CF_GROUPS};

use super::types::{GroupError, GroupId, GroupManifest};

/// Encode a `GroupManifest` to postcard bytes.
pub fn encode_manifest(manifest: &GroupManifest) -> Result<Vec<u8>, GroupError> {
    postcard::to_allocvec(manifest).map_err(|e| GroupError::Mls(format!("encode: {e}")))
}

/// Decode a `GroupManifest` from postcard bytes.
pub fn decode_manifest(bytes: &[u8]) -> Result<GroupManifest, GroupError> {
    postcard::from_bytes(bytes).map_err(|e| GroupError::Mls(format!("decode: {e}")))
}

/// Sort manifest members by `identity_id` bytes (ascending).
pub fn normalize_members(manifest: &mut GroupManifest) {
    manifest
        .members
        .sort_by(|a, b| a.identity_id.0.cmp(&b.identity_id.0));
}

/// Persist a manifest to `CF_GROUPS`, keyed by `GroupId`.
pub fn persist_manifest(db: &Arc<ZeroDb>, manifest: &GroupManifest) -> Result<(), GroupError> {
    let key = &manifest.group_id.0;
    let value = encode_manifest(manifest)?;
    db.put_raw(CF_GROUPS, key, &value)?;
    Ok(())
}

/// Merge two manifests for the same group. Higher `mls_epoch` wins;
/// if equal, latest `updated_at_ms` wins. Deterministic and commutative.
pub fn merge_manifests(a: &GroupManifest, b: &GroupManifest) -> GroupManifest {
    debug_assert_eq!(a.group_id, b.group_id);
    let winner = if a.mls_epoch > b.mls_epoch {
        a
    } else if b.mls_epoch > a.mls_epoch {
        b
    } else if a.updated_at_ms >= b.updated_at_ms {
        a
    } else {
        b
    };
    let mut result = winner.clone();
    normalize_members(&mut result);
    result
}

/// Load a manifest from `CF_GROUPS` by `GroupId`.
pub fn load_manifest(
    db: &Arc<ZeroDb>,
    group_id: &GroupId,
) -> Result<Option<GroupManifest>, GroupError> {
    match db.get_raw(CF_GROUPS, &group_id.0)? {
        Some(bytes) => Ok(Some(decode_manifest(&bytes)?)),
        None => Ok(None),
    }
}

/// Merge two manifests for the same group.
///
/// Resolution rule (deterministic, commutative):
/// - Higher `mls_epoch` wins.
/// - On equal epoch, higher `updated_at_ms` wins.
/// - On exact tie, `a` is returned (stable fallback).
///
/// Panics in debug mode if the `group_id` values differ.
pub fn merge_manifest(a: GroupManifest, b: GroupManifest) -> GroupManifest {
    debug_assert_eq!(
        a.group_id, b.group_id,
        "merge_manifest called with mismatched group_ids"
    );
    if a.mls_epoch > b.mls_epoch {
        return a;
    }
    if b.mls_epoch > a.mls_epoch {
        return b;
    }
    // Equal epoch: later update wins; ties favour `a` for determinism.
    if b.updated_at_ms > a.updated_at_ms {
        b
    } else {
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::types::{GroupMember, Role};
    use zero_crypto::aad::{IdentityId, MachineId};

    fn sample_manifest() -> GroupManifest {
        GroupManifest {
            group_id: GroupId([1; 16]),
            name: "Test Group".to_string(),
            creator: IdentityId([10; 16]),
            members: vec![
                GroupMember {
                    identity_id: IdentityId([20; 16]),
                    machine_id: MachineId([30; 16]),
                    role: Role::Member,
                    added_at_ms: 1000,
                },
                GroupMember {
                    identity_id: IdentityId([10; 16]),
                    machine_id: MachineId([11; 16]),
                    role: Role::Owner,
                    added_at_ms: 999,
                },
            ],
            mls_epoch: 0,
            mls_state_blob: Vec::new(),
            created_at_ms: 999,
            updated_at_ms: 999,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let manifest = sample_manifest();
        let bytes = encode_manifest(&manifest).unwrap();
        let decoded = decode_manifest(&bytes).unwrap();
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn normalize_sorts_by_identity_id() {
        let mut manifest = sample_manifest();
        assert!(manifest.members[0].identity_id.0 > manifest.members[1].identity_id.0);
        normalize_members(&mut manifest);
        assert!(manifest.members[0].identity_id.0 < manifest.members[1].identity_id.0);
    }
}
