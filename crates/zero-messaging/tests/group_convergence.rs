//! Integration tests for group multi-party convergence, manifest merge,
//! and the 256-member cap (task 6.5).
//!
//! Acceptance criteria:
//!   - Three-party round-trip: owner creates, adds, removes, promotes; final
//!     manifest reflects correct membership and role assignments.
//!   - `merge_manifest` is commutative and idempotent (proptest).
//!   - `GroupFull` is returned at exactly the 257th member.

use std::sync::Arc;

use proptest::prelude::*;
use tempfile::TempDir;
use zero_crypto::aad::{IdentityId, MachineId};
use zero_messaging::group::{
    add_member, create_group, get_manifest, merge_manifest, promote, remove_member, send_message,
    GroupError, GroupId, GroupManifest, GroupMember, Role,
};
use zero_storage::db::ZeroDb;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn open_db() -> (TempDir, Arc<ZeroDb>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ZeroDb::open(dir.path()).expect("ZeroDb::open"));
    (dir, db)
}

fn identity(b: u8) -> IdentityId {
    IdentityId([b; 16])
}

fn machine(b: u8) -> MachineId {
    MachineId([b; 16])
}

/// Build a minimal `GroupManifest` for merge tests.
fn make_manifest(
    group_id: GroupId,
    creator: IdentityId,
    mls_epoch: u64,
    updated_at_ms: u64,
) -> GroupManifest {
    GroupManifest {
        group_id,
        name: "test-group".into(),
        creator,
        members: vec![GroupMember {
            identity_id: creator,
            machine_id: MachineId([0u8; 16]),
            role: Role::Owner,
            added_at_ms: 0,
        }],
        mls_epoch,
        mls_state_blob: Vec::new(),
        created_at_ms: 0,
        updated_at_ms,
    }
}

// ---------------------------------------------------------------------------
// Three-party convergence
// ---------------------------------------------------------------------------

/// All three parties share a single `ZeroDb` — the natural convergence point.
/// Owner (identity 1) creates the group, adds user_b (identity 2) and user_c
/// (identity 3), promotes user_b to Admin, then user_b removes user_c.
/// Both send messages. The final manifest must reflect: owner=Owner,
/// user_b=Admin, user_c absent; epoch > 0.
#[test]
fn three_party_convergence() {
    let (_dir, db) = open_db();

    let owner = identity(1);
    let user_b = identity(2);
    let user_c = identity(3);
    let machine_owner = machine(1);
    let machine_b = machine(2);

    // Owner creates group.
    let gid = create_group(&db, "convergence-test".into(), &[owner]).unwrap();

    // Owner adds user_b and user_c.
    add_member(&db, gid, owner, user_b).unwrap();
    add_member(&db, gid, owner, user_c).unwrap();

    // Epoch should have advanced twice from adds.
    let epoch_after_adds = get_manifest(&db, gid).unwrap().mls_epoch;
    assert!(epoch_after_adds >= 2, "epoch should advance on each add");

    // Owner promotes user_b to Admin.
    promote(&db, gid, owner, user_b, Role::Admin).unwrap();

    // Admin (user_b) removes user_c (Member).
    remove_member(&db, gid, user_b, user_c).unwrap();

    // Both remaining members send messages.
    send_message(&db, gid, owner, machine_owner, "hello from owner".into()).unwrap();
    send_message(&db, gid, user_b, machine_b, "hello from b".into()).unwrap();

    // Verify final manifest.
    let manifest = get_manifest(&db, gid).unwrap();

    // user_c was removed.
    assert!(
        !manifest.members.iter().any(|m| m.identity_id == user_c),
        "user_c should not be in manifest after removal"
    );

    // Exactly 2 members remain.
    assert_eq!(manifest.members.len(), 2);

    // owner is still Owner.
    let owner_entry = manifest
        .members
        .iter()
        .find(|m| m.identity_id == owner)
        .expect("owner should still be a member");
    assert_eq!(owner_entry.role, Role::Owner);

    // user_b is Admin.
    let b_entry = manifest
        .members
        .iter()
        .find(|m| m.identity_id == user_b)
        .expect("user_b should still be a member");
    assert_eq!(b_entry.role, Role::Admin);

    // Epoch advanced beyond where it was after the adds.
    assert!(
        manifest.mls_epoch > epoch_after_adds,
        "epoch should advance on remove"
    );
}

// ---------------------------------------------------------------------------
// GroupFull at exactly 257 members
// ---------------------------------------------------------------------------

/// Create a group and add members up to the 256-member cap.
/// Adding the 257th must return `GroupError::GroupFull`.
#[test]
fn group_full_at_257() {
    let (_dir, db) = open_db();
    let owner = identity(0);

    // Create with owner as sole member (count = 1).
    let gid = create_group(&db, "big-group".into(), &[owner]).unwrap();

    // Add identities 1..=255 to reach exactly 256 members.
    for i in 1u8..=255 {
        add_member(&db, gid, owner, identity(i)).unwrap();
    }

    let manifest = get_manifest(&db, gid).unwrap();
    assert_eq!(
        manifest.members.len(),
        256,
        "should have exactly 256 members at cap"
    );

    // The 257th member: [1, 0, 0, …, 0] — distinct from every [b; 16].
    let overflow = IdentityId({
        let mut a = [0u8; 16];
        a[0] = 1;
        a[1] = 0;
        a
    });

    match add_member(&db, gid, owner, overflow) {
        Err(GroupError::GroupFull { size: 256 }) => {}
        other => panic!("expected GroupFull{{size:256}}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Proptest: merge_manifest commutativity and idempotence
// ---------------------------------------------------------------------------

proptest! {
    /// `merge_manifest(a, b) == merge_manifest(b, a)` for any two manifests
    /// with the same `group_id`. When epoch and timestamp are both equal, `a`
    /// and `b` are structurally identical (same construction parameters), so
    /// either result satisfies the equality.
    #[test]
    fn merge_is_commutative(
        epoch_a in 0u64..50,
        ts_a    in 0u64..10_000u64,
        epoch_b in 0u64..50,
        ts_b    in 0u64..10_000u64,
    ) {
        let gid     = GroupId([0u8; 16]);
        let creator = IdentityId([0u8; 16]);

        let a = make_manifest(gid, creator, epoch_a, ts_a);
        let b = make_manifest(gid, creator, epoch_b, ts_b);

        let ab = merge_manifest(a.clone(), b.clone());
        let ba = merge_manifest(b, a);

        prop_assert_eq!(ab, ba);
    }

    /// `merge_manifest(a, a) == a` for any manifest.
    #[test]
    fn merge_is_idempotent(
        epoch  in 0u64..50,
        ts     in 0u64..10_000u64,
    ) {
        let gid     = GroupId([0u8; 16]);
        let creator = IdentityId([0u8; 16]);

        let a = make_manifest(gid, creator, epoch, ts);
        let merged = merge_manifest(a.clone(), a.clone());

        prop_assert_eq!(merged, a);
    }
}
