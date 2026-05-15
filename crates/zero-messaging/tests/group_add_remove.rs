//! Integration tests for group add_member / remove_member (task 6.2).
//!
//! Acceptance criteria:
//!   - Add/remove round-trip: manifest reflects current membership.
//!   - Epoch advances on each MLS commit (add or remove).
//!   - GroupFull is returned at exactly the 257th member (cap = 256).

use std::sync::Arc;

use tempfile::TempDir;
use zero_crypto::aad::IdentityId;
use zero_messaging::group::{add_member, create_group, get_manifest, remove_member, GroupError};
use zero_storage::db::ZeroDb;

/// Open a temporary `ZeroDb`. Returns the `TempDir` so the caller keeps it
/// alive for the lifetime of the test — dropping it would delete the path.
fn open_db() -> (TempDir, Arc<ZeroDb>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(ZeroDb::open(dir.path()).expect("ZeroDb::open"));
    (dir, db)
}

fn identity(b: u8) -> IdentityId {
    IdentityId([b; 16])
}

// ---------------------------------------------------------------------------
// Round-trip: add then remove
// ---------------------------------------------------------------------------

#[test]
fn add_member_appears_in_manifest() {
    let (_dir, db) = open_db();
    let owner = identity(1);
    let member = identity(2);

    let gid = create_group(&db, "round-trip".into(), &[owner]).unwrap();
    add_member(&db, gid, owner, member).unwrap();

    let manifest = get_manifest(&db, gid).unwrap();
    assert!(
        manifest.members.iter().any(|m| m.identity_id == member),
        "new member must appear in manifest"
    );
}

#[test]
fn remove_member_absent_from_manifest() {
    let (_dir, db) = open_db();
    let owner = identity(1);
    let member = identity(2);

    let gid = create_group(&db, "round-trip".into(), &[owner]).unwrap();
    add_member(&db, gid, owner, member).unwrap();
    remove_member(&db, gid, owner, member).unwrap();

    let manifest = get_manifest(&db, gid).unwrap();
    assert!(
        !manifest.members.iter().any(|m| m.identity_id == member),
        "removed member must not appear in manifest"
    );
}

// ---------------------------------------------------------------------------
// Epoch advances on each commit
// ---------------------------------------------------------------------------

#[test]
fn epoch_advances_on_add() {
    let (_dir, db) = open_db();
    let owner = identity(1);
    let m1 = identity(2);
    let m2 = identity(3);

    let gid = create_group(&db, "epoch-add".into(), &[owner]).unwrap();
    let epoch0 = get_manifest(&db, gid).unwrap().mls_epoch;

    add_member(&db, gid, owner, m1).unwrap();
    let epoch1 = get_manifest(&db, gid).unwrap().mls_epoch;
    assert_eq!(epoch1, epoch0 + 1, "epoch must advance after first add");

    add_member(&db, gid, owner, m2).unwrap();
    let epoch2 = get_manifest(&db, gid).unwrap().mls_epoch;
    assert_eq!(epoch2, epoch1 + 1, "epoch must advance after second add");
}

#[test]
fn epoch_advances_on_remove() {
    let (_dir, db) = open_db();
    let owner = identity(1);
    let member = identity(2);

    let gid = create_group(&db, "epoch-remove".into(), &[owner]).unwrap();
    add_member(&db, gid, owner, member).unwrap();
    let epoch_before = get_manifest(&db, gid).unwrap().mls_epoch;

    remove_member(&db, gid, owner, member).unwrap();
    let epoch_after = get_manifest(&db, gid).unwrap().mls_epoch;

    assert_eq!(
        epoch_after,
        epoch_before + 1,
        "epoch must advance after remove"
    );
}

#[test]
fn epoch_advances_independently_for_add_and_remove() {
    let (_dir, db) = open_db();
    let owner = identity(1);
    let m2 = identity(2);
    let m3 = identity(3);

    let gid = create_group(&db, "epoch-seq".into(), &[owner]).unwrap();
    let e0 = get_manifest(&db, gid).unwrap().mls_epoch;

    add_member(&db, gid, owner, m2).unwrap();
    add_member(&db, gid, owner, m3).unwrap();
    remove_member(&db, gid, owner, m2).unwrap();

    let e3 = get_manifest(&db, gid).unwrap().mls_epoch;
    assert_eq!(e3, e0 + 3, "three commits must advance epoch by exactly 3");
}

// ---------------------------------------------------------------------------
// Cap: GroupFull at the 257th member
// ---------------------------------------------------------------------------

#[test]
fn group_full_at_257() {
    let (_dir, db) = open_db();
    // identity(0) = owner; identities 1..=255 are 255 additional members
    // Owner + 255 = 256 total (at cap). The 257th add must fail.
    let owner = identity(0);
    let gid = create_group(&db, "full".into(), &[owner]).unwrap();

    // Fill to exactly 256 members (owner + 255 more).
    for i in 1u8..=255 {
        add_member(&db, gid, owner, identity(i)).expect("add within cap");
    }

    // Verify we are at the cap.
    let manifest = get_manifest(&db, gid).unwrap();
    assert_eq!(
        manifest.members.len(),
        256,
        "should be at cap before overflow"
    );

    // The 257th identity uses two bytes so it doesn't collide with the first 256.
    let overflow = IdentityId({
        let mut a = [0u8; 16];
        a[0] = 1;
        a[1] = 0;
        a
    });
    let err = add_member(&db, gid, owner, overflow).unwrap_err();
    match err {
        GroupError::GroupFull { size } => {
            assert_eq!(size, 256, "GroupFull must report size = 256");
        }
        other => panic!("expected GroupFull, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Permission: Member cannot add; Member cannot remove
// ---------------------------------------------------------------------------

#[test]
fn member_cannot_add() {
    let (_dir, db) = open_db();
    let owner = identity(1);
    let regular = identity(2);
    let newcomer = identity(3);

    let gid = create_group(&db, "perms".into(), &[owner]).unwrap();
    add_member(&db, gid, owner, regular).unwrap();

    let err = add_member(&db, gid, regular, newcomer).unwrap_err();
    assert!(
        matches!(err, GroupError::PermissionDenied { .. }),
        "Member add must be PermissionDenied, got: {err:?}"
    );
}

#[test]
fn member_cannot_remove() {
    let (_dir, db) = open_db();
    let owner = identity(1);
    let m2 = identity(2);
    let m3 = identity(3);

    let gid = create_group(&db, "perms-remove".into(), &[owner]).unwrap();
    add_member(&db, gid, owner, m2).unwrap();
    add_member(&db, gid, owner, m3).unwrap();

    let err = remove_member(&db, gid, m2, m3).unwrap_err();
    assert!(
        matches!(err, GroupError::PermissionDenied { .. }),
        "Member remove must be PermissionDenied, got: {err:?}"
    );
}
