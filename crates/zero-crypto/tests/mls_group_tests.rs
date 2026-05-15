//! Integration tests for MLS group-key wrappers (task 4.7).
//!
//! These tests exercise the public API from outside the crate and
//! directly verify the task acceptance criteria:
//!   - A group of 3 members forms, sends, and receives application messages.
//!   - Epoch advances on every commit.

use zero_crypto::group_key::{
    add_member, create_group, decrypt_from_group, encrypt_for_group, epoch, epoch_secret,
    join_group, process_commit, MlsMember,
};

fn member(name: &str) -> MlsMember {
    MlsMember::new(name, "machine-0").expect("member creation failed")
}

#[test]
fn group_of_three_forms_sends_and_receives() {
    let alice = member("alice");
    let bob = member("bob");
    let carol = member("carol");

    // Alice creates the group (epoch 0).
    let mut alice_group = create_group(&alice).unwrap();
    assert_eq!(epoch(&alice_group), 0);

    // Alice adds Bob -> epoch 1.
    let bob_kp = bob.key_package().unwrap();
    let (_commit_ab, welcome_bob) = add_member(&mut alice_group, &alice, bob_kp).unwrap();
    assert_eq!(epoch(&alice_group), 1);

    let mut bob_group = join_group(&bob, welcome_bob).unwrap();
    assert_eq!(epoch(&bob_group), 1);

    // Alice adds Carol -> epoch 2; Bob processes the commit.
    let carol_kp = carol.key_package().unwrap();
    let (commit_ac, welcome_carol) = add_member(&mut alice_group, &alice, carol_kp).unwrap();
    assert_eq!(epoch(&alice_group), 2);

    process_commit(&mut bob_group, &bob, commit_ac).unwrap();
    assert_eq!(epoch(&bob_group), 2);

    let mut carol_group = join_group(&carol, welcome_carol).unwrap();
    assert_eq!(epoch(&carol_group), 2);

    // Alice broadcasts a message; Bob and Carol both decrypt it.
    let msg = b"hello group of three";
    let ct = encrypt_for_group(&mut alice_group, &alice, msg).unwrap();
    let bob_pt = decrypt_from_group(&mut bob_group, &bob, ct.clone()).unwrap();
    let carol_pt = decrypt_from_group(&mut carol_group, &carol, ct).unwrap();
    assert_eq!(bob_pt, msg);
    assert_eq!(carol_pt, msg);

    // Bob replies; Alice and Carol decrypt.
    let reply = b"reply from bob";
    let ct2 = encrypt_for_group(&mut bob_group, &bob, reply).unwrap();
    let alice_pt = decrypt_from_group(&mut alice_group, &alice, ct2.clone()).unwrap();
    let carol_pt2 = decrypt_from_group(&mut carol_group, &carol, ct2).unwrap();
    assert_eq!(alice_pt, reply);
    assert_eq!(carol_pt2, reply);
}

#[test]
fn epoch_advances_on_commit() {
    let alice = member("alice");
    let bob = member("bob");
    let carol = member("carol");

    let mut group = create_group(&alice).unwrap();
    assert_eq!(epoch(&group), 0);

    let bob_kp = bob.key_package().unwrap();
    add_member(&mut group, &alice, bob_kp).unwrap();
    assert_eq!(epoch(&group), 1);

    let carol_kp = carol.key_package().unwrap();
    add_member(&mut group, &alice, carol_kp).unwrap();
    assert_eq!(epoch(&group), 2);
}

#[test]
fn epoch_secret_exported_consistently() {
    let alice = member("alice");
    let bob = member("bob");

    let mut alice_group = create_group(&alice).unwrap();
    let bob_kp = bob.key_package().unwrap();
    let (_commit, welcome) = add_member(&mut alice_group, &alice, bob_kp).unwrap();
    let bob_group = join_group(&bob, welcome).unwrap();

    let label = "zero.group.export.v1";
    let alice_sec = epoch_secret(&alice_group, &alice, label, 32).unwrap();
    let bob_sec = epoch_secret(&bob_group, &bob, label, 32).unwrap();
    assert_eq!(
        alice_sec, bob_sec,
        "all members share the same epoch secret"
    );
    assert_eq!(alice_sec.len(), 32);
}
