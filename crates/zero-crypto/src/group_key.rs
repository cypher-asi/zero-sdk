//! MLS group-key helpers.
//!
//! Stateless wrappers around `openmls` for creating groups, adding members,
//! processing commits, and exchanging application messages.

use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::error::CryptoError;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn map_mls<E: core::fmt::Debug>(e: E) -> CryptoError {
    CryptoError::Mls(format!("{e:?}"))
}

/// Persistent state for a single MLS member (identity + machine).
pub struct MlsMember {
    pub provider: OpenMlsRustCrypto,
    pub credential_with_key: CredentialWithKey,
    pub signer: SignatureKeyPair,
}

impl MlsMember {
    /// Bootstrap a new MLS member from an identity/machine pair.
    pub fn new(identity_id: &str, machine_id: &str) -> Result<Self, CryptoError> {
        let provider = OpenMlsRustCrypto::default();

        let signature_keys =
            SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(map_mls)?;
        signature_keys.store(provider.storage()).map_err(map_mls)?;

        let identity = format!("{identity_id}:{machine_id}");
        let credential = BasicCredential::new(identity.into_bytes());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        Ok(Self {
            provider,
            credential_with_key,
            signer: signature_keys,
        })
    }

    /// Generate a fresh `KeyPackage` for this member.
    pub fn key_package(&self) -> Result<KeyPackage, CryptoError> {
        let kp = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(map_mls)?;

        Ok(kp.key_package().clone())
    }
}

/// Serialised MLS `KeyPackage` bytes.
pub struct MlsKeyPackage(pub Vec<u8>);

/// Generate a fresh MLS `KeyPackage` for the given identity/machine.
pub fn generate_key_package(
    identity_id: &str,
    machine_id: &str,
) -> Result<MlsKeyPackage, CryptoError> {
    let member = MlsMember::new(identity_id, machine_id)?;
    let kp = member.key_package()?;
    let bytes = kp.tls_serialize_detached().map_err(map_mls)?;
    Ok(MlsKeyPackage(bytes))
}

/// Create a new MLS group owned by `creator`.
pub fn create_group(creator: &MlsMember) -> Result<MlsGroup, CryptoError> {
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    MlsGroup::new(
        &creator.provider,
        &creator.signer,
        &group_config,
        creator.credential_with_key.clone(),
    )
    .map_err(map_mls)
}

/// Add a member (via their `KeyPackage`) to `group` and return
/// `(commit_msg, welcome)` ready for transport.
pub fn add_member(
    group: &mut MlsGroup,
    adder: &MlsMember,
    joiner_kp: KeyPackage,
) -> Result<(MlsMessageOut, MlsMessageOut), CryptoError> {
    let (commit_msg, welcome, _group_info) = group
        .add_members(&adder.provider, &adder.signer, &[joiner_kp])
        .map_err(map_mls)?;

    group
        .merge_pending_commit(&adder.provider)
        .map_err(map_mls)?;

    Ok((commit_msg, welcome))
}

/// Join a group from a received `Welcome` message.
pub fn join_group(member: &MlsMember, welcome: MlsMessageOut) -> Result<MlsGroup, CryptoError> {
    let serialized = welcome
        .to_bytes()
        .map_err(|e| CryptoError::Mls(format!("serialize welcome: {e:?}")))?;
    let msg_in = MlsMessageIn::tls_deserialize_exact(serialized)
        .map_err(|e| CryptoError::Mls(format!("deserialize welcome: {e:?}")))?;

    let group_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let welcome = match msg_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err(CryptoError::Mls("expected welcome message".into())),
    };

    StagedWelcome::new_from_welcome(&member.provider, &group_config, welcome, None)
        .map_err(map_mls)?
        .into_group(&member.provider)
        .map_err(map_mls)
}

/// Encrypt an application message for the group.
pub fn encrypt_for_group(
    group: &mut MlsGroup,
    sender: &MlsMember,
    plaintext: &[u8],
) -> Result<MlsMessageOut, CryptoError> {
    group
        .create_message(&sender.provider, &sender.signer, plaintext)
        .map_err(map_mls)
}

/// Decrypt an application message received from the group.
pub fn decrypt_from_group(
    group: &mut MlsGroup,
    receiver: &MlsMember,
    mls_msg: MlsMessageOut,
) -> Result<Vec<u8>, CryptoError> {
    let serialized = mls_msg
        .to_bytes()
        .map_err(|e| CryptoError::Mls(format!("serialize msg: {e:?}")))?;
    let msg_in = MlsMessageIn::tls_deserialize_exact(serialized)
        .map_err(|e| CryptoError::Mls(format!("deserialize msg: {e:?}")))?;

    let protocol_msg = msg_in.try_into_protocol_message().map_err(map_mls)?;

    let processed = group
        .process_message(&receiver.provider, protocol_msg)
        .map_err(map_mls)?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(app_msg.into_bytes()),
        other => Err(CryptoError::Mls(format!(
            "expected application message, got {other:?}"
        ))),
    }
}

/// Process a commit message received from the group (e.g. when another member
/// adds a new participant). Returns the processed content for inspection.
pub fn process_commit(
    group: &mut MlsGroup,
    receiver: &MlsMember,
    commit_msg: MlsMessageOut,
) -> Result<(), CryptoError> {
    let serialized = commit_msg
        .to_bytes()
        .map_err(|e| CryptoError::Mls(format!("serialize commit: {e:?}")))?;
    let msg_in = MlsMessageIn::tls_deserialize_exact(serialized)
        .map_err(|e| CryptoError::Mls(format!("deserialize commit: {e:?}")))?;

    let protocol_msg = msg_in.try_into_protocol_message().map_err(map_mls)?;

    let processed = group
        .process_message(&receiver.provider, protocol_msg)
        .map_err(map_mls)?;

    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(&receiver.provider, *staged)
                .map_err(map_mls)?;
            Ok(())
        }
        other => Err(CryptoError::Mls(format!(
            "expected commit message, got {other:?}"
        ))),
    }
}

/// Export a secret from the current group epoch.
///
/// `label` identifies the purpose; `len` is the desired output length in bytes.
pub fn epoch_secret(
    group: &MlsGroup,
    member: &MlsMember,
    label: &str,
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    group
        .export_secret(&member.provider, label, &[], len)
        .map_err(map_mls)
}

/// Return the current epoch of the group.
pub fn epoch(group: &MlsGroup) -> u64 {
    group.epoch().as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_member(name: &str) -> MlsMember {
        MlsMember::new(name, "machine-0").expect("member creation")
    }

    #[test]
    fn generate_key_package_produces_distinct_bytes() {
        let a = generate_key_package("alice", "m1").unwrap();
        let b = generate_key_package("alice", "m1").unwrap();
        assert_ne!(a.0, b.0, "key packages must use fresh randomness");
    }

    #[test]
    fn key_package_round_trip_deserialize() {
        let pkg = generate_key_package("bob", "m2").unwrap();
        let _kp = KeyPackageIn::tls_deserialize_exact(pkg.0).expect("deserialization must succeed");
    }

    #[test]
    fn two_member_group_send_receive() {
        let alice = make_member("alice");
        let bob = make_member("bob");

        let mut alice_group = create_group(&alice).unwrap();
        let bob_kp = bob.key_package().unwrap();

        let (_commit, welcome) = add_member(&mut alice_group, &alice, bob_kp).unwrap();
        let mut bob_group = join_group(&bob, welcome).unwrap();

        let plaintext = b"hello from alice";
        let ct = encrypt_for_group(&mut alice_group, &alice, plaintext).unwrap();
        let decrypted = decrypt_from_group(&mut bob_group, &bob, ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn group_of_three_forms_and_exchanges_messages() {
        let alice = make_member("alice");
        let bob = make_member("bob");
        let carol = make_member("carol");

        // Alice creates the group (epoch 1).
        let mut alice_group = create_group(&alice).unwrap();
        assert_eq!(epoch(&alice_group), 0);

        // Alice adds Bob.
        let bob_kp = bob.key_package().unwrap();
        let (_commit_ab, welcome_bob) = add_member(&mut alice_group, &alice, bob_kp).unwrap();
        assert_eq!(
            epoch(&alice_group),
            1,
            "epoch advances after add_member commit"
        );

        let mut bob_group = join_group(&bob, welcome_bob).unwrap();
        // Bob's group epoch matches Alice's after join.
        assert_eq!(epoch(&bob_group), 1);

        // Alice adds Carol. Bob must process the commit.
        let carol_kp = carol.key_package().unwrap();
        let (commit_ac, welcome_carol) = add_member(&mut alice_group, &alice, carol_kp).unwrap();
        assert_eq!(epoch(&alice_group), 2);

        // Bob processes Alice's commit that added Carol.
        process_commit(&mut bob_group, &bob, commit_ac).unwrap();
        assert_eq!(
            epoch(&bob_group),
            2,
            "Bob's epoch advances after processing commit"
        );

        let mut carol_group = join_group(&carol, welcome_carol).unwrap();
        assert_eq!(epoch(&carol_group), 2);

        // Alice sends a message; Bob and Carol both decrypt it.
        let msg = b"hello group of three";
        let ct = encrypt_for_group(&mut alice_group, &alice, msg).unwrap();

        let bob_pt = decrypt_from_group(&mut bob_group, &bob, ct.clone()).unwrap();
        assert_eq!(bob_pt, msg);

        let carol_pt = decrypt_from_group(&mut carol_group, &carol, ct).unwrap();
        assert_eq!(carol_pt, msg);

        // Bob sends a message; Alice and Carol decrypt it.
        let msg2 = b"bob here";
        let ct2 = encrypt_for_group(&mut bob_group, &bob, msg2).unwrap();

        let alice_pt2 = decrypt_from_group(&mut alice_group, &alice, ct2.clone()).unwrap();
        assert_eq!(alice_pt2, msg2);

        let carol_pt2 = decrypt_from_group(&mut carol_group, &carol, ct2).unwrap();
        assert_eq!(carol_pt2, msg2);
    }

    #[test]
    fn epoch_advances_on_each_commit() {
        let alice = make_member("alice");
        let bob = make_member("bob");
        let carol = make_member("carol");

        let mut group = create_group(&alice).unwrap();
        assert_eq!(epoch(&group), 0);

        let bob_kp = bob.key_package().unwrap();
        let _ = add_member(&mut group, &alice, bob_kp).unwrap();
        assert_eq!(epoch(&group), 1);

        let carol_kp = carol.key_package().unwrap();
        let _ = add_member(&mut group, &alice, carol_kp).unwrap();
        assert_eq!(epoch(&group), 2);
    }

    #[test]
    fn epoch_secret_changes_per_epoch() {
        let alice = make_member("alice");
        let bob = make_member("bob");

        let mut group = create_group(&alice).unwrap();
        let secret_e0 = epoch_secret(&group, &alice, "zero.test.v1", 32).unwrap();
        assert_eq!(secret_e0.len(), 32);

        let bob_kp = bob.key_package().unwrap();
        let _ = add_member(&mut group, &alice, bob_kp).unwrap();
        let secret_e1 = epoch_secret(&group, &alice, "zero.test.v1", 32).unwrap();
        assert_eq!(secret_e1.len(), 32);

        assert_ne!(
            secret_e0, secret_e1,
            "different epochs must yield different secrets"
        );
    }

    #[test]
    fn epoch_secret_same_for_all_members_in_epoch() {
        let alice = make_member("alice");
        let bob = make_member("bob");

        let mut alice_group = create_group(&alice).unwrap();
        let bob_kp = bob.key_package().unwrap();
        let (_commit, welcome) = add_member(&mut alice_group, &alice, bob_kp).unwrap();
        let bob_group = join_group(&bob, welcome).unwrap();

        let label = "zero.group.export.v1";
        let alice_sec = epoch_secret(&alice_group, &alice, label, 32).unwrap();
        let bob_sec = epoch_secret(&bob_group, &bob, label, 32).unwrap();
        assert_eq!(
            alice_sec, bob_sec,
            "same epoch secret for all group members"
        );
    }
}
