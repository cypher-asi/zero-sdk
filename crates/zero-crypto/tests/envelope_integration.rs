//! Integration tests for `seal_envelope` / `open_envelope` round-trips.
//! Covers: success path, tampered ciphertext, tampered signature.

use zero_crypto::aad::{Epoch, IdentityId, MachineId, MessageAad, SchemaTag, SectorId};
use zero_crypto::encrypt::{RecipientPublicKey, SenderPrivateKey};
use zero_crypto::envelope::{open_envelope, seal_envelope};
use zero_crypto::error::CryptoError;
use zero_crypto::sign::{SigningKeys, VerifyingKeys};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

fn make_aad() -> MessageAad {
    MessageAad {
        schema_tag: SchemaTag(1),
        sector_id: SectorId([1u8; 16]),
        sender_identity: IdentityId([2u8; 16]),
        sender_machine: MachineId([3u8; 16]),
        epoch: Epoch(42),
        prev_sector_id: None,
    }
}

fn make_keys() -> (
    RecipientPublicKey,
    SenderPrivateKey,
    SigningKeys,
    VerifyingKeys,
) {
    let mut rng = OsRng;

    // X25519
    let x25519_secret = X25519Secret::random_from_rng(rng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // ML-KEM-768
    let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut rng);
    let mlkem_encap_key = mlkem_ek.as_bytes().to_vec();
    let mlkem_decap_key = mlkem_dk.as_bytes().to_vec();

    // Ed25519
    let mut ed_seed = [0u8; 32];
    rng.fill_bytes(&mut ed_seed);
    let ed_signing = Ed25519SigningKey::from_bytes(&ed_seed);
    let ed_verifying = ed_signing.verifying_key();

    // ML-DSA-65
    let (mldsa_pk, mldsa_sk) = mldsa65::keypair();

    let recipient_pk = RecipientPublicKey {
        x25519: x25519_public.to_bytes(),
        mlkem_encap_key,
    };
    let sender_sk = SenderPrivateKey {
        x25519_secret: x25519_secret.to_bytes(),
        mlkem_decap_key,
    };
    let signing_keys = SigningKeys {
        ed25519_secret: ed_seed,
        mldsa_secret: mldsa_sk.as_bytes().to_vec(),
    };
    let verifying_keys = VerifyingKeys {
        ed25519_public: ed_verifying.to_bytes(),
        mldsa_public: mldsa_pk.as_bytes().to_vec(),
    };

    (recipient_pk, sender_sk, signing_keys, verifying_keys)
}

#[test]
fn seal_open_round_trip() {
    let plaintext = b"hello, zero-sdk sealed world!";
    let aad = make_aad();
    let (rpk, rsk, sk, vk) = make_keys();

    let env = seal_envelope(plaintext, &aad, &rpk, &sk).expect("seal failed");
    let (recovered, recovered_aad) = open_envelope(&env, &rsk, &vk).expect("open failed");

    assert_eq!(recovered, plaintext);
    assert_eq!(recovered_aad.epoch, aad.epoch);
    assert_eq!(recovered_aad.sector_id, aad.sector_id);
}

#[test]
fn seal_open_empty_plaintext() {
    let aad = make_aad();
    let (rpk, rsk, sk, vk) = make_keys();

    let env = seal_envelope(b"", &aad, &rpk, &sk).expect("seal failed");
    let (recovered, _) = open_envelope(&env, &rsk, &vk).expect("open failed");
    assert!(recovered.is_empty());
}

#[test]
fn tampered_ciphertext_returns_decryption_failed() {
    let aad = make_aad();
    let (rpk, rsk, sk, vk) = make_keys();

    let mut env = seal_envelope(b"secret data", &aad, &rpk, &sk).expect("seal failed");
    // Flip a byte in the ciphertext
    let last = env.ciphertext.ciphertext.len() - 1;
    env.ciphertext.ciphertext[last] ^= 0xFF;

    let result = open_envelope(&env, &rsk, &vk);
    assert!(
        matches!(result, Err(CryptoError::DecryptionFailed)),
        "expected DecryptionFailed, got: {result:?}"
    );
}

#[test]
fn tampered_ed25519_signature_returns_sig_verification_failed() {
    let aad = make_aad();
    let (rpk, rsk, sk, vk) = make_keys();

    let mut env = seal_envelope(b"signed data", &aad, &rpk, &sk).expect("seal failed");
    env.signature.ed25519[0] ^= 0xFF;

    let result = open_envelope(&env, &rsk, &vk);
    assert!(
        matches!(result, Err(CryptoError::SignatureVerificationFailed { .. })),
        "expected SignatureVerificationFailed, got: {result:?}"
    );
}

#[test]
fn tampered_mldsa_signature_returns_sig_verification_failed() {
    let aad = make_aad();
    let (rpk, rsk, sk, vk) = make_keys();

    let mut env = seal_envelope(b"signed data", &aad, &rpk, &sk).expect("seal failed");
    env.signature.mldsa[0] ^= 0xFF;

    let result = open_envelope(&env, &rsk, &vk);
    assert!(
        matches!(result, Err(CryptoError::SignatureVerificationFailed { .. })),
        "expected SignatureVerificationFailed, got: {result:?}"
    );
}

#[test]
fn signature_checked_before_decryption() {
    let aad = make_aad();
    let (rpk, rsk, sk, vk) = make_keys();

    let mut env = seal_envelope(b"check order", &aad, &rpk, &sk).expect("seal failed");
    // Tamper both signature AND ciphertext; signature error must surface first
    env.signature.ed25519[0] ^= 0xFF;
    let last = env.ciphertext.ciphertext.len() - 1;
    env.ciphertext.ciphertext[last] ^= 0xFF;

    let result = open_envelope(&env, &rsk, &vk);
    assert!(
        matches!(result, Err(CryptoError::SignatureVerificationFailed { .. })),
        "expected SignatureVerificationFailed first, got: {result:?}"
    );
}

#[test]
fn wrong_recipient_key_fails() {
    let aad = make_aad();
    let (rpk, _rsk, sk, vk) = make_keys();
    let (_, wrong_rsk, _, _) = make_keys();

    let env = seal_envelope(b"for someone else", &aad, &rpk, &sk).expect("seal failed");
    // Signature will verify with correct vk, but decryption should fail with wrong key
    // Note: signature check happens first; since we use correct vk, sig passes, then decrypt fails
    let result = open_envelope(&env, &wrong_rsk, &vk);
    assert!(result.is_err(), "expected error with wrong recipient key");
}
