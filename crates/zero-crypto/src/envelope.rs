//! Assembled encrypt + sign envelope.
//!
//! `seal_envelope` composes AAD CBOR encoding, HPKE-PQ-hybrid encryption,
//! and dual-signing (Ed25519 + ML-DSA-65) into a single `CryptoEnvelope`.
//!
//! `open_envelope` reverses the process: it verifies the dual signature
//! **before** attempting decryption, then decrypts and returns the
//! original plaintext along with the decoded `MessageAad`.

use crate::aad::MessageAad;
use crate::encrypt::{
    hybrid_decrypt, hybrid_encrypt, HybridCiphertext, RecipientPublicKey, SenderPrivateKey,
};
use crate::error::CryptoError;
use crate::sign::{dual_sign, dual_verify, DualSignature, SigningKeys, VerifyingKeys};

/// A fully encrypted + dual-signed sector ready for GRID publication.
#[derive(Debug, Clone)]
pub struct CryptoEnvelope {
    pub aad: Vec<u8>,
    pub ciphertext: HybridCiphertext,
    pub signature: DualSignature,
}

/// Build the message bytes that get signed / verified.
///
/// Concatenates: `aad_bytes || kem_output || nonce`.
/// The AEAD ciphertext is intentionally excluded: ChaCha20-Poly1305 already
/// authenticates the ciphertext via its tag, so the signature only needs to
/// cover the metadata and KEM transcript.
fn signing_message(aad: &[u8], ct: &HybridCiphertext) -> Vec<u8> {
    let mut msg = Vec::with_capacity(aad.len() + ct.kem_output.len() + 12);
    msg.extend_from_slice(aad);
    msg.extend_from_slice(&ct.kem_output);
    msg.extend_from_slice(&ct.nonce);
    msg
}

/// Seal plaintext into a `CryptoEnvelope`.
///
/// Steps:
/// 1. CBOR-encode the AAD.
/// 2. Encrypt the plaintext with HPKE-PQ-hybrid, binding the AAD.
/// 3. Dual-sign the AAD bytes + ciphertext fields.
pub fn seal_envelope(
    plaintext: &[u8],
    aad: &MessageAad,
    recipient_pk: &RecipientPublicKey,
    sender_sk: &SigningKeys,
) -> Result<CryptoEnvelope, CryptoError> {
    let aad_bytes = aad.encode()?;
    let ciphertext = hybrid_encrypt(plaintext, recipient_pk, &aad_bytes)?;
    let sig_msg = signing_message(&aad_bytes, &ciphertext);
    let signature = dual_sign(&sig_msg, sender_sk)?;

    Ok(CryptoEnvelope {
        aad: aad_bytes,
        ciphertext,
        signature,
    })
}

/// Open a `CryptoEnvelope`, returning the decrypted plaintext and decoded AAD.
///
/// Steps:
/// 1. Verify the dual signature (fails fast before any decryption).
/// 2. Decrypt the ciphertext with HPKE-PQ-hybrid.
/// 3. Decode the CBOR AAD.
pub fn open_envelope(
    env: &CryptoEnvelope,
    recipient_sk: &SenderPrivateKey,
    sender_vk: &VerifyingKeys,
) -> Result<(Vec<u8>, MessageAad), CryptoError> {
    let sig_msg = signing_message(&env.aad, &env.ciphertext);
    dual_verify(&sig_msg, &env.signature, sender_vk)?;

    let plaintext = hybrid_decrypt(&env.ciphertext, recipient_sk, &env.aad)?;
    let aad = MessageAad::decode(&env.aad)?;

    Ok((plaintext, aad))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aad::{Epoch, IdentityId, MachineId, SchemaTag, SectorId};
    use crate::encrypt::{generate_mlkem_keypair, generate_x25519_keypair};
    use crate::sign::{generate_ed25519_keypair, generate_mldsa_keypair};

    fn make_test_aad() -> MessageAad {
        MessageAad {
            schema_tag: SchemaTag(1),
            sector_id: SectorId([0x10; 16]),
            sender_identity: IdentityId([0x20; 16]),
            sender_machine: MachineId([0x30; 16]),
            epoch: Epoch(100),
            prev_sector_id: None,
        }
    }

    struct TestKeys {
        recipient_pk: RecipientPublicKey,
        recipient_sk: SenderPrivateKey,
        sender_signing: SigningKeys,
        sender_verifying: VerifyingKeys,
    }

    fn make_test_keys() -> TestKeys {
        let (x_sk, x_pk) = generate_x25519_keypair();
        let (mlkem_dk, mlkem_ek) = generate_mlkem_keypair();
        let (ed_sk, ed_pk) = generate_ed25519_keypair();
        let (mldsa_sk, mldsa_pk) = generate_mldsa_keypair();

        TestKeys {
            recipient_pk: RecipientPublicKey {
                x25519: x_pk,
                mlkem_encap_key: mlkem_ek,
            },
            recipient_sk: SenderPrivateKey {
                x25519_secret: x_sk,
                mlkem_decap_key: mlkem_dk,
            },
            sender_signing: SigningKeys {
                ed25519_secret: ed_sk,
                mldsa_secret: mldsa_sk,
            },
            sender_verifying: VerifyingKeys {
                ed25519_public: ed_pk,
                mldsa_public: mldsa_pk,
            },
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let keys = make_test_keys();
        let aad = make_test_aad();
        let plaintext = b"hello, crypto envelope!";

        let env = seal_envelope(plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        let (recovered, recovered_aad) =
            open_envelope(&env, &keys.recipient_sk, &keys.sender_verifying)
                .expect("open should succeed");

        assert_eq!(recovered, plaintext);
        assert_eq!(recovered_aad, aad);
    }

    #[test]
    fn seal_open_with_prev_sector_id() {
        let keys = make_test_keys();
        let aad = MessageAad {
            prev_sector_id: Some(SectorId([0xAA; 16])),
            ..make_test_aad()
        };
        let plaintext = b"with prev sector";

        let env = seal_envelope(plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        let (recovered, recovered_aad) =
            open_envelope(&env, &keys.recipient_sk, &keys.sender_verifying)
                .expect("open should succeed");

        assert_eq!(recovered, plaintext);
        assert_eq!(recovered_aad, aad);
    }

    #[test]
    fn seal_open_empty_plaintext() {
        let keys = make_test_keys();
        let aad = make_test_aad();

        let env = seal_envelope(b"", &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        let (recovered, _) = open_envelope(&env, &keys.recipient_sk, &keys.sender_verifying)
            .expect("open should succeed");

        assert!(recovered.is_empty());
    }

    #[test]
    fn tampered_ciphertext_returns_decryption_failed() {
        let keys = make_test_keys();
        let aad = make_test_aad();
        let plaintext = b"tamper ciphertext test";

        let mut env = seal_envelope(plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        // Tamper with the AEAD ciphertext but fix the signature so it
        // passes verification -- this isolates the decryption failure.
        env.ciphertext.ciphertext[0] ^= 0xFF;
        let sig_msg = signing_message(&env.aad, &env.ciphertext);
        env.signature = dual_sign(&sig_msg, &keys.sender_signing).expect("re-sign");

        let err = open_envelope(&env, &keys.recipient_sk, &keys.sender_verifying)
            .expect_err("should fail on tampered ciphertext");

        assert!(
            matches!(err, CryptoError::DecryptionFailed),
            "expected DecryptionFailed, got: {err}"
        );
    }

    #[test]
    fn tampered_signature_fails_before_decrypt() {
        let keys = make_test_keys();
        let aad = make_test_aad();
        let plaintext = b"tamper signature test";

        let mut env = seal_envelope(plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        // Flip a byte in the Ed25519 signature.
        env.signature.ed25519[0] ^= 0xFF;

        let err = open_envelope(&env, &keys.recipient_sk, &keys.sender_verifying)
            .expect_err("should fail on tampered signature");

        assert!(
            matches!(err, CryptoError::SignatureVerificationFailed { .. }),
            "expected SignatureVerificationFailed, got: {err}"
        );
    }

    #[test]
    fn tampered_mldsa_signature_fails() {
        let keys = make_test_keys();
        let aad = make_test_aad();
        let plaintext = b"tamper mldsa sig test";

        let mut env = seal_envelope(plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        env.signature.mldsa[0] ^= 0xFF;

        let err = open_envelope(&env, &keys.recipient_sk, &keys.sender_verifying)
            .expect_err("should fail on tampered ML-DSA signature");

        assert!(
            matches!(err, CryptoError::SignatureVerificationFailed { .. }),
            "expected SignatureVerificationFailed, got: {err}"
        );
    }

    #[test]
    fn tampered_aad_bytes_fails_signature() {
        let keys = make_test_keys();
        let aad = make_test_aad();
        let plaintext = b"tamper aad test";

        let mut env = seal_envelope(plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        // Tamper with the AAD bytes -- signature verification should fail.
        if let Some(byte) = env.aad.first_mut() {
            *byte ^= 0xFF;
        }

        let err = open_envelope(&env, &keys.recipient_sk, &keys.sender_verifying)
            .expect_err("should fail on tampered AAD");

        assert!(
            matches!(err, CryptoError::SignatureVerificationFailed { .. }),
            "expected SignatureVerificationFailed, got: {err}"
        );
    }

    #[test]
    fn wrong_sender_verifying_key_fails() {
        let keys = make_test_keys();
        let keys2 = make_test_keys();
        let aad = make_test_aad();
        let plaintext = b"wrong sender key";

        let env = seal_envelope(plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        let err = open_envelope(&env, &keys.recipient_sk, &keys2.sender_verifying)
            .expect_err("should fail with wrong verifying keys");

        assert!(
            matches!(err, CryptoError::SignatureVerificationFailed { .. }),
            "expected SignatureVerificationFailed, got: {err}"
        );
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let keys = make_test_keys();
        let keys2 = make_test_keys();
        let aad = make_test_aad();
        let plaintext = b"wrong recipient key";

        let env = seal_envelope(plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        // Correct sender verifying key, but wrong recipient secret key.
        let err = open_envelope(&env, &keys2.recipient_sk, &keys.sender_verifying)
            .expect_err("should fail with wrong recipient key");

        assert!(
            matches!(err, CryptoError::DecryptionFailed),
            "expected DecryptionFailed, got: {err}"
        );
    }

    #[test]
    fn large_plaintext_round_trip() {
        let keys = make_test_keys();
        let aad = make_test_aad();
        let plaintext = vec![0xABu8; 65536];

        let env = seal_envelope(&plaintext, &aad, &keys.recipient_pk, &keys.sender_signing)
            .expect("seal should succeed");

        let (recovered, _) = open_envelope(&env, &keys.recipient_sk, &keys.sender_verifying)
            .expect("open should succeed");

        assert_eq!(recovered, plaintext);
    }
}
