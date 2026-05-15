//! Dual-sign / dual-verify: Ed25519 + ML-DSA-65.
//!
//! Signs the same message bytes with both algorithms. Verification
//! checks both signatures; either failure returns
//! `SignatureVerificationFailed` with the algorithm name.

use ed25519_dalek::{Signer, Verifier};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};

use crate::error::CryptoError;

/// Both signatures over a single message.
#[derive(Debug, Clone)]
pub struct DualSignature {
    pub ed25519: [u8; 64],
    pub mldsa: Vec<u8>,
}

/// Secret keys for dual signing.
#[derive(Debug)]
pub struct SigningKeys {
    pub ed25519_secret: [u8; 32],
    pub mldsa_secret: Vec<u8>,
}

/// Public keys for dual verification.
#[derive(Debug, Clone)]
pub struct VerifyingKeys {
    pub ed25519_public: [u8; 32],
    pub mldsa_public: Vec<u8>,
}

/// Sign `message` with both Ed25519 and ML-DSA-65.
pub fn dual_sign(message: &[u8], keys: &SigningKeys) -> Result<DualSignature, CryptoError> {
    // Ed25519
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&keys.ed25519_secret);
    let ed_sig = ed_sk.sign(message);
    let ed_sig_bytes: [u8; 64] = ed_sig.to_bytes();

    // ML-DSA-65
    let mldsa_sk = mldsa65::SecretKey::from_bytes(&keys.mldsa_secret)
        .map_err(|e| CryptoError::MlDsa(format!("invalid ML-DSA-65 secret key: {e}")))?;
    let mldsa_sig = mldsa65::detached_sign(message, &mldsa_sk);
    let mldsa_sig_bytes = mldsa_sig.as_bytes().to_vec();

    Ok(DualSignature {
        ed25519: ed_sig_bytes,
        mldsa: mldsa_sig_bytes,
    })
}

/// Verify both Ed25519 and ML-DSA-65 signatures over `message`.
///
/// Fails immediately if either signature is invalid.
pub fn dual_verify(
    message: &[u8],
    sig: &DualSignature,
    keys: &VerifyingKeys,
) -> Result<(), CryptoError> {
    // Ed25519
    let ed_pk = ed25519_dalek::VerifyingKey::from_bytes(&keys.ed25519_public)
        .map_err(|e| CryptoError::Ed25519(format!("invalid Ed25519 public key: {e}")))?;
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);
    ed_pk
        .verify(message, &ed_sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed {
            algorithm: "Ed25519",
        })?;

    // ML-DSA-65
    let mldsa_pk = mldsa65::PublicKey::from_bytes(&keys.mldsa_public)
        .map_err(|e| CryptoError::MlDsa(format!("invalid ML-DSA-65 public key: {e}")))?;
    let mldsa_sig = mldsa65::DetachedSignature::from_bytes(&sig.mldsa)
        .map_err(|e| CryptoError::MlDsa(format!("invalid ML-DSA-65 signature: {e}")))?;
    mldsa65::verify_detached_signature(&mldsa_sig, message, &mldsa_pk).map_err(|_| {
        CryptoError::SignatureVerificationFailed {
            algorithm: "ML-DSA-65",
        }
    })?;

    Ok(())
}

/// Generate a fresh Ed25519 keypair. Returns (secret_32_bytes, public_32_bytes).
pub fn generate_ed25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    let sk = ed25519_dalek::SigningKey::generate(&mut rng);
    let pk = sk.verifying_key();
    (sk.to_bytes(), pk.to_bytes())
}

/// Generate a fresh ML-DSA-65 keypair. Returns (secret_key_bytes, public_key_bytes).
pub fn generate_mldsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mldsa65::keypair();
    (sk.as_bytes().to_vec(), pk.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signing_keys() -> (SigningKeys, VerifyingKeys) {
        let (ed_sk, ed_pk) = generate_ed25519_keypair();
        let (mldsa_sk, mldsa_pk) = generate_mldsa_keypair();
        let signing = SigningKeys {
            ed25519_secret: ed_sk,
            mldsa_secret: mldsa_sk,
        };
        let verifying = VerifyingKeys {
            ed25519_public: ed_pk,
            mldsa_public: mldsa_pk,
        };
        (signing, verifying)
    }

    #[test]
    fn round_trip_sign_verify() {
        let (sk, vk) = make_signing_keys();
        let message = b"hello, dual signatures!";
        let sig = dual_sign(message, &sk).expect("sign should succeed");
        dual_verify(message, &sig, &vk).expect("verify should succeed");
    }

    #[test]
    fn empty_message_round_trip() {
        let (sk, vk) = make_signing_keys();
        let sig = dual_sign(b"", &sk).expect("sign should succeed");
        dual_verify(b"", &sig, &vk).expect("verify should succeed");
    }

    #[test]
    fn large_message_round_trip() {
        let (sk, vk) = make_signing_keys();
        let message = vec![0xABu8; 65536];
        let sig = dual_sign(&message, &sk).expect("sign should succeed");
        dual_verify(&message, &sig, &vk).expect("verify should succeed");
    }

    #[test]
    fn flipped_ed25519_byte_fails() {
        let (sk, vk) = make_signing_keys();
        let message = b"tamper test";
        let mut sig = dual_sign(message, &sk).expect("sign should succeed");
        sig.ed25519[0] ^= 0xff;
        let err = dual_verify(message, &sig, &vk).expect_err("should fail");
        match err {
            CryptoError::SignatureVerificationFailed { algorithm } => {
                assert_eq!(algorithm, "Ed25519");
            }
            other => panic!("expected SignatureVerificationFailed(Ed25519), got: {other}"),
        }
    }

    #[test]
    fn flipped_mldsa_byte_fails() {
        let (sk, vk) = make_signing_keys();
        let message = b"tamper test mldsa";
        let mut sig = dual_sign(message, &sk).expect("sign should succeed");
        sig.mldsa[0] ^= 0xff;
        let err = dual_verify(message, &sig, &vk).expect_err("should fail");
        match err {
            CryptoError::SignatureVerificationFailed { algorithm } => {
                assert_eq!(algorithm, "ML-DSA-65");
            }
            other => panic!("expected SignatureVerificationFailed(ML-DSA-65), got: {other}"),
        }
    }

    #[test]
    fn wrong_message_fails_ed25519() {
        let (sk, vk) = make_signing_keys();
        let sig = dual_sign(b"original", &sk).expect("sign should succeed");
        let err = dual_verify(b"modified", &sig, &vk).expect_err("should fail");
        assert!(matches!(
            err,
            CryptoError::SignatureVerificationFailed {
                algorithm: "Ed25519"
            }
        ));
    }

    #[test]
    fn wrong_public_key_fails() {
        let (sk, _vk) = make_signing_keys();
        let (_sk2, vk2) = make_signing_keys();
        let message = b"wrong key test";
        let sig = dual_sign(message, &sk).expect("sign should succeed");
        let err = dual_verify(message, &sig, &vk2).expect_err("should fail");
        assert!(matches!(
            err,
            CryptoError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn signature_is_non_empty() {
        let (sk, _vk) = make_signing_keys();
        let sig = dual_sign(b"data", &sk).expect("sign should succeed");
        assert_eq!(sig.ed25519.len(), 64);
        assert!(!sig.mldsa.is_empty());
    }
}
