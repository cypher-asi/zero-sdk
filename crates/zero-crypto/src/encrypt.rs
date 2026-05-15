//! HPKE-PQ-hybrid encrypt / decrypt.
//!
//! Combines X25519 Diffie-Hellman with ML-KEM-768 encapsulation.
//! The two shared secrets are concatenated and fed through HKDF-SHA256
//! to derive a 32-byte ChaCha20-Poly1305 key.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};

use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::error::CryptoError;
use serde::{Deserialize, Serialize};

/// Recipient public keys used for encryption (X25519 + ML-KEM-768).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPublicKey {
    pub x25519: [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub mlkem_encap_key: Vec<u8>,
}

/// Sender / recipient private keys used for decryption.
#[derive(Debug, Clone)]
pub struct SenderPrivateKey {
    pub x25519_secret: [u8; 32],
    /// ML-KEM-768 decapsulation key (2400 bytes).
    pub mlkem_decap_key: Vec<u8>,
}

/// Wire representation of an HPKE-PQ hybrid ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// Encapsulated shared secrets: 32 bytes X25519 public + ML-KEM-768 ciphertext.
    pub kem_output: Vec<u8>,
    /// ChaCha20-Poly1305 ciphertext (includes 16-byte AEAD tag).
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

fn derive_aead_key(x25519_ss: &[u8], mlkem_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(x25519_ss.len() + mlkem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"zero.hybrid.v1", &mut okm)
        .expect("HKDF expand with 32-byte output is always valid");
    okm
}

/// Generate a fresh X25519 keypair. Returns `(secret_bytes, public_bytes)`.
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    let secret = X25519Secret::random_from_rng(&mut rng);
    let public = X25519PublicKey::from(&secret);
    (*secret.as_bytes(), *public.as_bytes())
}

/// Generate a fresh ML-KEM-768 keypair.
/// Returns `(decapsulation_key_bytes, encapsulation_key_bytes)`.
pub fn generate_mlkem_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);
    (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
}

/// Generate a matched `(SenderPrivateKey, RecipientPublicKey)` pair for testing.
pub fn make_keypair() -> (SenderPrivateKey, RecipientPublicKey) {
    let (x_sec, x_pub) = generate_x25519_keypair();
    let (ml_dec, ml_enc) = generate_mlkem_keypair();
    (
        SenderPrivateKey {
            x25519_secret: x_sec,
            mlkem_decap_key: ml_dec,
        },
        RecipientPublicKey {
            x25519: x_pub,
            mlkem_encap_key: ml_enc,
        },
    )
}

/// Encrypt `plaintext` for `recipient` using X25519 + ML-KEM-768 hybrid KEM
/// with ChaCha20-Poly1305 AEAD. `aad_bytes` is bound into the AEAD tag.
pub fn hybrid_encrypt(
    plaintext: &[u8],
    recipient: &RecipientPublicKey,
    aad_bytes: &[u8],
) -> Result<HybridCiphertext, CryptoError> {
    let mut rng = rand::thread_rng();

    // Ephemeral X25519 DH
    let eph_secret = X25519Secret::random_from_rng(&mut rng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let recipient_pub = X25519PublicKey::from(recipient.x25519);
    let x25519_ss = eph_secret.diffie_hellman(&recipient_pub);

    // ML-KEM-768 encapsulation
    let ek_encoded =
        Encoded::<EncapsulationKey<MlKem768Params>>::try_from(recipient.mlkem_encap_key.as_slice())
            .map_err(|_| CryptoError::MlKem("invalid encapsulation key length".into()))?;
    let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_encoded);
    let (mlkem_ct, mlkem_ss) = ek
        .encapsulate(&mut rng)
        .map_err(|e| CryptoError::MlKem(format!("{e:?}")))?;

    // Combine secrets via HKDF-SHA256 to derive ChaCha20-Poly1305 key
    let aead_key = derive_aead_key(x25519_ss.as_bytes(), mlkem_ss.as_ref());

    // kem_output = eph_public_bytes (32) || ML-KEM ciphertext bytes
    let ct_as_bytes: &[u8] = &mlkem_ct;
    let mut kem_output = Vec::with_capacity(32 + ct_as_bytes.len());
    kem_output.extend_from_slice(eph_public.as_bytes());
    kem_output.extend_from_slice(ct_as_bytes);

    // Encrypt plaintext
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rng, &mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: aad_bytes,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(HybridCiphertext {
        kem_output,
        ciphertext: ct,
        nonce: nonce_bytes,
    })
}

/// Decrypt a `HybridCiphertext` produced by `hybrid_encrypt`.
pub fn hybrid_decrypt(
    ciphertext: &HybridCiphertext,
    recipient_sk: &SenderPrivateKey,
    aad_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.kem_output.len() < 33 {
        return Err(CryptoError::DecryptionFailed);
    }
    let (eph_pub_bytes, mlkem_ct_bytes) = ciphertext.kem_output.split_at(32);

    // X25519 DH with ephemeral public key
    let our_secret = X25519Secret::from(recipient_sk.x25519_secret);
    let eph_pub_arr: [u8; 32] = eph_pub_bytes
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let eph_public = X25519PublicKey::from(eph_pub_arr);
    let x25519_ss = our_secret.diffie_hellman(&eph_public);

    // ML-KEM-768 decapsulation
    let dk_encoded = Encoded::<DecapsulationKey<MlKem768Params>>::try_from(
        recipient_sk.mlkem_decap_key.as_slice(),
    )
    .map_err(|_| CryptoError::MlKem("invalid decapsulation key length".into()))?;
    let dk = DecapsulationKey::<MlKem768Params>::from_bytes(&dk_encoded);

    let mlkem_ct = Ciphertext::<MlKem768>::try_from(mlkem_ct_bytes)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let mlkem_ss = dk
        .decapsulate(&mlkem_ct)
        .map_err(|e| CryptoError::MlKem(format!("{e:?}")))?;

    // Derive ChaCha20-Poly1305 key
    let aead_key = derive_aead_key(x25519_ss.as_bytes(), mlkem_ss.as_ref());

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let nonce = Nonce::from_slice(&ciphertext.nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext.ciphertext,
                aad: aad_bytes,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_basic() {
        let (sk, pk) = make_keypair();
        let plaintext = b"hello zero-crypto";
        let aad = b"test-aad";
        let ct = hybrid_encrypt(plaintext, &pk, aad).expect("encrypt");
        let recovered = hybrid_decrypt(&ct, &sk, aad).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_aad_fails() {
        let (sk, pk) = make_keypair();
        let ct = hybrid_encrypt(b"secret", &pk, b"correct-aad").expect("encrypt");
        let result = hybrid_decrypt(&ct, &sk, b"wrong-aad");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn tampered_kem_output_fails() {
        let (sk, pk) = make_keypair();
        let mut ct = hybrid_encrypt(b"secret", &pk, b"aad").expect("encrypt");
        ct.kem_output[40] ^= 0xff;
        let result = hybrid_decrypt(&ct, &sk, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (sk, pk) = make_keypair();
        let mut ct = hybrid_encrypt(b"secret", &pk, b"aad").expect("encrypt");
        let last = ct.ciphertext.len() - 1;
        ct.ciphertext[last] ^= 0xff;
        let result = hybrid_decrypt(&ct, &sk, b"aad");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hybrid_round_trip(
            plaintext in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096),
            aad in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        ) {
            let (sk, pk) = make_keypair();
            let ct = super::hybrid_encrypt(&plaintext, &pk, &aad)
                .expect("encrypt should succeed");
            let recovered = super::hybrid_decrypt(&ct, &sk, &aad)
                .expect("decrypt should succeed");
            prop_assert_eq!(recovered, plaintext);
        }
    }
}
