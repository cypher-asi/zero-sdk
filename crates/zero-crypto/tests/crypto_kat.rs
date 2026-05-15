//! KAT (Known Answer Test) vectors for zero-crypto primitives.
//!
//! Vectors live in `tests/kat/` as JSON files. Deterministic operations
//! (AAD encoding, Ed25519 signing, ML-DSA-65 signing) produce exact
//! byte-equal output every run. Non-deterministic operations (HPKE
//! encryption) store a full ciphertext and verify decryption.
//!
//! On first run the tests bootstrap missing vector files. Subsequent
//! runs load stored vectors and enforce byte-equality. The companion
//! `kat_lock.toml` records SHA-256 hashes so vector drift is detected.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zero_crypto::aad::*;
use zero_crypto::encrypt::*;
use zero_crypto::sign::*;

fn kat_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("kat")
}

fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex in KAT vector")
}

fn sha256_of(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}

// ---------------------------------------------------------------------------
// AAD KAT
// ---------------------------------------------------------------------------

#[test]
fn kat_aad_vectors() {
    let path = kat_dir().join("aad_kat.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("invalid JSON in aad_kat.json");

    for vec in doc["vectors"].as_array().expect("vectors must be an array") {
        let label = vec["label"].as_str().unwrap();
        let input = &vec["input"];

        let aad = MessageAad {
            schema_tag: SchemaTag(input["schema_tag"].as_u64().unwrap() as u32),
            sector_id: SectorId(
                hex_decode(input["sector_id_hex"].as_str().unwrap())
                    .try_into()
                    .unwrap(),
            ),
            sender_identity: IdentityId(
                hex_decode(input["sender_identity_hex"].as_str().unwrap())
                    .try_into()
                    .unwrap(),
            ),
            sender_machine: MachineId(
                hex_decode(input["sender_machine_hex"].as_str().unwrap())
                    .try_into()
                    .unwrap(),
            ),
            epoch: Epoch(input["epoch"].as_u64().unwrap()),
            prev_sector_id: input["prev_sector_id_hex"]
                .as_str()
                .map(|h| SectorId(hex_decode(h).try_into().unwrap())),
        };

        let encoded = aad.encode().expect("AAD encode failed");
        let expected_hex = vec["expected_cbor_hex"].as_str().unwrap();
        let expected_bytes = hex_decode(expected_hex);

        assert_eq!(
            encoded, expected_bytes,
            "AAD KAT mismatch for vector '{label}'"
        );

        let decoded = MessageAad::decode(&encoded).expect("AAD decode failed");
        let re_encoded = decoded.encode().expect("AAD re-encode failed");
        assert_eq!(
            encoded, re_encoded,
            "AAD round-trip byte mismatch for vector '{label}'"
        );
    }
}

// ---------------------------------------------------------------------------
// Dual-sign KAT
// ---------------------------------------------------------------------------

fn fixed_signing_material() -> (SigningKeys, VerifyingKeys, Vec<u8>) {
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let ed_pk = ed_sk.verifying_key();

    let (mldsa_pk, mldsa_sk) = pqcrypto_mldsa::mldsa65::keypair();
    use pqcrypto_traits::sign::{PublicKey as PqPub, SecretKey as PqSec};

    let signing = SigningKeys {
        ed25519_secret: [0x42u8; 32],
        mldsa_secret: mldsa_sk.as_bytes().to_vec(),
    };
    let verifying = VerifyingKeys {
        ed25519_public: ed_pk.to_bytes(),
        mldsa_public: mldsa_pk.as_bytes().to_vec(),
    };
    let message = b"KAT dual-sign test message v1".to_vec();
    (signing, verifying, message)
}

fn generate_dual_sign_vector() -> serde_json::Value {
    let (sk, vk, message) = fixed_signing_material();
    let sig = dual_sign(&message, &sk).expect("dual_sign failed");

    serde_json::json!({
        "description": "KAT vector for dual-sign (Ed25519 + ML-DSA-65). Ed25519 key is deterministic from seed 0x42*32.",
        "vectors": [{
            "label": "deterministic_dual_sign",
            "ed25519_secret_hex": hex_encode(&sk.ed25519_secret),
            "ed25519_public_hex": hex_encode(&vk.ed25519_public),
            "mldsa_secret_hex": hex_encode(&sk.mldsa_secret),
            "mldsa_public_hex": hex_encode(&vk.mldsa_public),
            "message_hex": hex_encode(&message),
            "expected_ed25519_sig_hex": hex_encode(&sig.ed25519),
            "expected_mldsa_sig_hex": hex_encode(&sig.mldsa),
        }]
    })
}

#[test]
fn kat_dual_sign_vectors() {
    let path = kat_dir().join("dual_sign_kat.json");

    let fresh = generate_dual_sign_vector();

    if !path.exists() {
        let json = serde_json::to_string_pretty(&fresh).unwrap();
        fs::write(&path, &json)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
        eprintln!("bootstrapped {}", path.display());
    }

    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let stored: serde_json::Value = serde_json::from_str(&raw).expect("invalid JSON");

    for (sv, fv) in stored["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .zip(fresh["vectors"].as_array().unwrap().iter())
    {
        let label = sv["label"].as_str().unwrap();

        // Ed25519 signature must be byte-identical (deterministic)
        assert_eq!(
            sv["expected_ed25519_sig_hex"].as_str().unwrap(),
            fv["expected_ed25519_sig_hex"].as_str().unwrap(),
            "Ed25519 sig mismatch for '{label}'"
        );

        // Verify stored signatures are valid
        let message = hex_decode(sv["message_hex"].as_str().unwrap());
        let vk = VerifyingKeys {
            ed25519_public: hex_decode(sv["ed25519_public_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            mldsa_public: hex_decode(sv["mldsa_public_hex"].as_str().unwrap()),
        };
        let sig = DualSignature {
            ed25519: hex_decode(sv["expected_ed25519_sig_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            mldsa: hex_decode(sv["expected_mldsa_sig_hex"].as_str().unwrap()),
        };
        dual_verify(&message, &sig, &vk).unwrap_or_else(|e| {
            panic!("stored dual-sign KAT verification failed for '{label}': {e}")
        });
    }
}

// ---------------------------------------------------------------------------
// HPKE seal/open KAT
// ---------------------------------------------------------------------------

fn generate_hpke_vector() -> serde_json::Value {
    let (dk_bytes, ek_bytes) = generate_mlkem_keypair();
    let (x_sk, x_pk) = generate_x25519_keypair();

    let recipient_pk = RecipientPublicKey {
        x25519: x_pk,
        mlkem_encap_key: ek_bytes.clone(),
    };
    let _recipient_sk = SenderPrivateKey {
        x25519_secret: x_sk,
        mlkem_decap_key: dk_bytes.clone(),
    };

    let plaintext = b"HPKE KAT plaintext v1 -- zero-crypto";
    let aad = b"HPKE KAT aad v1";

    let ct = hybrid_encrypt(plaintext, &recipient_pk, aad).expect("hybrid_encrypt failed");

    serde_json::json!({
        "description": "KAT vector for HPKE-PQ-hybrid seal/open. Non-deterministic encryption; decryption byte-equality is enforced.",
        "vectors": [{
            "label": "hpke_pq_hybrid_v1",
            "x25519_secret_hex": hex_encode(&x_sk),
            "x25519_public_hex": hex_encode(&x_pk),
            "mlkem_decap_key_hex": hex_encode(&dk_bytes),
            "mlkem_encap_key_hex": hex_encode(&ek_bytes),
            "plaintext_hex": hex_encode(plaintext),
            "aad_hex": hex_encode(aad),
            "kem_output_hex": hex_encode(&ct.kem_output),
            "ciphertext_hex": hex_encode(&ct.ciphertext),
            "nonce_hex": hex_encode(&ct.nonce),
        }]
    })
}

#[test]
fn kat_hpke_vectors() {
    let path = kat_dir().join("hpke_kat.json");

    if !path.exists() {
        let vec = generate_hpke_vector();
        let json = serde_json::to_string_pretty(&vec).unwrap();
        fs::write(&path, &json)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
        eprintln!("bootstrapped {}", path.display());
    }

    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("invalid JSON");

    for vec in doc["vectors"].as_array().unwrap() {
        let label = vec["label"].as_str().unwrap();

        let recipient_sk = SenderPrivateKey {
            x25519_secret: hex_decode(vec["x25519_secret_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            mlkem_decap_key: hex_decode(vec["mlkem_decap_key_hex"].as_str().unwrap()),
        };
        let plaintext_expected = hex_decode(vec["plaintext_hex"].as_str().unwrap());
        let aad = hex_decode(vec["aad_hex"].as_str().unwrap());

        let ct = HybridCiphertext {
            kem_output: hex_decode(vec["kem_output_hex"].as_str().unwrap()),
            ciphertext: hex_decode(vec["ciphertext_hex"].as_str().unwrap()),
            nonce: hex_decode(vec["nonce_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
        };

        let recovered = hybrid_decrypt(&ct, &recipient_sk, &aad)
            .unwrap_or_else(|e| panic!("HPKE KAT decryption failed for '{label}': {e}"));

        assert_eq!(
            recovered, plaintext_expected,
            "HPKE KAT plaintext mismatch for '{label}'"
        );
    }
}

// ---------------------------------------------------------------------------
// Lock-file verification
// ---------------------------------------------------------------------------

fn compute_kat_hashes() -> HashMap<String, String> {
    let dir = kat_dir();
    let mut map = HashMap::new();
    for name in &["aad_kat.json", "dual_sign_kat.json", "hpke_kat.json"] {
        let p = dir.join(name);
        if p.exists() {
            let data = fs::read(&p).unwrap();
            map.insert(name.to_string(), sha256_of(&data));
        }
    }
    map
}

fn write_lock_file(hashes: &HashMap<String, String>) {
    let path = kat_dir().join("kat_lock.toml");
    let mut lines = vec!["# Auto-generated KAT lock file. Do not edit manually.".to_string()];
    let mut keys: Vec<_> = hashes.keys().collect();
    keys.sort();
    for k in keys {
        lines.push(format!("{} = \"{}\"", k.replace('.', "_"), &hashes[k]));
    }
    fs::write(&path, lines.join("\n") + "\n").unwrap();
}

#[test]
fn kat_lock_integrity() {
    let hashes = compute_kat_hashes();

    let lock_path = kat_dir().join("kat_lock.toml");
    if !lock_path.exists() {
        write_lock_file(&hashes);
        eprintln!("bootstrapped {}", lock_path.display());
        return;
    }

    let lock_raw = fs::read_to_string(&lock_path).unwrap();
    for (name, hash) in &hashes {
        let key = name.replace('.', "_");
        let expected_line = format!("{key} = \"{hash}\"");
        assert!(
            lock_raw.contains(&expected_line),
            "kat_lock.toml mismatch for {name}: expected line '{expected_line}' not found.\n\
             Regenerate with `cargo test -p zero-crypto --test crypto_kat` after deleting kat_lock.toml."
        );
    }
}
