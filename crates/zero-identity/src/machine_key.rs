//! `machine_key` --- machine-key store with sealed on-disk persistence.
//!
//! This module exposes [`MachineKeyEntry`], [`MachineKeyRecord`], and
//! [`MachineKeyStore`], an in-memory registry of machine keys generated
//! for a given [`NeuralKey`](crate::neural_key::NeuralKey).
//!
//! Phase D1 of the zero-sdk integration introduces sealed serialization
//! so derived devices survive process restarts: the store now retains
//! the full [`MachineKeyPair`] alongside the seeds used to derive it,
//! and exposes [`MachineKeyStore::to_sealed_bytes`] /
//! [`MachineKeyStore::from_sealed_bytes`] for round-tripping the entire
//! store through a single ChaCha20-Poly1305-sealed CBOR blob keyed off
//! the owning [`NeuralKey`]. Callers never observe raw secret halves;
//! signing happens via [`MachineKeyStore::sign_with`] /
//! [`MachineKeyStore::ml_dsa_sign_with`].

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;
use zid::keys::machine::{MachineKeyCapabilities, MachineKeyPair};
use zid::types::{IdentityId, MachineId};

use crate::error::IdentityError;
use crate::neural_key::NeuralKey;

/// Domain-separation context for the HKDF-SHA256 expansion that turns
/// the owning [`NeuralKey`]'s identity-id bytes into the 32-byte AEAD
/// key. Bumping the suffix invalidates every previously-sealed blob.
const HKDF_INFO: &[u8] = b"zero-identity/machine-key-store/v1";

/// Version byte stamped into the CBOR payload before sealing. Mirrors
/// `HKDF_INFO`'s `/v1` suffix; bump in lock-step on breaking changes.
const SEAL_VERSION: u8 = 1;

/// ChaCha20-Poly1305 nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Stack size reserved for ML-DSA-65 signing scratch space.
///
/// The pure-Rust `ml-dsa = "0.0.4"` implementation allocates large
/// matrices on the stack during sign/key-gen; on Windows the default
/// 2 MiB test-thread stack is not always enough. We offload every
/// signing operation onto a dedicated thread with this stack size so
/// `MachineKeyStore::sign_with` / `ml_dsa_sign_with` behave the same
/// regardless of the caller's thread configuration.
const ML_DSA_SIGN_STACK: usize = 8 * 1024 * 1024;

/// Public, display-oriented summary of a machine key persisted in a
/// [`MachineKeyStore`].
///
/// All public-key fields are raw byte representations so that callers
/// may hex/base64-encode them as needed without depending on `zid`
/// types.
#[derive(Debug, Clone)]
pub struct MachineKeyEntry {
    /// Stable 128-bit machine identifier.
    pub machine_id: MachineId,
    /// Caller-provided human-readable label (e.g. `"laptop-2024"`).
    pub label: String,
    /// Creation timestamp expressed as seconds since the Unix epoch.
    pub created_at: u64,
    /// Ed25519 verifying key (32 bytes).
    pub ed25519_pub: [u8; 32],
    /// ML-DSA-65 verifying key (1952 bytes).
    pub mldsa65_pub: Vec<u8>,
}

/// Richer record returned by [`MachineKeyStore::list_machine_records`].
///
/// Exposes the capability bitflags and epoch alongside the public
/// summary. Higher layers (e.g. `zos-grid`) use this when projecting
/// the store into a DTO list without needing the secret halves.
#[derive(Debug, Clone)]
pub struct MachineKeyRecord {
    /// Public summary identical to the one returned by
    /// [`MachineKeyStore::list_machine_keys`].
    pub entry: MachineKeyEntry,
    /// Capability bitflags chosen at generation time (raw u32; decode
    /// via [`MachineKeyCapabilities::from_bits_truncate`]).
    pub capabilities: u32,
    /// Epoch (rotation counter) under which the key was generated.
    pub epoch: u64,
}

/// Seed quadruple required to deterministically reconstruct a
/// [`MachineKeyPair`] via [`MachineKeyPair::from_seeds`]. Kept in-memory
/// alongside the derived pair so we can serialize the store to disk
/// without ever exposing the seeds to callers.
#[derive(Clone)]
struct StoredSeeds {
    /// 32-byte Ed25519 signing seed.
    sign: [u8; 32],
    /// 32-byte X25519 encryption seed.
    encrypt: [u8; 32],
    /// 32-byte ML-DSA-65 signing seed (post-quantum signature).
    pq_sign: [u8; 32],
    /// 32-byte ML-KEM-768 encapsulation seed (post-quantum KEM).
    pq_encrypt: [u8; 32],
}

// `StoredSeeds` holds 128 bytes of raw secret material. Avoid leaking
// it through `Debug` -- the surrounding `MachineKeyStore` debug print
// just notes "<sealed>".
impl core::fmt::Debug for StoredSeeds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StoredSeeds(<redacted>)")
    }
}

/// Internal record held inside the store's mutex. Pairs the public
/// summary with the live [`MachineKeyPair`] (used by the `*_sign_with`
/// capability methods) and the seeds required to seal it.
///
/// The `pair` is heap-allocated (`Box<MachineKeyPair>`) because the
/// upstream type is ~tens of KB once `ml-dsa` / `ml-kem` keys are
/// expanded; moving it through a return value would otherwise blow
/// small-stack callers (HTTP handlers, test threads).
#[derive(Debug)]
struct EntryRecord {
    identity_id: IdentityId,
    entry: MachineKeyEntry,
    capabilities: u32,
    epoch: u64,
    seeds: StoredSeeds,
    pair: Box<MachineKeyPair>,
}

/// In-memory registry of machine keys keyed by their owning identity.
///
/// The store is `Send + Sync` and may be cloned cheaply by wrapping in
/// an [`std::sync::Arc`]. Persistence is provided via
/// [`Self::to_sealed_bytes`] /
/// [`Self::from_sealed_bytes`] (Phase D1).
#[derive(Debug, Default)]
pub struct MachineKeyStore {
    entries: Mutex<Vec<EntryRecord>>,
}

impl MachineKeyStore {
    /// Construct an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a fresh machine key for `identity` with empty
    /// capabilities and epoch zero. See
    /// [`Self::generate_machine_key_with`] for the rich-record variant.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Zid`] if the upstream key derivation
    /// rejects the freshly drawn seed material (e.g. ML-DSA key gen
    /// fails internally), or [`IdentityError::SerializationError`] if
    /// the system clock is set before the Unix epoch.
    pub fn generate_machine_key(
        &self,
        identity: &NeuralKey,
        label: impl Into<String>,
    ) -> Result<MachineKeyEntry, IdentityError> {
        self.generate_machine_key_with(identity, label, 0, 0)
            .map(|record| record.entry)
    }

    /// Generate a fresh machine key for `identity`, retaining the
    /// derived [`MachineKeyPair`] and the seeds used to construct it.
    ///
    /// `capabilities_bits` is the raw [`MachineKeyCapabilities::bits`]
    /// representation -- exposed as a plain `u32` so callers (e.g.
    /// `zos-grid`) don't have to depend on `zid` directly. Unknown
    /// bits are silently dropped via
    /// [`MachineKeyCapabilities::from_bits_truncate`].
    ///
    /// The returned [`MachineKeyRecord`] surfaces the `capabilities`
    /// bitflags and `epoch` for callers that project the store into a
    /// richer DTO than [`MachineKeyEntry`] provides.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Zid`] if upstream key derivation
    /// rejects the seed material, or [`IdentityError::SerializationError`]
    /// if the system clock is before the Unix epoch or the internal
    /// mutex is poisoned.
    pub fn generate_machine_key_with(
        &self,
        identity: &NeuralKey,
        label: impl Into<String>,
        capabilities_bits: u32,
        epoch: u64,
    ) -> Result<MachineKeyRecord, IdentityError> {
        let capabilities = MachineKeyCapabilities::from_bits_truncate(capabilities_bits);
        let mut rng = OsRng;

        let mut seed_buf = Zeroizing::new([0u8; 32 * 4]);
        rng.fill_bytes(seed_buf.as_mut_slice());
        let mut sign_seed = [0u8; 32];
        let mut encrypt_seed = [0u8; 32];
        let mut pq_sign_seed = [0u8; 32];
        let mut pq_encrypt_seed = [0u8; 32];
        sign_seed.copy_from_slice(&seed_buf[0..32]);
        encrypt_seed.copy_from_slice(&seed_buf[32..64]);
        pq_sign_seed.copy_from_slice(&seed_buf[64..96]);
        pq_encrypt_seed.copy_from_slice(&seed_buf[96..128]);

        let mut machine_id_bytes = [0u8; 16];
        rng.fill_bytes(&mut machine_id_bytes);
        let machine_id = MachineId::from(machine_id_bytes);

        let DerivedPair { pair, ed25519_pub, mldsa65_pub } = run_on_big_stack(move || {
            derive_pair_and_public(
                sign_seed,
                encrypt_seed,
                pq_sign_seed,
                pq_encrypt_seed,
                capabilities,
                epoch,
            )
        })??;

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IdentityError::SerializationError)?
            .as_secs();

        let entry = MachineKeyEntry {
            machine_id,
            label: label.into(),
            created_at,
            ed25519_pub,
            mldsa65_pub,
        };

        let record = EntryRecord {
            identity_id: identity.identity_id(),
            entry: entry.clone(),
            capabilities: capabilities.bits(),
            epoch,
            seeds: StoredSeeds {
                sign: sign_seed,
                encrypt: encrypt_seed,
                pq_sign: pq_sign_seed,
                pq_encrypt: pq_encrypt_seed,
            },
            pair,
        };

        let caps_bits = capabilities.bits();
        self.entries
            .lock()
            .map_err(|_| IdentityError::SerializationError)?
            .push(record);

        Ok(MachineKeyRecord {
            entry,
            capabilities: caps_bits,
            epoch,
        })
    }

    /// List every machine key previously generated for `identity`, in
    /// insertion order. Returns the public summary only; secret halves
    /// stay inside the store.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::SerializationError`] if the internal
    /// mutex has been poisoned by a panic in another thread.
    pub fn list_machine_keys(
        &self,
        identity: &NeuralKey,
    ) -> Result<Vec<MachineKeyEntry>, IdentityError> {
        let target = identity.identity_id();
        let guard = self
            .entries
            .lock()
            .map_err(|_| IdentityError::SerializationError)?;
        Ok(guard
            .iter()
            .filter(|record| record.identity_id == target)
            .map(|record| record.entry.clone())
            .collect())
    }

    /// List every machine key previously generated for `identity` as a
    /// [`MachineKeyRecord`] (public summary plus capabilities + epoch).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::SerializationError`] if the internal
    /// mutex has been poisoned by a panic in another thread.
    pub fn list_machine_records(
        &self,
        identity: &NeuralKey,
    ) -> Result<Vec<MachineKeyRecord>, IdentityError> {
        let target = identity.identity_id();
        let guard = self
            .entries
            .lock()
            .map_err(|_| IdentityError::SerializationError)?;
        Ok(guard
            .iter()
            .filter(|record| record.identity_id == target)
            .map(|record| MachineKeyRecord {
                entry: record.entry.clone(),
                capabilities: record.capabilities,
                epoch: record.epoch,
            })
            .collect())
    }

    /// Sign `payload` with the Ed25519 half of the stored
    /// [`MachineKeyPair`] for `machine_id`. Returns the 64-byte
    /// Ed25519 signature.
    ///
    /// Ed25519 signatures are deterministic, so repeated calls with
    /// identical inputs (across restart, post-unseal) return identical
    /// bytes -- this is exercised by `sign_after_unseal_verifies`.
    ///
    /// # Errors
    ///
    /// * [`IdentityError::KeyNotFound`] if no entry matches
    ///   `machine_id`.
    /// * [`IdentityError::SerializationError`] if the internal mutex
    ///   has been poisoned by a panic in another thread.
    pub fn sign_with(
        &self,
        machine_id: MachineId,
        payload: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        let ed25519_sig = self.with_pair(machine_id, |pair| {
            run_on_big_stack(|| pair.sign(payload).ed25519)
        })??;
        Ok(ed25519_sig.to_vec())
    }

    /// Sign `payload` with the ML-DSA-65 half of the stored
    /// [`MachineKeyPair`] for `machine_id`. Returns the 3309-byte
    /// ML-DSA-65 signature.
    ///
    /// # Errors
    ///
    /// * [`IdentityError::KeyNotFound`] if no entry matches
    ///   `machine_id`.
    /// * [`IdentityError::SerializationError`] if the internal mutex
    ///   has been poisoned by a panic in another thread.
    pub fn ml_dsa_sign_with(
        &self,
        machine_id: MachineId,
        payload: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        let ml_dsa_sig = self.with_pair(machine_id, |pair| {
            run_on_big_stack(|| pair.sign(payload).ml_dsa)
        })??;
        Ok(ml_dsa_sig.to_vec())
    }

    /// Look up the stored [`MachineKeyPair`] matching `machine_id`
    /// and hand it to `f` while the entries mutex is held.
    ///
    /// The mutex guard's lifetime is intentionally bounded by the
    /// helper -- callers are not exposed to it, so signing work can
    /// happen inside `f` without leaking the guard into longer-lived
    /// scopes (see `clippy::significant_drop_tightening`).
    #[allow(clippy::significant_drop_tightening)]
    fn with_pair<T, F>(
        &self,
        machine_id: MachineId,
        f: F,
    ) -> Result<T, IdentityError>
    where
        F: FnOnce(&MachineKeyPair) -> T,
    {
        let guard = self
            .entries
            .lock()
            .map_err(|_| IdentityError::SerializationError)?;
        let record = guard
            .iter()
            .find(|r| r.entry.machine_id == machine_id)
            .ok_or(IdentityError::KeyNotFound)?;
        Ok(f(record.pair.as_ref()))
    }

    /// Serialize the entire store into a single sealed blob suitable
    /// for atomic on-disk persistence.
    ///
    /// The wire format is `nonce || ciphertext`, where:
    /// * `nonce` is a fresh 12-byte ChaCha20-Poly1305 nonce drawn from
    ///   [`OsRng`] on every call (do not reuse blobs without re-sealing).
    /// * `ciphertext` is ChaCha20-Poly1305(`key`, `nonce`,
    ///   `cbor(SealedPayload)`), where `key` is the 32-byte HKDF-SHA256
    ///   output of `neural_key.identity_id().as_bytes()` with empty
    ///   salt and the static info string [`HKDF_INFO`].
    ///
    /// Round-trip pair: [`Self::from_sealed_bytes`].
    ///
    /// # Errors
    ///
    /// * [`IdentityError::SerializationError`] if the internal mutex
    ///   has been poisoned.
    /// * [`IdentityError::SealError`] if CBOR encoding, HKDF expansion,
    ///   or AEAD encryption fails.
    pub fn to_sealed_bytes(&self, neural_key: &NeuralKey) -> Result<Vec<u8>, IdentityError> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| IdentityError::SerializationError)?;
        let payload = SealedPayload {
            version: SEAL_VERSION,
            entries: guard.iter().map(SealedEntry::from_record).collect(),
        };
        drop(guard);

        let mut plaintext_inner: Vec<u8> = Vec::with_capacity(256);
        ciborium::into_writer(&payload, &mut plaintext_inner)
            .map_err(|e| IdentityError::SealError(format!("cbor encode: {e}")))?;
        let plaintext = Zeroizing::new(plaintext_inner);

        let aead = aead_from_neural_key(neural_key)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = aead
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|_| IdentityError::SealError("aead encrypt failed".into()))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Reconstruct a [`MachineKeyStore`] from bytes previously emitted
    /// by [`Self::to_sealed_bytes`] under the same `neural_key`.
    ///
    /// Every entry's [`MachineKeyPair`] is rebuilt from the persisted
    /// seeds via [`MachineKeyPair::from_seeds`], so post-unseal calls
    /// to [`Self::sign_with`] / [`Self::ml_dsa_sign_with`] produce the
    /// same signatures as the pre-seal store.
    ///
    /// # Errors
    ///
    /// * [`IdentityError::UnsealError`] for truncated payloads, AEAD
    ///   authentication failures (wrong key), unsupported versions,
    ///   or CBOR decode errors.
    /// * [`IdentityError::SealError`] propagated from HKDF expansion.
    /// * [`IdentityError::Zid`] propagated from re-deriving an entry's
    ///   key pair from its seeds.
    pub fn from_sealed_bytes(neural_key: &NeuralKey, bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() < NONCE_LEN {
            return Err(IdentityError::UnsealError(
                "payload shorter than nonce".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
        let aead = aead_from_neural_key(neural_key)?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = aead
            .decrypt(nonce, ciphertext)
            .map_err(|_| IdentityError::UnsealError("aead authentication failed".into()))?;
        let plaintext = Zeroizing::new(plaintext);

        let payload: SealedPayload = ciborium::from_reader(plaintext.as_slice())
            .map_err(|e| IdentityError::UnsealError(format!("cbor decode: {e}")))?;
        if payload.version != SEAL_VERSION {
            return Err(IdentityError::UnsealError(format!(
                "unsupported sealed version: {}",
                payload.version
            )));
        }

        let mut records: Vec<EntryRecord> = Vec::with_capacity(payload.entries.len());
        for sealed in payload.entries {
            records.push(sealed.into_record()?);
        }
        Ok(Self {
            entries: Mutex::new(records),
        })
    }
}

/// On-disk CBOR payload sealed by [`MachineKeyStore::to_sealed_bytes`].
/// Internal to this module -- callers see only the sealed byte slice.
#[derive(Serialize, Deserialize)]
struct SealedPayload {
    version: u8,
    entries: Vec<SealedEntry>,
}

/// On-disk record for one machine key inside [`SealedPayload`].
///
/// Persisting the four seeds (rather than the derived pair) keeps the
/// disk format size-bounded and lets us upgrade the upstream
/// [`MachineKeyPair`] internals without breaking sealed blobs.
#[derive(Serialize, Deserialize)]
struct SealedEntry {
    identity_id: [u8; 16],
    machine_id: [u8; 16],
    label: String,
    created_at: u64,
    capabilities: u32,
    epoch: u64,
    #[serde(with = "serde_byte_array_32")]
    sign_seed: [u8; 32],
    #[serde(with = "serde_byte_array_32")]
    encrypt_seed: [u8; 32],
    #[serde(with = "serde_byte_array_32")]
    pq_sign_seed: [u8; 32],
    #[serde(with = "serde_byte_array_32")]
    pq_encrypt_seed: [u8; 32],
}

impl SealedEntry {
    fn from_record(record: &EntryRecord) -> Self {
        Self {
            identity_id: *record.identity_id.as_bytes(),
            machine_id: *record.entry.machine_id.as_bytes(),
            label: record.entry.label.clone(),
            created_at: record.entry.created_at,
            capabilities: record.capabilities,
            epoch: record.epoch,
            sign_seed: record.seeds.sign,
            encrypt_seed: record.seeds.encrypt,
            pq_sign_seed: record.seeds.pq_sign,
            pq_encrypt_seed: record.seeds.pq_encrypt,
        }
    }

    fn into_record(self) -> Result<EntryRecord, IdentityError> {
        let caps = MachineKeyCapabilities::from_bits_truncate(self.capabilities);
        let sign_seed = self.sign_seed;
        let encrypt_seed = self.encrypt_seed;
        let pq_sign_seed = self.pq_sign_seed;
        let pq_encrypt_seed = self.pq_encrypt_seed;
        let epoch = self.epoch;
        let DerivedPair { pair, ed25519_pub, mldsa65_pub } = run_on_big_stack(move || {
            derive_pair_and_public(
                sign_seed,
                encrypt_seed,
                pq_sign_seed,
                pq_encrypt_seed,
                caps,
                epoch,
            )
        })??;
        let entry = MachineKeyEntry {
            machine_id: MachineId::from(self.machine_id),
            label: self.label,
            created_at: self.created_at,
            ed25519_pub,
            mldsa65_pub,
        };
        Ok(EntryRecord {
            identity_id: IdentityId::new(self.identity_id),
            entry,
            capabilities: self.capabilities,
            epoch: self.epoch,
            seeds: StoredSeeds {
                sign: self.sign_seed,
                encrypt: self.encrypt_seed,
                pq_sign: self.pq_sign_seed,
                pq_encrypt: self.pq_encrypt_seed,
            },
            pair,
        })
    }
}

/// Tuple returned by [`derive_pair_and_public`]: a heap-allocated
/// [`MachineKeyPair`] plus its small public-key byte projections,
/// kept together so [`MachineKeyStore::generate_machine_key_with`]
/// and [`SealedEntry::into_record`] can build their respective
/// records without ever materializing a full [`MachineKeyPair`] on
/// the caller's stack.
struct DerivedPair {
    pair: Box<MachineKeyPair>,
    ed25519_pub: [u8; 32],
    mldsa65_pub: Vec<u8>,
}

/// Reconstruct a [`MachineKeyPair`] from `seeds` and capture its
/// public-key byte projections, all while running on the caller's
/// (big-stack) thread.
///
/// This is the only place `MachineKeyPair::from_seeds` /
/// `MachinePublicKey` materialize, and the caller wraps it in
/// [`run_on_big_stack`] to keep the heavyweight `ml-dsa` matrices off
/// small-stack callers.
fn derive_pair_and_public(
    sign_seed: [u8; 32],
    encrypt_seed: [u8; 32],
    pq_sign_seed: [u8; 32],
    pq_encrypt_seed: [u8; 32],
    capabilities: MachineKeyCapabilities,
    epoch: u64,
) -> Result<DerivedPair, zid::CryptoError> {
    let pair = Box::new(MachineKeyPair::from_seeds(
        sign_seed,
        encrypt_seed,
        pq_sign_seed,
        pq_encrypt_seed,
        capabilities,
        epoch,
    )?);
    let public = pair.public_key();
    let ed25519_pub = public.ed25519_bytes();
    let mldsa65_pub = public.ml_dsa_bytes();
    Ok(DerivedPair {
        pair,
        ed25519_pub,
        mldsa65_pub,
    })
}

/// Run `f` on a freshly-spawned scoped thread with
/// [`ML_DSA_SIGN_STACK`] bytes of stack.
///
/// `ml-dsa = "0.0.4"` allocates large arrays on the stack during sign
/// and key-gen; on Windows the default 2 MiB test-thread stack is not
/// always enough, and HTTP servers may also use small per-request
/// stacks. Every code path that triggers `MachineKeyPair::from_seeds`
/// or `MachineKeyPair::sign` routes through this helper so the store
/// behaves the same regardless of caller stack configuration.
///
/// The closure is scoped (it may borrow non-`'static` data such as
/// the in-store [`MachineKeyPair`]), and the return type only needs
/// `Send`.
fn run_on_big_stack<R, F>(f: F) -> Result<R, IdentityError>
where
    R: Send,
    F: FnOnce() -> R + Send,
{
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .stack_size(ML_DSA_SIGN_STACK)
            .spawn_scoped(scope, f)
            .map_err(|e| IdentityError::SealError(format!("spawn big-stack thread: {e}")))?;
        handle
            .join()
            .map_err(|_| IdentityError::SealError("big-stack thread panicked".into()))
    })
}

/// Build the [`ChaCha20Poly1305`] AEAD from the owning [`NeuralKey`].
///
/// The IKM is currently derived from `identity_id_bytes()` (16 bytes),
/// which is publicly knowable from the persisted Shamir shares. The
/// sealed file therefore relies on OS-level filesystem permissions for
/// confidentiality rather than the key being a true secret. This is
/// acceptable for v1 since the data directory is already gated by user
/// permissions.
///
/// TODO(security): promote the IKM to a true secret (raw 32-byte
/// `NeuralKey` material, or an OS-keyring-stored DEK) in a follow-up
/// so the sealed blob is confidential even when the file is exfiltrated.
fn aead_from_neural_key(neural_key: &NeuralKey) -> Result<ChaCha20Poly1305, IdentityError> {
    let ikm = neural_key.identity_id_bytes();
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .map_err(|e| IdentityError::SealError(format!("hkdf expand: {e}")))?;
    ChaCha20Poly1305::new_from_slice(okm.as_ref())
        .map_err(|e| IdentityError::SealError(format!("aead key init: {e}")))
}

/// Local serde adapter so a `[u8; 32]` round-trips through CBOR as a
/// bytes value (`Major type 2`) rather than a 32-element array of
/// integers, halving the on-disk size and matching `serde_bytes`
/// conventions.
mod serde_byte_array_32 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let bytes = <Vec<u8>>::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom(format!(
                "expected 32-byte seed, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{MachineKeyEntry, MachineKeyStore};
    use crate::error::IdentityError;
    use crate::neural_key::NeuralKey;
    use std::collections::HashSet;

    /// ML-DSA-65 verifying-key encoded length in bytes (FIPS 204).
    const MLDSA65_PUB_LEN: usize = 1952;

    #[test]
    fn generate_three_then_list_returns_three_entries() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("generate neural key");

        let mut created: Vec<MachineKeyEntry> = Vec::new();
        for i in 0..3 {
            let entry = store
                .generate_machine_key(&identity, format!("machine-{i}"))
                .expect("generate machine key");
            assert_eq!(entry.ed25519_pub.len(), 32);
            assert_eq!(entry.mldsa65_pub.len(), MLDSA65_PUB_LEN);
            created.push(entry);
        }

        let listed = store
            .list_machine_keys(&identity)
            .expect("list machine keys");
        assert_eq!(listed.len(), 3, "expected exactly 3 entries");

        let listed_ids: HashSet<_> = listed.iter().map(|e| e.machine_id).collect();
        let created_ids: HashSet<_> = created.iter().map(|e| e.machine_id).collect();
        assert_eq!(listed_ids.len(), 3, "machine ids must be distinct");
        assert_eq!(
            listed_ids, created_ids,
            "listed ids must match those returned by generate_machine_key"
        );

        for entry in &listed {
            assert_eq!(entry.ed25519_pub.len(), 32);
            assert_eq!(entry.mldsa65_pub.len(), MLDSA65_PUB_LEN);
        }
    }

    #[test]
    fn list_is_scoped_per_identity() {
        let store = MachineKeyStore::new();
        let alice = NeuralKey::generate().expect("alice");
        let bob = NeuralKey::generate().expect("bob");

        store
            .generate_machine_key(&alice, "alice-laptop")
            .expect("generate alice key");
        store
            .generate_machine_key(&bob, "bob-phone")
            .expect("generate bob key");
        store
            .generate_machine_key(&bob, "bob-laptop")
            .expect("generate bob key");

        let alice_keys = store.list_machine_keys(&alice).expect("list alice");
        let bob_keys = store.list_machine_keys(&bob).expect("list bob");

        assert_eq!(alice_keys.len(), 1);
        assert_eq!(bob_keys.len(), 2);
        assert_eq!(alice_keys[0].label, "alice-laptop");
    }

    /// Task 1.10 acceptance: every key-bearing field of
    /// [`MachineKeyEntry`] has the exact byte length mandated by its
    /// underlying primitive, and [`MachineId`] matches the ZID
    /// 128-bit-identifier spec.
    #[test]
    fn byte_length_invariants() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("generate neural key");
        let entry = store
            .generate_machine_key(&identity, "byte-length-check")
            .expect("generate machine key");

        assert_eq!(
            entry.ed25519_pub.len(),
            32,
            "Ed25519 verifying key must be exactly 32 bytes"
        );

        assert_eq!(
            entry.mldsa65_pub.len(),
            MLDSA65_PUB_LEN,
            "ML-DSA-65 verifying key must be exactly {MLDSA65_PUB_LEN} bytes"
        );

        assert_eq!(
            entry.machine_id.as_bytes().len(),
            16,
            "MachineId must be exactly 16 bytes (128 bits) per ZID spec"
        );
    }

    /// Task 1.6 acceptance: the first `generate_machine_key` call binds a
    /// genesis machine key under a fresh `NeuralKey`, and subsequent
    /// calls produce additional, distinct machine ids that are all
    /// scoped to the same `NeuralKey`.
    #[test]
    fn first_and_subsequent_generates_share_one_neural_key() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("generate neural key");

        let genesis = store
            .generate_machine_key(&identity, "genesis")
            .expect("first generate must succeed");

        let mut ids: HashSet<_> = HashSet::new();
        ids.insert(genesis.machine_id);

        for i in 0..4 {
            let entry = store
                .generate_machine_key(&identity, format!("subsequent-{i}"))
                .expect("subsequent generate must succeed");
            assert!(
                ids.insert(entry.machine_id),
                "machine id collision between generated keys"
            );
        }
        assert_eq!(ids.len(), 5, "expected five distinct machine ids");

        let listed = store
            .list_machine_keys(&identity)
            .expect("list under owning identity");
        assert_eq!(
            listed.len(),
            5,
            "all generated keys must be bound to the originating NeuralKey"
        );
        let listed_ids: HashSet<_> = listed.iter().map(|e| e.machine_id).collect();
        assert_eq!(
            listed_ids, ids,
            "listed ids must exactly match the generated ids"
        );

        let unrelated = NeuralKey::generate().expect("generate unrelated neural key");
        let foreign = store
            .list_machine_keys(&unrelated)
            .expect("list under unrelated identity");
        assert!(
            foreign.is_empty(),
            "no machine keys should leak across NeuralKeys"
        );
    }

    /// Phase D1 acceptance: sealing a populated store and unsealing it
    /// into a fresh instance preserves every entry's machine id, label,
    /// and public-key material.
    #[test]
    fn seal_unseal_roundtrip_three_entries() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("generate neural key");

        let mut originals: Vec<MachineKeyEntry> = Vec::new();
        for i in 0..3 {
            let entry = store
                .generate_machine_key(&identity, format!("seed-{i}"))
                .expect("generate machine key");
            originals.push(entry);
        }

        let blob = store
            .to_sealed_bytes(&identity)
            .expect("seal populated store");
        let restored = MachineKeyStore::from_sealed_bytes(&identity, &blob)
            .expect("unseal into fresh store");

        let listed = restored
            .list_machine_keys(&identity)
            .expect("list after unseal");
        assert_eq!(listed.len(), 3, "expected 3 entries after unseal");

        let original_ids: HashSet<_> = originals.iter().map(|e| e.machine_id).collect();
        let restored_ids: HashSet<_> = listed.iter().map(|e| e.machine_id).collect();
        assert_eq!(
            original_ids, restored_ids,
            "machine ids must round-trip across seal/unseal"
        );

        for original in &originals {
            let restored = listed
                .iter()
                .find(|e| e.machine_id == original.machine_id)
                .expect("restored entry");
            assert_eq!(restored.label, original.label);
            assert_eq!(restored.ed25519_pub, original.ed25519_pub);
            assert_eq!(restored.mldsa65_pub, original.mldsa65_pub);
            assert_eq!(restored.created_at, original.created_at);
        }
    }

    /// Phase D1 acceptance: Ed25519 is deterministic, so signing the
    /// same payload after unseal must produce byte-identical output --
    /// proof that the secret half survived persistence.
    #[test]
    fn sign_after_unseal_verifies() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("generate neural key");
        let entry = store
            .generate_machine_key(&identity, "signing-device")
            .expect("generate machine key");

        let payload = b"phase-D1: prove the secret half persists";
        let sig_before = store
            .sign_with(entry.machine_id, payload)
            .expect("sign before seal");
        assert_eq!(sig_before.len(), 64, "Ed25519 sig must be 64 bytes");

        let blob = store
            .to_sealed_bytes(&identity)
            .expect("seal");
        let restored = MachineKeyStore::from_sealed_bytes(&identity, &blob)
            .expect("unseal");

        let sig_after = restored
            .sign_with(entry.machine_id, payload)
            .expect("sign after unseal");

        assert_eq!(
            sig_before, sig_after,
            "Ed25519 signatures must be deterministic across seal/unseal"
        );
    }

    /// Phase D1 acceptance: sealing under one `NeuralKey` and unsealing
    /// under another yields an [`IdentityError::UnsealError`] (AEAD
    /// authentication failure).
    #[test]
    fn unseal_with_wrong_neural_key_fails() {
        let store = MachineKeyStore::new();
        let alice = NeuralKey::generate().expect("alice");
        let other = NeuralKey::generate().expect("other");
        store
            .generate_machine_key(&alice, "alice-laptop")
            .expect("generate alice key");

        let sealed = store
            .to_sealed_bytes(&alice)
            .expect("seal under alice");
        let err = MachineKeyStore::from_sealed_bytes(&other, &sealed)
            .expect_err("unseal under wrong key must fail");
        assert!(
            matches!(err, IdentityError::UnsealError(_)),
            "expected UnsealError, got {err:?}"
        );
    }

    /// Sealed blobs are bound to the v1 HKDF info string + AEAD scheme;
    /// a single-bit flip in the ciphertext must fail authentication.
    #[test]
    fn unseal_rejects_tampered_blob() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("identity");
        store
            .generate_machine_key(&identity, "tamper-target")
            .expect("generate");
        let mut blob = store.to_sealed_bytes(&identity).expect("seal");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let err =
            MachineKeyStore::from_sealed_bytes(&identity, &blob).expect_err("must reject tamper");
        assert!(matches!(err, IdentityError::UnsealError(_)));
    }

    /// Phase D1 coverage: ML-DSA signing also recovers post-unseal
    /// (signature length is the canonical 3309 bytes).
    #[test]
    fn ml_dsa_sign_after_unseal_recovers_length() {
        let store = MachineKeyStore::new();
        let identity = NeuralKey::generate().expect("identity");
        let entry = store
            .generate_machine_key(&identity, "pq-device")
            .expect("generate");
        let payload = b"pq sign";
        let blob = store.to_sealed_bytes(&identity).expect("seal");
        let restored =
            MachineKeyStore::from_sealed_bytes(&identity, &blob).expect("unseal");
        let sig = restored
            .ml_dsa_sign_with(entry.machine_id, payload)
            .expect("ml-dsa sign after unseal");
        assert_eq!(sig.len(), 3_309, "ML-DSA-65 sig length is 3309 bytes");
    }
}
