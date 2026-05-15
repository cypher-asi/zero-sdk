//! `NeuralKey` wrapper and Shamir share helpers.
//!
//! This module exposes [`NeuralKey::generate`], [`NeuralKey::identity_id`],
//! and the Shamir split/recover free functions [`split_neural_key`] and
//! [`recover_neural_key`]. HKDF derivation lands in a later task.

use rand::rngs::OsRng;
use zid::types::IdentityId;
use zid::{shamir_combine, shamir_split, ShamirShare};

use crate::error::IdentityError;

/// Inclusive upper bound on the number of shares produced by
/// [`split_neural_key`]. Matches the per-task 1.5 acceptance criterion
/// of `0 < threshold <= total <= 16`.
pub const MAX_SHARES: u8 = 16;

/// Domain-separation context for the BLAKE3 keyed hash that turns the
/// 256-bit `NeuralKey` into a stable 128-bit `IdentityId`. Bumping the
/// suffix breaks compatibility with previously persisted ids.
const IDENTITY_ID_CONTEXT: &str = "zero-identity:identity-id:v1";

/// A 256-bit root secret from which all identity and machine keys are
/// derived. Wraps [`zid::keys::neural::NeuralKey`].
pub struct NeuralKey(zid::keys::neural::NeuralKey);

impl NeuralKey {
    /// Generate a fresh 256-bit `NeuralKey` from the operating-system
    /// CSPRNG ([`OsRng`]).
    ///
    /// # Errors
    /// Returns [`IdentityError::Zid`] if the upstream ZID entropy
    /// validator rejects the freshly drawn key material (for example,
    /// the all-zero vector).
    pub fn generate() -> Result<Self, IdentityError> {
        let inner = zid::keys::neural::NeuralKey::generate(&mut OsRng);
        inner.validate_entropy()?;
        Ok(Self(inner))
    }

    /// Return the 128-bit [`IdentityId`] for this key.
    ///
    /// The id is a deterministic function of the underlying key bytes:
    /// the same `NeuralKey` always produces the same `IdentityId`, and
    /// distinct keys produce distinct ids with overwhelming probability.
    #[must_use]
    pub fn identity_id(&self) -> IdentityId {
        IdentityId::from(self.identity_id_bytes())
    }

    /// Return the raw 16-byte identity id derived from this key.
    ///
    /// Useful when the caller needs `[u8; 16]` directly (e.g. to
    /// construct a `zero_crypto::aad::IdentityId` without pulling in the
    /// `zid` crate).
    #[must_use]
    pub fn identity_id_bytes(&self) -> [u8; 16] {
        let bytes = self.0.to_bytes();
        let hash = blake3::keyed_hash(blake3_context_key(), &bytes);
        let digest = hash.as_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }
}

/// Configuration for [`split_neural_key`].
///
/// `threshold` shares (out of `total`) are required to reconstruct the
/// secret. Per task 1.5, the parameters are constrained to
/// `0 < threshold <= total <= 16`; values outside this range are
/// rejected with [`IdentityError::InvalidShareConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareConfig {
    /// Minimum number of shares required for recovery.
    pub threshold: u8,
    /// Total number of shares to emit.
    pub total: u8,
}

impl Default for ShareConfig {
    /// Default policy: 3-of-5, matching the spec's recommended setup.
    fn default() -> Self {
        Self {
            threshold: 3,
            total: 5,
        }
    }
}

/// Output of [`split_neural_key`]: opaque per-share byte blobs plus the
/// threshold needed to reconstruct via [`recover_neural_key`].
#[derive(Debug, Clone)]
pub struct NeuralKeyShares {
    /// Each share is the upstream `ShamirShare` serialised via
    /// [`ShamirShare::to_bytes`] (1-byte index prefix + 32 share bytes).
    pub shares: Vec<Vec<u8>>,
    /// Threshold required to recombine; pass through to
    /// [`recover_neural_key`].
    pub threshold: u8,
}

/// Split a [`NeuralKey`] into Shamir shares.
///
/// # Errors
/// * [`IdentityError::InvalidShareConfig`] when `cfg.threshold == 0`,
///   `cfg.total < cfg.threshold`, or `cfg.total > 16`.
/// * [`IdentityError::Zid`] if the upstream split fails.
pub fn split_neural_key(
    key: &NeuralKey,
    cfg: ShareConfig,
) -> Result<NeuralKeyShares, IdentityError> {
    if cfg.threshold == 0 || cfg.total < cfg.threshold || cfg.total > MAX_SHARES {
        return Err(IdentityError::InvalidShareConfig);
    }
    let secret = key.0.to_bytes();
    let raw = shamir_split(
        &secret,
        cfg.total as usize,
        cfg.threshold as usize,
        &mut OsRng,
    )?;
    let shares = raw.iter().map(ShamirShare::to_bytes).collect();
    Ok(NeuralKeyShares {
        shares,
        threshold: cfg.threshold,
    })
}

/// Recover a [`NeuralKey`] from at least `threshold` shares previously
/// emitted by [`split_neural_key`].
///
/// # Errors
/// * [`IdentityError::InvalidShareConfig`] when `threshold` is zero or
///   `shares.len()` is outside `threshold..=16`.
/// * [`IdentityError::ShareRecoveryFailed`] when the upstream Shamir
///   combine rejects the shares (insufficient, duplicate, or corrupt).
pub fn recover_neural_key(shares: &[Vec<u8>], threshold: u8) -> Result<NeuralKey, IdentityError> {
    if threshold == 0 || shares.len() < threshold as usize || shares.len() > MAX_SHARES as usize {
        return Err(IdentityError::InvalidShareConfig);
    }
    let mut decoded = Vec::with_capacity(shares.len());
    for raw in shares {
        let share = ShamirShare::from_bytes(raw).map_err(|_| IdentityError::ShareRecoveryFailed)?;
        decoded.push(share);
    }
    let secret = shamir_combine(&decoded).map_err(|_| IdentityError::ShareRecoveryFailed)?;
    Ok(NeuralKey(zid::keys::neural::NeuralKey::from_bytes(secret)))
}

/// Derive a fixed 32-byte BLAKE3 key from the static context string.
/// `blake3::keyed_hash` requires a `&[u8; 32]` key, so we hash the
/// context once at call-time and reuse the digest.
fn blake3_context_key() -> &'static [u8; 32] {
    use std::sync::OnceLock;
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| *blake3::hash(IDENTITY_ID_CONTEXT.as_bytes()).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::NeuralKey;

    #[test]
    fn two_generated_keys_have_distinct_identity_ids() {
        let a = NeuralKey::generate().expect("generate a");
        let b = NeuralKey::generate().expect("generate b");
        assert_ne!(
            a.identity_id(),
            b.identity_id(),
            "two fresh NeuralKeys must yield distinct IdentityIds"
        );
    }

    #[test]
    fn identity_id_is_stable_across_repeated_calls() {
        let key = NeuralKey::generate().expect("generate");
        let first = key.identity_id();
        for _ in 0..8 {
            assert_eq!(
                first,
                key.identity_id(),
                "identity_id() must be deterministic on the same NeuralKey"
            );
        }
    }
}
