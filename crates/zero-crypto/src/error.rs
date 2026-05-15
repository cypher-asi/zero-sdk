//! Cryptographic error types for zero-crypto.

/// Errors produced by cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("HPKE error: {0}")]
    Hpke(String),

    #[error("ML-KEM error: {0}")]
    MlKem(String),

    #[error("Ed25519 error: {0}")]
    Ed25519(String),

    #[error("ML-DSA error: {0}")]
    MlDsa(String),

    #[error("AAD encoding error: {0}")]
    AadEncoding(String),

    #[error("signature verification failed: {algorithm}")]
    SignatureVerificationFailed { algorithm: &'static str },

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("MLS error: {0}")]
    Mls(String),
}

const _: fn() = || {
    fn assert_bounds<T: Send + Sync + 'static>() {}
    assert_bounds::<CryptoError>();
};
