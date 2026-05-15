//! Error types for `zero-identity`.
//!
//! [`IdentityError`] is the single error type returned from every public
//! API in this crate. Upstream `zid` cryptographic failures and standard
//! I/O errors are wrapped via `#[from]` to keep call-sites ergonomic.

use thiserror::Error;

/// Errors produced by the `zero-identity` crate.
///
/// Every variant is `Send + Sync + 'static` so values may be propagated
/// across `tokio` task boundaries and stored in `Arc`-shared state.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// A cryptographic operation in the upstream `zid` crate failed.
    #[error("zid cryptographic error: {0}")]
    Zid(#[from] zid::CryptoError),

    /// An underlying I/O operation (e.g. reading a key file) failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A Shamir share configuration was rejected (e.g. `threshold < 2`,
    /// `total < threshold`, or `total > 255`).
    #[error("invalid Shamir share configuration")]
    InvalidShareConfig,

    /// Recovery from Shamir shares failed (insufficient or corrupt shares).
    #[error("Shamir share recovery failed")]
    ShareRecoveryFailed,

    /// A requested machine key was not present in the local store.
    #[error("machine key not found")]
    KeyNotFound,

    /// (De)serialisation of a persisted artefact failed.
    #[error("serialization error")]
    SerializationError,
}

#[cfg(test)]
mod tests {
    use super::IdentityError;

    const fn assert_send_sync_static<T: Send + Sync + 'static>() {}

    #[test]
    fn identity_error_is_send_sync_static() {
        assert_send_sync_static::<IdentityError>();
    }

    #[test]
    fn zid_variant_displays() {
        let inner = zid::CryptoError::HkdfExpandFailed;
        let err = IdentityError::from(inner);
        assert!(matches!(err, IdentityError::Zid(_)));
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn io_variant_displays() {
        let inner = std::io::Error::other("boom");
        let err = IdentityError::from(inner);
        assert!(matches!(err, IdentityError::Io(_)));
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn invalid_share_config_displays() {
        let err = IdentityError::InvalidShareConfig;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn share_recovery_failed_displays() {
        let err = IdentityError::ShareRecoveryFailed;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn key_not_found_displays() {
        let err = IdentityError::KeyNotFound;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn serialization_error_displays() {
        let err = IdentityError::SerializationError;
        assert!(!err.to_string().is_empty());
    }
}
