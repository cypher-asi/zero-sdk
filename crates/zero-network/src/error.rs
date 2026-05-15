//! Network error types.

/// Errors produced by the network layer.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// An I/O error occurred.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The publish retry budget was exhausted.
    #[error("max retries exceeded for sector {sector_id} after {attempts} attempts")]
    MaxRetriesExceeded {
        /// Opaque sector identifier (hex-encoded for display).
        sector_id: String,
        /// Total publish attempts made.
        attempts: u8,
    },

    /// The subscription channel was closed by the broker.
    #[error("subscription closed")]
    SubscriptionClosed,

    /// A network operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// Catch-all for upstream / unclassified errors.
    #[error("grid error: {0}")]
    Other(String),
}
