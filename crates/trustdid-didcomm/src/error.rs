//! Error types for the DIDComm crate.

use thiserror::Error;

/// Errors that can occur during DIDComm operations.
#[derive(Debug, Error)]
pub enum DIDCommError {
    /// Error packing a message into an envelope.
    #[error("pack error: {0}")]
    PackError(String),

    /// Error unpacking an envelope to recover a message.
    #[error("unpack error: {0}")]
    UnpackError(String),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// Message validation failed.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Protocol-level error.
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// Routing error (no handler, forward failure, etc.).
    #[error("routing error: {0}")]
    RoutingError(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),
}

/// Convenience result type for DIDComm operations.
pub type Result<T> = std::result::Result<T, DIDCommError>;
