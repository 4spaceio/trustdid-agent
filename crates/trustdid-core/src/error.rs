use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustDIDError {
    #[error("invalid DID syntax: {0}")]
    InvalidDID(String),

    #[error("invalid DID document: {0}")]
    InvalidDocument(String),

    #[error("unsupported network: {0}")]
    UnsupportedNetwork(String),

    #[error("unsupported agent class: {0}")]
    UnsupportedAgentClass(String),

    #[error("DID not found: {0}")]
    NotFound(String),

    #[error("DID already exists: {0}")]
    AlreadyExists(String),

    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidLifecycleTransition {
        from: crate::types::LifecycleState,
        to: crate::types::LifecycleState,
    },

    #[error("delegation depth exceeded: max {max}, requested {requested}")]
    DelegationDepthExceeded { max: u8, requested: u8 },

    #[error("invalid delegation: {0}")]
    InvalidDelegation(String),

    #[error("pre-rotation verification failed: {0}")]
    PreRotationFailed(String),

    #[error("cryptographic error: {0}")]
    CryptoError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("ledger error: {0}")]
    LedgerError(String),

    #[error("capability not granted: {0}")]
    CapabilityNotGranted(String),

    #[error("agent decommissioned: {0}")]
    AgentDecommissioned(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, TrustDIDError>;
