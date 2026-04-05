//! DIDComm v2.1 messaging for TrustDID agent communication.
//!
//! This crate implements DIDComm v2.1 messaging primitives for secure,
//! decentralized agent-to-agent communication in the TrustDID system.
//!
//! # Modules
//!
//! - [`message`] -- Core DIDComm message types, builder, and attachments.
//! - [`envelope`] -- Pack/unpack operations (encryption and signing envelopes).
//! - [`protocols`] -- Protocol handlers (Trust Ping, Agent Auth).
//! - [`routing`] -- Message routing by type URI.
//! - [`error`] -- Error types for DIDComm operations.

pub mod envelope;
pub mod error;
pub mod message;
pub mod protocols;
pub mod routing;

// Re-export primary types for ergonomic use.
pub use envelope::{pack, unpack, Envelope, EnvelopeBuilder, PackMode};
pub use error::{DIDCommError, Result};
pub use message::{protocol, Attachment, AttachmentData, DIDCommMessage, DIDCommMessageBuilder};
pub use protocols::{AgentAuth, TrustPing};
pub use routing::{HandlerFn, Router, RoutingResult, SyncHandlerFn};
