//! OpenID4VCI + OpenID4VP flows for TrustDID.
//!
//! Implements the OpenID for Verifiable Credential Issuance (OID4VCI) protocol
//! and the OpenID for Verifiable Presentations (OID4VP) protocol, along with
//! issuer and wallet metadata discovery.

pub mod issuance;
pub mod metadata;
pub mod presentation;

pub use issuance::*;
pub use metadata::*;
pub use presentation::*;
