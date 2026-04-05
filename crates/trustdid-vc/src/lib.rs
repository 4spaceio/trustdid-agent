//! W3C Verifiable Credentials v2.0 engine for TrustDID.
//!
//! Implements credential issuance, verification, presentation, and revocation
//! conforming to the W3C VC Data Model v2.0 (Recommendation, May 2025).

pub mod credential;
pub mod engine;
pub mod presentation;
pub mod schema;
pub mod status;

pub use credential::*;
pub use engine::*;
pub use presentation::*;
pub use schema::*;
pub use status::*;
