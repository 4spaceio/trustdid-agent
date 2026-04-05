//! Web-based DID resolution driver for TrustDID.
//!
//! Implements `trustdid_core::LedgerDriver` using a did:web-style resolution
//! mechanism. DIDs are mapped to HTTPS URLs where the DID document can be
//! fetched. In this implementation, an in-memory store simulates the HTTPS
//! resolution for development and testing.

pub mod driver;

pub use driver::WebLedgerDriver;
