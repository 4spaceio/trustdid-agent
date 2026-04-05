//! KERI ledger driver for TrustDID (ledger-less).
//!
//! Implements `trustdid_core::LedgerDriver` using KERI key event infrastructure
//! instead of a traditional distributed ledger. DID documents are anchored
//! via inception events and updated via interaction events in the KERI
//! Key Event Log.

pub mod driver;

pub use driver::KeriLedgerDriver;
