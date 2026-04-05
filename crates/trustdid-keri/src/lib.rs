//! KERI controller for key events and pre-rotation in TrustDID.
//!
//! This crate implements a KERI (Key Event Receipt Infrastructure) inspired
//! controller for managing decentralized identifiers with:
//!
//! - **Key Events** (`event`) -- inception, rotation, interaction, and delegated inception.
//! - **Key Event Log** (`log`) -- append-only, hash-chained event history.
//! - **Controller** (`controller`) -- high-level key management with pre-rotation.
//! - **Witness** (`witness`) -- receipt infrastructure for event observability.

pub mod controller;
pub mod event;
pub mod log;
pub mod witness;

pub use controller::KeriController;
pub use event::KeyEvent;
pub use log::KeyEventLog;
pub use witness::{Receipt, Witness, verify_receipt};
