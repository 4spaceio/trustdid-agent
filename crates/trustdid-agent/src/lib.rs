//! Agent lifecycle, delegation, and capabilities for TrustDID.
//!
//! This crate provides three core subsystems:
//!
//! - **Capability engine** ([`capability`]) -- parsing, subset checking,
//!   attenuation, and constraint evaluation for structured capability tokens.
//! - **Delegation engine** ([`delegation`]) -- managing delegation chains
//!   between agents with depth limits and cascading revocation.
//! - **Lifecycle manager** ([`lifecycle`]) -- full agent lifecycle management
//!   from creation through decommissioning.

pub mod capability;
pub mod delegation;
pub mod lifecycle;

pub use capability::CapabilityEngine;
pub use delegation::{DelegationChain, DelegationManager, DelegationRecord};
pub use lifecycle::{AgentManager, AgentRecord, DecommissionResult};
