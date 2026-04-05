//! Trust registry client, scoring, and ecosystem management for TrustDID.
//!
//! This crate implements the trust layer aligned with the
//! [ToIP Trust Registry](https://trustoverip.org/) framework, providing:
//!
//! - **Trust Registry** -- ecosystem creation, participant registration, and
//!   status management ([`registry`] module).
//! - **Trust Scoring** -- a basis-point scoring engine driven by endorsements,
//!   delegation depth, identity age and behaviour ([`scoring`] module).
//! - **Trust Query Protocol** -- a builder-pattern query API aligned with the
//!   TRQP v2.0 specification ([`query`] module).

pub mod query;
pub mod registry;
pub mod scoring;

pub use query::{TrustQuery, TrustQueryBuilder, TrustQueryResult, execute_query};
pub use registry::{
    Ecosystem, ParticipantRecord, ParticipantRole, ParticipantStatus, TrustRegistry,
};
pub use scoring::{Endorsement, TrustScore, TrustScorer};
