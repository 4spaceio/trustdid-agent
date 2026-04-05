//! Trust Registry Query Protocol (TRQP v2.0 aligned).
//!
//! Provides a builder-pattern API for querying participants in a
//! [`TrustRegistry`](crate::registry::TrustRegistry).  Queries can filter by
//! ecosystem, DID substring, role, and status.

use crate::registry::{ParticipantRecord, ParticipantRole, ParticipantStatus, TrustRegistry};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Query types
// ---------------------------------------------------------------------------

/// A fully-formed trust-registry query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustQuery {
    /// The ecosystem to search in.
    pub ecosystem_id: String,
    /// Optional DID substring filter (case-sensitive contains match).
    pub subject_did: Option<String>,
    /// Optional role filter -- only participants holding this role are returned.
    pub role: Option<ParticipantRole>,
    /// Optional status filter -- only participants with this status are returned.
    pub status: Option<ParticipantStatus>,
}

/// Builder for constructing a [`TrustQuery`] incrementally.
#[derive(Debug, Clone)]
pub struct TrustQueryBuilder {
    ecosystem_id: String,
    subject_did: Option<String>,
    role: Option<ParticipantRole>,
    status: Option<ParticipantStatus>,
}

impl TrustQueryBuilder {
    /// Start building a query for the given ecosystem.
    pub fn new(ecosystem_id: impl Into<String>) -> Self {
        Self {
            ecosystem_id: ecosystem_id.into(),
            subject_did: None,
            role: None,
            status: None,
        }
    }

    /// Filter by a DID substring (case-sensitive contains match).
    pub fn subject_did(mut self, did: impl Into<String>) -> Self {
        self.subject_did = Some(did.into());
        self
    }

    /// Filter by participant role.
    pub fn role(mut self, role: ParticipantRole) -> Self {
        self.role = Some(role);
        self
    }

    /// Filter by participant status.
    pub fn status(mut self, status: ParticipantStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Consume the builder and produce a [`TrustQuery`].
    pub fn build(self) -> TrustQuery {
        TrustQuery {
            ecosystem_id: self.ecosystem_id,
            subject_did: self.subject_did,
            role: self.role,
            status: self.status,
        }
    }
}

// ---------------------------------------------------------------------------
// Query result
// ---------------------------------------------------------------------------

/// The result of executing a [`TrustQuery`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustQueryResult {
    /// The matching participant records.
    pub matches: Vec<ParticipantRecord>,
    /// Total number of matches (equal to `matches.len()`).
    pub total: usize,
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Execute a [`TrustQuery`] against a [`TrustRegistry`].
///
/// Returns a [`TrustQueryResult`] containing every participant in the
/// specified ecosystem that passes all supplied filters.
pub async fn execute_query(registry: &TrustRegistry, query: &TrustQuery) -> TrustQueryResult {
    let all = registry.list_participants(&query.ecosystem_id).await;

    let matches: Vec<ParticipantRecord> = all
        .into_iter()
        .filter(|p| {
            // DID substring filter.
            if let Some(ref did_filter) = query.subject_did {
                if !p.did.contains(did_filter.as_str()) {
                    return false;
                }
            }
            // Role filter.
            if let Some(ref role_filter) = query.role {
                if !p.roles.contains(role_filter) {
                    return false;
                }
            }
            // Status filter.
            if let Some(ref status_filter) = query.status {
                if p.status != *status_filter {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = matches.len();
    TrustQueryResult { matches, total }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{ParticipantRole, ParticipantStatus, TrustRegistry};
    use pretty_assertions::assert_eq;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Helper: set up a registry with one ecosystem and a handful of participants.
    async fn setup_registry() -> (TrustRegistry, String) {
        let registry = TrustRegistry::new();
        let eco = registry
            .create_ecosystem(
                "Health Credentials",
                "desc",
                "https://health.example/governance",
            )
            .await
            .unwrap();

        // Participant 1: Active Issuer + TrustAnchor
        registry
            .register_participant(
                &eco.id,
                "did:trustagent:evm:1:org:z6MkIssuer1",
                vec![ParticipantRole::Issuer, ParticipantRole::TrustAnchor],
                ParticipantStatus::Active,
            )
            .await
            .unwrap();

        // Participant 2: Active Verifier
        registry
            .register_participant(
                &eco.id,
                "did:trustagent:evm:1:org:z6MkVerifier1",
                vec![ParticipantRole::Verifier],
                ParticipantStatus::Active,
            )
            .await
            .unwrap();

        // Participant 3: Suspended Issuer
        registry
            .register_participant(
                &eco.id,
                "did:trustagent:keri:autonomous:z6MkSuspIssuer",
                vec![ParticipantRole::Issuer],
                ParticipantStatus::Active,
            )
            .await
            .unwrap();
        registry
            .update_status(
                &eco.id,
                "did:trustagent:keri:autonomous:z6MkSuspIssuer",
                ParticipantStatus::Suspended,
            )
            .await
            .unwrap();

        // Participant 4: Active Holder
        registry
            .register_participant(
                &eco.id,
                "did:trustagent:web:example.com:human:z6MkHolder1",
                vec![ParticipantRole::Holder],
                ParticipantStatus::Active,
            )
            .await
            .unwrap();

        // Participant 5: Revoked Verifier
        registry
            .register_participant(
                &eco.id,
                "did:trustagent:evm:137:delegated:z6MkRevoked",
                vec![ParticipantRole::Verifier],
                ParticipantStatus::Active,
            )
            .await
            .unwrap();
        registry
            .update_status(
                &eco.id,
                "did:trustagent:evm:137:delegated:z6MkRevoked",
                ParticipantStatus::Revoked,
            )
            .await
            .unwrap();

        (registry, eco.id)
    }

    #[test]
    fn test_query_all_participants() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id).build();
            let result = execute_query(&registry, &query).await;

            assert_eq!(result.total, 5);
            assert_eq!(result.matches.len(), 5);
        });
    }

    #[test]
    fn test_query_filter_by_role_issuer() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .role(ParticipantRole::Issuer)
                .build();
            let result = execute_query(&registry, &query).await;

            // Issuer1 (active) + SuspIssuer (suspended) = 2
            assert_eq!(result.total, 2);
            for r in &result.matches {
                assert!(r.roles.contains(&ParticipantRole::Issuer));
            }
        });
    }

    #[test]
    fn test_query_filter_by_role_trust_anchor() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .role(ParticipantRole::TrustAnchor)
                .build();
            let result = execute_query(&registry, &query).await;

            assert_eq!(result.total, 1);
            assert!(result.matches[0].did.contains("Issuer1"));
        });
    }

    #[test]
    fn test_query_filter_by_status_active() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .status(ParticipantStatus::Active)
                .build();
            let result = execute_query(&registry, &query).await;

            // Issuer1, Verifier1, Holder1 = 3
            assert_eq!(result.total, 3);
            for r in &result.matches {
                assert_eq!(r.status, ParticipantStatus::Active);
            }
        });
    }

    #[test]
    fn test_query_filter_by_status_suspended() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .status(ParticipantStatus::Suspended)
                .build();
            let result = execute_query(&registry, &query).await;

            assert_eq!(result.total, 1);
            assert!(result.matches[0].did.contains("SuspIssuer"));
        });
    }

    #[test]
    fn test_query_filter_by_status_revoked() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .status(ParticipantStatus::Revoked)
                .build();
            let result = execute_query(&registry, &query).await;

            assert_eq!(result.total, 1);
            assert!(result.matches[0].did.contains("Revoked"));
        });
    }

    #[test]
    fn test_query_filter_by_did_substring() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .subject_did("evm:1:")
                .build();
            let result = execute_query(&registry, &query).await;

            // Issuer1 and Verifier1 have evm:1:
            assert_eq!(result.total, 2);
        });
    }

    #[test]
    fn test_query_combined_role_and_status() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .role(ParticipantRole::Issuer)
                .status(ParticipantStatus::Active)
                .build();
            let result = execute_query(&registry, &query).await;

            // Only Issuer1 is both Issuer and Active.
            assert_eq!(result.total, 1);
            assert!(result.matches[0].did.contains("Issuer1"));
        });
    }

    #[test]
    fn test_query_combined_all_filters() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .subject_did("keri")
                .role(ParticipantRole::Issuer)
                .status(ParticipantStatus::Suspended)
                .build();
            let result = execute_query(&registry, &query).await;

            assert_eq!(result.total, 1);
            assert!(result.matches[0].did.contains("SuspIssuer"));
        });
    }

    #[test]
    fn test_query_no_matches() {
        runtime().block_on(async {
            let (registry, eco_id) = setup_registry().await;

            let query = TrustQueryBuilder::new(&eco_id)
                .role(ParticipantRole::Holder)
                .status(ParticipantStatus::Revoked)
                .build();
            let result = execute_query(&registry, &query).await;

            assert_eq!(result.total, 0);
            assert!(result.matches.is_empty());
        });
    }

    #[test]
    fn test_query_nonexistent_ecosystem() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let query = TrustQueryBuilder::new("does-not-exist").build();
            let result = execute_query(&registry, &query).await;

            assert_eq!(result.total, 0);
        });
    }

    #[test]
    fn test_query_builder_produces_correct_struct() {
        let query = TrustQueryBuilder::new("eco-123")
            .subject_did("did:example:abc")
            .role(ParticipantRole::Verifier)
            .status(ParticipantStatus::Active)
            .build();

        assert_eq!(query.ecosystem_id, "eco-123");
        assert_eq!(query.subject_did.as_deref(), Some("did:example:abc"));
        assert_eq!(query.role, Some(ParticipantRole::Verifier));
        assert_eq!(query.status, Some(ParticipantStatus::Active));
    }

    #[test]
    fn test_query_serialization() {
        let query = TrustQueryBuilder::new("eco-ser")
            .role(ParticipantRole::Issuer)
            .build();

        let json = serde_json::to_string(&query).unwrap();
        let parsed: TrustQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ecosystem_id, "eco-ser");
        assert_eq!(parsed.role, Some(ParticipantRole::Issuer));
        assert!(parsed.subject_did.is_none());
        assert!(parsed.status.is_none());
    }

    #[test]
    fn test_query_result_serialization() {
        let result = TrustQueryResult {
            matches: vec![],
            total: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: TrustQueryResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total, 0);
        assert!(parsed.matches.is_empty());
    }
}
