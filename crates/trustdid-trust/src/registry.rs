//! Trust Registry -- ToIP-aligned ecosystem and participant management.
//!
//! Provides an in-memory trust registry that can create ecosystems,
//! register participants with roles and statuses, and query/update them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors specific to trust-registry operations.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("ecosystem not found: {0}")]
    EcosystemNotFound(String),

    #[error("participant not found: {did} in ecosystem {ecosystem_id}")]
    ParticipantNotFound { ecosystem_id: String, did: String },

    #[error("participant already registered: {did} in ecosystem {ecosystem_id}")]
    ParticipantAlreadyRegistered { ecosystem_id: String, did: String },

    #[error("invalid status transition from {from:?} to {to:?}")]
    InvalidStatusTransition {
        from: ParticipantStatus,
        to: ParticipantStatus,
    },
}

pub type Result<T> = std::result::Result<T, RegistryError>;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A trust ecosystem registered in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ecosystem {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Optional longer description.
    pub description: String,
    /// URL pointing to the governance framework document.
    pub governance_url: String,
    /// When the ecosystem was created.
    pub created_at: DateTime<Utc>,
}

/// Roles a participant can hold inside an ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParticipantRole {
    Issuer,
    Verifier,
    Holder,
    TrustAnchor,
}

/// Current status of a participant within an ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParticipantStatus {
    Active,
    Suspended,
    Revoked,
}

impl ParticipantStatus {
    /// Returns `true` when the transition from `self` to `target` is valid.
    pub fn can_transition_to(&self, target: ParticipantStatus) -> bool {
        matches!(
            (self, target),
            (Self::Active, Self::Suspended)
                | (Self::Active, Self::Revoked)
                | (Self::Suspended, Self::Active)
                | (Self::Suspended, Self::Revoked)
        )
    }
}

/// Record for a single participant inside an ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantRecord {
    /// The DID of the participant.
    pub did: String,
    /// Roles the participant holds.
    pub roles: Vec<ParticipantRole>,
    /// Current participation status.
    pub status: ParticipantStatus,
    /// When the participant was first registered.
    pub registered_at: DateTime<Utc>,
    /// Last time the record was modified.
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Internal storage
// ---------------------------------------------------------------------------

/// Per-ecosystem data kept in the store.
#[derive(Debug, Clone)]
struct EcosystemEntry {
    ecosystem: Ecosystem,
    participants: HashMap<String, ParticipantRecord>,
}

// ---------------------------------------------------------------------------
// TrustRegistry
// ---------------------------------------------------------------------------

/// An in-memory trust registry aligned with the ToIP Trust Registry protocol.
#[derive(Debug, Clone)]
pub struct TrustRegistry {
    store: Arc<RwLock<HashMap<String, EcosystemEntry>>>,
}

impl TrustRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new ecosystem and return the metadata.
    pub async fn create_ecosystem(
        &self,
        name: impl Into<String>,
        description: impl Into<String>,
        governance_url: impl Into<String>,
    ) -> Result<Ecosystem> {
        let ecosystem = Ecosystem {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            description: description.into(),
            governance_url: governance_url.into(),
            created_at: Utc::now(),
        };

        let entry = EcosystemEntry {
            ecosystem: ecosystem.clone(),
            participants: HashMap::new(),
        };

        let mut store = self.store.write().await;
        store.insert(ecosystem.id.clone(), entry);

        Ok(ecosystem)
    }

    /// Register a participant inside an ecosystem.
    pub async fn register_participant(
        &self,
        ecosystem_id: &str,
        did: impl Into<String>,
        roles: Vec<ParticipantRole>,
        status: ParticipantStatus,
    ) -> Result<()> {
        let did = did.into();
        let mut store = self.store.write().await;
        let entry = store
            .get_mut(ecosystem_id)
            .ok_or_else(|| RegistryError::EcosystemNotFound(ecosystem_id.to_string()))?;

        if entry.participants.contains_key(&did) {
            return Err(RegistryError::ParticipantAlreadyRegistered {
                ecosystem_id: ecosystem_id.to_string(),
                did,
            });
        }

        let now = Utc::now();
        let record = ParticipantRecord {
            did: did.clone(),
            roles,
            status,
            registered_at: now,
            updated_at: now,
        };
        entry.participants.insert(did, record);

        Ok(())
    }

    /// Look up a participant by DID within an ecosystem.
    pub async fn check_participant(
        &self,
        ecosystem_id: &str,
        did: &str,
    ) -> Option<ParticipantRecord> {
        let store = self.store.read().await;
        store
            .get(ecosystem_id)
            .and_then(|e| e.participants.get(did).cloned())
    }

    /// Update the status of an existing participant.
    pub async fn update_status(
        &self,
        ecosystem_id: &str,
        did: &str,
        new_status: ParticipantStatus,
    ) -> Result<()> {
        let mut store = self.store.write().await;
        let entry = store
            .get_mut(ecosystem_id)
            .ok_or_else(|| RegistryError::EcosystemNotFound(ecosystem_id.to_string()))?;

        let record = entry.participants.get_mut(did).ok_or_else(|| {
            RegistryError::ParticipantNotFound {
                ecosystem_id: ecosystem_id.to_string(),
                did: did.to_string(),
            }
        })?;

        if !record.status.can_transition_to(new_status) {
            return Err(RegistryError::InvalidStatusTransition {
                from: record.status,
                to: new_status,
            });
        }

        record.status = new_status;
        record.updated_at = Utc::now();

        Ok(())
    }

    /// List all participants in the given ecosystem.
    pub async fn list_participants(&self, ecosystem_id: &str) -> Vec<ParticipantRecord> {
        let store = self.store.read().await;
        store
            .get(ecosystem_id)
            .map(|e| e.participants.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Retrieve ecosystem metadata by ID.
    pub async fn get_ecosystem(&self, ecosystem_id: &str) -> Option<Ecosystem> {
        let store = self.store.read().await;
        store.get(ecosystem_id).map(|e| e.ecosystem.clone())
    }
}

impl Default for TrustRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_create_ecosystem() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco = registry
                .create_ecosystem(
                    "Health Credentials",
                    "A trust ecosystem for health credential issuance",
                    "https://example.com/governance",
                )
                .await
                .unwrap();

            assert_eq!(eco.name, "Health Credentials");
            assert_eq!(
                eco.description,
                "A trust ecosystem for health credential issuance"
            );
            assert_eq!(eco.governance_url, "https://example.com/governance");
            assert!(!eco.id.is_empty());

            // Verify we can retrieve it back.
            let fetched = registry.get_ecosystem(&eco.id).await.unwrap();
            assert_eq!(fetched.id, eco.id);
        });
    }

    #[test]
    fn test_register_and_check_participant() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco = registry
                .create_ecosystem("Test Eco", "desc", "https://gov.example")
                .await
                .unwrap();

            let did = "did:trustagent:keri:autonomous:z6MkTest1";
            registry
                .register_participant(
                    &eco.id,
                    did,
                    vec![ParticipantRole::Issuer, ParticipantRole::Verifier],
                    ParticipantStatus::Active,
                )
                .await
                .unwrap();

            let record = registry
                .check_participant(&eco.id, did)
                .await
                .expect("participant should exist");

            assert_eq!(record.did, did);
            assert_eq!(record.status, ParticipantStatus::Active);
            assert_eq!(record.roles.len(), 2);
            assert!(record.roles.contains(&ParticipantRole::Issuer));
            assert!(record.roles.contains(&ParticipantRole::Verifier));
        });
    }

    #[test]
    fn test_duplicate_participant_rejected() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco = registry
                .create_ecosystem("Eco", "desc", "https://gov.example")
                .await
                .unwrap();

            let did = "did:trustagent:keri:autonomous:z6MkDup";
            registry
                .register_participant(
                    &eco.id,
                    did,
                    vec![ParticipantRole::Holder],
                    ParticipantStatus::Active,
                )
                .await
                .unwrap();

            let res = registry
                .register_participant(
                    &eco.id,
                    did,
                    vec![ParticipantRole::Issuer],
                    ParticipantStatus::Active,
                )
                .await;

            assert!(res.is_err());
        });
    }

    #[test]
    fn test_register_into_nonexistent_ecosystem() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let res = registry
                .register_participant(
                    "nonexistent-id",
                    "did:trustagent:keri:autonomous:z6MkX",
                    vec![ParticipantRole::Holder],
                    ParticipantStatus::Active,
                )
                .await;

            assert!(res.is_err());
        });
    }

    #[test]
    fn test_update_status() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco = registry
                .create_ecosystem("Eco", "d", "https://g.example")
                .await
                .unwrap();

            let did = "did:trustagent:keri:autonomous:z6MkUpdate";
            registry
                .register_participant(
                    &eco.id,
                    did,
                    vec![ParticipantRole::Issuer],
                    ParticipantStatus::Active,
                )
                .await
                .unwrap();

            // Active -> Suspended is valid.
            registry
                .update_status(&eco.id, did, ParticipantStatus::Suspended)
                .await
                .unwrap();

            let record = registry.check_participant(&eco.id, did).await.unwrap();
            assert_eq!(record.status, ParticipantStatus::Suspended);

            // Suspended -> Active is valid.
            registry
                .update_status(&eco.id, did, ParticipantStatus::Active)
                .await
                .unwrap();

            let record = registry.check_participant(&eco.id, did).await.unwrap();
            assert_eq!(record.status, ParticipantStatus::Active);
        });
    }

    #[test]
    fn test_invalid_status_transition() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco = registry
                .create_ecosystem("Eco", "d", "https://g.example")
                .await
                .unwrap();

            let did = "did:trustagent:keri:autonomous:z6MkBadTx";
            registry
                .register_participant(
                    &eco.id,
                    did,
                    vec![ParticipantRole::Issuer],
                    ParticipantStatus::Active,
                )
                .await
                .unwrap();

            // Active -> Revoked is valid.
            registry
                .update_status(&eco.id, did, ParticipantStatus::Revoked)
                .await
                .unwrap();

            // Revoked -> Active is NOT valid.
            let res = registry
                .update_status(&eco.id, did, ParticipantStatus::Active)
                .await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_list_participants() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco = registry
                .create_ecosystem("Eco", "d", "https://g.example")
                .await
                .unwrap();

            for i in 0..5 {
                let did = format!("did:trustagent:keri:autonomous:z6MkList{i}");
                registry
                    .register_participant(
                        &eco.id,
                        &did,
                        vec![ParticipantRole::Holder],
                        ParticipantStatus::Active,
                    )
                    .await
                    .unwrap();
            }

            let participants = registry.list_participants(&eco.id).await;
            assert_eq!(participants.len(), 5);
        });
    }

    #[test]
    fn test_list_participants_empty_ecosystem() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco = registry
                .create_ecosystem("Empty", "d", "https://g.example")
                .await
                .unwrap();

            let participants = registry.list_participants(&eco.id).await;
            assert!(participants.is_empty());
        });
    }

    #[test]
    fn test_list_participants_nonexistent_ecosystem() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let participants = registry.list_participants("nope").await;
            assert!(participants.is_empty());
        });
    }

    #[test]
    fn test_check_nonexistent_participant() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco = registry
                .create_ecosystem("Eco", "d", "https://g.example")
                .await
                .unwrap();

            let record = registry
                .check_participant(&eco.id, "did:trustagent:keri:autonomous:z6MkGhost")
                .await;
            assert!(record.is_none());
        });
    }

    #[test]
    fn test_participant_status_transitions() {
        // Active -> Suspended
        assert!(ParticipantStatus::Active.can_transition_to(ParticipantStatus::Suspended));
        // Active -> Revoked
        assert!(ParticipantStatus::Active.can_transition_to(ParticipantStatus::Revoked));
        // Suspended -> Active
        assert!(ParticipantStatus::Suspended.can_transition_to(ParticipantStatus::Active));
        // Suspended -> Revoked
        assert!(ParticipantStatus::Suspended.can_transition_to(ParticipantStatus::Revoked));
        // Revoked is terminal
        assert!(!ParticipantStatus::Revoked.can_transition_to(ParticipantStatus::Active));
        assert!(!ParticipantStatus::Revoked.can_transition_to(ParticipantStatus::Suspended));
    }

    #[test]
    fn test_ecosystem_serialization() {
        let eco = Ecosystem {
            id: "test-id".to_string(),
            name: "Test".to_string(),
            description: "desc".to_string(),
            governance_url: "https://gov.example".to_string(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&eco).unwrap();
        let parsed: Ecosystem = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, eco.id);
        assert_eq!(parsed.name, eco.name);
    }

    #[test]
    fn test_participant_record_serialization() {
        let record = ParticipantRecord {
            did: "did:trustagent:keri:autonomous:z6MkSer".to_string(),
            roles: vec![ParticipantRole::Issuer, ParticipantRole::TrustAnchor],
            status: ParticipantStatus::Active,
            registered_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&record).unwrap();
        let parsed: ParticipantRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.did, record.did);
        assert_eq!(parsed.roles.len(), 2);
        assert_eq!(parsed.status, ParticipantStatus::Active);
    }

    #[test]
    fn test_multiple_ecosystems_isolated() {
        runtime().block_on(async {
            let registry = TrustRegistry::new();
            let eco_a = registry
                .create_ecosystem("A", "desc a", "https://a.example")
                .await
                .unwrap();
            let eco_b = registry
                .create_ecosystem("B", "desc b", "https://b.example")
                .await
                .unwrap();

            let did = "did:trustagent:keri:autonomous:z6MkShared";
            registry
                .register_participant(
                    &eco_a.id,
                    did,
                    vec![ParticipantRole::Issuer],
                    ParticipantStatus::Active,
                )
                .await
                .unwrap();

            // Same DID should not appear in eco_b.
            assert!(registry.check_participant(&eco_b.id, did).await.is_none());

            // But can be independently registered in eco_b.
            registry
                .register_participant(
                    &eco_b.id,
                    did,
                    vec![ParticipantRole::Holder],
                    ParticipantStatus::Suspended,
                )
                .await
                .unwrap();

            let rec_a = registry.check_participant(&eco_a.id, did).await.unwrap();
            let rec_b = registry.check_participant(&eco_b.id, did).await.unwrap();
            assert_eq!(rec_a.status, ParticipantStatus::Active);
            assert_eq!(rec_b.status, ParticipantStatus::Suspended);
        });
    }
}
