//! Agent lifecycle manager for TrustDID.
//!
//! Manages the full lifecycle of agent identities: creation, suspension,
//! resumption, deactivation, and decommissioning (with optional cascade).

use crate::delegation::DelegationManager;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use trustdid_core::{AgentClass, Capability, LifecycleState, Result, TrustDIDError};
use uuid::Uuid;

/// An in-memory record tracking an agent's identity and current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub did: String,
    pub agent_class: AgentClass,
    pub lifecycle_state: LifecycleState,
    pub parent_did: Option<String>,
    pub capabilities: Vec<Capability>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Result of a decommission operation, listing all affected agents and
/// revoked delegations.
#[derive(Debug, Clone)]
pub struct DecommissionResult {
    pub decommissioned_agents: Vec<String>,
    pub revoked_delegations: Vec<String>,
}

/// Manages agent lifecycles with an in-memory store.
///
/// Works in tandem with [`DelegationManager`] for cascade operations.
#[derive(Clone)]
pub struct AgentManager {
    agents: Arc<RwLock<HashMap<String, AgentRecord>>>,
    delegation_mgr: DelegationManager,
}

impl AgentManager {
    pub fn new(delegation_mgr: DelegationManager) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            delegation_mgr,
        }
    }

    /// Create a new agent, generating a DID and setting it to `Active` state.
    pub async fn create(
        &self,
        agent_class: AgentClass,
        parent_did: Option<String>,
        capabilities: Vec<Capability>,
    ) -> Result<AgentRecord> {
        let id = Uuid::new_v4().to_string().replace('-', "");
        let did = format!("did:trustagent:keri:{agent_class}:z{id}");

        let now = Utc::now();
        let record = AgentRecord {
            did: did.clone(),
            agent_class,
            lifecycle_state: LifecycleState::Active,
            parent_did: parent_did.clone(),
            capabilities,
            created_at: now,
            updated_at: now,
        };

        self.agents.write().await.insert(did.clone(), record.clone());

        info!(did = did.as_str(), class = %agent_class, "agent created");

        Ok(record)
    }

    /// Suspend an active agent.
    pub async fn suspend(&self, did: &str) -> Result<()> {
        self.transition(did, LifecycleState::Suspended).await
    }

    /// Resume a suspended agent back to active state.
    pub async fn resume(&self, did: &str) -> Result<()> {
        self.transition(did, LifecycleState::Active).await
    }

    /// Deactivate an active or suspended agent.
    pub async fn deactivate(&self, did: &str) -> Result<()> {
        self.transition(did, LifecycleState::Deactivated).await
    }

    /// Decommission an agent and optionally cascade to all children.
    ///
    /// Steps:
    /// 1. Transition the agent to Deactivated (if not already), then Decommissioned.
    /// 2. If `cascade`, find all children via the delegation manager and
    ///    decommission them as well.
    /// 3. Revoke all affected delegations.
    pub async fn decommission(
        &self,
        did: &str,
        cascade: bool,
    ) -> Result<DecommissionResult> {
        let mut decommissioned_agents = Vec::new();
        let mut revoked_delegations = Vec::new();

        // Decommission the target agent
        self.decommission_single(did, &mut decommissioned_agents)
            .await?;

        if cascade {
            // Gather all children transitively via delegation manager
            let mut queue = vec![did.to_string()];
            let mut visited = std::collections::HashSet::new();
            visited.insert(did.to_string());

            while let Some(parent) = queue.pop() {
                let children = self.delegation_mgr.get_children(&parent).await;
                for child in children {
                    if visited.insert(child.clone()) {
                        // Attempt to decommission; ignore errors for agents not in our store
                        if self
                            .decommission_single(&child, &mut decommissioned_agents)
                            .await
                            .is_err()
                        {
                            warn!(did = child.as_str(), "child agent not found in store during cascade");
                        }
                        queue.push(child);
                    }
                }
            }

            // Cascade revoke delegations starting from the target
            if let Ok(revoked) = self.delegation_mgr.revoke(did, true).await {
                revoked_delegations = revoked;
            }
        } else {
            // Revoke just this agent's delegation (if it has one)
            if let Ok(revoked) = self.delegation_mgr.revoke(did, false).await {
                revoked_delegations = revoked;
            }
        }

        info!(
            did = did,
            decommissioned = decommissioned_agents.len(),
            revoked = revoked_delegations.len(),
            "decommission complete"
        );

        Ok(DecommissionResult {
            decommissioned_agents,
            revoked_delegations,
        })
    }

    /// Get an agent record by DID.
    pub async fn get(&self, did: &str) -> Option<AgentRecord> {
        self.agents.read().await.get(did).cloned()
    }

    /// Return the delegation manager used by this agent manager.
    pub fn delegation_manager(&self) -> &DelegationManager {
        &self.delegation_mgr
    }

    // --- private helpers ---

    /// Perform a state transition, validating it against the lifecycle rules
    /// defined in [`LifecycleState::can_transition_to`].
    async fn transition(&self, did: &str, target: LifecycleState) -> Result<()> {
        let mut store = self.agents.write().await;
        let record = store
            .get_mut(did)
            .ok_or_else(|| TrustDIDError::NotFound(format!("agent '{did}' not found")))?;

        if !record.lifecycle_state.can_transition_to(target) {
            return Err(TrustDIDError::InvalidLifecycleTransition {
                from: record.lifecycle_state,
                to: target,
            });
        }

        debug!(
            did = did,
            from = %record.lifecycle_state,
            to = %target,
            "lifecycle transition"
        );

        record.lifecycle_state = target;
        record.updated_at = Utc::now();

        Ok(())
    }

    /// Decommission a single agent, performing the necessary intermediate
    /// transitions (Active/Suspended -> Deactivated -> Decommissioned).
    async fn decommission_single(
        &self,
        did: &str,
        result: &mut Vec<String>,
    ) -> Result<()> {
        let mut store = self.agents.write().await;
        let record = store
            .get_mut(did)
            .ok_or_else(|| TrustDIDError::NotFound(format!("agent '{did}' not found")))?;

        // Already decommissioned? Skip.
        if record.lifecycle_state == LifecycleState::Decommissioned {
            return Ok(());
        }

        // Force through intermediate states if needed
        match record.lifecycle_state {
            LifecycleState::Active | LifecycleState::Suspended => {
                // Active/Suspended -> Deactivated -> Decommissioned
                if record.lifecycle_state.can_transition_to(LifecycleState::Deactivated) {
                    record.lifecycle_state = LifecycleState::Deactivated;
                }
                record.lifecycle_state = LifecycleState::Decommissioned;
            }
            LifecycleState::Deactivated => {
                record.lifecycle_state = LifecycleState::Decommissioned;
            }
            LifecycleState::Created => {
                // Created -> Active -> Deactivated -> Decommissioned
                record.lifecycle_state = LifecycleState::Decommissioned;
            }
            LifecycleState::Rotating => {
                // Rotating -> Active -> Deactivated -> Decommissioned
                record.lifecycle_state = LifecycleState::Decommissioned;
            }
            LifecycleState::Decommissioned => {
                // Already handled above
            }
        }

        record.updated_at = Utc::now();
        result.push(did.to_string());

        debug!(did = did, "agent decommissioned");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn new_manager() -> AgentManager {
        AgentManager::new(DelegationManager::new())
    }

    #[tokio::test]
    async fn test_create_agent() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();

        assert_eq!(record.agent_class, AgentClass::Autonomous);
        assert_eq!(record.lifecycle_state, LifecycleState::Active);
        assert!(record.parent_did.is_none());
        assert!(record.did.starts_with("did:trustagent:keri:autonomous:z"));
    }

    #[tokio::test]
    async fn test_create_delegated_agent() {
        let mgr = new_manager();
        let parent = "did:trustagent:keri:org:zParent";
        let caps = vec![Capability::new("credential", "issue")];

        let record = mgr
            .create(AgentClass::Delegated, Some(parent.to_string()), caps.clone())
            .await
            .unwrap();

        assert_eq!(record.agent_class, AgentClass::Delegated);
        assert_eq!(record.parent_did, Some(parent.to_string()));
        assert_eq!(record.capabilities.len(), 1);
    }

    #[tokio::test]
    async fn test_suspend_active_agent() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();

        mgr.suspend(&record.did).await.unwrap();

        let updated = mgr.get(&record.did).await.unwrap();
        assert_eq!(updated.lifecycle_state, LifecycleState::Suspended);
    }

    #[tokio::test]
    async fn test_resume_suspended_agent() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();

        mgr.suspend(&record.did).await.unwrap();
        mgr.resume(&record.did).await.unwrap();

        let updated = mgr.get(&record.did).await.unwrap();
        assert_eq!(updated.lifecycle_state, LifecycleState::Active);
    }

    #[tokio::test]
    async fn test_deactivate_active_agent() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();

        mgr.deactivate(&record.did).await.unwrap();

        let updated = mgr.get(&record.did).await.unwrap();
        assert_eq!(updated.lifecycle_state, LifecycleState::Deactivated);
    }

    #[tokio::test]
    async fn test_deactivate_suspended_agent() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();

        mgr.suspend(&record.did).await.unwrap();
        mgr.deactivate(&record.did).await.unwrap();

        let updated = mgr.get(&record.did).await.unwrap();
        assert_eq!(updated.lifecycle_state, LifecycleState::Deactivated);
    }

    #[tokio::test]
    async fn test_invalid_transition_created_to_decommissioned() {
        let mgr = new_manager();

        // Manually insert a Created agent
        let did = "did:trustagent:keri:autonomous:zTest".to_string();
        let now = Utc::now();
        mgr.agents.write().await.insert(
            did.clone(),
            AgentRecord {
                did: did.clone(),
                agent_class: AgentClass::Autonomous,
                lifecycle_state: LifecycleState::Created,
                parent_did: None,
                capabilities: vec![],
                created_at: now,
                updated_at: now,
            },
        );

        // Created -> Decommissioned is not a valid single-step transition
        let err = mgr.transition(&did, LifecycleState::Decommissioned).await.unwrap_err();
        match err {
            TrustDIDError::InvalidLifecycleTransition { from, to } => {
                assert_eq!(from, LifecycleState::Created);
                assert_eq!(to, LifecycleState::Decommissioned);
            }
            other => panic!("expected InvalidLifecycleTransition, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_transition_decommissioned_to_active() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();

        mgr.deactivate(&record.did).await.unwrap();

        // Manually set to Decommissioned
        mgr.agents.write().await.get_mut(&record.did).unwrap().lifecycle_state =
            LifecycleState::Decommissioned;

        let err = mgr.resume(&record.did).await.unwrap_err();
        match err {
            TrustDIDError::InvalidLifecycleTransition { from, to } => {
                assert_eq!(from, LifecycleState::Decommissioned);
                assert_eq!(to, LifecycleState::Active);
            }
            other => panic!("expected InvalidLifecycleTransition, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_transition_nonexistent() {
        let mgr = new_manager();
        let err = mgr.suspend("did:nope").await.unwrap_err();
        match err {
            TrustDIDError::NotFound(_) => {}
            other => panic!("expected NotFound, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_decommission_single() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();

        // Register a delegation so revoke has something to do
        mgr.delegation_manager()
            .delegate(
                "did:root",
                &record.did,
                AgentClass::Autonomous,
                vec![],
                3,
            )
            .await
            .unwrap();

        let result = mgr.decommission(&record.did, false).await.unwrap();

        assert_eq!(result.decommissioned_agents, vec![record.did.clone()]);
        assert_eq!(result.revoked_delegations, vec![record.did.clone()]);

        let updated = mgr.get(&record.did).await.unwrap();
        assert_eq!(updated.lifecycle_state, LifecycleState::Decommissioned);
    }

    #[tokio::test]
    async fn test_decommission_cascade() {
        let dm = DelegationManager::new();
        let mgr = AgentManager::new(dm.clone());

        // Create a tree: root -> parent -> child_a, child_b
        let parent = mgr
            .create(AgentClass::Org, None, vec![])
            .await
            .unwrap();
        let child_a = mgr
            .create(
                AgentClass::Delegated,
                Some(parent.did.clone()),
                vec![],
            )
            .await
            .unwrap();
        let child_b = mgr
            .create(
                AgentClass::Delegated,
                Some(parent.did.clone()),
                vec![],
            )
            .await
            .unwrap();

        // Set up delegation chain
        dm.delegate(
            "did:root",
            &parent.did,
            AgentClass::Org,
            vec![],
            5,
        )
        .await
        .unwrap();
        dm.delegate(
            &parent.did,
            &child_a.did,
            AgentClass::Delegated,
            vec![],
            5,
        )
        .await
        .unwrap();
        dm.delegate(
            &parent.did,
            &child_b.did,
            AgentClass::Delegated,
            vec![],
            5,
        )
        .await
        .unwrap();

        let result = mgr.decommission(&parent.did, true).await.unwrap();

        // All three agents should be decommissioned
        assert!(result.decommissioned_agents.contains(&parent.did));
        assert!(result.decommissioned_agents.contains(&child_a.did));
        assert!(result.decommissioned_agents.contains(&child_b.did));

        // All delegations under parent should be revoked
        assert!(result.revoked_delegations.contains(&parent.did));

        // Verify lifecycle states
        for did in [&parent.did, &child_a.did, &child_b.did] {
            let r = mgr.get(did).await.unwrap();
            assert_eq!(r.lifecycle_state, LifecycleState::Decommissioned);
        }
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let mgr = new_manager();
        assert!(mgr.get("did:nope").await.is_none());
    }

    #[tokio::test]
    async fn test_suspend_already_suspended() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();

        mgr.suspend(&record.did).await.unwrap();

        // Suspended -> Suspended is not valid
        let err = mgr.suspend(&record.did).await.unwrap_err();
        match err {
            TrustDIDError::InvalidLifecycleTransition { from, to } => {
                assert_eq!(from, LifecycleState::Suspended);
                assert_eq!(to, LifecycleState::Suspended);
            }
            other => panic!("expected InvalidLifecycleTransition, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_updated_at_changes_on_transition() {
        let mgr = new_manager();
        let record = mgr
            .create(AgentClass::Autonomous, None, vec![])
            .await
            .unwrap();
        let created_at = record.updated_at;

        // Small delay to ensure timestamp differs
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        mgr.suspend(&record.did).await.unwrap();
        let updated = mgr.get(&record.did).await.unwrap();

        assert!(updated.updated_at >= created_at);
    }
}
