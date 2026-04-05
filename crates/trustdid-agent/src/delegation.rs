//! Delegation engine for TrustDID agents.
//!
//! Manages delegation chains between agents, enforcing capability attenuation,
//! depth limits, and cascading revocation.

use crate::capability::CapabilityEngine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use trustdid_core::{AgentClass, Capability, Result, TrustDIDError};

/// A single link in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub parent_did: String,
    pub child_did: String,
    pub child_class: AgentClass,
    pub capabilities: Vec<Capability>,
    pub depth: u8,
    pub max_depth: u8,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

/// A verified delegation chain from a child back to its root.
#[derive(Debug, Clone)]
pub struct DelegationChain {
    /// Links ordered from the queried child up to the root.
    pub links: Vec<DelegationRecord>,
    /// The root DID (has no parent delegation).
    pub root_did: String,
    /// Total depth of the chain.
    pub depth: u8,
}

/// Manages the delegation graph between agents.
///
/// Uses an in-memory store keyed by child DID. Each entry records who delegated
/// to that child and with what capabilities.
#[derive(Clone)]
pub struct DelegationManager {
    /// Map from child DID -> DelegationRecord
    records: Arc<RwLock<HashMap<String, DelegationRecord>>>,
}

impl DelegationManager {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a delegation from `parent_did` to `child_did`.
    ///
    /// Validates:
    /// - The parent exists and is not revoked (unless it is the root).
    /// - The depth does not exceed `max_depth`.
    /// - The requested capabilities are a subset of the parent's capabilities
    ///   (capability attenuation).
    pub async fn delegate(
        &self,
        parent_did: &str,
        child_did: &str,
        child_class: AgentClass,
        capabilities: Vec<Capability>,
        max_depth: u8,
    ) -> Result<DelegationRecord> {
        let store = self.records.read().await;

        // Determine parent's depth and capabilities
        let (parent_depth, parent_caps) = match store.get(parent_did) {
            Some(parent_record) => {
                if parent_record.revoked {
                    return Err(TrustDIDError::InvalidDelegation(format!(
                        "parent delegation for '{parent_did}' has been revoked"
                    )));
                }
                (parent_record.depth, parent_record.capabilities.clone())
            }
            None => {
                // Parent is a root agent (no delegation record) -- depth 0, no cap restriction
                (0, Vec::new())
            }
        };

        // Check if child already has a delegation
        if store.contains_key(child_did) {
            return Err(TrustDIDError::AlreadyExists(format!(
                "delegation already exists for '{child_did}'"
            )));
        }

        let new_depth = parent_depth + 1;
        if new_depth > max_depth {
            return Err(TrustDIDError::DelegationDepthExceeded {
                max: max_depth,
                requested: new_depth,
            });
        }

        // Capability attenuation: child caps must be subset of parent's caps
        // (skip if parent is root with no explicit caps)
        if !parent_caps.is_empty() && !CapabilityEngine::is_subset(&capabilities, &parent_caps) {
            return Err(TrustDIDError::CapabilityNotGranted(
                "requested capabilities exceed parent's capabilities".to_string(),
            ));
        }

        drop(store);

        let record = DelegationRecord {
            parent_did: parent_did.to_string(),
            child_did: child_did.to_string(),
            child_class,
            capabilities,
            depth: new_depth,
            max_depth,
            created_at: Utc::now(),
            revoked: false,
        };

        debug!(
            parent = parent_did,
            child = child_did,
            depth = new_depth,
            "created delegation"
        );

        self.records
            .write()
            .await
            .insert(child_did.to_string(), record.clone());

        Ok(record)
    }

    /// Walk the delegation chain from `did` back to its root.
    ///
    /// Returns an error if any link in the chain is revoked.
    pub async fn verify_chain(&self, did: &str) -> Result<DelegationChain> {
        let store = self.records.read().await;
        let mut links = Vec::new();
        let mut current = did.to_string();

        loop {
            match store.get(&current) {
                Some(record) => {
                    if record.revoked {
                        return Err(TrustDIDError::InvalidDelegation(format!(
                            "delegation for '{}' has been revoked",
                            record.child_did
                        )));
                    }
                    links.push(record.clone());
                    current = record.parent_did.clone();
                }
                None => {
                    // Reached the root
                    break;
                }
            }
        }

        let depth = links.len() as u8;
        let root_did = if links.is_empty() {
            did.to_string()
        } else {
            links.last().unwrap().parent_did.clone()
        };

        Ok(DelegationChain {
            links,
            root_did,
            depth,
        })
    }

    /// Revoke a delegation. If `cascade` is true, also revoke all transitive
    /// children.
    ///
    /// Returns the list of DIDs whose delegations were revoked.
    pub async fn revoke(&self, did: &str, cascade: bool) -> Result<Vec<String>> {
        let mut store = self.records.write().await;
        let mut revoked = Vec::new();

        // Revoke the target
        if let Some(record) = store.get_mut(did) {
            if record.revoked {
                return Err(TrustDIDError::InvalidDelegation(format!(
                    "delegation for '{did}' is already revoked"
                )));
            }
            record.revoked = true;
            revoked.push(did.to_string());
            debug!(did = did, "revoked delegation");
        } else {
            return Err(TrustDIDError::NotFound(format!(
                "no delegation found for '{did}'"
            )));
        }

        if cascade {
            // Collect all transitive children via BFS
            let mut queue = vec![did.to_string()];
            while let Some(parent) = queue.pop() {
                let children: Vec<String> = store
                    .iter()
                    .filter(|(_, r)| r.parent_did == parent && !r.revoked)
                    .map(|(k, _)| k.clone())
                    .collect();

                for child in children {
                    if let Some(record) = store.get_mut(&child) {
                        record.revoked = true;
                        revoked.push(child.clone());
                        queue.push(child);
                        warn!(did = record.child_did.as_str(), "cascade-revoked delegation");
                    }
                }
            }
        }

        Ok(revoked)
    }

    /// Get the parent DID for a given delegated DID.
    pub async fn get_parent(&self, did: &str) -> Option<String> {
        self.records
            .read()
            .await
            .get(did)
            .map(|r| r.parent_did.clone())
    }

    /// Get all direct children of a DID.
    pub async fn get_children(&self, did: &str) -> Vec<String> {
        self.records
            .read()
            .await
            .iter()
            .filter(|(_, r)| r.parent_did == did && !r.revoked)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Get the delegation record for a DID, if one exists.
    pub async fn get(&self, did: &str) -> Option<DelegationRecord> {
        self.records.read().await.get(did).cloned()
    }
}

impl Default for DelegationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use trustdid_core::Constraint;

    fn cap(resource: &str, action: &str) -> Capability {
        Capability::new(resource, action)
    }

    fn cap_with(resource: &str, action: &str, key: &str, value: &str) -> Capability {
        Capability::new(resource, action).with_constraint(Constraint::new(key, value))
    }

    #[tokio::test]
    async fn test_basic_delegation() {
        let mgr = DelegationManager::new();

        let record = mgr
            .delegate(
                "did:trustagent:keri:org:root",
                "did:trustagent:keri:delegated:child1",
                AgentClass::Delegated,
                vec![cap("credential", "issue")],
                3,
            )
            .await
            .unwrap();

        assert_eq!(record.parent_did, "did:trustagent:keri:org:root");
        assert_eq!(record.child_did, "did:trustagent:keri:delegated:child1");
        assert_eq!(record.depth, 1);
        assert_eq!(record.max_depth, 3);
        assert!(!record.revoked);
    }

    #[tokio::test]
    async fn test_multi_level_delegation() {
        let mgr = DelegationManager::new();

        // Root -> Level 1
        mgr.delegate(
            "did:root",
            "did:level1",
            AgentClass::Delegated,
            vec![cap("credential", "issue"), cap("payment", "authorize")],
            3,
        )
        .await
        .unwrap();

        // Level 1 -> Level 2 (attenuated capabilities)
        let record = mgr
            .delegate(
                "did:level1",
                "did:level2",
                AgentClass::Delegated,
                vec![cap("credential", "issue")],
                3,
            )
            .await
            .unwrap();

        assert_eq!(record.depth, 2);
    }

    #[tokio::test]
    async fn test_depth_exceeded() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:l1", AgentClass::Delegated, vec![], 1)
            .await
            .unwrap();

        let err = mgr
            .delegate("did:l1", "did:l2", AgentClass::Delegated, vec![], 1)
            .await
            .unwrap_err();

        match err {
            TrustDIDError::DelegationDepthExceeded { max, requested } => {
                assert_eq!(max, 1);
                assert_eq!(requested, 2);
            }
            other => panic!("expected DelegationDepthExceeded, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_capability_attenuation_enforced() {
        let mgr = DelegationManager::new();

        // Root delegates with limited capabilities
        mgr.delegate(
            "did:root",
            "did:parent",
            AgentClass::Delegated,
            vec![cap("credential", "issue")],
            3,
        )
        .await
        .unwrap();

        // Try to delegate a capability the parent doesn't have
        let err = mgr
            .delegate(
                "did:parent",
                "did:child",
                AgentClass::Delegated,
                vec![cap("credential", "issue"), cap("payment", "authorize")],
                3,
            )
            .await
            .unwrap_err();

        match err {
            TrustDIDError::CapabilityNotGranted(_) => {}
            other => panic!("expected CapabilityNotGranted, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_capability_attenuation_with_constraints() {
        let mgr = DelegationManager::new();

        // Parent has limit=1000
        mgr.delegate(
            "did:root",
            "did:parent",
            AgentClass::Delegated,
            vec![cap_with("payment", "authorize", "limit", "1000")],
            3,
        )
        .await
        .unwrap();

        // Child tries limit=500 (stricter, should succeed)
        mgr.delegate(
            "did:parent",
            "did:child-ok",
            AgentClass::Delegated,
            vec![cap_with("payment", "authorize", "limit", "500")],
            3,
        )
        .await
        .unwrap();

        // Child tries limit=2000 (looser, should fail)
        let err = mgr
            .delegate(
                "did:parent",
                "did:child-bad",
                AgentClass::Delegated,
                vec![cap_with("payment", "authorize", "limit", "2000")],
                3,
            )
            .await
            .unwrap_err();

        match err {
            TrustDIDError::CapabilityNotGranted(_) => {}
            other => panic!("expected CapabilityNotGranted, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_verify_chain() {
        let mgr = DelegationManager::new();

        mgr.delegate(
            "did:root",
            "did:l1",
            AgentClass::Delegated,
            vec![cap("credential", "issue")],
            3,
        )
        .await
        .unwrap();

        mgr.delegate(
            "did:l1",
            "did:l2",
            AgentClass::Delegated,
            vec![cap("credential", "issue")],
            3,
        )
        .await
        .unwrap();

        let chain = mgr.verify_chain("did:l2").await.unwrap();
        assert_eq!(chain.depth, 2);
        assert_eq!(chain.root_did, "did:root");
        assert_eq!(chain.links.len(), 2);
        assert_eq!(chain.links[0].child_did, "did:l2");
        assert_eq!(chain.links[1].child_did, "did:l1");
    }

    #[tokio::test]
    async fn test_verify_chain_root() {
        let mgr = DelegationManager::new();

        let chain = mgr.verify_chain("did:root").await.unwrap();
        assert_eq!(chain.depth, 0);
        assert_eq!(chain.root_did, "did:root");
        assert!(chain.links.is_empty());
    }

    #[tokio::test]
    async fn test_verify_chain_revoked_fails() {
        let mgr = DelegationManager::new();

        mgr.delegate(
            "did:root",
            "did:child",
            AgentClass::Delegated,
            vec![],
            3,
        )
        .await
        .unwrap();

        mgr.revoke("did:child", false).await.unwrap();

        let err = mgr.verify_chain("did:child").await.unwrap_err();
        match err {
            TrustDIDError::InvalidDelegation(_) => {}
            other => panic!("expected InvalidDelegation, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_revoke_single() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:child", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();

        let revoked = mgr.revoke("did:child", false).await.unwrap();
        assert_eq!(revoked, vec!["did:child"]);

        let record = mgr.get("did:child").await.unwrap();
        assert!(record.revoked);
    }

    #[tokio::test]
    async fn test_revoke_cascade() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:l1", AgentClass::Delegated, vec![], 5)
            .await
            .unwrap();
        mgr.delegate("did:l1", "did:l2a", AgentClass::Delegated, vec![], 5)
            .await
            .unwrap();
        mgr.delegate("did:l1", "did:l2b", AgentClass::Delegated, vec![], 5)
            .await
            .unwrap();
        mgr.delegate("did:l2a", "did:l3", AgentClass::Delegated, vec![], 5)
            .await
            .unwrap();

        let revoked = mgr.revoke("did:l1", true).await.unwrap();
        assert!(revoked.contains(&"did:l1".to_string()));
        assert!(revoked.contains(&"did:l2a".to_string()));
        assert!(revoked.contains(&"did:l2b".to_string()));
        assert!(revoked.contains(&"did:l3".to_string()));
        assert_eq!(revoked.len(), 4);
    }

    #[tokio::test]
    async fn test_revoke_nonexistent() {
        let mgr = DelegationManager::new();
        let err = mgr.revoke("did:nope", false).await.unwrap_err();
        match err {
            TrustDIDError::NotFound(_) => {}
            other => panic!("expected NotFound, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_revoke_already_revoked() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:child", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();
        mgr.revoke("did:child", false).await.unwrap();

        let err = mgr.revoke("did:child", false).await.unwrap_err();
        match err {
            TrustDIDError::InvalidDelegation(_) => {}
            other => panic!("expected InvalidDelegation, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_duplicate_delegation() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:child", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();

        let err = mgr
            .delegate("did:root", "did:child", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap_err();

        match err {
            TrustDIDError::AlreadyExists(_) => {}
            other => panic!("expected AlreadyExists, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_get_parent() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:child", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();

        assert_eq!(
            mgr.get_parent("did:child").await,
            Some("did:root".to_string())
        );
        assert_eq!(mgr.get_parent("did:root").await, None);
    }

    #[tokio::test]
    async fn test_get_children() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:a", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();
        mgr.delegate("did:root", "did:b", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();

        let mut children = mgr.get_children("did:root").await;
        children.sort();
        assert_eq!(children, vec!["did:a", "did:b"]);
    }

    #[tokio::test]
    async fn test_get_children_excludes_revoked() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:a", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();
        mgr.delegate("did:root", "did:b", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();

        mgr.revoke("did:a", false).await.unwrap();

        let children = mgr.get_children("did:root").await;
        assert_eq!(children, vec!["did:b"]);
    }

    #[tokio::test]
    async fn test_delegate_from_revoked_parent() {
        let mgr = DelegationManager::new();

        mgr.delegate("did:root", "did:parent", AgentClass::Delegated, vec![], 3)
            .await
            .unwrap();

        mgr.revoke("did:parent", false).await.unwrap();

        let err = mgr
            .delegate(
                "did:parent",
                "did:child",
                AgentClass::Delegated,
                vec![],
                3,
            )
            .await
            .unwrap_err();

        match err {
            TrustDIDError::InvalidDelegation(_) => {}
            other => panic!("expected InvalidDelegation, got: {other}"),
        }
    }
}
