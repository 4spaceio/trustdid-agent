//! Credential status management using Bitstring Status List.
//!
//! Implements W3C Bitstring Status List v1.0 for efficient revocation checking.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory credential status list.
pub struct StatusList {
    list_id: String,
    purpose: StatusPurpose,
    revoked: Arc<RwLock<HashSet<usize>>>,
    size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusPurpose {
    Revocation,
    Suspension,
}

impl StatusPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Revocation => "revocation",
            Self::Suspension => "suspension",
        }
    }
}

impl StatusList {
    pub fn new(list_id: impl Into<String>, purpose: StatusPurpose, size: usize) -> Self {
        Self {
            list_id: list_id.into(),
            purpose,
            revoked: Arc::new(RwLock::new(HashSet::new())),
            size,
        }
    }

    pub fn id(&self) -> &str {
        &self.list_id
    }

    pub fn purpose(&self) -> StatusPurpose {
        self.purpose
    }

    pub async fn set(&self, index: usize) -> bool {
        if index >= self.size {
            return false;
        }
        let mut set = self.revoked.write().await;
        set.insert(index)
    }

    pub async fn unset(&self, index: usize) -> bool {
        let mut set = self.revoked.write().await;
        set.remove(&index)
    }

    pub async fn is_set(&self, index: usize) -> bool {
        let set = self.revoked.read().await;
        set.contains(&index)
    }

    pub async fn count(&self) -> usize {
        let set = self.revoked.read().await;
        set.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_status_list() {
        let list = StatusList::new("urn:status:1", StatusPurpose::Revocation, 1000);

        assert!(!list.is_set(42).await);
        list.set(42).await;
        assert!(list.is_set(42).await);
        assert_eq!(list.count().await, 1);

        list.unset(42).await;
        assert!(!list.is_set(42).await);
        assert_eq!(list.count().await, 0);
    }

    #[tokio::test]
    async fn test_out_of_bounds() {
        let list = StatusList::new("urn:status:1", StatusPurpose::Revocation, 10);
        assert!(!list.set(100).await);
    }
}
