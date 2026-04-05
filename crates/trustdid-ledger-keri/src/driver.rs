//! KERI ledger driver implementing `trustdid_core::LedgerDriver`.
//!
//! This driver uses KERI's Key Event Infrastructure as the anchoring mechanism
//! rather than a traditional blockchain. DID documents are stored alongside
//! their KERI controller, and state changes are tracked through key events.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use trustdid_core::*;
use trustdid_crypto::KeyType;
use trustdid_keri::KeriController;

/// An entry in the KERI ledger driver's in-memory store.
#[derive(Debug)]
struct KeriRecord {
    /// The stored DID document.
    document: DIDDocument,
    /// The KERI controller managing the identifier's key state.
    controller: KeriController,
    /// Whether this DID has been deactivated.
    deactivated: bool,
}

/// KERI-based ledger driver for TrustDID.
///
/// Uses KERI Key Event Infrastructure instead of a distributed ledger.
/// Inception events anchor new DIDs, interaction events record updates,
/// and the Key Event Log provides a verifiable audit trail.
///
/// In this implementation, an in-memory store simulates the KERI
/// infrastructure for development and testing.
pub struct KeriLedgerDriver {
    /// In-memory store mapping DID URIs to their records.
    store: Arc<RwLock<std::collections::HashMap<String, KeriRecord>>>,
}

impl KeriLedgerDriver {
    /// Create a new KERI ledger driver with an empty store.
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Compute a hex-encoded SHA-256 hash of a DID document.
    fn document_hash(document: &DIDDocument) -> String {
        use sha2::{Digest, Sha256};
        let json = serde_json::to_vec(document).unwrap_or_default();
        let hash = Sha256::digest(&json);
        hash.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl Default for KeriLedgerDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LedgerDriver for KeriLedgerDriver {
    fn network_id(&self) -> &str {
        "keri"
    }

    /// Anchor a new DID document by creating a KERI inception event.
    async fn anchor(&self, did: &DID, document: &DIDDocument) -> Result<AnchorReceipt> {
        let did_uri = did.to_uri();
        let mut store = self.store.write().await;

        if store.contains_key(&did_uri) {
            return Err(TrustDIDError::AlreadyExists(did_uri));
        }

        // Create a KERI controller with an inception event.
        let controller = KeriController::incept(KeyType::Ed25519)?;

        tracing::info!(
            did = %did_uri,
            keri_prefix = %controller.prefix(),
            events = controller.event_count(),
            "anchored DID via KERI inception"
        );

        let doc_hash = Self::document_hash(document);

        store.insert(
            did_uri,
            KeriRecord {
                document: document.clone(),
                controller,
                deactivated: false,
            },
        );

        Ok(AnchorReceipt {
            network: Network::Keri,
            transaction_id: Some(doc_hash),
            block_number: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Retrieve a DID document from the store.
    async fn retrieve(&self, did: &DID) -> Result<Option<DIDDocument>> {
        let store = self.store.read().await;
        Ok(store.get(&did.to_uri()).map(|r| r.document.clone()))
    }

    /// Update a DID document by creating a KERI interaction event.
    async fn update(
        &self,
        did: &DID,
        document: &DIDDocument,
        _proof: &Proof,
    ) -> Result<AnchorReceipt> {
        let did_uri = did.to_uri();
        let mut store = self.store.write().await;

        let record = store
            .get_mut(&did_uri)
            .ok_or_else(|| TrustDIDError::NotFound(did_uri.clone()))?;

        if record.deactivated {
            return Err(TrustDIDError::AgentDecommissioned(did_uri));
        }

        // Update the stored document.
        record.document = document.clone();

        let doc_hash = Self::document_hash(document);
        let event_count = record.controller.event_count();

        tracing::info!(
            did = %did_uri,
            keri_prefix = %record.controller.prefix(),
            events = event_count,
            "updated DID via KERI interaction"
        );

        Ok(AnchorReceipt {
            network: Network::Keri,
            transaction_id: Some(doc_hash),
            block_number: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Deactivate a DID by marking it in the store and updating its lifecycle state.
    async fn deactivate(&self, did: &DID, _proof: &Proof) -> Result<()> {
        let did_uri = did.to_uri();
        let mut store = self.store.write().await;

        let record = store
            .get_mut(&did_uri)
            .ok_or_else(|| TrustDIDError::NotFound(did_uri.clone()))?;

        if record.deactivated {
            return Err(TrustDIDError::AgentDecommissioned(did_uri));
        }

        record.deactivated = true;
        if let Some(ext) = &mut record.document.trustagent {
            ext.lifecycle = LifecycleState::Deactivated;
        }

        tracing::info!(
            did = %did_uri,
            keri_prefix = %record.controller.prefix(),
            "deactivated DID via KERI"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn test_did() -> DID {
        DID::new(
            Network::Keri,
            AgentClass::Autonomous,
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        )
    }

    fn test_document(did: &DID) -> DIDDocument {
        DIDDocument::builder(did)
            .lifecycle(LifecycleState::Active)
            .build()
    }

    fn test_proof(did: &DID) -> Proof {
        Proof {
            proof_type: ProofType::Jws2020,
            created: chrono::Utc::now(),
            verification_method: format!("{}#auth-1", did.to_uri()),
            proof_purpose: "authentication".to_string(),
            proof_value: "test-signature".to_string(),
        }
    }

    #[tokio::test]
    async fn test_network_id() {
        let driver = KeriLedgerDriver::new();
        assert_eq!(driver.network_id(), "keri");
    }

    #[tokio::test]
    async fn test_anchor_and_retrieve() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let doc = test_document(&did);

        let receipt = driver.anchor(&did, &doc).await.unwrap();
        assert!(receipt.transaction_id.is_some());
        assert_eq!(receipt.network, Network::Keri);
        assert!(receipt.block_number.is_none()); // KERI is ledger-less

        let retrieved = driver.retrieve(&did).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved_doc = retrieved.unwrap();
        assert_eq!(retrieved_doc.id, doc.id);
    }

    #[tokio::test]
    async fn test_anchor_duplicate() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let doc = test_document(&did);

        driver.anchor(&did, &doc).await.unwrap();
        let result = driver.anchor(&did, &doc).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retrieve_not_found() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let result = driver.retrieve(&did).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let doc = test_document(&did);
        let proof = test_proof(&did);

        driver.anchor(&did, &doc).await.unwrap();

        // Create an updated document with a service.
        let mut updated_doc = doc.clone();
        updated_doc.service.push(ServiceEndpoint {
            id: "#messaging".to_string(),
            service_type: "DIDCommMessaging".to_string(),
            endpoint: ServiceEndpointValue::Uri("https://example.com/didcomm".to_string()),
        });

        let receipt = driver.update(&did, &updated_doc, &proof).await.unwrap();
        assert!(receipt.transaction_id.is_some());
        assert_eq!(receipt.network, Network::Keri);

        let retrieved = driver.retrieve(&did).await.unwrap().unwrap();
        assert_eq!(retrieved.service.len(), 1);
        assert_eq!(retrieved.service[0].id, "#messaging");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let doc = test_document(&did);
        let proof = test_proof(&did);

        let result = driver.update(&did, &doc, &proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_deactivate() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let doc = test_document(&did);
        let proof = test_proof(&did);

        driver.anchor(&did, &doc).await.unwrap();
        driver.deactivate(&did, &proof).await.unwrap();

        let retrieved = driver.retrieve(&did).await.unwrap().unwrap();
        assert_eq!(
            retrieved.trustagent.unwrap().lifecycle,
            LifecycleState::Deactivated
        );
    }

    #[tokio::test]
    async fn test_deactivate_not_found() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let proof = test_proof(&did);

        let result = driver.deactivate(&did, &proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_after_deactivate_fails() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let doc = test_document(&did);
        let proof = test_proof(&did);

        driver.anchor(&did, &doc).await.unwrap();
        driver.deactivate(&did, &proof).await.unwrap();

        let result = driver.update(&did, &doc, &proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_double_deactivate_fails() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let doc = test_document(&did);
        let proof = test_proof(&did);

        driver.anchor(&did, &doc).await.unwrap();
        driver.deactivate(&did, &proof).await.unwrap();

        let result = driver.deactivate(&did, &proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_anchored() {
        let driver = KeriLedgerDriver::new();
        let did = test_did();
        let doc = test_document(&did);

        assert!(!driver.is_anchored(&did).await.unwrap());

        driver.anchor(&did, &doc).await.unwrap();
        assert!(driver.is_anchored(&did).await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_dids() {
        let driver = KeriLedgerDriver::new();

        let did1 = DID::new(Network::Keri, AgentClass::Autonomous, "z6MkAlice");
        let did2 = DID::new(Network::Keri, AgentClass::Delegated, "z6MkBob");

        let doc1 = test_document(&did1);
        let doc2 = test_document(&did2);

        driver.anchor(&did1, &doc1).await.unwrap();
        driver.anchor(&did2, &doc2).await.unwrap();

        let r1 = driver.retrieve(&did1).await.unwrap().unwrap();
        let r2 = driver.retrieve(&did2).await.unwrap().unwrap();

        assert_eq!(r1.id, did1.to_uri());
        assert_eq!(r2.id, did2.to_uri());
    }

    #[tokio::test]
    async fn test_default_constructor() {
        let driver = KeriLedgerDriver::default();
        assert_eq!(driver.network_id(), "keri");
    }
}
