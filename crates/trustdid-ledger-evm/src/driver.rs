use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use trustdid_core::*;

/// EVM-based ledger driver for TrustDID.
///
/// Interacts with the TrustDIDRegistry smart contract on EVM chains.
/// In development mode, uses an in-memory store for testing.
pub struct EvmLedgerDriver {
    chain_id: u64,
    rpc_url: Option<String>,
    // In-memory store for development/testing
    store: Arc<RwLock<std::collections::HashMap<String, StoredRecord>>>,
}

#[derive(Debug, Clone)]
struct StoredRecord {
    document: DIDDocument,
    document_hash: Vec<u8>,
    block_number: u64,
    nonce: u64,
}

impl EvmLedgerDriver {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            rpc_url: None,
            store: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub fn with_rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = Some(rpc_url.into());
        self
    }

    fn compute_document_hash(document: &DIDDocument) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let json = serde_json::to_vec(document).unwrap_or_default();
        Sha256::digest(&json).to_vec()
    }
}

#[async_trait]
impl LedgerDriver for EvmLedgerDriver {
    fn network_id(&self) -> &str {
        // We leak a string here for the static lifetime, but in production
        // this would be a pre-computed constant
        Box::leak(format!("evm:{}", self.chain_id).into_boxed_str())
    }

    async fn anchor(&self, did: &DID, document: &DIDDocument) -> Result<AnchorReceipt> {
        let did_uri = did.to_uri();
        let mut store = self.store.write().await;

        if store.contains_key(&did_uri) {
            return Err(TrustDIDError::AlreadyExists(did_uri));
        }

        let doc_hash = Self::compute_document_hash(document);
        let block_number = store.len() as u64 + 1;

        store.insert(
            did_uri.clone(),
            StoredRecord {
                document: document.clone(),
                document_hash: doc_hash.clone(),
                block_number,
                nonce: 0,
            },
        );

        tracing::info!(
            did = %did_uri,
            chain_id = self.chain_id,
            block = block_number,
            "anchored DID on EVM"
        );

        Ok(AnchorReceipt {
            network: Network::Evm(self.chain_id),
            transaction_id: Some(format!("0x{}", hex_encode(&doc_hash[..16]))),
            block_number: Some(block_number),
            timestamp: chrono::Utc::now(),
        })
    }

    async fn retrieve(&self, did: &DID) -> Result<Option<DIDDocument>> {
        let store = self.store.read().await;
        Ok(store.get(&did.to_uri()).map(|r| r.document.clone()))
    }

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

        record.document = document.clone();
        record.document_hash = Self::compute_document_hash(document);
        record.nonce += 1;
        record.block_number += 1;

        let block_number = record.block_number;
        let tx_hash = format!("0x{}", hex_encode(&record.document_hash[..16]));

        tracing::info!(
            did = %did_uri,
            chain_id = self.chain_id,
            block = block_number,
            "updated DID on EVM"
        );

        Ok(AnchorReceipt {
            network: Network::Evm(self.chain_id),
            transaction_id: Some(tx_hash),
            block_number: Some(block_number),
            timestamp: chrono::Utc::now(),
        })
    }

    async fn deactivate(&self, did: &DID, _proof: &Proof) -> Result<()> {
        let did_uri = did.to_uri();
        let mut store = self.store.write().await;

        if let Some(record) = store.get_mut(&did_uri) {
            if let Some(ext) = &mut record.document.trustagent {
                ext.lifecycle = LifecycleState::Deactivated;
            }
            tracing::info!(did = %did_uri, "deactivated DID on EVM");
            Ok(())
        } else {
            Err(TrustDIDError::NotFound(did_uri))
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anchor_and_retrieve() {
        let driver = EvmLedgerDriver::new(137);
        let did = DID::new(Network::Evm(137), AgentClass::Autonomous, "z6MkTest");
        let doc = DIDDocument::builder(&did)
            .lifecycle(LifecycleState::Active)
            .build();

        let receipt = driver.anchor(&did, &doc).await.unwrap();
        assert!(receipt.transaction_id.is_some());
        assert_eq!(receipt.block_number, Some(1));

        let retrieved = driver.retrieve(&did).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, doc.id);
    }

    #[tokio::test]
    async fn test_anchor_duplicate() {
        let driver = EvmLedgerDriver::new(137);
        let did = DID::new(Network::Evm(137), AgentClass::Autonomous, "z6MkTest");
        let doc = DIDDocument::builder(&did)
            .lifecycle(LifecycleState::Active)
            .build();

        driver.anchor(&did, &doc).await.unwrap();
        let result = driver.anchor(&did, &doc).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update() {
        let driver = EvmLedgerDriver::new(137);
        let did = DID::new(Network::Evm(137), AgentClass::Autonomous, "z6MkTest");
        let doc = DIDDocument::builder(&did)
            .lifecycle(LifecycleState::Active)
            .build();

        driver.anchor(&did, &doc).await.unwrap();

        let mut updated_doc = doc.clone();
        updated_doc.service.push(ServiceEndpoint {
            id: "#new-service".into(),
            service_type: "TestService".into(),
            endpoint: ServiceEndpointValue::Uri("https://example.com".into()),
        });

        let proof = Proof {
            proof_type: ProofType::Jws2020,
            created: chrono::Utc::now(),
            verification_method: format!("{}#auth-1", did.to_uri()),
            proof_purpose: "authentication".into(),
            proof_value: "test-signature".into(),
        };

        let receipt = driver.update(&did, &updated_doc, &proof).await.unwrap();
        assert_eq!(receipt.block_number, Some(2));

        let retrieved = driver.retrieve(&did).await.unwrap().unwrap();
        assert_eq!(retrieved.service.len(), 1);
    }

    #[tokio::test]
    async fn test_deactivate() {
        let driver = EvmLedgerDriver::new(137);
        let did = DID::new(Network::Evm(137), AgentClass::Autonomous, "z6MkTest");
        let doc = DIDDocument::builder(&did)
            .lifecycle(LifecycleState::Active)
            .build();

        let proof = Proof {
            proof_type: ProofType::Jws2020,
            created: chrono::Utc::now(),
            verification_method: format!("{}#auth-1", did.to_uri()),
            proof_purpose: "authentication".into(),
            proof_value: "test-signature".into(),
        };

        driver.anchor(&did, &doc).await.unwrap();
        driver.deactivate(&did, &proof).await.unwrap();

        let retrieved = driver.retrieve(&did).await.unwrap().unwrap();
        assert_eq!(
            retrieved.trustagent.unwrap().lifecycle,
            LifecycleState::Deactivated
        );
    }

    #[tokio::test]
    async fn test_retrieve_not_found() {
        let driver = EvmLedgerDriver::new(137);
        let did = DID::new(Network::Evm(137), AgentClass::Autonomous, "z6MkNone");
        let result = driver.retrieve(&did).await.unwrap();
        assert!(result.is_none());
    }
}
