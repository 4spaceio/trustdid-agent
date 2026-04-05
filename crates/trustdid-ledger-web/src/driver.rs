//! Web ledger driver implementing `trustdid_core::LedgerDriver`.
//!
//! This driver resolves DIDs by converting them to HTTPS URLs in a did:web-like
//! fashion. The DID format `did:trustagent:web:<domain>:<class>:<id>` maps to
//! `https://<domain>/.well-known/did.json`.
//!
//! In production, the driver would perform actual HTTPS requests. This
//! implementation uses an in-memory store for development and testing.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use trustdid_core::*;

/// An entry in the web ledger driver's in-memory store.
#[derive(Debug, Clone)]
struct WebRecord {
    /// The stored DID document.
    document: DIDDocument,
    /// The resolved URL for this DID.
    url: String,
    /// Whether this DID has been deactivated.
    deactivated: bool,
}

/// Web-based ledger driver for TrustDID.
///
/// Resolves `did:trustagent:web:*` identifiers by converting them to HTTPS URLs
/// and fetching the DID document. This implementation uses an in-memory store
/// that simulates the HTTPS resolution layer.
pub struct WebLedgerDriver {
    /// In-memory store mapping DID URIs to their records.
    store: Arc<RwLock<std::collections::HashMap<String, WebRecord>>>,
}

impl WebLedgerDriver {
    /// Create a new web ledger driver with an empty store.
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Convert a DID to its corresponding HTTPS well-known URL.
    ///
    /// The mapping follows did:web conventions:
    /// `did:trustagent:web:<domain>:<class>:<id>` -> `https://<domain>/.well-known/did.json`
    ///
    /// For DIDs with path segments after the domain, colons are converted to
    /// path separators:
    /// `did:trustagent:web:example.com:org:z6Mk...` -> `https://example.com/.well-known/did.json`
    pub fn resolve_url(did: &DID) -> Result<String> {
        match &did.network {
            Network::Web(domain) => {
                if domain.is_empty() {
                    return Err(TrustDIDError::InvalidDID(
                        "web DID has empty domain".to_string(),
                    ));
                }

                // Percent-decode the domain (colons in domain become port separators).
                let decoded_domain = domain.replace("%3A", ":");

                Ok(format!(
                    "https://{}/.well-known/did.json",
                    decoded_domain
                ))
            }
            other => Err(TrustDIDError::UnsupportedNetwork(format!(
                "WebLedgerDriver only supports web network, got '{}'",
                other
            ))),
        }
    }
}

impl Default for WebLedgerDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LedgerDriver for WebLedgerDriver {
    fn network_id(&self) -> &str {
        "web"
    }

    /// Anchor a DID document by storing it at the resolved URL.
    ///
    /// In production, this would publish the document at the HTTPS endpoint.
    async fn anchor(&self, did: &DID, document: &DIDDocument) -> Result<AnchorReceipt> {
        let did_uri = did.to_uri();
        let url = Self::resolve_url(did)?;
        let mut store = self.store.write().await;

        if store.contains_key(&did_uri) {
            return Err(TrustDIDError::AlreadyExists(did_uri));
        }

        tracing::info!(
            did = %did_uri,
            url = %url,
            "anchored DID document at web URL"
        );

        store.insert(
            did_uri,
            WebRecord {
                document: document.clone(),
                url: url.clone(),
                deactivated: false,
            },
        );

        Ok(AnchorReceipt {
            network: Network::Web(
                match &did.network {
                    Network::Web(d) => d.clone(),
                    _ => unreachable!(),
                },
            ),
            transaction_id: Some(url),
            block_number: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Retrieve a DID document from the in-memory store.
    ///
    /// In production, this would perform an HTTPS GET to the resolved URL.
    async fn retrieve(&self, did: &DID) -> Result<Option<DIDDocument>> {
        let store = self.store.read().await;
        Ok(store.get(&did.to_uri()).map(|r| r.document.clone()))
    }

    /// Update a DID document in the store.
    ///
    /// In production, this would update the document at the HTTPS endpoint.
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

        let url = record.url.clone();
        record.document = document.clone();

        tracing::info!(
            did = %did_uri,
            url = %url,
            "updated DID document at web URL"
        );

        Ok(AnchorReceipt {
            network: Network::Web(
                match &did.network {
                    Network::Web(d) => d.clone(),
                    _ => unreachable!(),
                },
            ),
            transaction_id: Some(url),
            block_number: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Deactivate a DID by marking it in the store.
    ///
    /// In production, this would remove or tombstone the document at the HTTPS endpoint.
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

        tracing::info!(did = %did_uri, "deactivated web DID");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn web_did(domain: &str) -> DID {
        DID::new(
            Network::Web(domain.to_string()),
            AgentClass::Org,
            "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2xJfmm7M8Go8J",
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

    // --- URL resolution tests ---

    #[test]
    fn test_resolve_url_simple_domain() {
        let did = web_did("example.com");
        let url = WebLedgerDriver::resolve_url(&did).unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn test_resolve_url_subdomain() {
        let did = web_did("id.example.com");
        let url = WebLedgerDriver::resolve_url(&did).unwrap();
        assert_eq!(url, "https://id.example.com/.well-known/did.json");
    }

    #[test]
    fn test_resolve_url_with_port() {
        let did = web_did("localhost%3A8080");
        let url = WebLedgerDriver::resolve_url(&did).unwrap();
        assert_eq!(url, "https://localhost:8080/.well-known/did.json");
    }

    #[test]
    fn test_resolve_url_empty_domain() {
        let did = DID::new(
            Network::Web(String::new()),
            AgentClass::Org,
            "z6MkTest",
        );
        let result = WebLedgerDriver::resolve_url(&did);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_url_wrong_network() {
        let did = DID::new(Network::Keri, AgentClass::Org, "z6MkTest");
        let result = WebLedgerDriver::resolve_url(&did);
        assert!(result.is_err());
    }

    // --- LedgerDriver trait tests ---

    #[tokio::test]
    async fn test_network_id() {
        let driver = WebLedgerDriver::new();
        assert_eq!(driver.network_id(), "web");
    }

    #[tokio::test]
    async fn test_anchor_and_retrieve() {
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
        let doc = test_document(&did);

        let receipt = driver.anchor(&did, &doc).await.unwrap();
        assert_eq!(
            receipt.transaction_id,
            Some("https://example.com/.well-known/did.json".to_string())
        );
        assert_eq!(receipt.network, Network::Web("example.com".to_string()));
        assert!(receipt.block_number.is_none());

        let retrieved = driver.retrieve(&did).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, doc.id);
    }

    #[tokio::test]
    async fn test_anchor_duplicate() {
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
        let doc = test_document(&did);

        driver.anchor(&did, &doc).await.unwrap();
        let result = driver.anchor(&did, &doc).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retrieve_not_found() {
        let driver = WebLedgerDriver::new();
        let did = web_did("nonexistent.example.com");
        let result = driver.retrieve(&did).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update() {
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
        let doc = test_document(&did);
        let proof = test_proof(&did);

        driver.anchor(&did, &doc).await.unwrap();

        let mut updated_doc = doc.clone();
        updated_doc.service.push(ServiceEndpoint {
            id: "#api".to_string(),
            service_type: "APIEndpoint".to_string(),
            endpoint: ServiceEndpointValue::Uri("https://api.example.com/v1".to_string()),
        });

        let receipt = driver.update(&did, &updated_doc, &proof).await.unwrap();
        assert_eq!(
            receipt.transaction_id,
            Some("https://example.com/.well-known/did.json".to_string())
        );

        let retrieved = driver.retrieve(&did).await.unwrap().unwrap();
        assert_eq!(retrieved.service.len(), 1);
        assert_eq!(retrieved.service[0].id, "#api");
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
        let doc = test_document(&did);
        let proof = test_proof(&did);

        let result = driver.update(&did, &doc, &proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_deactivate() {
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
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
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
        let proof = test_proof(&did);

        let result = driver.deactivate(&did, &proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_after_deactivate_fails() {
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
        let doc = test_document(&did);
        let proof = test_proof(&did);

        driver.anchor(&did, &doc).await.unwrap();
        driver.deactivate(&did, &proof).await.unwrap();

        let result = driver.update(&did, &doc, &proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_double_deactivate_fails() {
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
        let doc = test_document(&did);
        let proof = test_proof(&did);

        driver.anchor(&did, &doc).await.unwrap();
        driver.deactivate(&did, &proof).await.unwrap();

        let result = driver.deactivate(&did, &proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_anchored() {
        let driver = WebLedgerDriver::new();
        let did = web_did("example.com");
        let doc = test_document(&did);

        assert!(!driver.is_anchored(&did).await.unwrap());

        driver.anchor(&did, &doc).await.unwrap();
        assert!(driver.is_anchored(&did).await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_domains() {
        let driver = WebLedgerDriver::new();

        let did1 = web_did("alpha.example.com");
        let did2 = web_did("beta.example.com");

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
        let driver = WebLedgerDriver::default();
        assert_eq!(driver.network_id(), "web");
    }
}
