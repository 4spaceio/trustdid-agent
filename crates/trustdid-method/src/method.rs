use async_trait::async_trait;
use std::sync::Arc;
use trustdid_core::*;
use trustdid_crypto::{generate_keypair, pre_rotation_commitment, KeyType};

use crate::registry::DriverRegistry;

/// The `did:trustagent` method implementation.
///
/// This is the central orchestrator that ties together:
/// - DID parsing and building
/// - Multi-ledger driver dispatch
/// - Key generation and pre-rotation
/// - Agent lifecycle state management
pub struct TrustAgentMethod {
    drivers: Arc<DriverRegistry>,
    default_key_type: KeyType,
}

impl TrustAgentMethod {
    pub fn new(drivers: Arc<DriverRegistry>) -> Self {
        Self {
            drivers,
            default_key_type: KeyType::Ed25519,
        }
    }

    pub fn with_default_key_type(mut self, key_type: KeyType) -> Self {
        self.default_key_type = key_type;
        self
    }

    fn driver_for(&self, did: &DID) -> Result<Arc<dyn LedgerDriver>> {
        self.drivers.driver_for(&did.network)
    }

    fn build_did_document(
        &self,
        did: &DID,
        keypair: &trustdid_crypto::KeyPair,
        options: &CreateOptions,
        commitment: &str,
    ) -> DIDDocument {
        let did_uri = did.to_uri();

        let auth_method = keypair.to_verification_method(&did_uri, "auth-1");

        let mut builder = DIDDocument::builder(did)
            .add_verification_method(auth_method)
            .pre_rotation_commitment(commitment)
            .lifecycle(LifecycleState::Active)
            .capabilities(options.capabilities.clone());

        if let Some(parent) = &options.parent_did {
            builder = builder
                .controller(parent.clone())
                .parent_did(parent.clone());
        }

        for svc in &options.services {
            builder = builder.add_service(svc.clone());
        }

        builder.build()
    }
}

#[async_trait]
impl DIDMethod for TrustAgentMethod {
    fn method_name(&self) -> &str {
        "trustagent"
    }

    async fn create(&self, options: CreateOptions) -> Result<DIDDocument> {
        // Generate primary authentication keypair
        let keypair = generate_keypair(self.default_key_type)?;

        // Generate pre-rotation commitment (hash of next key)
        let next_keypair = generate_keypair(self.default_key_type)?;
        let commitment = pre_rotation_commitment(&next_keypair.public_key);

        // Build the DID identifier from the public key
        let identifier = keypair.public_key_multibase();
        let did = DID::new(options.network.clone(), options.agent_class, identifier);

        // Build the DID Document
        let document = self.build_did_document(&did, &keypair, &options, &commitment);

        // Anchor on the appropriate ledger
        let driver = self.drivers.driver_for(&options.network)?;
        driver.anchor(&did, &document).await?;

        tracing::info!(did = %did, "created agent DID");

        Ok(document)
    }

    async fn resolve(&self, did: &DID, _options: ResolveOptions) -> Result<ResolutionResult> {
        let driver = self.driver_for(did)?;

        let document = driver
            .retrieve(did)
            .await?
            .ok_or_else(|| TrustDIDError::NotFound(did.to_uri()))?;

        Ok(ResolutionResult {
            did_document: document,
            resolution_metadata: ResolutionMetadata {
                content_type: Some("application/did+ld+json".to_string()),
                error: None,
                duration: None,
            },
            document_metadata: DocumentMetadata::default(),
        })
    }

    async fn update(
        &self,
        did: &DID,
        operations: Vec<UpdateOp>,
        proof: Proof,
    ) -> Result<DIDDocument> {
        let driver = self.driver_for(did)?;

        let mut document = driver
            .retrieve(did)
            .await?
            .ok_or_else(|| TrustDIDError::NotFound(did.to_uri()))?;

        // Apply operations
        for op in operations {
            apply_update(&mut document, op)?;
        }

        driver.update(did, &document, &proof).await?;

        tracing::info!(did = %did, "updated agent DID document");

        Ok(document)
    }

    async fn deactivate(&self, did: &DID, proof: Proof) -> Result<()> {
        let driver = self.driver_for(did)?;
        driver.deactivate(did, &proof).await?;

        tracing::info!(did = %did, "deactivated agent DID");

        Ok(())
    }
}

fn apply_update(document: &mut DIDDocument, op: UpdateOp) -> Result<()> {
    match op {
        UpdateOp::AddVerificationMethod { method } => {
            document.verification_method.push(method);
        }
        UpdateOp::RemoveVerificationMethod { id } => {
            document.verification_method.retain(|m| m.id != id);
        }
        UpdateOp::AddService { service } => {
            document.service.push(service);
        }
        UpdateOp::RemoveService { id } => {
            document.service.retain(|s| s.id != id);
        }
        UpdateOp::SetController { controller } => {
            document.controller = Some(controller);
        }
        UpdateOp::UpdateCapabilities { capabilities } => {
            if let Some(ext) = &mut document.trustagent {
                ext.capabilities = capabilities;
            }
        }
        UpdateOp::SetLifecycle { state } => {
            if let Some(ext) = &mut document.trustagent {
                if !ext.lifecycle.can_transition_to(state) {
                    return Err(TrustDIDError::InvalidLifecycleTransition {
                        from: ext.lifecycle,
                        to: state,
                    });
                }
                ext.lifecycle = state;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::DriverRegistry;

    // In-memory ledger driver for testing
    struct InMemoryDriver {
        store: tokio::sync::RwLock<std::collections::HashMap<String, DIDDocument>>,
    }

    impl InMemoryDriver {
        fn new() -> Self {
            Self {
                store: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl LedgerDriver for InMemoryDriver {
        fn network_id(&self) -> &str {
            "memory"
        }

        async fn anchor(&self, did: &DID, document: &DIDDocument) -> Result<AnchorReceipt> {
            let mut store = self.store.write().await;
            store.insert(did.to_uri(), document.clone());
            Ok(AnchorReceipt {
                network: Network::Keri,
                transaction_id: Some("test-tx".into()),
                block_number: Some(1),
                timestamp: chrono::Utc::now(),
            })
        }

        async fn retrieve(&self, did: &DID) -> Result<Option<DIDDocument>> {
            let store = self.store.read().await;
            Ok(store.get(&did.to_uri()).cloned())
        }

        async fn update(&self, did: &DID, document: &DIDDocument, _proof: &Proof) -> Result<AnchorReceipt> {
            let mut store = self.store.write().await;
            store.insert(did.to_uri(), document.clone());
            Ok(AnchorReceipt {
                network: Network::Keri,
                transaction_id: Some("test-tx-update".into()),
                block_number: Some(2),
                timestamp: chrono::Utc::now(),
            })
        }

        async fn deactivate(&self, did: &DID, _proof: &Proof) -> Result<()> {
            let mut store = self.store.write().await;
            store.remove(&did.to_uri());
            Ok(())
        }
    }

    fn test_method() -> TrustAgentMethod {
        let mut registry = DriverRegistry::new();
        registry.register_keri(Arc::new(InMemoryDriver::new()));
        registry.register_evm(137, Arc::new(InMemoryDriver::new()));
        TrustAgentMethod::new(Arc::new(registry))
    }

    #[tokio::test]
    async fn test_create_keri_did() {
        let method = test_method();

        let doc = method
            .create(CreateOptions {
                network: Network::Keri,
                agent_class: AgentClass::Autonomous,
                parent_did: None,
                capabilities: vec![Capability::new("credential", "issue")],
                services: vec![],
            })
            .await
            .unwrap();

        assert!(doc.id.starts_with("did:trustagent:keri:autonomous:"));
        assert_eq!(doc.verification_method.len(), 1);
        let ext = doc.trustagent.unwrap();
        assert_eq!(ext.agent_class, AgentClass::Autonomous);
        assert_eq!(ext.lifecycle, LifecycleState::Active);
        assert!(ext.pre_rotation_commitment.is_some());
    }

    #[tokio::test]
    async fn test_create_evm_did() {
        let method = test_method();

        let doc = method
            .create(CreateOptions {
                network: Network::Evm(137),
                agent_class: AgentClass::Delegated,
                parent_did: Some("did:trustagent:evm:137:org:z6MkParent".into()),
                capabilities: vec![],
                services: vec![],
            })
            .await
            .unwrap();

        assert!(doc.id.starts_with("did:trustagent:evm:137:delegated:"));
        assert_eq!(
            doc.controller,
            Some("did:trustagent:evm:137:org:z6MkParent".to_string())
        );
    }

    #[tokio::test]
    async fn test_create_and_resolve() {
        let method = test_method();

        let doc = method
            .create(CreateOptions {
                network: Network::Keri,
                agent_class: AgentClass::Autonomous,
                parent_did: None,
                capabilities: vec![],
                services: vec![],
            })
            .await
            .unwrap();

        let did = DID::parse(&doc.id).unwrap();
        let result = method
            .resolve(&did, ResolveOptions::default())
            .await
            .unwrap();

        assert_eq!(result.did_document.id, doc.id);
    }

    #[tokio::test]
    async fn test_resolve_not_found() {
        let method = test_method();
        let did = DID::new(Network::Keri, AgentClass::Autonomous, "z6MkNonexistent");

        let result = method.resolve(&did, ResolveOptions::default()).await;
        assert!(result.is_err());
    }
}
