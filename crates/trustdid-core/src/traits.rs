use crate::types::*;
use crate::{DID, DIDDocument, Result};
use async_trait::async_trait;

/// W3C DID Core v1.1 compliant DID Method operations.
#[async_trait]
pub trait DIDMethod: Send + Sync {
    fn method_name(&self) -> &str;

    async fn create(&self, options: CreateOptions) -> Result<DIDDocument>;

    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Result<ResolutionResult>;

    async fn update(
        &self,
        did: &DID,
        operations: Vec<UpdateOp>,
        proof: Proof,
    ) -> Result<DIDDocument>;

    async fn deactivate(&self, did: &DID, proof: Proof) -> Result<()>;
}

/// Abstraction over ledger backends (EVM, KERI, Web).
#[async_trait]
pub trait LedgerDriver: Send + Sync {
    fn network_id(&self) -> &str;

    async fn anchor(&self, did: &DID, document: &DIDDocument) -> Result<AnchorReceipt>;

    async fn retrieve(&self, did: &DID) -> Result<Option<DIDDocument>>;

    async fn update(
        &self,
        did: &DID,
        document: &DIDDocument,
        proof: &Proof,
    ) -> Result<AnchorReceipt>;

    async fn deactivate(&self, did: &DID, proof: &Proof) -> Result<()>;

    async fn is_anchored(&self, did: &DID) -> Result<bool> {
        Ok(self.retrieve(did).await?.is_some())
    }
}

/// Agent-specific identity lifecycle operations.
#[async_trait]
pub trait AgentLifecycle: Send + Sync {
    async fn create_agent(
        &self,
        class: AgentClass,
        parent: Option<&DID>,
        caps: &[Capability],
    ) -> Result<AgentIdentity>;

    async fn delegate(
        &self,
        parent: &DID,
        child_class: AgentClass,
        caps: &[Capability],
        depth_limit: u8,
    ) -> Result<DelegationCredential>;

    async fn rotate_key(
        &self,
        did: &DID,
        pre_rotation_proof: PreRotationProof,
    ) -> Result<KeyRotationReceipt>;

    async fn decommission(&self, did: &DID, cascade: bool) -> Result<DecommissionReceipt>;

    async fn suspend(&self, did: &DID) -> Result<()>;

    async fn resume(&self, did: &DID) -> Result<()>;
}

/// Verifiable Credential issuance (W3C VC v2.0).
#[async_trait]
pub trait CredentialIssuer: Send + Sync {
    async fn issue(
        &self,
        claims: serde_json::Value,
        holder: &DID,
        options: IssueOptions,
    ) -> Result<serde_json::Value>;

    async fn revoke(&self, credential_id: &str) -> Result<()>;
}

/// Verifiable Credential verification.
#[async_trait]
pub trait CredentialVerifier: Send + Sync {
    async fn verify(&self, credential: &serde_json::Value) -> Result<VerificationResult>;
}

/// Verifiable Credential holder operations.
#[async_trait]
pub trait CredentialHolder: Send + Sync {
    async fn present(
        &self,
        credentials: &[serde_json::Value],
        challenge: &str,
        domain: &str,
    ) -> Result<serde_json::Value>;
}

/// Options for credential issuance.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IssueOptions {
    #[serde(rename = "credentialType", default)]
    pub credential_type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "proofType", default)]
    pub proof_type: Option<ProofType>,
    #[serde(rename = "selectiveDisclosure", default)]
    pub selective_disclosure: bool,
}

/// Result of credential verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub issuer: Option<String>,
    pub holder: Option<String>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}
