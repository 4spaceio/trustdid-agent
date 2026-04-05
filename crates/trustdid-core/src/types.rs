use serde::{Deserialize, Serialize};
use std::fmt;

/// Agent classification within the TrustDID system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentClass {
    Autonomous,
    Delegated,
    Ephemeral,
    Org,
    Human,
}

impl AgentClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Autonomous => "autonomous",
            Self::Delegated => "delegated",
            Self::Ephemeral => "ephemeral",
            Self::Org => "org",
            Self::Human => "human",
        }
    }

    pub fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "autonomous" => Ok(Self::Autonomous),
            "delegated" => Ok(Self::Delegated),
            "ephemeral" => Ok(Self::Ephemeral),
            "org" => Ok(Self::Org),
            "human" => Ok(Self::Human),
            _ => Err(crate::TrustDIDError::UnsupportedAgentClass(s.to_string())),
        }
    }
}

impl fmt::Display for AgentClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Network identifier for the ledger backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Network {
    /// EVM-compatible chain with chain ID (e.g., 1 for Ethereum, 137 for Polygon)
    #[serde(rename = "evm")]
    Evm(u64),
    /// KERI ledger-less infrastructure
    #[serde(rename = "keri")]
    Keri,
    /// Web-based DID resolution with domain
    #[serde(rename = "web")]
    Web(String),
}

impl Network {
    pub fn as_method_segment(&self) -> String {
        match self {
            Self::Evm(chain_id) => format!("evm:{chain_id}"),
            Self::Keri => "keri".to_string(),
            Self::Web(domain) => format!("web:{domain}"),
        }
    }

    pub fn from_segments(segments: &[&str]) -> crate::Result<Self> {
        match segments.first().copied() {
            Some("evm") => {
                let chain_id = segments
                    .get(1)
                    .ok_or_else(|| crate::TrustDIDError::InvalidDID("missing chain ID".into()))?
                    .parse::<u64>()
                    .map_err(|e| crate::TrustDIDError::InvalidDID(format!("invalid chain ID: {e}")))?;
                Ok(Self::Evm(chain_id))
            }
            Some("keri") => Ok(Self::Keri),
            Some("web") => {
                let domain = segments
                    .get(1)
                    .ok_or_else(|| crate::TrustDIDError::InvalidDID("missing domain".into()))?;
                Ok(Self::Web(domain.to_string()))
            }
            _ => Err(crate::TrustDIDError::UnsupportedNetwork(
                segments.join(":"),
            )),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_method_segment())
    }
}

/// Identity lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleState {
    Created,
    Active,
    Suspended,
    Rotating,
    Deactivated,
    Decommissioned,
}

impl LifecycleState {
    pub fn can_transition_to(&self, target: LifecycleState) -> bool {
        matches!(
            (self, target),
            (Self::Created, Self::Active)
                | (Self::Active, Self::Suspended)
                | (Self::Active, Self::Rotating)
                | (Self::Active, Self::Deactivated)
                | (Self::Suspended, Self::Active)
                | (Self::Suspended, Self::Deactivated)
                | (Self::Rotating, Self::Active)
                | (Self::Deactivated, Self::Decommissioned)
        )
    }

    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Created => "created",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Rotating => "rotating",
            Self::Deactivated => "deactivated",
            Self::Decommissioned => "decommissioned",
        };
        f.write_str(s)
    }
}

/// A structured capability token describing what an agent is authorized to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub resource: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
}

impl Capability {
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            constraints: Vec::new(),
        }
    }

    pub fn with_constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    pub fn to_compact(&self) -> String {
        if self.constraints.is_empty() {
            format!("{}:{}", self.resource, self.action)
        } else {
            let constraints: Vec<String> = self.constraints.iter().map(|c| c.to_string()).collect();
            format!("{}:{}:{}", self.resource, self.action, constraints.join(","))
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_compact())
    }
}

/// A constraint on a capability (e.g., rate limit, amount limit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    pub key: String,
    pub value: String,
}

impl Constraint {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

/// Proof types supported by TrustDID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProofType {
    #[serde(rename = "JsonWebSignature2020")]
    Jws2020,
    #[serde(rename = "DataIntegrityProof")]
    DataIntegrity,
    #[serde(rename = "EcdsaSecp256k1Signature2019")]
    EcdsaSecp256k1,
}

/// A cryptographic proof attached to a DID Document or credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: ProofType,
    pub created: chrono::DateTime<chrono::Utc>,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: String,
}

/// Options for creating a new DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOptions {
    pub network: Network,
    pub agent_class: AgentClass,
    pub parent_did: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub services: Vec<ServiceEndpoint>,
}

/// Options for resolving a DID.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolveOptions {
    pub version_id: Option<String>,
    pub version_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub no_cache: bool,
}

/// An update operation on a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum UpdateOp {
    #[serde(rename = "addVerificationMethod")]
    AddVerificationMethod { method: VerificationMethod },
    #[serde(rename = "removeVerificationMethod")]
    RemoveVerificationMethod { id: String },
    #[serde(rename = "addService")]
    AddService { service: ServiceEndpoint },
    #[serde(rename = "removeService")]
    RemoveService { id: String },
    #[serde(rename = "setController")]
    SetController { controller: String },
    #[serde(rename = "updateCapabilities")]
    UpdateCapabilities { capabilities: Vec<Capability> },
    #[serde(rename = "setLifecycle")]
    SetLifecycle { state: LifecycleState },
}

/// A verification method within a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

/// A service endpoint within a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub endpoint: ServiceEndpointValue,
}

/// Value of a service endpoint (string URL or structured object).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpointValue {
    Uri(String),
    Map(serde_json::Map<String, serde_json::Value>),
}

/// The result of resolving a DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionResult {
    #[serde(rename = "didDocument")]
    pub did_document: crate::DIDDocument,
    #[serde(rename = "didResolutionMetadata")]
    pub resolution_metadata: ResolutionMetadata,
    #[serde(rename = "didDocumentMetadata")]
    pub document_metadata: DocumentMetadata,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolutionMetadata {
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub created: Option<chrono::DateTime<chrono::Utc>>,
    pub updated: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "versionId", skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

/// Receipt from anchoring a DID on a ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorReceipt {
    pub network: Network,
    pub transaction_id: Option<String>,
    pub block_number: Option<u64>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Pre-rotation proof for KERI-inspired key management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreRotationProof {
    pub new_public_key: Vec<u8>,
    pub commitment_hash: String,
    pub next_commitment: String,
    pub signature: Vec<u8>,
}

/// Result of a key rotation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationReceipt {
    pub did: String,
    pub old_key_id: String,
    pub new_key_id: String,
    pub next_commitment: String,
    pub anchor: AnchorReceipt,
}

/// Result of decommissioning an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecommissionReceipt {
    pub did: String,
    pub revoked_credentials: Vec<String>,
    pub revoked_delegations: Vec<String>,
    pub anchor: AnchorReceipt,
}

/// Agent identity bundle (returned from creation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub did: String,
    pub document: crate::DIDDocument,
    pub agent_class: AgentClass,
    pub pre_rotation_commitment: String,
    pub anchor: AnchorReceipt,
}

/// Delegation credential (VC wrapping a capability delegation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCredential {
    pub id: String,
    pub parent_did: String,
    pub child_did: String,
    pub capabilities: Vec<Capability>,
    pub depth: u8,
    pub max_depth: u8,
    pub issued: chrono::DateTime<chrono::Utc>,
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
    pub proof: Proof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_class_roundtrip() {
        for class in [
            AgentClass::Autonomous,
            AgentClass::Delegated,
            AgentClass::Ephemeral,
            AgentClass::Org,
            AgentClass::Human,
        ] {
            let s = class.as_str();
            let parsed = AgentClass::from_str(s).unwrap();
            assert_eq!(class, parsed);
        }
    }

    #[test]
    fn test_agent_class_invalid() {
        assert!(AgentClass::from_str("invalid").is_err());
    }

    #[test]
    fn test_network_evm_roundtrip() {
        let net = Network::Evm(137);
        assert_eq!(net.as_method_segment(), "evm:137");
        let parsed = Network::from_segments(&["evm", "137"]).unwrap();
        assert_eq!(net, parsed);
    }

    #[test]
    fn test_network_keri() {
        let net = Network::Keri;
        assert_eq!(net.as_method_segment(), "keri");
        let parsed = Network::from_segments(&["keri"]).unwrap();
        assert_eq!(net, parsed);
    }

    #[test]
    fn test_network_web() {
        let net = Network::Web("example.com".into());
        assert_eq!(net.as_method_segment(), "web:example.com");
        let parsed = Network::from_segments(&["web", "example.com"]).unwrap();
        assert_eq!(net, parsed);
    }

    #[test]
    fn test_lifecycle_transitions() {
        assert!(LifecycleState::Created.can_transition_to(LifecycleState::Active));
        assert!(LifecycleState::Active.can_transition_to(LifecycleState::Suspended));
        assert!(LifecycleState::Active.can_transition_to(LifecycleState::Rotating));
        assert!(LifecycleState::Active.can_transition_to(LifecycleState::Deactivated));
        assert!(LifecycleState::Suspended.can_transition_to(LifecycleState::Active));
        assert!(LifecycleState::Rotating.can_transition_to(LifecycleState::Active));
        assert!(LifecycleState::Deactivated.can_transition_to(LifecycleState::Decommissioned));

        assert!(!LifecycleState::Created.can_transition_to(LifecycleState::Decommissioned));
        assert!(!LifecycleState::Decommissioned.can_transition_to(LifecycleState::Active));
        assert!(!LifecycleState::Active.can_transition_to(LifecycleState::Created));
    }

    #[test]
    fn test_lifecycle_operational() {
        assert!(LifecycleState::Active.is_operational());
        assert!(LifecycleState::Rotating.is_operational());
        assert!(!LifecycleState::Created.is_operational());
        assert!(!LifecycleState::Suspended.is_operational());
        assert!(!LifecycleState::Deactivated.is_operational());
        assert!(!LifecycleState::Decommissioned.is_operational());
    }

    #[test]
    fn test_capability_compact() {
        let cap = Capability::new("credential", "issue");
        assert_eq!(cap.to_compact(), "credential:issue");

        let cap_with_constraint =
            Capability::new("payment", "authorize").with_constraint(Constraint::new("limit", "1000"));
        assert_eq!(cap_with_constraint.to_compact(), "payment:authorize:limit=1000");
    }
}
