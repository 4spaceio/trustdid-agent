use crate::types::*;
use crate::DID;
use serde::{Deserialize, Serialize};

const W3C_DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const JWS_2020_CONTEXT: &str = "https://w3id.org/security/suites/jws-2020/v1";
const TRUSTAGENT_CONTEXT: &str = "https://trustdid.org/ns/agent/v1";

/// W3C DID Core v1.1 compliant DID Document with TrustAgent extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,

    #[serde(rename = "verificationMethod", default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<VerificationRelationship>,

    #[serde(rename = "assertionMethod", default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<VerificationRelationship>,

    #[serde(rename = "keyAgreement", default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<VerificationRelationship>,

    #[serde(rename = "capabilityInvocation", default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<VerificationRelationship>,

    #[serde(rename = "capabilityDelegation", default, skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<VerificationRelationship>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<ServiceEndpoint>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trustagent: Option<TrustAgentExtension>,
}

/// A verification relationship can be a reference (string) or an embedded method.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerificationRelationship {
    Reference(String),
    Embedded(VerificationMethod),
}

/// TrustAgent-specific DID Document extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAgentExtension {
    #[serde(rename = "agentClass")]
    pub agent_class: AgentClass,

    #[serde(rename = "parentDID", skip_serializing_if = "Option::is_none")]
    pub parent_did: Option<String>,

    #[serde(rename = "delegationChainRoot", skip_serializing_if = "Option::is_none")]
    pub delegation_chain_root: Option<String>,

    #[serde(rename = "delegationDepth", skip_serializing_if = "Option::is_none")]
    pub delegation_depth: Option<u8>,

    #[serde(rename = "preRotationCommitment", skip_serializing_if = "Option::is_none")]
    pub pre_rotation_commitment: Option<String>,

    pub lifecycle: LifecycleState,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
}

impl DIDDocument {
    pub fn builder(did: &DID) -> DIDDocumentBuilder {
        DIDDocumentBuilder::new(did)
    }

    pub fn default_contexts() -> Vec<String> {
        vec![
            W3C_DID_CONTEXT.to_string(),
            JWS_2020_CONTEXT.to_string(),
            TRUSTAGENT_CONTEXT.to_string(),
        ]
    }

    pub fn did(&self) -> crate::Result<DID> {
        DID::parse(&self.id)
    }
}

/// Builder for constructing DID Documents.
pub struct DIDDocumentBuilder {
    doc: DIDDocument,
}

impl DIDDocumentBuilder {
    pub fn new(did: &DID) -> Self {
        Self {
            doc: DIDDocument {
                context: DIDDocument::default_contexts(),
                id: did.to_uri(),
                controller: None,
                verification_method: Vec::new(),
                authentication: Vec::new(),
                assertion_method: Vec::new(),
                key_agreement: Vec::new(),
                capability_invocation: Vec::new(),
                capability_delegation: Vec::new(),
                service: Vec::new(),
                trustagent: Some(TrustAgentExtension {
                    agent_class: did.agent_class,
                    parent_did: None,
                    delegation_chain_root: None,
                    delegation_depth: None,
                    pre_rotation_commitment: None,
                    lifecycle: LifecycleState::Created,
                    capabilities: Vec::new(),
                }),
            },
        }
    }

    pub fn controller(mut self, controller: impl Into<String>) -> Self {
        self.doc.controller = Some(controller.into());
        self
    }

    pub fn add_verification_method(mut self, method: VerificationMethod) -> Self {
        let ref_id = method.id.clone();
        self.doc.verification_method.push(method);
        self.doc
            .authentication
            .push(VerificationRelationship::Reference(ref_id.clone()));
        self.doc
            .assertion_method
            .push(VerificationRelationship::Reference(ref_id));
        self
    }

    pub fn add_key_agreement(mut self, method: VerificationMethod) -> Self {
        let ref_id = method.id.clone();
        self.doc.verification_method.push(method);
        self.doc
            .key_agreement
            .push(VerificationRelationship::Reference(ref_id));
        self
    }

    pub fn add_service(mut self, service: ServiceEndpoint) -> Self {
        self.doc.service.push(service);
        self
    }

    pub fn parent_did(mut self, parent: impl Into<String>) -> Self {
        if let Some(ext) = &mut self.doc.trustagent {
            ext.parent_did = Some(parent.into());
        }
        self
    }

    pub fn delegation_chain_root(mut self, root: impl Into<String>) -> Self {
        if let Some(ext) = &mut self.doc.trustagent {
            ext.delegation_chain_root = Some(root.into());
        }
        self
    }

    pub fn delegation_depth(mut self, depth: u8) -> Self {
        if let Some(ext) = &mut self.doc.trustagent {
            ext.delegation_depth = Some(depth);
        }
        self
    }

    pub fn pre_rotation_commitment(mut self, commitment: impl Into<String>) -> Self {
        if let Some(ext) = &mut self.doc.trustagent {
            ext.pre_rotation_commitment = Some(commitment.into());
        }
        self
    }

    pub fn lifecycle(mut self, state: LifecycleState) -> Self {
        if let Some(ext) = &mut self.doc.trustagent {
            ext.lifecycle = state;
        }
        self
    }

    pub fn capabilities(mut self, caps: Vec<Capability>) -> Self {
        if let Some(ext) = &mut self.doc.trustagent {
            ext.capabilities = caps;
        }
        self
    }

    pub fn build(self) -> DIDDocument {
        self.doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_build_did_document() {
        let did = DID::new(Network::Evm(137), AgentClass::Delegated, "z6MkTest");
        let doc = DIDDocument::builder(&did)
            .controller("did:trustagent:evm:137:org:z6MkParent")
            .parent_did("did:trustagent:evm:137:org:z6MkParent")
            .delegation_chain_root("did:trustagent:evm:137:human:z6MkRoot")
            .delegation_depth(2)
            .pre_rotation_commitment("z6MkCommitment")
            .lifecycle(LifecycleState::Active)
            .capabilities(vec![Capability::new("credential", "issue")])
            .add_verification_method(VerificationMethod {
                id: format!("{}#key-1", did.to_uri()),
                method_type: "JsonWebKey2020".to_string(),
                controller: did.to_uri(),
                public_key_multibase: Some("z6MkTest".to_string()),
                public_key_jwk: None,
            })
            .build();

        assert_eq!(doc.id, "did:trustagent:evm:137:delegated:z6MkTest");
        assert_eq!(
            doc.controller,
            Some("did:trustagent:evm:137:org:z6MkParent".to_string())
        );
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);

        let ext = doc.trustagent.unwrap();
        assert_eq!(ext.agent_class, AgentClass::Delegated);
        assert_eq!(ext.lifecycle, LifecycleState::Active);
        assert_eq!(ext.delegation_depth, Some(2));
        assert_eq!(ext.capabilities.len(), 1);
    }

    #[test]
    fn test_document_serialization_roundtrip() {
        let did = DID::new(Network::Keri, AgentClass::Autonomous, "z6MkTest");
        let doc = DIDDocument::builder(&did)
            .lifecycle(LifecycleState::Active)
            .build();

        let json = serde_json::to_string_pretty(&doc).unwrap();
        let parsed: DIDDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(doc.id, parsed.id);
        assert_eq!(doc.context, parsed.context);
        assert_eq!(
            doc.trustagent.as_ref().unwrap().lifecycle,
            parsed.trustagent.as_ref().unwrap().lifecycle
        );
    }

    #[test]
    fn test_default_contexts() {
        let contexts = DIDDocument::default_contexts();
        assert_eq!(contexts.len(), 3);
        assert!(contexts[0].contains("w3.org/ns/did"));
        assert!(contexts[1].contains("jws-2020"));
        assert!(contexts[2].contains("trustdid.org"));
    }
}
