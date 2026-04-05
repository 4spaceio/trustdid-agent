use crate::credential::VerifiableCredential;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// W3C Verifiable Presentation v2.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "type")]
    pub types: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,

    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<PresentationProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    pub challenge: String,
    pub domain: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl VerifiablePresentation {
    pub fn builder() -> VPBuilder {
        VPBuilder::new()
    }
}

pub struct VPBuilder {
    vp: VerifiablePresentation,
}

impl VPBuilder {
    pub fn new() -> Self {
        Self {
            vp: VerifiablePresentation {
                context: vec!["https://www.w3.org/ns/credentials/v2".to_string()],
                id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
                types: vec!["VerifiablePresentation".to_string()],
                holder: None,
                verifiable_credential: Vec::new(),
                proof: None,
            },
        }
    }

    pub fn holder(mut self, holder_did: impl Into<String>) -> Self {
        self.vp.holder = Some(holder_did.into());
        self
    }

    pub fn add_credential(mut self, vc: VerifiableCredential) -> Self {
        self.vp.verifiable_credential.push(vc);
        self
    }

    pub fn proof(mut self, proof: PresentationProof) -> Self {
        self.vp.proof = Some(proof);
        self
    }

    pub fn build(self) -> VerifiablePresentation {
        self.vp
    }
}

impl Default for VPBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_presentation() {
        let vc = VerifiableCredential::builder()
            .issuer_did("did:test:issuer")
            .subject_id("did:test:holder")
            .build();

        let vp = VerifiablePresentation::builder()
            .holder("did:test:holder")
            .add_credential(vc)
            .build();

        assert_eq!(vp.holder.as_deref(), Some("did:test:holder"));
        assert_eq!(vp.verifiable_credential.len(), 1);
        assert!(vp.id.is_some());
    }
}
