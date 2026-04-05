use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
const TRUSTAGENT_CONTEXT: &str = "https://trustdid.org/ns/agent/v1";

/// W3C Verifiable Credential v2.0 data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "type")]
    pub types: Vec<String>,

    pub issuer: Issuer,

    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,

    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,

    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,

    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,

    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<CredentialSchema>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<CredentialProof>,
}

/// Issuer of a credential (can be a simple DID string or a structured object).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Issuer {
    Uri(String),
    Object {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

impl Issuer {
    pub fn did(&self) -> &str {
        match self {
            Self::Uri(uri) => uri,
            Self::Object { id, .. } => id,
        }
    }
}

/// Credential subject containing claims about an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(flatten)]
    pub claims: HashMap<String, serde_json::Value>,
}

/// Credential status for revocation checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
    #[serde(rename = "statusPurpose")]
    pub status_purpose: String,
    #[serde(rename = "statusListIndex")]
    pub status_list_index: String,
    #[serde(rename = "statusListCredential")]
    pub status_list_credential: String,
}

/// Schema the credential conforms to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSchema {
    pub id: String,
    #[serde(rename = "type")]
    pub schema_type: String,
}

/// Cryptographic proof attached to a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl VerifiableCredential {
    pub fn builder() -> VerifiableCredentialBuilder {
        VerifiableCredentialBuilder::new()
    }

    pub fn default_contexts() -> Vec<String> {
        vec![VC_CONTEXT_V2.to_string(), TRUSTAGENT_CONTEXT.to_string()]
    }

    pub fn is_expired(&self) -> bool {
        if let Some(until) = self.valid_until {
            Utc::now() > until
        } else {
            false
        }
    }

    pub fn is_valid_at(&self, time: DateTime<Utc>) -> bool {
        if let Some(from) = self.valid_from {
            if time < from {
                return false;
            }
        }
        if let Some(until) = self.valid_until {
            if time > until {
                return false;
            }
        }
        true
    }
}

/// Builder for constructing Verifiable Credentials.
pub struct VerifiableCredentialBuilder {
    vc: VerifiableCredential,
}

impl VerifiableCredentialBuilder {
    pub fn new() -> Self {
        Self {
            vc: VerifiableCredential {
                context: VerifiableCredential::default_contexts(),
                id: None,
                types: vec!["VerifiableCredential".to_string()],
                issuer: Issuer::Uri(String::new()),
                valid_from: Some(Utc::now()),
                valid_until: None,
                credential_subject: CredentialSubject {
                    id: None,
                    claims: HashMap::new(),
                },
                credential_status: None,
                credential_schema: None,
                proof: None,
            },
        }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.vc.id = Some(id.into());
        self
    }

    pub fn add_type(mut self, t: impl Into<String>) -> Self {
        self.vc.types.push(t.into());
        self
    }

    pub fn issuer_did(mut self, did: impl Into<String>) -> Self {
        self.vc.issuer = Issuer::Uri(did.into());
        self
    }

    pub fn issuer(mut self, issuer: Issuer) -> Self {
        self.vc.issuer = issuer;
        self
    }

    pub fn valid_from(mut self, from: DateTime<Utc>) -> Self {
        self.vc.valid_from = Some(from);
        self
    }

    pub fn valid_until(mut self, until: DateTime<Utc>) -> Self {
        self.vc.valid_until = Some(until);
        self
    }

    pub fn subject_id(mut self, id: impl Into<String>) -> Self {
        self.vc.credential_subject.id = Some(id.into());
        self
    }

    pub fn claim(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.vc.credential_subject.claims.insert(key.into(), value);
        self
    }

    pub fn status(mut self, status: CredentialStatus) -> Self {
        self.vc.credential_status = Some(status);
        self
    }

    pub fn schema(mut self, schema: CredentialSchema) -> Self {
        self.vc.credential_schema = Some(schema);
        self
    }

    pub fn proof(mut self, proof: CredentialProof) -> Self {
        self.vc.proof = Some(proof);
        self
    }

    pub fn build(self) -> VerifiableCredential {
        self.vc
    }
}

impl Default for VerifiableCredentialBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_build_credential() {
        let vc = VerifiableCredential::builder()
            .id("urn:uuid:test-credential-1")
            .add_type("AgentDelegationCredential")
            .issuer_did("did:trustagent:evm:137:org:z6MkParent")
            .subject_id("did:trustagent:evm:137:delegated:z6MkChild")
            .claim("capabilities", json!(["credential:issue"]))
            .claim("delegationDepth", json!(2))
            .build();

        assert_eq!(vc.types.len(), 2);
        assert!(vc.types.contains(&"AgentDelegationCredential".to_string()));
        assert_eq!(vc.issuer.did(), "did:trustagent:evm:137:org:z6MkParent");
        assert_eq!(
            vc.credential_subject.id.as_deref(),
            Some("did:trustagent:evm:137:delegated:z6MkChild")
        );
        assert!(vc.credential_subject.claims.contains_key("capabilities"));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let vc = VerifiableCredential::builder()
            .id("urn:uuid:test")
            .issuer_did("did:trustagent:keri:autonomous:z6MkIssuer")
            .subject_id("did:trustagent:keri:delegated:z6MkHolder")
            .claim("name", json!("Test Agent"))
            .build();

        let json = serde_json::to_string_pretty(&vc).unwrap();
        let parsed: VerifiableCredential = serde_json::from_str(&json).unwrap();

        assert_eq!(vc.id, parsed.id);
        assert_eq!(vc.issuer.did(), parsed.issuer.did());
    }

    #[test]
    fn test_expiration_check() {
        let vc = VerifiableCredential::builder()
            .issuer_did("did:test")
            .valid_until(Utc::now() + chrono::Duration::hours(1))
            .build();
        assert!(!vc.is_expired());

        let expired_vc = VerifiableCredential::builder()
            .issuer_did("did:test")
            .valid_until(Utc::now() - chrono::Duration::hours(1))
            .build();
        assert!(expired_vc.is_expired());
    }

    #[test]
    fn test_default_contexts() {
        let contexts = VerifiableCredential::default_contexts();
        assert!(contexts[0].contains("credentials/v2"));
        assert!(contexts[1].contains("trustdid.org"));
    }
}
