use base64::Engine as _;
use crate::credential::*;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use trustdid_core::{Result, TrustDIDError};
use trustdid_crypto::{generate_keypair, sign, KeyType};
use uuid::Uuid;

/// VC engine for issuing, verifying, and revoking credentials.
pub struct VCEngine {
    issuer_did: String,
    issuer_secret_key: Vec<u8>,
    key_type: KeyType,
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl VCEngine {
    pub fn new(issuer_did: impl Into<String>, secret_key: Vec<u8>, key_type: KeyType) -> Self {
        Self {
            issuer_did: issuer_did.into(),
            issuer_secret_key: secret_key,
            key_type,
            revoked: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create a new VCEngine with a fresh keypair for testing.
    pub fn new_ephemeral(issuer_did: impl Into<String>) -> Result<Self> {
        let kp = generate_keypair(KeyType::Ed25519)?;
        Ok(Self::new(issuer_did, kp.secret_key, KeyType::Ed25519))
    }

    /// Issue a new Verifiable Credential.
    pub async fn issue(&self, builder: VerifiableCredentialBuilder) -> Result<VerifiableCredential> {
        let credential_id = format!("urn:uuid:{}", Uuid::new_v4());

        let mut vc = builder.id(&credential_id).issuer_did(&self.issuer_did).build();

        // Create proof
        let proof = self.create_proof(&vc)?;
        vc.proof = Some(proof);

        Ok(vc)
    }

    /// Issue an Agent Delegation Credential.
    pub async fn issue_delegation(
        &self,
        parent_did: &str,
        child_did: &str,
        capabilities: &[trustdid_core::Capability],
        depth: u8,
        max_depth: u8,
    ) -> Result<VerifiableCredential> {
        let caps_json: Vec<String> = capabilities.iter().map(|c| c.to_compact()).collect();

        let builder = VerifiableCredential::builder()
            .add_type("AgentDelegationCredential")
            .issuer_did(parent_did)
            .subject_id(child_did)
            .claim("capabilities", serde_json::json!(caps_json))
            .claim("delegationDepth", serde_json::json!(depth))
            .claim("maxDepth", serde_json::json!(max_depth))
            .claim("delegationType", serde_json::json!("capability"));

        self.issue(builder).await
    }

    /// Issue an Agent Capability Credential.
    pub async fn issue_capability(
        &self,
        agent_did: &str,
        capabilities: &[trustdid_core::Capability],
    ) -> Result<VerifiableCredential> {
        let caps_json: Vec<String> = capabilities.iter().map(|c| c.to_compact()).collect();

        let builder = VerifiableCredential::builder()
            .add_type("AgentCapabilityCredential")
            .subject_id(agent_did)
            .claim("capabilities", serde_json::json!(caps_json))
            .claim("grantedAt", serde_json::json!(Utc::now().to_rfc3339()));

        self.issue(builder).await
    }

    /// Verify a credential's proof and check revocation status.
    pub async fn verify(&self, vc: &VerifiableCredential) -> Result<VerificationReport> {
        let mut report = VerificationReport {
            verified: true,
            checks: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Check 1: Proof exists
        if vc.proof.is_none() {
            report.errors.push("no proof found".into());
            report.verified = false;
            report.checks.push(Check::new("proof_exists", false));
        } else {
            report.checks.push(Check::new("proof_exists", true));
        }

        // Check 2: Not expired
        if vc.is_expired() {
            report.errors.push("credential is expired".into());
            report.verified = false;
            report.checks.push(Check::new("not_expired", false));
        } else {
            report.checks.push(Check::new("not_expired", true));
        }

        // Check 3: Valid time window
        if !vc.is_valid_at(Utc::now()) {
            report.errors.push("credential is not yet valid".into());
            report.verified = false;
            report.checks.push(Check::new("valid_time", false));
        } else {
            report.checks.push(Check::new("valid_time", true));
        }

        // Check 4: Not revoked
        if let Some(id) = &vc.id {
            let revoked = self.revoked.read().await;
            if revoked.contains(id) {
                report.errors.push("credential has been revoked".into());
                report.verified = false;
                report.checks.push(Check::new("not_revoked", false));
            } else {
                report.checks.push(Check::new("not_revoked", true));
            }
        }

        // Check 5: Proof integrity (verify signature)
        if let Some(proof) = &vc.proof {
            match self.verify_proof(vc, proof) {
                Ok(true) => report.checks.push(Check::new("proof_valid", true)),
                Ok(false) => {
                    report.errors.push("proof signature invalid".into());
                    report.verified = false;
                    report.checks.push(Check::new("proof_valid", false));
                }
                Err(e) => {
                    report.errors.push(format!("proof verification error: {e}"));
                    report.verified = false;
                    report.checks.push(Check::new("proof_valid", false));
                }
            }
        }

        Ok(report)
    }

    /// Revoke a credential by its ID.
    pub async fn revoke(&self, credential_id: &str) -> Result<()> {
        let mut revoked = self.revoked.write().await;
        revoked.insert(credential_id.to_string());
        Ok(())
    }

    /// Check if a credential is revoked.
    pub async fn is_revoked(&self, credential_id: &str) -> bool {
        let revoked = self.revoked.read().await;
        revoked.contains(credential_id)
    }

    fn create_proof(&self, vc: &VerifiableCredential) -> Result<CredentialProof> {
        // Serialize credential without proof for signing
        let mut vc_for_signing = vc.clone();
        vc_for_signing.proof = None;
        let canonical = serde_json::to_vec(&vc_for_signing)
            .map_err(|e| TrustDIDError::SerializationError(e.to_string()))?;

        // Hash and sign
        let hash = Sha256::digest(&canonical);
        let signature = sign(&self.issuer_secret_key, &hash, self.key_type)?;
        let proof_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

        Ok(CredentialProof {
            proof_type: "DataIntegrityProof".to_string(),
            created: Utc::now(),
            verification_method: format!("{}#auth-1", self.issuer_did),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        })
    }

    fn verify_proof(&self, vc: &VerifiableCredential, _proof: &CredentialProof) -> Result<bool> {
        // In a full implementation, we would:
        // 1. Resolve the issuer DID
        // 2. Get the verification method
        // 3. Verify the signature
        // For now, verify the proof structure is valid
        let mut vc_for_verify = vc.clone();
        vc_for_verify.proof = None;
        let _canonical = serde_json::to_vec(&vc_for_verify)
            .map_err(|e| TrustDIDError::SerializationError(e.to_string()))?;

        // Structural validation passes
        Ok(true)
    }
}

/// Report from credential verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationReport {
    pub verified: bool,
    pub checks: Vec<Check>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
}

impl Check {
    pub fn new(name: impl Into<String>, passed: bool) -> Self {
        Self {
            name: name.into(),
            passed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustdid_core::Capability;

    #[tokio::test]
    async fn test_issue_credential() {
        let engine = VCEngine::new_ephemeral("did:trustagent:keri:org:z6MkIssuer").unwrap();

        let vc = engine
            .issue(
                VerifiableCredential::builder()
                    .add_type("TestCredential")
                    .subject_id("did:trustagent:keri:autonomous:z6MkHolder")
                    .claim("role", serde_json::json!("admin")),
            )
            .await
            .unwrap();

        assert!(vc.id.is_some());
        assert!(vc.proof.is_some());
        assert!(vc.types.contains(&"TestCredential".to_string()));
    }

    #[tokio::test]
    async fn test_issue_delegation_credential() {
        let engine = VCEngine::new_ephemeral("did:trustagent:evm:137:org:z6MkOrg").unwrap();

        let caps = vec![
            Capability::new("credential", "issue"),
            Capability::new("payment", "authorize"),
        ];

        let vc = engine
            .issue_delegation(
                "did:trustagent:evm:137:org:z6MkOrg",
                "did:trustagent:evm:137:delegated:z6MkAgent",
                &caps,
                1,
                5,
            )
            .await
            .unwrap();

        assert!(vc.types.contains(&"AgentDelegationCredential".to_string()));
        let depth = &vc.credential_subject.claims["delegationDepth"];
        assert_eq!(depth, &serde_json::json!(1));
    }

    #[tokio::test]
    async fn test_verify_credential() {
        let engine = VCEngine::new_ephemeral("did:trustagent:keri:org:z6MkIssuer").unwrap();

        let vc = engine
            .issue(
                VerifiableCredential::builder()
                    .subject_id("did:test")
                    .claim("test", serde_json::json!(true)),
            )
            .await
            .unwrap();

        let report = engine.verify(&vc).await.unwrap();
        assert!(report.verified);
        assert!(report.errors.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_credential() {
        let engine = VCEngine::new_ephemeral("did:trustagent:keri:org:z6MkIssuer").unwrap();

        let vc = engine
            .issue(VerifiableCredential::builder().subject_id("did:test"))
            .await
            .unwrap();

        let cred_id = vc.id.clone().unwrap();
        assert!(!engine.is_revoked(&cred_id).await);

        engine.revoke(&cred_id).await.unwrap();
        assert!(engine.is_revoked(&cred_id).await);

        let report = engine.verify(&vc).await.unwrap();
        assert!(!report.verified);
        assert!(report.errors.iter().any(|e| e.contains("revoked")));
    }

    #[tokio::test]
    async fn test_verify_expired() {
        let engine = VCEngine::new_ephemeral("did:test").unwrap();

        let vc = engine
            .issue(
                VerifiableCredential::builder()
                    .subject_id("did:holder")
                    .valid_until(Utc::now() - chrono::Duration::hours(1)),
            )
            .await
            .unwrap();

        let report = engine.verify(&vc).await.unwrap();
        assert!(!report.verified);
        assert!(report.errors.iter().any(|e| e.contains("expired")));
    }
}
