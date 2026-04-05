//! SD-JWT Issuer: creates SD-JWTs from a set of claims, replacing specified
//! claim names with their disclosure digests.

use serde_json::Value;

use crate::disclosure::Disclosure;
use crate::types::{SdJwt, SdJwtError};

/// An SD-JWT issuer that creates SD-JWTs from claims.
#[derive(Debug, Clone)]
pub struct SdJwtIssuer {
    /// The DID of the issuer (placed in the `iss` claim).
    pub issuer_did: String,
}

impl SdJwtIssuer {
    /// Create a new issuer with the given DID.
    pub fn new(issuer_did: &str) -> Self {
        Self {
            issuer_did: issuer_did.to_string(),
        }
    }

    /// Issue an SD-JWT from the given claims.
    ///
    /// - `claims`: A JSON object containing all claims.
    /// - `sd_claims`: The names of claims that should be selectively disclosable.
    ///   These claims will be removed from the payload and replaced with their
    ///   digests in the `_sd` array.
    ///
    /// Returns an `SdJwt` containing the modified payload and all disclosures.
    pub fn issue(
        &self,
        claims: Value,
        sd_claims: &[String],
    ) -> Result<SdJwt, SdJwtError> {
        let obj = claims
            .as_object()
            .ok_or_else(|| SdJwtError::InvalidFormat("claims must be a JSON object".into()))?;

        let mut payload = serde_json::Map::new();
        let mut disclosures = Vec::new();
        let mut sd_digests: Vec<Value> = Vec::new();

        for (key, value) in obj {
            if sd_claims.contains(key) {
                // Create a disclosure for this claim and add its digest to _sd.
                let disclosure = Disclosure::new(key, value);
                sd_digests.push(Value::String(disclosure.digest()));
                disclosures.push(disclosure);
            } else {
                // Keep the claim in the payload as-is.
                payload.insert(key.clone(), value.clone());
            }
        }

        // Always set the issuer.
        payload.insert("iss".to_string(), Value::String(self.issuer_did.clone()));

        // Add the `_sd` array if there are any selectively disclosable claims.
        if !sd_digests.is_empty() {
            payload.insert("_sd".to_string(), Value::Array(sd_digests));
        }

        // Add the `_sd_alg` claim to indicate the hash algorithm.
        payload.insert("_sd_alg".to_string(), Value::String("sha-256".to_string()));

        Ok(SdJwt {
            jwt_payload: Value::Object(payload),
            disclosures,
            key_binding_jwt: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_issuer_new() {
        let issuer = SdJwtIssuer::new("did:example:issuer");
        assert_eq!(issuer.issuer_did, "did:example:issuer");
    }

    #[test]
    fn test_issue_no_sd_claims() {
        let issuer = SdJwtIssuer::new("did:example:issuer");
        let claims = serde_json::json!({
            "sub": "did:example:subject",
            "name": "Alice"
        });

        let sd_jwt = issuer.issue(claims, &[]).expect("should issue");

        // All claims should be in the payload.
        assert_eq!(sd_jwt.jwt_payload["sub"], "did:example:subject");
        assert_eq!(sd_jwt.jwt_payload["name"], "Alice");
        assert_eq!(sd_jwt.jwt_payload["iss"], "did:example:issuer");
        assert!(sd_jwt.disclosures.is_empty());
        // _sd should not be present when no sd claims.
        assert!(sd_jwt.jwt_payload.get("_sd").is_none());
    }

    #[test]
    fn test_issue_with_sd_claims() {
        let issuer = SdJwtIssuer::new("did:example:issuer");
        let claims = serde_json::json!({
            "sub": "did:example:subject",
            "given_name": "Alice",
            "family_name": "Smith",
            "email": "alice@example.com"
        });

        let sd_claims = vec![
            "given_name".to_string(),
            "email".to_string(),
        ];

        let sd_jwt = issuer.issue(claims, &sd_claims).expect("should issue");

        // Non-SD claims should remain in the payload.
        assert_eq!(sd_jwt.jwt_payload["sub"], "did:example:subject");
        assert_eq!(sd_jwt.jwt_payload["family_name"], "Smith");

        // SD claims should NOT be in the payload directly.
        assert!(sd_jwt.jwt_payload.get("given_name").is_none());
        assert!(sd_jwt.jwt_payload.get("email").is_none());

        // _sd array should contain digests.
        let sd_array = sd_jwt.jwt_payload["_sd"].as_array().expect("_sd must be array");
        assert_eq!(sd_array.len(), 2);

        // Should have 2 disclosures.
        assert_eq!(sd_jwt.disclosures.len(), 2);

        // Each disclosure digest should be in the _sd array.
        for disclosure in &sd_jwt.disclosures {
            let digest = disclosure.digest();
            assert!(
                sd_array.iter().any(|d| d.as_str() == Some(&digest)),
                "disclosure digest {} not found in _sd array",
                digest
            );
        }
    }

    #[test]
    fn test_issue_sets_sd_alg() {
        let issuer = SdJwtIssuer::new("did:example:issuer");
        let claims = serde_json::json!({"sub": "user", "name": "Alice"});

        let sd_jwt = issuer
            .issue(claims, &["name".to_string()])
            .expect("should issue");

        assert_eq!(sd_jwt.jwt_payload["_sd_alg"], "sha-256");
    }

    #[test]
    fn test_issue_overwrites_iss() {
        let issuer = SdJwtIssuer::new("did:example:correct-issuer");
        let claims = serde_json::json!({
            "iss": "did:example:wrong-issuer",
            "sub": "user"
        });

        let sd_jwt = issuer.issue(claims, &[]).expect("should issue");
        assert_eq!(sd_jwt.jwt_payload["iss"], "did:example:correct-issuer");
    }

    #[test]
    fn test_issue_invalid_claims() {
        let issuer = SdJwtIssuer::new("did:example:issuer");
        let claims = serde_json::json!("not an object");

        let result = issuer.issue(claims, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_sd_claim_not_in_claims() {
        let issuer = SdJwtIssuer::new("did:example:issuer");
        let claims = serde_json::json!({"sub": "user"});

        // Requesting an SD claim that doesn't exist should just ignore it.
        let sd_jwt = issuer
            .issue(claims, &["nonexistent".to_string()])
            .expect("should issue");

        assert_eq!(sd_jwt.disclosures.len(), 0);
    }

    #[test]
    fn test_issue_complex_claim_value() {
        let issuer = SdJwtIssuer::new("did:example:issuer");
        let claims = serde_json::json!({
            "sub": "user",
            "address": {
                "street": "123 Main St",
                "city": "Springfield"
            }
        });

        let sd_jwt = issuer
            .issue(claims, &["address".to_string()])
            .expect("should issue");

        assert_eq!(sd_jwt.disclosures.len(), 1);
        assert_eq!(sd_jwt.disclosures[0].claim_name, "address");
        assert_eq!(
            sd_jwt.disclosures[0].claim_value,
            serde_json::json!({"street": "123 Main St", "city": "Springfield"})
        );
    }
}
