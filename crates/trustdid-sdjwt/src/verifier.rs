//! SD-JWT Verifier: validates an SD-JWT and reconstructs the disclosed claims.
//!
//! The verifier receives a presented SD-JWT (potentially with a subset of
//! disclosures) and rebuilds the claim set by matching disclosure digests
//! against the `_sd` array in the JWT payload.

use std::collections::HashMap;

use crate::types::{SdJwt, SdJwtError, VerifiedClaims};

/// An SD-JWT verifier that validates disclosures and reconstructs claims.
#[derive(Debug, Clone)]
pub struct SdJwtVerifier;

impl SdJwtVerifier {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self
    }

    /// Verify an SD-JWT and reconstruct the disclosed claims.
    ///
    /// This method:
    /// 1. Reads the `_sd` array from the JWT payload.
    /// 2. For each provided disclosure, computes its digest.
    /// 3. Checks that the digest is present in the `_sd` array.
    /// 4. Adds the disclosed claim to the result.
    /// 5. Includes all non-`_sd` / non-`_sd_alg` claims from the payload.
    pub fn verify(&self, sd_jwt: &SdJwt) -> Result<VerifiedClaims, SdJwtError> {
        let payload = sd_jwt
            .jwt_payload
            .as_object()
            .ok_or_else(|| SdJwtError::InvalidFormat("JWT payload must be a JSON object".into()))?;

        // Collect the _sd digests from the payload.
        let sd_digests: Vec<String> = match payload.get("_sd") {
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(_) => {
                return Err(SdJwtError::InvalidFormat(
                    "_sd must be a JSON array".into(),
                ));
            }
            None => Vec::new(),
        };

        let mut claims = HashMap::new();

        // Process each disclosure: verify its digest is in _sd and add the claim.
        for disclosure in &sd_jwt.disclosures {
            let digest = disclosure.digest();

            if !sd_digests.contains(&digest) {
                return Err(SdJwtError::DigestMismatch);
            }

            claims.insert(
                disclosure.claim_name.clone(),
                disclosure.claim_value.clone(),
            );
        }

        // Include all non-SD-specific claims from the payload.
        for (key, value) in payload {
            match key.as_str() {
                "_sd" | "_sd_alg" => continue,
                _ => {
                    claims.insert(key.clone(), value.clone());
                }
            }
        }

        Ok(VerifiedClaims { claims })
    }
}

impl Default for SdJwtVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclosure::Disclosure;
    use crate::issuer::SdJwtIssuer;
    use crate::holder::SdJwtHolder;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_verifier_no_disclosures() {
        let payload = serde_json::json!({
            "iss": "did:example:issuer",
            "sub": "did:example:subject",
            "_sd_alg": "sha-256"
        });

        let sd_jwt = SdJwt {
            jwt_payload: payload,
            disclosures: vec![],
            key_binding_jwt: None,
        };

        let verifier = SdJwtVerifier::new();
        let result = verifier.verify(&sd_jwt).expect("should verify");

        assert_eq!(result.claims["iss"], "did:example:issuer");
        assert_eq!(result.claims["sub"], "did:example:subject");
        assert!(!result.claims.contains_key("_sd"));
        assert!(!result.claims.contains_key("_sd_alg"));
    }

    #[test]
    fn test_verifier_with_valid_disclosures() {
        let d_name = Disclosure::with_salt("salt1", "given_name", &serde_json::json!("Alice"));
        let d_email = Disclosure::with_salt("salt2", "email", &serde_json::json!("alice@example.com"));

        let payload = serde_json::json!({
            "iss": "did:example:issuer",
            "sub": "did:example:subject",
            "_sd": [d_name.digest(), d_email.digest()],
            "_sd_alg": "sha-256"
        });

        let sd_jwt = SdJwt {
            jwt_payload: payload,
            disclosures: vec![d_name, d_email],
            key_binding_jwt: None,
        };

        let verifier = SdJwtVerifier::new();
        let result = verifier.verify(&sd_jwt).expect("should verify");

        assert_eq!(result.claims["given_name"], "Alice");
        assert_eq!(result.claims["email"], "alice@example.com");
        assert_eq!(result.claims["iss"], "did:example:issuer");
    }

    #[test]
    fn test_verifier_partial_disclosures() {
        let d_name = Disclosure::with_salt("salt1", "given_name", &serde_json::json!("Alice"));
        let d_email = Disclosure::with_salt("salt2", "email", &serde_json::json!("alice@example.com"));

        let payload = serde_json::json!({
            "iss": "did:example:issuer",
            "_sd": [d_name.digest(), d_email.digest()],
            "_sd_alg": "sha-256"
        });

        // Only present the name disclosure.
        let sd_jwt = SdJwt {
            jwt_payload: payload,
            disclosures: vec![d_name],
            key_binding_jwt: None,
        };

        let verifier = SdJwtVerifier::new();
        let result = verifier.verify(&sd_jwt).expect("should verify");

        assert_eq!(result.claims["given_name"], "Alice");
        assert!(!result.claims.contains_key("email"));
    }

    #[test]
    fn test_verifier_invalid_disclosure_digest() {
        let d_name = Disclosure::with_salt("salt1", "given_name", &serde_json::json!("Alice"));

        // Create payload with a different digest than what the disclosure produces.
        let payload = serde_json::json!({
            "iss": "did:example:issuer",
            "_sd": ["completely-wrong-digest"],
            "_sd_alg": "sha-256"
        });

        let sd_jwt = SdJwt {
            jwt_payload: payload,
            disclosures: vec![d_name],
            key_binding_jwt: None,
        };

        let verifier = SdJwtVerifier::new();
        let result = verifier.verify(&sd_jwt);
        assert!(result.is_err());
    }

    #[test]
    fn test_verifier_invalid_payload_not_object() {
        let sd_jwt = SdJwt {
            jwt_payload: serde_json::json!("not an object"),
            disclosures: vec![],
            key_binding_jwt: None,
        };

        let verifier = SdJwtVerifier::new();
        let result = verifier.verify(&sd_jwt);
        assert!(result.is_err());
    }

    #[test]
    fn test_verifier_sd_not_array() {
        let payload = serde_json::json!({
            "iss": "did:example:issuer",
            "_sd": "not-an-array"
        });

        let sd_jwt = SdJwt {
            jwt_payload: payload,
            disclosures: vec![],
            key_binding_jwt: None,
        };

        let verifier = SdJwtVerifier::new();
        let result = verifier.verify(&sd_jwt);
        assert!(result.is_err());
    }

    #[test]
    fn test_full_flow_issue_present_verify() {
        // Issuer creates an SD-JWT.
        let issuer = SdJwtIssuer::new("did:example:issuer");
        let claims = serde_json::json!({
            "sub": "did:example:holder",
            "given_name": "Alice",
            "family_name": "Smith",
            "email": "alice@example.com",
            "age": 30
        });

        let sd_claims = vec![
            "given_name".to_string(),
            "family_name".to_string(),
            "email".to_string(),
            "age".to_string(),
        ];

        let sd_jwt = issuer.issue(claims, &sd_claims).expect("should issue");
        assert_eq!(sd_jwt.disclosures.len(), 4);

        // Holder presents only name and age.
        let holder = SdJwtHolder::new();
        let presented = holder
            .present(&sd_jwt, &["given_name".to_string(), "age".to_string()])
            .expect("should present");
        assert_eq!(presented.disclosures.len(), 2);

        // Verifier verifies and gets the disclosed claims.
        let verifier = SdJwtVerifier::new();
        let verified = verifier.verify(&presented).expect("should verify");

        assert_eq!(verified.claims["given_name"], "Alice");
        assert_eq!(verified.claims["age"], 30);
        assert_eq!(verified.claims["sub"], "did:example:holder");
        assert_eq!(verified.claims["iss"], "did:example:issuer");

        // Non-disclosed claims should not be present.
        assert!(!verified.claims.contains_key("family_name"));
        assert!(!verified.claims.contains_key("email"));
    }

    #[test]
    fn test_full_flow_compact_roundtrip() {
        let issuer = SdJwtIssuer::new("did:example:issuer");
        let claims = serde_json::json!({
            "sub": "did:example:holder",
            "name": "Bob",
            "email": "bob@example.com"
        });

        let sd_jwt = issuer
            .issue(claims, &["name".to_string(), "email".to_string()])
            .expect("should issue");

        // Holder selects name only.
        let holder = SdJwtHolder::new();
        let presented = holder
            .present(&sd_jwt, &["name".to_string()])
            .expect("should present");

        // Serialize to compact, parse back, and verify.
        let compact = presented.compact();
        let parsed = SdJwt::parse(&compact).expect("should parse");

        let verifier = SdJwtVerifier::new();
        let verified = verifier.verify(&parsed).expect("should verify");

        assert_eq!(verified.claims["name"], "Bob");
        assert_eq!(verified.claims["sub"], "did:example:holder");
        assert!(!verified.claims.contains_key("email"));
    }

    #[test]
    fn test_verifier_default() {
        let verifier = SdJwtVerifier::default();
        let payload = serde_json::json!({"iss": "test"});
        let sd_jwt = SdJwt {
            jwt_payload: payload,
            disclosures: vec![],
            key_binding_jwt: None,
        };
        let result = verifier.verify(&sd_jwt).expect("should verify");
        assert_eq!(result.claims["iss"], "test");
    }
}
