//! SD-JWT Holder: selects which disclosures to present to a verifier.
//!
//! The holder receives an SD-JWT from an issuer (containing all disclosures)
//! and creates a presentation with only the desired disclosures.

use crate::types::{SdJwt, SdJwtError};

/// An SD-JWT holder that creates presentations with selected disclosures.
#[derive(Debug, Clone)]
pub struct SdJwtHolder;

impl SdJwtHolder {
    /// Create a new holder.
    pub fn new() -> Self {
        Self
    }

    /// Create a presentation from an SD-JWT, including only the specified claims.
    ///
    /// - `sd_jwt`: The full SD-JWT received from the issuer (with all disclosures).
    /// - `disclosed_claims`: The names of claims to disclose in this presentation.
    ///
    /// Returns a new `SdJwt` containing only the selected disclosures. The JWT
    /// payload remains unchanged.
    pub fn present(
        &self,
        sd_jwt: &SdJwt,
        disclosed_claims: &[String],
    ) -> Result<SdJwt, SdJwtError> {
        let selected_disclosures: Vec<_> = sd_jwt
            .disclosures
            .iter()
            .filter(|d| disclosed_claims.contains(&d.claim_name))
            .cloned()
            .collect();

        Ok(SdJwt {
            jwt_payload: sd_jwt.jwt_payload.clone(),
            disclosures: selected_disclosures,
            key_binding_jwt: sd_jwt.key_binding_jwt.clone(),
        })
    }
}

impl Default for SdJwtHolder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclosure::Disclosure;
    use pretty_assertions::assert_eq;

    fn make_test_sd_jwt() -> SdJwt {
        let d_name = Disclosure::with_salt("salt1", "given_name", &serde_json::json!("Alice"));
        let d_email = Disclosure::with_salt("salt2", "email", &serde_json::json!("alice@example.com"));
        let d_age = Disclosure::with_salt("salt3", "age", &serde_json::json!(30));

        let payload = serde_json::json!({
            "iss": "did:example:issuer",
            "sub": "did:example:holder",
            "_sd": [d_name.digest(), d_email.digest(), d_age.digest()],
            "_sd_alg": "sha-256"
        });

        SdJwt {
            jwt_payload: payload,
            disclosures: vec![d_name, d_email, d_age],
            key_binding_jwt: None,
        }
    }

    #[test]
    fn test_holder_present_all_claims() {
        let holder = SdJwtHolder::new();
        let sd_jwt = make_test_sd_jwt();

        let disclosed = vec![
            "given_name".to_string(),
            "email".to_string(),
            "age".to_string(),
        ];

        let presented = holder.present(&sd_jwt, &disclosed).expect("should present");
        assert_eq!(presented.disclosures.len(), 3);
        assert_eq!(presented.jwt_payload, sd_jwt.jwt_payload);
    }

    #[test]
    fn test_holder_present_subset() {
        let holder = SdJwtHolder::new();
        let sd_jwt = make_test_sd_jwt();

        let disclosed = vec!["given_name".to_string()];

        let presented = holder.present(&sd_jwt, &disclosed).expect("should present");
        assert_eq!(presented.disclosures.len(), 1);
        assert_eq!(presented.disclosures[0].claim_name, "given_name");
    }

    #[test]
    fn test_holder_present_no_claims() {
        let holder = SdJwtHolder::new();
        let sd_jwt = make_test_sd_jwt();

        let presented = holder.present(&sd_jwt, &[]).expect("should present");
        assert_eq!(presented.disclosures.len(), 0);
        // The payload should still contain the _sd array.
        assert!(presented.jwt_payload.get("_sd").is_some());
    }

    #[test]
    fn test_holder_present_nonexistent_claim() {
        let holder = SdJwtHolder::new();
        let sd_jwt = make_test_sd_jwt();

        let disclosed = vec!["nonexistent".to_string()];

        let presented = holder.present(&sd_jwt, &disclosed).expect("should present");
        assert_eq!(presented.disclosures.len(), 0);
    }

    #[test]
    fn test_holder_present_preserves_key_binding() {
        let holder = SdJwtHolder::new();
        let mut sd_jwt = make_test_sd_jwt();
        sd_jwt.key_binding_jwt = Some("kb-jwt".to_string());

        let disclosed = vec!["given_name".to_string()];
        let presented = holder.present(&sd_jwt, &disclosed).expect("should present");

        assert_eq!(presented.key_binding_jwt, Some("kb-jwt".to_string()));
    }

    #[test]
    fn test_holder_present_preserves_payload() {
        let holder = SdJwtHolder::new();
        let sd_jwt = make_test_sd_jwt();

        let disclosed = vec!["email".to_string()];
        let presented = holder.present(&sd_jwt, &disclosed).expect("should present");

        // The payload should be identical (including _sd with all 3 digests).
        assert_eq!(presented.jwt_payload, sd_jwt.jwt_payload);
    }

    #[test]
    fn test_holder_present_multiple_claims() {
        let holder = SdJwtHolder::new();
        let sd_jwt = make_test_sd_jwt();

        let disclosed = vec!["given_name".to_string(), "age".to_string()];

        let presented = holder.present(&sd_jwt, &disclosed).expect("should present");
        assert_eq!(presented.disclosures.len(), 2);

        let names: Vec<&str> = presented.disclosures.iter().map(|d| d.claim_name.as_str()).collect();
        assert!(names.contains(&"given_name"));
        assert!(names.contains(&"age"));
    }

    #[test]
    fn test_holder_default() {
        let holder = SdJwtHolder::default();
        let sd_jwt = make_test_sd_jwt();
        let presented = holder.present(&sd_jwt, &[]).expect("should present");
        assert_eq!(presented.disclosures.len(), 0);
    }
}
