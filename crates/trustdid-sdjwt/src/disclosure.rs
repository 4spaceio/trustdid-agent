//! SD-JWT Disclosure implementation per RFC 9901.
//!
//! A disclosure is a JSON array `[salt, claim_name, claim_value]` that is
//! base64url-encoded. The SHA-256 hash of the encoded disclosure is placed
//! into the `_sd` array within the JWT payload.

use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::SdJwtError;

/// A single SD-JWT disclosure binding a salt, claim name, and claim value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disclosure {
    /// Random salt (16 bytes, base64url-encoded for serialization).
    pub salt: String,
    /// The name of the claim being disclosed.
    pub claim_name: String,
    /// The value of the claim being disclosed.
    pub claim_value: serde_json::Value,
}

impl Disclosure {
    /// Create a new disclosure with a randomly generated salt.
    pub fn new(claim_name: &str, claim_value: &serde_json::Value) -> Self {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut salt_bytes = [0u8; 16];
        rand::thread_rng().fill(&mut salt_bytes);
        let salt = engine.encode(salt_bytes);

        Self {
            salt,
            claim_name: claim_name.to_string(),
            claim_value: claim_value.clone(),
        }
    }

    /// Create a disclosure with a specific salt (useful for deterministic testing).
    pub fn with_salt(salt: &str, claim_name: &str, claim_value: &serde_json::Value) -> Self {
        Self {
            salt: salt.to_string(),
            claim_name: claim_name.to_string(),
            claim_value: claim_value.clone(),
        }
    }

    /// Encode this disclosure as a base64url string.
    ///
    /// The encoded form is `base64url([salt, claim_name, claim_value])`.
    pub fn encode(&self) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let array = serde_json::json!([self.salt, self.claim_name, self.claim_value]);
        let json_str = serde_json::to_string(&array).expect("disclosure must be serializable");
        engine.encode(json_str.as_bytes())
    }

    /// Decode a disclosure from its base64url-encoded form.
    pub fn decode(encoded: &str) -> Result<Self, SdJwtError> {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let bytes = engine.decode(encoded).map_err(|e| {
            SdJwtError::InvalidDisclosure(format!("invalid base64url: {e}"))
        })?;

        let array: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            SdJwtError::InvalidDisclosure(format!("invalid JSON: {e}"))
        })?;

        let arr = array.as_array().ok_or_else(|| {
            SdJwtError::InvalidDisclosure("disclosure must be a JSON array".into())
        })?;

        if arr.len() != 3 {
            return Err(SdJwtError::InvalidDisclosure(format!(
                "disclosure array must have 3 elements, found {}",
                arr.len()
            )));
        }

        let salt = arr[0]
            .as_str()
            .ok_or_else(|| SdJwtError::InvalidDisclosure("salt must be a string".into()))?
            .to_string();

        let claim_name = arr[1]
            .as_str()
            .ok_or_else(|| SdJwtError::InvalidDisclosure("claim_name must be a string".into()))?
            .to_string();

        let claim_value = arr[2].clone();

        Ok(Self {
            salt,
            claim_name,
            claim_value,
        })
    }

    /// Compute the SHA-256 digest of this disclosure's encoded form.
    ///
    /// This digest is what gets placed into the `_sd` array in the JWT payload.
    pub fn digest(&self) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let encoded = self.encode();
        let hash = Sha256::digest(encoded.as_bytes());
        engine.encode(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_disclosure_new_has_random_salt() {
        let d1 = Disclosure::new("name", &serde_json::json!("Alice"));
        let d2 = Disclosure::new("name", &serde_json::json!("Alice"));
        // Two independently created disclosures should have different salts.
        assert_ne!(d1.salt, d2.salt);
    }

    #[test]
    fn test_disclosure_with_salt() {
        let d = Disclosure::with_salt("test-salt", "email", &serde_json::json!("a@b.com"));
        assert_eq!(d.salt, "test-salt");
        assert_eq!(d.claim_name, "email");
        assert_eq!(d.claim_value, serde_json::json!("a@b.com"));
    }

    #[test]
    fn test_disclosure_encode_decode_roundtrip() {
        let original = Disclosure::with_salt(
            "2GLC42sKQveCfGfryNRN9w",
            "given_name",
            &serde_json::json!("John"),
        );

        let encoded = original.encode();
        let decoded = Disclosure::decode(&encoded).expect("should decode");

        assert_eq!(decoded.salt, original.salt);
        assert_eq!(decoded.claim_name, original.claim_name);
        assert_eq!(decoded.claim_value, original.claim_value);
    }

    #[test]
    fn test_disclosure_encode_decode_complex_value() {
        let value = serde_json::json!({
            "street": "123 Main St",
            "city": "Anytown"
        });
        let original = Disclosure::with_salt("salt123", "address", &value);

        let encoded = original.encode();
        let decoded = Disclosure::decode(&encoded).expect("should decode");

        assert_eq!(decoded.claim_value, value);
    }

    #[test]
    fn test_disclosure_encode_decode_numeric_value() {
        let original = Disclosure::with_salt("salt-num", "age", &serde_json::json!(30));

        let encoded = original.encode();
        let decoded = Disclosure::decode(&encoded).expect("should decode");

        assert_eq!(decoded.claim_value, serde_json::json!(30));
    }

    #[test]
    fn test_disclosure_encode_decode_boolean_value() {
        let original = Disclosure::with_salt("salt-bool", "active", &serde_json::json!(true));

        let encoded = original.encode();
        let decoded = Disclosure::decode(&encoded).expect("should decode");

        assert_eq!(decoded.claim_value, serde_json::json!(true));
    }

    #[test]
    fn test_disclosure_encode_decode_array_value() {
        let original = Disclosure::with_salt(
            "salt-arr",
            "nationalities",
            &serde_json::json!(["US", "DE"]),
        );

        let encoded = original.encode();
        let decoded = Disclosure::decode(&encoded).expect("should decode");

        assert_eq!(decoded.claim_value, serde_json::json!(["US", "DE"]));
    }

    #[test]
    fn test_disclosure_digest_is_deterministic() {
        let d = Disclosure::with_salt("fixed-salt", "name", &serde_json::json!("Alice"));

        let digest1 = d.digest();
        let digest2 = d.digest();
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_disclosure_different_claims_have_different_digests() {
        let d1 = Disclosure::with_salt("same-salt", "name", &serde_json::json!("Alice"));
        let d2 = Disclosure::with_salt("same-salt", "email", &serde_json::json!("alice@example.com"));

        assert_ne!(d1.digest(), d2.digest());
    }

    #[test]
    fn test_disclosure_different_salts_have_different_digests() {
        let d1 = Disclosure::with_salt("salt-a", "name", &serde_json::json!("Alice"));
        let d2 = Disclosure::with_salt("salt-b", "name", &serde_json::json!("Alice"));

        assert_ne!(d1.digest(), d2.digest());
    }

    #[test]
    fn test_disclosure_decode_invalid_base64() {
        let result = Disclosure::decode("!!!not-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_disclosure_decode_invalid_json() {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let encoded = engine.encode(b"not json");
        let result = Disclosure::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_disclosure_decode_wrong_array_length() {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let json = serde_json::to_string(&serde_json::json!(["salt", "name"])).unwrap();
        let encoded = engine.encode(json.as_bytes());
        let result = Disclosure::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_disclosure_decode_non_string_salt() {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let json = serde_json::to_string(&serde_json::json!([123, "name", "value"])).unwrap();
        let encoded = engine.encode(json.as_bytes());
        let result = Disclosure::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_disclosure_decode_non_string_claim_name() {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let json = serde_json::to_string(&serde_json::json!(["salt", 42, "value"])).unwrap();
        let encoded = engine.encode(json.as_bytes());
        let result = Disclosure::decode(&encoded);
        assert!(result.is_err());
    }
}
