//! Core types for the SD-JWT implementation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::disclosure::Disclosure;

/// An SD-JWT token consisting of a JWT payload, a set of disclosures,
/// and an optional key binding JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwt {
    /// The JWT payload (with `_sd` digest arrays replacing selectively disclosable claims).
    pub jwt_payload: serde_json::Value,
    /// The set of disclosures associated with this SD-JWT.
    pub disclosures: Vec<Disclosure>,
    /// An optional key binding JWT proving holder possession.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_binding_jwt: Option<String>,
}

impl SdJwt {
    /// Serialize to the SD-JWT compact format:
    /// `<jwt_payload_b64>~<disclosure1>~<disclosure2>~[<kb_jwt>]`
    ///
    /// The JWT payload is base64url-encoded JSON. Each disclosure is already
    /// base64url-encoded. A trailing `~` is always present after the last disclosure.
    pub fn compact(&self) -> String {
        use base64::Engine;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let payload_json = serde_json::to_string(&self.jwt_payload)
            .expect("JWT payload must be serializable");
        let payload_b64 = engine.encode(payload_json.as_bytes());

        let mut parts = vec![payload_b64];
        for disclosure in &self.disclosures {
            parts.push(disclosure.encode());
        }

        let mut result = parts.join("~");
        result.push('~');

        if let Some(ref kb) = self.key_binding_jwt {
            result.push_str(kb);
        }

        result
    }

    /// Parse an SD-JWT from its compact serialization format.
    pub fn parse(compact: &str) -> Result<Self, SdJwtError> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Split on '~' — the first element is the JWT payload, the last might be
        // a key binding JWT (or empty), and everything in between is a disclosure.
        let parts: Vec<&str> = compact.split('~').collect();
        if parts.len() < 2 {
            return Err(SdJwtError::InvalidFormat(
                "compact SD-JWT must contain at least a payload and one separator".into(),
            ));
        }

        // Decode the JWT payload (first part).
        let payload_bytes = engine
            .decode(parts[0])
            .map_err(|e| SdJwtError::InvalidFormat(format!("invalid base64url payload: {e}")))?;
        let jwt_payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| SdJwtError::InvalidFormat(format!("invalid JSON payload: {e}")))?;

        // The last element after the final '~' is either a key binding JWT or empty.
        let last = *parts.last().unwrap();
        let key_binding_jwt = if last.is_empty() { None } else { Some(last.to_string()) };

        // Disclosures are everything between the payload and the trailing element.
        let disclosure_end = if key_binding_jwt.is_some() {
            parts.len() - 1
        } else {
            parts.len() - 1
        };

        let mut disclosures = Vec::new();
        for encoded in &parts[1..disclosure_end] {
            if encoded.is_empty() {
                continue;
            }
            let d = Disclosure::decode(encoded)?;
            disclosures.push(d);
        }

        Ok(Self {
            jwt_payload,
            disclosures,
            key_binding_jwt,
        })
    }
}

/// The result of verifying an SD-JWT, containing the fully disclosed claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedClaims {
    /// The reconstructed claims map after processing all disclosures.
    pub claims: HashMap<String, serde_json::Value>,
}

/// Errors that can occur during SD-JWT processing.
#[derive(Debug, thiserror::Error)]
pub enum SdJwtError {
    #[error("invalid SD-JWT format: {0}")]
    InvalidFormat(String),

    #[error("invalid disclosure: {0}")]
    InvalidDisclosure(String),

    #[error("digest mismatch: disclosure digest not found in _sd array")]
    DigestMismatch,

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("cryptographic error: {0}")]
    CryptoError(String),
}

impl From<serde_json::Error> for SdJwtError {
    fn from(e: serde_json::Error) -> Self {
        SdJwtError::SerializationError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclosure::Disclosure;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_sd_jwt_compact_roundtrip_no_disclosures() {
        let payload = serde_json::json!({
            "sub": "did:example:123",
            "iss": "did:example:issuer"
        });

        let sd_jwt = SdJwt {
            jwt_payload: payload.clone(),
            disclosures: vec![],
            key_binding_jwt: None,
        };

        let compact = sd_jwt.compact();
        assert!(compact.ends_with('~'), "compact format must end with ~");

        let parsed = SdJwt::parse(&compact).expect("should parse");
        assert_eq!(parsed.jwt_payload, payload);
        assert!(parsed.disclosures.is_empty());
        assert!(parsed.key_binding_jwt.is_none());
    }

    #[test]
    fn test_sd_jwt_compact_roundtrip_with_disclosures() {
        let disclosure1 = Disclosure::new("given_name", &serde_json::json!("Alice"));
        let disclosure2 = Disclosure::new("email", &serde_json::json!("alice@example.com"));

        let payload = serde_json::json!({
            "iss": "did:example:issuer",
            "_sd": [disclosure1.digest(), disclosure2.digest()]
        });

        let sd_jwt = SdJwt {
            jwt_payload: payload.clone(),
            disclosures: vec![disclosure1.clone(), disclosure2.clone()],
            key_binding_jwt: None,
        };

        let compact = sd_jwt.compact();
        let parsed = SdJwt::parse(&compact).expect("should parse");

        assert_eq!(parsed.jwt_payload, payload);
        assert_eq!(parsed.disclosures.len(), 2);
        assert_eq!(parsed.disclosures[0].claim_name, "given_name");
        assert_eq!(parsed.disclosures[1].claim_name, "email");
    }

    #[test]
    fn test_sd_jwt_compact_with_key_binding() {
        let payload = serde_json::json!({"sub": "user"});

        let sd_jwt = SdJwt {
            jwt_payload: payload.clone(),
            disclosures: vec![],
            key_binding_jwt: Some("kb-jwt-token".to_string()),
        };

        let compact = sd_jwt.compact();
        assert!(compact.ends_with("kb-jwt-token"));

        let parsed = SdJwt::parse(&compact).expect("should parse");
        assert_eq!(parsed.key_binding_jwt, Some("kb-jwt-token".to_string()));
    }

    #[test]
    fn test_sd_jwt_parse_invalid() {
        let result = SdJwt::parse("not-valid");
        assert!(result.is_err());
    }

    #[test]
    fn test_verified_claims_serialize() {
        let mut claims = HashMap::new();
        claims.insert("name".to_string(), serde_json::json!("Alice"));

        let vc = VerifiedClaims { claims };
        let json = serde_json::to_string(&vc).expect("should serialize");
        assert!(json.contains("Alice"));
    }
}
