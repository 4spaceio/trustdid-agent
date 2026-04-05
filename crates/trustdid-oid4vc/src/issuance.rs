//! OpenID for Verifiable Credential Issuance (OID4VCI) flow.
//!
//! Implements the credential offer, token exchange, and credential request/response
//! cycle as defined in the OID4VCI specification.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors specific to the OID4VCI flow.
#[derive(Debug, Error)]
pub enum OID4VCIError {
    #[error("invalid credential offer: {0}")]
    InvalidOffer(String),

    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("credential request failed: {0}")]
    CredentialRequestFailed(String),

    #[error("invalid grant type: {0}")]
    InvalidGrantType(String),

    #[error("invalid pin: {0}")]
    InvalidPin(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

/// A pre-authorized code grant for the OID4VCI flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreAuthorizedCodeGrant {
    /// The pre-authorized code issued by the credential issuer.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    /// Whether a user PIN is required to redeem the code.
    #[serde(rename = "user_pin_required", default)]
    pub user_pin_required: bool,
}

/// Definition of a credential type offered by the issuer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialDefinition {
    /// The credential format (e.g., "jwt_vc_json", "ldp_vc").
    pub format: String,

    /// The credential types (e.g., ["VerifiableCredential", "UniversityDegreeCredential"]).
    pub types: Vec<String>,

    /// Optional JSON schema describing the credential subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_subject: Option<serde_json::Value>,
}

/// A credential offer from the issuer to the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The identifier of the credential issuer.
    pub credential_issuer: String,

    /// The list of credential definitions being offered.
    pub credentials: Vec<CredentialDefinition>,

    /// The pre-authorized code grant for obtaining an access token.
    pub grants: PreAuthorizedCodeGrant,
}

impl CredentialOffer {
    /// Create a new credential offer with a builder.
    pub fn builder(issuer: impl Into<String>) -> CredentialOfferBuilder {
        CredentialOfferBuilder {
            credential_issuer: issuer.into(),
            credentials: Vec::new(),
            pre_authorized_code: String::new(),
            user_pin_required: false,
        }
    }

    /// Validate the credential offer.
    pub fn validate(&self) -> Result<(), OID4VCIError> {
        if self.credential_issuer.is_empty() {
            return Err(OID4VCIError::InvalidOffer(
                "credential_issuer is empty".into(),
            ));
        }
        if self.credentials.is_empty() {
            return Err(OID4VCIError::InvalidOffer(
                "no credentials in offer".into(),
            ));
        }
        if self.grants.pre_authorized_code.is_empty() {
            return Err(OID4VCIError::InvalidOffer(
                "pre_authorized_code is empty".into(),
            ));
        }
        Ok(())
    }
}

/// Builder for creating credential offers.
pub struct CredentialOfferBuilder {
    credential_issuer: String,
    credentials: Vec<CredentialDefinition>,
    pre_authorized_code: String,
    user_pin_required: bool,
}

impl CredentialOfferBuilder {
    pub fn add_credential(mut self, definition: CredentialDefinition) -> Self {
        self.credentials.push(definition);
        self
    }

    pub fn pre_authorized_code(mut self, code: impl Into<String>) -> Self {
        self.pre_authorized_code = code.into();
        self
    }

    pub fn user_pin_required(mut self, required: bool) -> Self {
        self.user_pin_required = required;
        self
    }

    pub fn build(self) -> CredentialOffer {
        CredentialOffer {
            credential_issuer: self.credential_issuer,
            credentials: self.credentials,
            grants: PreAuthorizedCodeGrant {
                pre_authorized_code: self.pre_authorized_code,
                user_pin_required: self.user_pin_required,
            },
        }
    }
}

/// OAuth 2.0 token request for the pre-authorized code flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The grant type (must be "urn:ietf:params:oauth:grant-type:pre-authorized_code").
    pub grant_type: String,

    /// The pre-authorized code from the credential offer.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    /// The user PIN, if required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pin: Option<String>,
}

/// OAuth 2.0 token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token for credential requests.
    pub access_token: String,

    /// The token type (typically "Bearer").
    pub token_type: String,

    /// Token expiration time in seconds.
    pub expires_in: u64,

    /// Optional nonce for proof of possession.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// Optional nonce expiration time in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<u64>,
}

/// A request for a specific credential from the issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// The credential format requested.
    pub format: String,

    /// The credential types requested.
    pub types: Vec<String>,

    /// Optional proof of possession (e.g., a JWT proving holder binding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<CredentialRequestProof>,
}

/// Proof of possession included in a credential request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequestProof {
    /// The proof type (e.g., "jwt").
    pub proof_type: String,

    /// The proof value (e.g., a compact JWT string).
    pub jwt: String,
}

/// The response from the issuer containing the issued credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The credential format of the issued credential.
    pub format: String,

    /// The issued credential (JWT string or JSON-LD object).
    pub credential: serde_json::Value,

    /// Optional nonce for subsequent requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// Optional nonce expiration time in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<u64>,
}

/// The pre-authorized code grant type URI.
pub const PRE_AUTHORIZED_CODE_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// Orchestrates the OID4VCI credential issuance flow.
pub struct OID4VCIFlow {
    /// The credential issuer URL.
    issuer_url: String,

    /// Current offer being processed, if any.
    current_offer: Option<CredentialOffer>,

    /// Current access token, if any.
    access_token: Option<String>,
}

impl OID4VCIFlow {
    /// Create a new OID4VCI flow for the given issuer.
    pub fn new(issuer_url: impl Into<String>) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            current_offer: None,
            access_token: None,
        }
    }

    /// Create a credential offer from this issuer.
    pub fn create_offer(
        &mut self,
        credentials: Vec<CredentialDefinition>,
        pre_authorized_code: impl Into<String>,
        user_pin_required: bool,
    ) -> Result<CredentialOffer, OID4VCIError> {
        let offer = CredentialOffer {
            credential_issuer: self.issuer_url.clone(),
            credentials,
            grants: PreAuthorizedCodeGrant {
                pre_authorized_code: pre_authorized_code.into(),
                user_pin_required,
            },
        };
        offer.validate()?;
        self.current_offer = Some(offer.clone());
        Ok(offer)
    }

    /// Exchange a pre-authorized code for an access token.
    ///
    /// In a real implementation this would make an HTTP POST to the token endpoint.
    /// Here we validate the request and produce a simulated token response.
    pub fn exchange_token(
        &mut self,
        request: &TokenRequest,
    ) -> Result<TokenResponse, OID4VCIError> {
        if request.grant_type != PRE_AUTHORIZED_CODE_GRANT_TYPE {
            return Err(OID4VCIError::InvalidGrantType(request.grant_type.clone()));
        }

        let offer = self.current_offer.as_ref().ok_or_else(|| {
            OID4VCIError::TokenExchangeFailed("no active credential offer".into())
        })?;

        if request.pre_authorized_code != offer.grants.pre_authorized_code {
            return Err(OID4VCIError::TokenExchangeFailed(
                "pre-authorized code mismatch".into(),
            ));
        }

        if offer.grants.user_pin_required && request.user_pin.is_none() {
            return Err(OID4VCIError::InvalidPin(
                "user PIN is required but not provided".into(),
            ));
        }

        let token = uuid::Uuid::new_v4().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        self.access_token = Some(token.clone());

        Ok(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: 86400,
            c_nonce: Some(nonce),
            c_nonce_expires_in: Some(86400),
        })
    }

    /// Request a credential from the issuer using the access token.
    ///
    /// In a real implementation this would make an HTTP POST to the credential endpoint.
    /// Here we validate the request and produce a simulated credential response.
    pub fn request_credential(
        &self,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse, OID4VCIError> {
        let _token = self.access_token.as_ref().ok_or_else(|| {
            OID4VCIError::CredentialRequestFailed("no access token; call exchange_token first".into())
        })?;

        let offer = self.current_offer.as_ref().ok_or_else(|| {
            OID4VCIError::CredentialRequestFailed("no active credential offer".into())
        })?;

        // Verify the requested credential type matches something in the offer.
        let _matched = offer
            .credentials
            .iter()
            .find(|c| c.format == request.format && c.types == request.types)
            .ok_or_else(|| {
                OID4VCIError::CredentialRequestFailed(
                    "requested credential type not in offer".into(),
                )
            })?;

        let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let credential = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": request.types,
            "id": credential_id,
            "issuer": offer.credential_issuer,
            "issuanceDate": chrono::Utc::now().to_rfc3339(),
            "credentialSubject": {}
        });

        Ok(CredentialResponse {
            format: request.format.clone(),
            credential,
            c_nonce: None,
            c_nonce_expires_in: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample_credential_definition() -> CredentialDefinition {
        CredentialDefinition {
            format: "jwt_vc_json".to_string(),
            types: vec![
                "VerifiableCredential".to_string(),
                "UniversityDegreeCredential".to_string(),
            ],
            credential_subject: None,
        }
    }

    #[test]
    fn test_credential_offer_builder() {
        let offer = CredentialOffer::builder("https://issuer.example.com")
            .add_credential(sample_credential_definition())
            .pre_authorized_code("code-123")
            .user_pin_required(true)
            .build();

        assert_eq!(offer.credential_issuer, "https://issuer.example.com");
        assert_eq!(offer.credentials.len(), 1);
        assert_eq!(offer.grants.pre_authorized_code, "code-123");
        assert!(offer.grants.user_pin_required);
    }

    #[test]
    fn test_credential_offer_validation() {
        let valid = CredentialOffer::builder("https://issuer.example.com")
            .add_credential(sample_credential_definition())
            .pre_authorized_code("code-123")
            .build();
        assert!(valid.validate().is_ok());

        let empty_issuer = CredentialOffer::builder("")
            .add_credential(sample_credential_definition())
            .pre_authorized_code("code-123")
            .build();
        assert!(empty_issuer.validate().is_err());

        let no_credentials = CredentialOffer::builder("https://issuer.example.com")
            .pre_authorized_code("code-123")
            .build();
        assert!(no_credentials.validate().is_err());

        let no_code = CredentialOffer::builder("https://issuer.example.com")
            .add_credential(sample_credential_definition())
            .build();
        assert!(no_code.validate().is_err());
    }

    #[test]
    fn test_credential_offer_serialization() {
        let offer = CredentialOffer::builder("https://issuer.example.com")
            .add_credential(sample_credential_definition())
            .pre_authorized_code("code-abc")
            .user_pin_required(false)
            .build();

        let json = serde_json::to_string_pretty(&offer).unwrap();
        let parsed: CredentialOffer = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.credential_issuer, offer.credential_issuer);
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.grants.pre_authorized_code, "code-abc");
    }

    #[test]
    fn test_token_request_serialization() {
        let req = TokenRequest {
            grant_type: PRE_AUTHORIZED_CODE_GRANT_TYPE.to_string(),
            pre_authorized_code: "code-123".to_string(),
            user_pin: Some("1234".to_string()),
        };

        let json = serde_json::to_string(&req).unwrap();
        let parsed: TokenRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.grant_type, PRE_AUTHORIZED_CODE_GRANT_TYPE);
        assert_eq!(parsed.user_pin, Some("1234".to_string()));
    }

    #[test]
    fn test_full_oid4vci_flow() {
        let mut flow = OID4VCIFlow::new("https://issuer.example.com");

        // Step 1: Create offer
        let offer = flow
            .create_offer(
                vec![sample_credential_definition()],
                "pre-auth-code-42",
                false,
            )
            .unwrap();
        assert_eq!(offer.credential_issuer, "https://issuer.example.com");

        // Step 2: Exchange token
        let token_req = TokenRequest {
            grant_type: PRE_AUTHORIZED_CODE_GRANT_TYPE.to_string(),
            pre_authorized_code: "pre-auth-code-42".to_string(),
            user_pin: None,
        };
        let token_resp = flow.exchange_token(&token_req).unwrap();
        assert_eq!(token_resp.token_type, "Bearer");
        assert!(!token_resp.access_token.is_empty());
        assert!(token_resp.c_nonce.is_some());

        // Step 3: Request credential
        let cred_req = CredentialRequest {
            format: "jwt_vc_json".to_string(),
            types: vec![
                "VerifiableCredential".to_string(),
                "UniversityDegreeCredential".to_string(),
            ],
            proof: None,
        };
        let cred_resp = flow.request_credential(&cred_req).unwrap();
        assert_eq!(cred_resp.format, "jwt_vc_json");
        assert!(cred_resp.credential.get("issuer").is_some());
    }

    #[test]
    fn test_token_exchange_wrong_grant_type() {
        let mut flow = OID4VCIFlow::new("https://issuer.example.com");
        flow.create_offer(
            vec![sample_credential_definition()],
            "code-1",
            false,
        )
        .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            pre_authorized_code: "code-1".to_string(),
            user_pin: None,
        };
        assert!(flow.exchange_token(&req).is_err());
    }

    #[test]
    fn test_token_exchange_wrong_code() {
        let mut flow = OID4VCIFlow::new("https://issuer.example.com");
        flow.create_offer(
            vec![sample_credential_definition()],
            "code-1",
            false,
        )
        .unwrap();

        let req = TokenRequest {
            grant_type: PRE_AUTHORIZED_CODE_GRANT_TYPE.to_string(),
            pre_authorized_code: "wrong-code".to_string(),
            user_pin: None,
        };
        assert!(flow.exchange_token(&req).is_err());
    }

    #[test]
    fn test_token_exchange_pin_required() {
        let mut flow = OID4VCIFlow::new("https://issuer.example.com");
        flow.create_offer(
            vec![sample_credential_definition()],
            "code-1",
            true,
        )
        .unwrap();

        // Missing PIN should fail.
        let req_no_pin = TokenRequest {
            grant_type: PRE_AUTHORIZED_CODE_GRANT_TYPE.to_string(),
            pre_authorized_code: "code-1".to_string(),
            user_pin: None,
        };
        assert!(flow.exchange_token(&req_no_pin).is_err());

        // With PIN should succeed.
        let req_with_pin = TokenRequest {
            grant_type: PRE_AUTHORIZED_CODE_GRANT_TYPE.to_string(),
            pre_authorized_code: "code-1".to_string(),
            user_pin: Some("9999".to_string()),
        };
        assert!(flow.exchange_token(&req_with_pin).is_ok());
    }

    #[test]
    fn test_credential_request_without_token() {
        let flow = OID4VCIFlow::new("https://issuer.example.com");
        let req = CredentialRequest {
            format: "jwt_vc_json".to_string(),
            types: vec!["VerifiableCredential".to_string()],
            proof: None,
        };
        assert!(flow.request_credential(&req).is_err());
    }

    #[test]
    fn test_credential_request_unmatched_type() {
        let mut flow = OID4VCIFlow::new("https://issuer.example.com");
        flow.create_offer(
            vec![sample_credential_definition()],
            "code-1",
            false,
        )
        .unwrap();

        let token_req = TokenRequest {
            grant_type: PRE_AUTHORIZED_CODE_GRANT_TYPE.to_string(),
            pre_authorized_code: "code-1".to_string(),
            user_pin: None,
        };
        flow.exchange_token(&token_req).unwrap();

        // Request a credential type not in the offer.
        let cred_req = CredentialRequest {
            format: "ldp_vc".to_string(),
            types: vec!["SomeOtherCredential".to_string()],
            proof: None,
        };
        assert!(flow.request_credential(&cred_req).is_err());
    }
}
