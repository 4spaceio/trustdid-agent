//! OpenID for Verifiable Presentations (OID4VP) flow.
//!
//! Implements the presentation definition, authorization request/response,
//! and presentation submission verification as defined in the OID4VP specification.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors specific to the OID4VP flow.
#[derive(Debug, Error)]
pub enum OID4VPError {
    #[error("invalid presentation definition: {0}")]
    InvalidPresentationDefinition(String),

    #[error("invalid authorization request: {0}")]
    InvalidAuthorizationRequest(String),

    #[error("invalid authorization response: {0}")]
    InvalidAuthorizationResponse(String),

    #[error("submission verification failed: {0}")]
    VerificationFailed(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

/// A field constraint within an input descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Field {
    /// JSONPath expressions identifying the target field(s).
    pub path: Vec<String>,

    /// Optional JSON Schema filter for the field value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
}

/// Constraints on the claims required by an input descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Constraints {
    /// The fields that must be present in the credential.
    pub fields: Vec<Field>,
}

/// An input descriptor specifying which credential claims are required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    /// Unique identifier for this input descriptor.
    pub id: String,

    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Human-readable purpose description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// Constraints on the claims required.
    pub constraints: Constraints,
}

/// A presentation definition describing what credentials the verifier requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    /// Unique identifier for this presentation definition.
    pub id: String,

    /// The input descriptors specifying required credentials and claims.
    pub input_descriptors: Vec<InputDescriptor>,
}

impl PresentationDefinition {
    /// Create a new presentation definition with a builder.
    pub fn builder(id: impl Into<String>) -> PresentationDefinitionBuilder {
        PresentationDefinitionBuilder {
            id: id.into(),
            input_descriptors: Vec::new(),
        }
    }

    /// Validate the presentation definition.
    pub fn validate(&self) -> Result<(), OID4VPError> {
        if self.id.is_empty() {
            return Err(OID4VPError::InvalidPresentationDefinition(
                "id is empty".into(),
            ));
        }
        if self.input_descriptors.is_empty() {
            return Err(OID4VPError::InvalidPresentationDefinition(
                "no input descriptors".into(),
            ));
        }
        for desc in &self.input_descriptors {
            if desc.id.is_empty() {
                return Err(OID4VPError::InvalidPresentationDefinition(
                    "input descriptor id is empty".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Builder for creating presentation definitions.
pub struct PresentationDefinitionBuilder {
    id: String,
    input_descriptors: Vec<InputDescriptor>,
}

impl PresentationDefinitionBuilder {
    pub fn add_input_descriptor(mut self, descriptor: InputDescriptor) -> Self {
        self.input_descriptors.push(descriptor);
        self
    }

    pub fn build(self) -> PresentationDefinition {
        PresentationDefinition {
            id: self.id,
            input_descriptors: self.input_descriptors,
        }
    }
}

/// An OID4VP authorization request from the verifier to the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The response type (must be "vp_token").
    pub response_type: String,

    /// The verifier's client identifier (typically a DID or URL).
    pub client_id: String,

    /// The redirect URI where the wallet sends the response.
    pub redirect_uri: String,

    /// The presentation definition describing required credentials.
    pub presentation_definition: PresentationDefinition,

    /// A unique nonce to bind the presentation to this request.
    pub nonce: String,

    /// An opaque state value for session correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl AuthorizationRequest {
    /// Validate the authorization request.
    pub fn validate(&self) -> Result<(), OID4VPError> {
        if self.response_type != "vp_token" {
            return Err(OID4VPError::InvalidAuthorizationRequest(format!(
                "response_type must be 'vp_token', got '{}'",
                self.response_type
            )));
        }
        if self.client_id.is_empty() {
            return Err(OID4VPError::InvalidAuthorizationRequest(
                "client_id is empty".into(),
            ));
        }
        if self.redirect_uri.is_empty() {
            return Err(OID4VPError::InvalidAuthorizationRequest(
                "redirect_uri is empty".into(),
            ));
        }
        if self.nonce.is_empty() {
            return Err(OID4VPError::InvalidAuthorizationRequest(
                "nonce is empty".into(),
            ));
        }
        self.presentation_definition.validate()?;
        Ok(())
    }
}

/// A descriptor map entry within a presentation submission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DescriptorMapEntry {
    /// The id of the input descriptor this entry satisfies.
    pub id: String,

    /// The credential format (e.g., "jwt_vp").
    pub format: String,

    /// JSONPath to the credential within the vp_token.
    pub path: String,
}

/// A presentation submission describing how the vp_token satisfies the definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    /// Unique identifier for this submission.
    pub id: String,

    /// The id of the presentation definition being satisfied.
    pub definition_id: String,

    /// Mapping from input descriptors to credentials in the vp_token.
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

/// An OID4VP authorization response from the wallet to the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The verifiable presentation token (JWT or JSON-LD VP).
    pub vp_token: serde_json::Value,

    /// The presentation submission describing the mapping.
    pub presentation_submission: PresentationSubmission,

    /// The state from the authorization request, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Orchestrates the OID4VP presentation flow.
pub struct OID4VPFlow {
    /// The verifier's client identifier.
    client_id: String,
}

impl OID4VPFlow {
    /// Create a new OID4VP flow for the given verifier.
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
        }
    }

    /// Create an authorization request to send to the wallet.
    pub fn create_request(
        &self,
        presentation_definition: PresentationDefinition,
        redirect_uri: impl Into<String>,
        nonce: impl Into<String>,
        state: Option<String>,
    ) -> Result<AuthorizationRequest, OID4VPError> {
        let request = AuthorizationRequest {
            response_type: "vp_token".to_string(),
            client_id: self.client_id.clone(),
            redirect_uri: redirect_uri.into(),
            presentation_definition,
            nonce: nonce.into(),
            state,
        };
        request.validate()?;
        Ok(request)
    }

    /// Create an authorization response from the wallet side.
    pub fn create_response(
        &self,
        vp_token: serde_json::Value,
        submission: PresentationSubmission,
        state: Option<String>,
    ) -> Result<AuthorizationResponse, OID4VPError> {
        if submission.descriptor_map.is_empty() {
            return Err(OID4VPError::InvalidAuthorizationResponse(
                "descriptor_map is empty".into(),
            ));
        }

        Ok(AuthorizationResponse {
            vp_token,
            presentation_submission: submission,
            state,
        })
    }

    /// Verify that a submission correctly maps to the presentation definition.
    pub fn verify_submission(
        &self,
        definition: &PresentationDefinition,
        submission: &PresentationSubmission,
    ) -> Result<bool, OID4VPError> {
        if submission.definition_id != definition.id {
            return Err(OID4VPError::VerificationFailed(format!(
                "definition_id mismatch: expected '{}', got '{}'",
                definition.id, submission.definition_id
            )));
        }

        // Check that every input descriptor is satisfied by a descriptor map entry.
        for input_desc in &definition.input_descriptors {
            let found = submission
                .descriptor_map
                .iter()
                .any(|entry| entry.id == input_desc.id);
            if !found {
                return Err(OID4VPError::VerificationFailed(format!(
                    "input descriptor '{}' not satisfied in submission",
                    input_desc.id
                )));
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample_input_descriptor() -> InputDescriptor {
        InputDescriptor {
            id: "degree_credential".to_string(),
            name: Some("University Degree".to_string()),
            purpose: Some("Verify education credentials".to_string()),
            constraints: Constraints {
                fields: vec![
                    Field {
                        path: vec!["$.credentialSubject.degree.type".to_string()],
                        filter: Some(serde_json::json!({
                            "type": "string",
                            "const": "BachelorDegree"
                        })),
                    },
                    Field {
                        path: vec!["$.credentialSubject.degree.name".to_string()],
                        filter: None,
                    },
                ],
            },
        }
    }

    fn sample_presentation_definition() -> PresentationDefinition {
        PresentationDefinition::builder("pd-1")
            .add_input_descriptor(sample_input_descriptor())
            .build()
    }

    #[test]
    fn test_presentation_definition_builder() {
        let pd = sample_presentation_definition();
        assert_eq!(pd.id, "pd-1");
        assert_eq!(pd.input_descriptors.len(), 1);
        assert_eq!(pd.input_descriptors[0].id, "degree_credential");
        assert_eq!(pd.input_descriptors[0].constraints.fields.len(), 2);
    }

    #[test]
    fn test_presentation_definition_validation() {
        let valid = sample_presentation_definition();
        assert!(valid.validate().is_ok());

        let empty_id = PresentationDefinition {
            id: String::new(),
            input_descriptors: vec![sample_input_descriptor()],
        };
        assert!(empty_id.validate().is_err());

        let no_descriptors = PresentationDefinition {
            id: "pd-1".to_string(),
            input_descriptors: Vec::new(),
        };
        assert!(no_descriptors.validate().is_err());
    }

    #[test]
    fn test_presentation_definition_serialization() {
        let pd = sample_presentation_definition();
        let json = serde_json::to_string_pretty(&pd).unwrap();
        let parsed: PresentationDefinition = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, pd.id);
        assert_eq!(parsed.input_descriptors.len(), 1);
        assert_eq!(
            parsed.input_descriptors[0].constraints.fields[0].path,
            vec!["$.credentialSubject.degree.type"]
        );
    }

    #[test]
    fn test_authorization_request_creation() {
        let flow = OID4VPFlow::new("did:trustagent:keri:org:z6MkVerifier");
        let pd = sample_presentation_definition();

        let request = flow
            .create_request(
                pd,
                "https://verifier.example.com/callback",
                "nonce-abc-123",
                Some("state-xyz".to_string()),
            )
            .unwrap();

        assert_eq!(request.response_type, "vp_token");
        assert_eq!(request.client_id, "did:trustagent:keri:org:z6MkVerifier");
        assert_eq!(request.nonce, "nonce-abc-123");
        assert_eq!(request.state, Some("state-xyz".to_string()));
    }

    #[test]
    fn test_authorization_request_validation() {
        let flow = OID4VPFlow::new("did:trustagent:keri:org:z6MkVerifier");

        // Empty redirect_uri should fail via validate in create_request.
        let pd = sample_presentation_definition();
        let result = flow.create_request(pd, "", "nonce-1", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorization_response_creation() {
        let flow = OID4VPFlow::new("did:trustagent:keri:org:z6MkVerifier");

        let vp_token = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": []
        });

        let submission = PresentationSubmission {
            id: "submission-1".to_string(),
            definition_id: "pd-1".to_string(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "degree_credential".to_string(),
                format: "jwt_vp".to_string(),
                path: "$".to_string(),
            }],
        };

        let response = flow
            .create_response(vp_token, submission, Some("state-xyz".to_string()))
            .unwrap();

        assert!(response.vp_token.get("type").is_some());
        assert_eq!(response.presentation_submission.definition_id, "pd-1");
        assert_eq!(response.state, Some("state-xyz".to_string()));
    }

    #[test]
    fn test_authorization_response_empty_descriptor_map() {
        let flow = OID4VPFlow::new("did:trustagent:keri:org:z6MkVerifier");

        let submission = PresentationSubmission {
            id: "submission-1".to_string(),
            definition_id: "pd-1".to_string(),
            descriptor_map: Vec::new(),
        };

        let result =
            flow.create_response(serde_json::json!({}), submission, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_submission_success() {
        let flow = OID4VPFlow::new("did:trustagent:keri:org:z6MkVerifier");
        let pd = sample_presentation_definition();

        let submission = PresentationSubmission {
            id: "submission-1".to_string(),
            definition_id: "pd-1".to_string(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "degree_credential".to_string(),
                format: "jwt_vp".to_string(),
                path: "$".to_string(),
            }],
        };

        let result = flow.verify_submission(&pd, &submission).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_submission_definition_mismatch() {
        let flow = OID4VPFlow::new("did:trustagent:keri:org:z6MkVerifier");
        let pd = sample_presentation_definition();

        let submission = PresentationSubmission {
            id: "submission-1".to_string(),
            definition_id: "wrong-pd-id".to_string(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "degree_credential".to_string(),
                format: "jwt_vp".to_string(),
                path: "$".to_string(),
            }],
        };

        assert!(flow.verify_submission(&pd, &submission).is_err());
    }

    #[test]
    fn test_verify_submission_missing_descriptor() {
        let flow = OID4VPFlow::new("did:trustagent:keri:org:z6MkVerifier");
        let pd = sample_presentation_definition();

        let submission = PresentationSubmission {
            id: "submission-1".to_string(),
            definition_id: "pd-1".to_string(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "some_other_credential".to_string(),
                format: "jwt_vp".to_string(),
                path: "$".to_string(),
            }],
        };

        assert!(flow.verify_submission(&pd, &submission).is_err());
    }

    #[test]
    fn test_field_with_filter_serialization() {
        let field = Field {
            path: vec!["$.credentialSubject.name".to_string()],
            filter: Some(serde_json::json!({"type": "string"})),
        };

        let json = serde_json::to_string(&field).unwrap();
        let parsed: Field = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path, field.path);
        assert_eq!(parsed.filter, field.filter);
    }

    #[test]
    fn test_field_without_filter_serialization() {
        let field = Field {
            path: vec!["$.credentialSubject.age".to_string()],
            filter: None,
        };

        let json = serde_json::to_string(&field).unwrap();
        assert!(!json.contains("filter"));
    }
}
