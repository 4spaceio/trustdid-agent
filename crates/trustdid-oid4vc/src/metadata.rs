//! Issuer and Wallet metadata for OID4VCI / OID4VP discovery.
//!
//! Implements the metadata structures that credential issuers and wallets publish
//! at well-known endpoints for protocol discovery.

use serde::{Deserialize, Serialize};

/// Display properties for an issuer or credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisplayProperties {
    /// Human-readable name.
    pub name: String,

    /// Locale (e.g., "en-US").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Optional logo URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A supported credential definition in the issuer metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialSupported {
    /// The credential format (e.g., "jwt_vc_json", "ldp_vc").
    pub format: String,

    /// The credential types.
    pub types: Vec<String>,

    /// Display properties for this credential.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<DisplayProperties>,
}

/// Issuer metadata published at `/.well-known/openid-credential-issuer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    /// The credential issuer identifier (URL).
    pub credential_issuer: String,

    /// The credential endpoint URL.
    pub credential_endpoint: String,

    /// Token endpoint URL (for the pre-authorized code flow).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,

    /// List of credentials the issuer supports.
    pub credentials_supported: Vec<CredentialSupported>,

    /// Display properties for the issuer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<DisplayProperties>,
}

impl IssuerMetadata {
    /// Create a new issuer metadata builder.
    pub fn builder(issuer_url: impl Into<String>) -> IssuerMetadataBuilder {
        let url = issuer_url.into();
        IssuerMetadataBuilder {
            credential_issuer: url.clone(),
            credential_endpoint: format!("{url}/credentials"),
            token_endpoint: Some(format!("{url}/token")),
            credentials_supported: Vec::new(),
            display: Vec::new(),
        }
    }
}

/// Builder for issuer metadata.
pub struct IssuerMetadataBuilder {
    credential_issuer: String,
    credential_endpoint: String,
    token_endpoint: Option<String>,
    credentials_supported: Vec<CredentialSupported>,
    display: Vec<DisplayProperties>,
}

impl IssuerMetadataBuilder {
    pub fn credential_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.credential_endpoint = endpoint.into();
        self
    }

    pub fn token_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.token_endpoint = Some(endpoint.into());
        self
    }

    pub fn add_credential_supported(mut self, credential: CredentialSupported) -> Self {
        self.credentials_supported.push(credential);
        self
    }

    pub fn add_display(mut self, display: DisplayProperties) -> Self {
        self.display.push(display);
        self
    }

    pub fn build(self) -> IssuerMetadata {
        IssuerMetadata {
            credential_issuer: self.credential_issuer,
            credential_endpoint: self.credential_endpoint,
            token_endpoint: self.token_endpoint,
            credentials_supported: self.credentials_supported,
            display: self.display,
        }
    }
}

/// Supported VP format in wallet metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VPFormatSupported {
    /// The VP format identifier (e.g., "jwt_vp", "ldp_vp").
    pub format: String,

    /// Supported algorithms for this format (e.g., ["ES256", "EdDSA"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alg_values_supported: Vec<String>,
}

/// Wallet metadata describing the wallet's OID4VP capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// Whether the wallet supports receiving presentation definitions via URI.
    #[serde(default)]
    pub presentation_definition_uri_supported: bool,

    /// The VP formats the wallet supports.
    pub vp_formats_supported: Vec<VPFormatSupported>,
}

impl WalletMetadata {
    /// Create a new wallet metadata builder.
    pub fn builder() -> WalletMetadataBuilder {
        WalletMetadataBuilder {
            presentation_definition_uri_supported: false,
            vp_formats_supported: Vec::new(),
        }
    }
}

/// Builder for wallet metadata.
pub struct WalletMetadataBuilder {
    presentation_definition_uri_supported: bool,
    vp_formats_supported: Vec<VPFormatSupported>,
}

impl WalletMetadataBuilder {
    pub fn presentation_definition_uri_supported(mut self, supported: bool) -> Self {
        self.presentation_definition_uri_supported = supported;
        self
    }

    pub fn add_vp_format(mut self, format: VPFormatSupported) -> Self {
        self.vp_formats_supported.push(format);
        self
    }

    pub fn build(self) -> WalletMetadata {
        WalletMetadata {
            presentation_definition_uri_supported: self.presentation_definition_uri_supported,
            vp_formats_supported: self.vp_formats_supported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_issuer_metadata_builder() {
        let metadata = IssuerMetadata::builder("https://issuer.example.com")
            .add_credential_supported(CredentialSupported {
                format: "jwt_vc_json".to_string(),
                types: vec![
                    "VerifiableCredential".to_string(),
                    "UniversityDegreeCredential".to_string(),
                ],
                display: vec![DisplayProperties {
                    name: "University Degree".to_string(),
                    locale: Some("en-US".to_string()),
                    logo_uri: None,
                    description: Some("A degree from Example University".to_string()),
                }],
            })
            .add_display(DisplayProperties {
                name: "Example University".to_string(),
                locale: Some("en-US".to_string()),
                logo_uri: Some("https://issuer.example.com/logo.png".to_string()),
                description: None,
            })
            .build();

        assert_eq!(metadata.credential_issuer, "https://issuer.example.com");
        assert_eq!(
            metadata.credential_endpoint,
            "https://issuer.example.com/credentials"
        );
        assert_eq!(
            metadata.token_endpoint,
            Some("https://issuer.example.com/token".to_string())
        );
        assert_eq!(metadata.credentials_supported.len(), 1);
        assert_eq!(metadata.display.len(), 1);
    }

    #[test]
    fn test_issuer_metadata_serialization() {
        let metadata = IssuerMetadata::builder("https://issuer.example.com")
            .add_credential_supported(CredentialSupported {
                format: "jwt_vc_json".to_string(),
                types: vec!["VerifiableCredential".to_string()],
                display: Vec::new(),
            })
            .build();

        let json = serde_json::to_string_pretty(&metadata).unwrap();
        let parsed: IssuerMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.credential_issuer, metadata.credential_issuer);
        assert_eq!(
            parsed.credentials_supported.len(),
            metadata.credentials_supported.len()
        );
    }

    #[test]
    fn test_issuer_metadata_custom_endpoints() {
        let metadata = IssuerMetadata::builder("https://issuer.example.com")
            .credential_endpoint("https://issuer.example.com/api/v2/credentials")
            .token_endpoint("https://auth.example.com/oauth/token")
            .build();

        assert_eq!(
            metadata.credential_endpoint,
            "https://issuer.example.com/api/v2/credentials"
        );
        assert_eq!(
            metadata.token_endpoint,
            Some("https://auth.example.com/oauth/token".to_string())
        );
    }

    #[test]
    fn test_wallet_metadata_builder() {
        let metadata = WalletMetadata::builder()
            .presentation_definition_uri_supported(true)
            .add_vp_format(VPFormatSupported {
                format: "jwt_vp".to_string(),
                alg_values_supported: vec!["ES256".to_string(), "EdDSA".to_string()],
            })
            .add_vp_format(VPFormatSupported {
                format: "ldp_vp".to_string(),
                alg_values_supported: vec!["Ed25519Signature2020".to_string()],
            })
            .build();

        assert!(metadata.presentation_definition_uri_supported);
        assert_eq!(metadata.vp_formats_supported.len(), 2);
        assert_eq!(metadata.vp_formats_supported[0].format, "jwt_vp");
        assert_eq!(
            metadata.vp_formats_supported[0].alg_values_supported,
            vec!["ES256", "EdDSA"]
        );
    }

    #[test]
    fn test_wallet_metadata_serialization() {
        let metadata = WalletMetadata::builder()
            .presentation_definition_uri_supported(false)
            .add_vp_format(VPFormatSupported {
                format: "jwt_vp".to_string(),
                alg_values_supported: vec!["ES256".to_string()],
            })
            .build();

        let json = serde_json::to_string_pretty(&metadata).unwrap();
        let parsed: WalletMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.presentation_definition_uri_supported,
            metadata.presentation_definition_uri_supported
        );
        assert_eq!(
            parsed.vp_formats_supported.len(),
            metadata.vp_formats_supported.len()
        );
    }

    #[test]
    fn test_display_properties_serialization() {
        let display = DisplayProperties {
            name: "Test Issuer".to_string(),
            locale: Some("en-US".to_string()),
            logo_uri: None,
            description: Some("A test issuer".to_string()),
        };

        let json = serde_json::to_string(&display).unwrap();
        assert!(!json.contains("logo_uri")); // None fields should be skipped
        let parsed: DisplayProperties = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, display);
    }

    #[test]
    fn test_credential_supported_with_display() {
        let cred = CredentialSupported {
            format: "ldp_vc".to_string(),
            types: vec![
                "VerifiableCredential".to_string(),
                "EmployeeCredential".to_string(),
            ],
            display: vec![
                DisplayProperties {
                    name: "Employee ID".to_string(),
                    locale: Some("en-US".to_string()),
                    logo_uri: None,
                    description: None,
                },
                DisplayProperties {
                    name: "Mitarbeiterausweis".to_string(),
                    locale: Some("de-DE".to_string()),
                    logo_uri: None,
                    description: None,
                },
            ],
        };

        let json = serde_json::to_string_pretty(&cred).unwrap();
        let parsed: CredentialSupported = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.display.len(), 2);
        assert_eq!(parsed.display[1].locale, Some("de-DE".to_string()));
    }
}
