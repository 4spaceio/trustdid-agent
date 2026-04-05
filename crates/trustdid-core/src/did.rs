use crate::{AgentClass, Network, Result, TrustDIDError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

const METHOD_NAME: &str = "trustagent";

/// A parsed `did:trustagent` identifier.
///
/// Format: `did:trustagent:<network>:<agent-class>:<identifier>`
///
/// Examples:
/// - `did:trustagent:evm:137:delegated:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP`
/// - `did:trustagent:keri:autonomous:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`
/// - `did:trustagent:web:example.com:org:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2xJfmm7M8Go8J`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DID {
    pub network: Network,
    pub agent_class: AgentClass,
    pub identifier: String,
}

impl DID {
    pub fn new(network: Network, agent_class: AgentClass, identifier: impl Into<String>) -> Self {
        Self {
            network,
            agent_class,
            identifier: identifier.into(),
        }
    }

    pub fn method() -> &'static str {
        METHOD_NAME
    }

    pub fn to_uri(&self) -> String {
        format!(
            "did:{}:{}:{}:{}",
            METHOD_NAME,
            self.network.as_method_segment(),
            self.agent_class.as_str(),
            self.identifier
        )
    }

    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();

        if !input.starts_with("did:") {
            return Err(TrustDIDError::InvalidDID(
                "must start with 'did:'".to_string(),
            ));
        }

        let rest = &input[4..];
        let parts: Vec<&str> = rest.split(':').collect();

        if parts.is_empty() || parts[0] != METHOD_NAME {
            return Err(TrustDIDError::InvalidDID(format!(
                "method must be '{METHOD_NAME}', got '{}'",
                parts.first().unwrap_or(&"")
            )));
        }

        // Minimum: method + network_type + agent_class + identifier = 4 parts
        // With EVM: method + evm + chain_id + agent_class + identifier = 5 parts
        // With Web: method + web + domain + agent_class + identifier = 5 parts
        // With KERI: method + keri + agent_class + identifier = 4 parts
        if parts.len() < 4 {
            return Err(TrustDIDError::InvalidDID(
                "not enough segments".to_string(),
            ));
        }

        let (network, agent_class_idx) = match parts[1] {
            "evm" => {
                if parts.len() < 5 {
                    return Err(TrustDIDError::InvalidDID(
                        "EVM network requires chain ID".to_string(),
                    ));
                }
                (Network::from_segments(&parts[1..3])?, 3)
            }
            "keri" => (Network::Keri, 2),
            "web" => {
                if parts.len() < 5 {
                    return Err(TrustDIDError::InvalidDID(
                        "Web network requires domain".to_string(),
                    ));
                }
                (Network::from_segments(&parts[1..3])?, 3)
            }
            other => {
                return Err(TrustDIDError::UnsupportedNetwork(other.to_string()));
            }
        };

        if agent_class_idx + 1 >= parts.len() {
            return Err(TrustDIDError::InvalidDID(
                "missing agent class or identifier".to_string(),
            ));
        }

        let agent_class = AgentClass::from_str(parts[agent_class_idx])?;
        let identifier = parts[agent_class_idx + 1..].join(":");

        if identifier.is_empty() {
            return Err(TrustDIDError::InvalidDID(
                "identifier cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            network,
            agent_class,
            identifier,
        })
    }
}

impl fmt::Display for DID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_uri())
    }
}

impl FromStr for DID {
    type Err = TrustDIDError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_evm_did() {
        let did_str = "did:trustagent:evm:137:delegated:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";
        let did = DID::parse(did_str).unwrap();

        assert_eq!(did.network, Network::Evm(137));
        assert_eq!(did.agent_class, AgentClass::Delegated);
        assert_eq!(did.identifier, "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP");
        assert_eq!(did.to_uri(), did_str);
    }

    #[test]
    fn test_parse_keri_did() {
        let did_str = "did:trustagent:keri:autonomous:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let did = DID::parse(did_str).unwrap();

        assert_eq!(did.network, Network::Keri);
        assert_eq!(did.agent_class, AgentClass::Autonomous);
        assert_eq!(did.identifier, "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(did.to_uri(), did_str);
    }

    #[test]
    fn test_parse_web_did() {
        let did_str = "did:trustagent:web:example.com:org:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2xJfmm7M8Go8J";
        let did = DID::parse(did_str).unwrap();

        assert_eq!(did.network, Network::Web("example.com".into()));
        assert_eq!(did.agent_class, AgentClass::Org);
        assert_eq!(did.identifier, "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2xJfmm7M8Go8J");
        assert_eq!(did.to_uri(), did_str);
    }

    #[test]
    fn test_parse_ethereum_mainnet() {
        let did_str = "did:trustagent:evm:1:human:z6MkpTHR8VNs5xhqzV43EYm1VNkKCX2i3s9WnHJA11Yi5GQa";
        let did = DID::parse(did_str).unwrap();

        assert_eq!(did.network, Network::Evm(1));
        assert_eq!(did.agent_class, AgentClass::Human);
    }

    #[test]
    fn test_parse_ephemeral() {
        let did_str = "did:trustagent:evm:137:ephemeral:z6Mktemp123";
        let did = DID::parse(did_str).unwrap();

        assert_eq!(did.agent_class, AgentClass::Ephemeral);
    }

    #[test]
    fn test_roundtrip() {
        let original = DID::new(
            Network::Evm(42161),
            AgentClass::Autonomous,
            "z6MkTestIdentifier",
        );
        let uri = original.to_uri();
        let parsed = DID::parse(&uri).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_invalid_prefix() {
        assert!(DID::parse("notadid:trustagent:keri:autonomous:abc").is_err());
    }

    #[test]
    fn test_wrong_method() {
        assert!(DID::parse("did:web:example.com").is_err());
    }

    #[test]
    fn test_missing_segments() {
        assert!(DID::parse("did:trustagent:evm").is_err());
        assert!(DID::parse("did:trustagent:evm:137").is_err());
        assert!(DID::parse("did:trustagent:evm:137:delegated").is_err());
    }

    #[test]
    fn test_invalid_agent_class() {
        assert!(DID::parse("did:trustagent:keri:robot:z6MkTest").is_err());
    }

    #[test]
    fn test_invalid_network() {
        assert!(DID::parse("did:trustagent:btc:autonomous:z6MkTest").is_err());
    }

    #[test]
    fn test_from_str_trait() {
        let did: DID = "did:trustagent:keri:autonomous:z6MkTest".parse().unwrap();
        assert_eq!(did.agent_class, AgentClass::Autonomous);
    }

    #[test]
    fn test_display_trait() {
        let did = DID::new(Network::Evm(137), AgentClass::Delegated, "z6MkTest");
        assert_eq!(
            format!("{did}"),
            "did:trustagent:evm:137:delegated:z6MkTest"
        );
    }
}
