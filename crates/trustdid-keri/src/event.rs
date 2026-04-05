//! Key Event types for KERI-inspired key management.
//!
//! Defines the core event types that form the Key Event Log:
//! inception, rotation, interaction, and delegated inception.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A KERI-inspired key event representing a state change for an identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum KeyEvent {
    /// Initial identity establishment event.
    #[serde(rename = "icp")]
    Inception {
        /// The self-addressing identifier (prefix) for this identity.
        prefix: String,
        /// Current signing keys (public key bytes).
        keys: Vec<Vec<u8>>,
        /// Pre-rotation commitment: digest of the next key set.
        next_key_digest: String,
        /// Witness identifiers that should provide receipts.
        witnesses: Vec<String>,
        /// Signing threshold (number of keys required).
        threshold: usize,
    },

    /// Key rotation event -- proves pre-rotation commitment and establishes new keys.
    #[serde(rename = "rot")]
    Rotation {
        /// The identifier being rotated.
        prefix: String,
        /// Digest of the previous event in the KEL.
        previous_digest: String,
        /// New current signing keys.
        keys: Vec<Vec<u8>>,
        /// New pre-rotation commitment for the *next* rotation.
        next_key_digest: String,
    },

    /// Interaction event -- a non-key-change event that anchors data.
    #[serde(rename = "ixn")]
    Interaction {
        /// The identifier this event belongs to.
        prefix: String,
        /// Digest of the previous event in the KEL.
        previous_digest: String,
        /// Arbitrary anchored data (seals, digests, etc.).
        data: serde_json::Value,
    },

    /// Delegated inception -- an inception whose authority derives from a delegator.
    #[serde(rename = "dip")]
    Delegated {
        /// The delegated identifier (prefix).
        prefix: String,
        /// The delegator's identifier.
        delegator: String,
        /// Current signing keys.
        keys: Vec<Vec<u8>>,
        /// Pre-rotation commitment.
        next_key_digest: String,
    },
}

impl KeyEvent {
    /// Compute the SHA-256 digest of this event's canonical JSON serialization.
    pub fn digest(&self) -> String {
        let serialized = serde_json::to_vec(self).expect("KeyEvent serialization cannot fail");
        let hash = Sha256::digest(&serialized);
        // Encode as hex for deterministic, human-readable digests.
        hex::encode(hash)
    }

    /// Return the prefix (identifier) associated with this event.
    pub fn prefix(&self) -> &str {
        match self {
            Self::Inception { prefix, .. }
            | Self::Rotation { prefix, .. }
            | Self::Interaction { prefix, .. }
            | Self::Delegated { prefix, .. } => prefix,
        }
    }

    /// Return the keys carried by this event, if any.
    pub fn keys(&self) -> Option<&[Vec<u8>]> {
        match self {
            Self::Inception { keys, .. }
            | Self::Rotation { keys, .. }
            | Self::Delegated { keys, .. } => Some(keys),
            Self::Interaction { .. } => None,
        }
    }

    /// Return the next-key digest (pre-rotation commitment), if present.
    pub fn next_key_digest(&self) -> Option<&str> {
        match self {
            Self::Inception {
                next_key_digest, ..
            }
            | Self::Rotation {
                next_key_digest, ..
            }
            | Self::Delegated {
                next_key_digest, ..
            } => Some(next_key_digest),
            Self::Interaction { .. } => None,
        }
    }

    /// Return the previous-event digest, if present (not on inception/delegated).
    pub fn previous_digest(&self) -> Option<&str> {
        match self {
            Self::Rotation {
                previous_digest, ..
            }
            | Self::Interaction {
                previous_digest, ..
            } => Some(previous_digest),
            Self::Inception { .. } | Self::Delegated { .. } => None,
        }
    }

    /// Returns `true` if this is an establishment event (inception, rotation, delegated).
    pub fn is_establishment(&self) -> bool {
        matches!(
            self,
            Self::Inception { .. } | Self::Rotation { .. } | Self::Delegated { .. }
        )
    }
}

/// Small helper -- `hex` is a lightweight crate we avoid by inlining.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample_inception() -> KeyEvent {
        KeyEvent::Inception {
            prefix: "did:trustdid:keri:abc123".into(),
            keys: vec![vec![1, 2, 3, 4]],
            next_key_digest: "nkd_commitment_hash".into(),
            witnesses: vec!["witness-1".into()],
            threshold: 1,
        }
    }

    fn sample_rotation(prev: &str) -> KeyEvent {
        KeyEvent::Rotation {
            prefix: "did:trustdid:keri:abc123".into(),
            previous_digest: prev.into(),
            keys: vec![vec![5, 6, 7, 8]],
            next_key_digest: "nkd_next_commitment".into(),
        }
    }

    #[test]
    fn test_inception_prefix() {
        let evt = sample_inception();
        assert_eq!(evt.prefix(), "did:trustdid:keri:abc123");
    }

    #[test]
    fn test_rotation_prefix() {
        let evt = sample_rotation("digest0");
        assert_eq!(evt.prefix(), "did:trustdid:keri:abc123");
    }

    #[test]
    fn test_interaction_prefix() {
        let evt = KeyEvent::Interaction {
            prefix: "did:trustdid:keri:abc123".into(),
            previous_digest: "prev".into(),
            data: serde_json::json!({"anchor": "seal"}),
        };
        assert_eq!(evt.prefix(), "did:trustdid:keri:abc123");
    }

    #[test]
    fn test_delegated_prefix() {
        let evt = KeyEvent::Delegated {
            prefix: "did:trustdid:keri:child".into(),
            delegator: "did:trustdid:keri:parent".into(),
            keys: vec![vec![10, 20]],
            next_key_digest: "nkd".into(),
        };
        assert_eq!(evt.prefix(), "did:trustdid:keri:child");
    }

    #[test]
    fn test_digest_deterministic() {
        let evt = sample_inception();
        let d1 = evt.digest();
        let d2 = evt.digest();
        assert_eq!(d1, d2);
        assert!(!d1.is_empty());
        // SHA-256 hex is 64 chars
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn test_digest_different_for_different_events() {
        let icp = sample_inception();
        let rot = sample_rotation("some_digest");
        assert_ne!(icp.digest(), rot.digest());
    }

    #[test]
    fn test_keys_accessor() {
        let icp = sample_inception();
        assert_eq!(icp.keys().unwrap(), &[vec![1u8, 2, 3, 4]]);

        let ixn = KeyEvent::Interaction {
            prefix: "p".into(),
            previous_digest: "d".into(),
            data: serde_json::Value::Null,
        };
        assert!(ixn.keys().is_none());
    }

    #[test]
    fn test_next_key_digest_accessor() {
        let icp = sample_inception();
        assert_eq!(icp.next_key_digest(), Some("nkd_commitment_hash"));

        let ixn = KeyEvent::Interaction {
            prefix: "p".into(),
            previous_digest: "d".into(),
            data: serde_json::Value::Null,
        };
        assert!(ixn.next_key_digest().is_none());
    }

    #[test]
    fn test_previous_digest_accessor() {
        let rot = sample_rotation("prev_hash");
        assert_eq!(rot.previous_digest(), Some("prev_hash"));

        let icp = sample_inception();
        assert!(icp.previous_digest().is_none());
    }

    #[test]
    fn test_is_establishment() {
        assert!(sample_inception().is_establishment());
        assert!(sample_rotation("d").is_establishment());

        let ixn = KeyEvent::Interaction {
            prefix: "p".into(),
            previous_digest: "d".into(),
            data: serde_json::Value::Null,
        };
        assert!(!ixn.is_establishment());

        let dip = KeyEvent::Delegated {
            prefix: "p".into(),
            delegator: "d".into(),
            keys: vec![],
            next_key_digest: "nkd".into(),
        };
        assert!(dip.is_establishment());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let icp = sample_inception();
        let json = serde_json::to_string(&icp).unwrap();
        let deserialized: KeyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(icp, deserialized);
    }

    #[test]
    fn test_rotation_serialization_roundtrip() {
        let rot = sample_rotation("abc");
        let json = serde_json::to_string(&rot).unwrap();
        let deserialized: KeyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(rot, deserialized);
    }

    #[test]
    fn test_interaction_serialization_roundtrip() {
        let ixn = KeyEvent::Interaction {
            prefix: "p".into(),
            previous_digest: "pd".into(),
            data: serde_json::json!({"key": "value", "num": 42}),
        };
        let json = serde_json::to_string(&ixn).unwrap();
        let deserialized: KeyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ixn, deserialized);
    }

    #[test]
    fn test_delegated_serialization_roundtrip() {
        let dip = KeyEvent::Delegated {
            prefix: "child".into(),
            delegator: "parent".into(),
            keys: vec![vec![99]],
            next_key_digest: "nkd".into(),
        };
        let json = serde_json::to_string(&dip).unwrap();
        let deserialized: KeyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(dip, deserialized);
    }

    #[test]
    fn test_serde_tag_field() {
        let icp = sample_inception();
        let json: serde_json::Value = serde_json::to_value(&icp).unwrap();
        assert_eq!(json["type"], "icp");

        let rot = sample_rotation("d");
        let json: serde_json::Value = serde_json::to_value(&rot).unwrap();
        assert_eq!(json["type"], "rot");
    }
}
