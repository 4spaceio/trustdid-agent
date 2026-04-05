//! Witness -- receipt infrastructure for KERI key events.
//!
//! Witnesses observe key events and issue signed receipts. A threshold of
//! witness receipts provides assurance that an event was broadly observed.

use crate::event::KeyEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use trustdid_core::TrustDIDError;
use trustdid_crypto::{KeyPair, KeyType};

/// A signed receipt from a witness acknowledging a key event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    /// The digest of the event being witnessed.
    pub event_digest: String,
    /// The witness identifier.
    pub witness_id: String,
    /// The witness's signature over the event digest.
    pub signature: Vec<u8>,
    /// When the receipt was created.
    pub timestamp: DateTime<Utc>,
}

/// A KERI witness that observes events and issues receipts.
#[derive(Debug)]
pub struct Witness {
    /// Unique identifier for this witness.
    id: String,
    /// The witness's signing keypair.
    keypair: KeyPair,
    /// The key type used by this witness.
    key_type: KeyType,
    /// Receipts issued, indexed by prefix.
    receipts: HashMap<String, Vec<Receipt>>,
}

impl Witness {
    /// Create a new witness with a generated Ed25519 keypair.
    pub fn new(id: impl Into<String>) -> trustdid_core::Result<Self> {
        Self::with_key_type(id, KeyType::Ed25519)
    }

    /// Create a new witness with a specific key type.
    pub fn with_key_type(id: impl Into<String>, key_type: KeyType) -> trustdid_core::Result<Self> {
        let keypair = trustdid_crypto::generate_keypair(key_type)?;
        Ok(Self {
            id: id.into(),
            keypair,
            key_type,
            receipts: HashMap::new(),
        })
    }

    /// Witness an event: compute its digest, sign it, and store a receipt.
    pub fn witness_event(
        &mut self,
        prefix: &str,
        event: &KeyEvent,
    ) -> trustdid_core::Result<Receipt> {
        if event.prefix() != prefix {
            return Err(TrustDIDError::VerificationFailed(format!(
                "event prefix '{}' does not match supplied prefix '{}'",
                event.prefix(),
                prefix
            )));
        }

        let event_digest = event.digest();

        // Sign the digest bytes.
        let signature =
            trustdid_crypto::sign(&self.keypair.secret_key, event_digest.as_bytes(), self.key_type)?;

        let receipt = Receipt {
            event_digest,
            witness_id: self.id.clone(),
            signature,
            timestamp: Utc::now(),
        };

        self.receipts
            .entry(prefix.to_string())
            .or_default()
            .push(receipt.clone());

        Ok(receipt)
    }

    /// Retrieve all receipts this witness has issued for a given prefix.
    pub fn get_receipts(&self, prefix: &str) -> Vec<Receipt> {
        self.receipts.get(prefix).cloned().unwrap_or_default()
    }

    /// The witness identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The witness's public key (for receipt verification).
    pub fn public_key(&self) -> &[u8] {
        &self.keypair.public_key
    }

    /// The key type used by this witness.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
}

/// Verify a receipt against a witness's public key.
///
/// Checks that the signature in the receipt is valid over the event_digest
/// using the provided witness public key.
pub fn verify_receipt(
    receipt: &Receipt,
    witness_public_key: &[u8],
    key_type: KeyType,
) -> trustdid_core::Result<bool> {
    trustdid_crypto::verify(
        witness_public_key,
        receipt.event_digest.as_bytes(),
        &receipt.signature,
        key_type,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample_event() -> KeyEvent {
        KeyEvent::Inception {
            prefix: "test-prefix".into(),
            keys: vec![vec![1, 2, 3]],
            next_key_digest: "nkd".into(),
            witnesses: vec!["w1".into()],
            threshold: 1,
        }
    }

    #[test]
    fn test_witness_creation() {
        let w = Witness::new("witness-1").unwrap();
        assert_eq!(w.id(), "witness-1");
        assert!(!w.public_key().is_empty());
    }

    #[test]
    fn test_witness_event() {
        let mut w = Witness::new("w1").unwrap();
        let event = sample_event();

        let receipt = w.witness_event("test-prefix", &event).unwrap();
        assert_eq!(receipt.witness_id, "w1");
        assert_eq!(receipt.event_digest, event.digest());
        assert!(!receipt.signature.is_empty());
    }

    #[test]
    fn test_witness_event_prefix_mismatch() {
        let mut w = Witness::new("w1").unwrap();
        let event = sample_event();
        let result = w.witness_event("wrong-prefix", &event);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_receipts_empty() {
        let w = Witness::new("w1").unwrap();
        let receipts = w.get_receipts("no-such-prefix");
        assert!(receipts.is_empty());
    }

    #[test]
    fn test_get_receipts_after_witnessing() {
        let mut w = Witness::new("w1").unwrap();
        let event = sample_event();
        w.witness_event("test-prefix", &event).unwrap();

        let receipts = w.get_receipts("test-prefix");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].witness_id, "w1");
    }

    #[test]
    fn test_multiple_receipts() {
        let mut w = Witness::new("w1").unwrap();

        let event1 = sample_event();
        w.witness_event("test-prefix", &event1).unwrap();

        // Witness the same event again (simulating re-witnessing).
        w.witness_event("test-prefix", &event1).unwrap();

        let receipts = w.get_receipts("test-prefix");
        assert_eq!(receipts.len(), 2);
    }

    #[test]
    fn test_verify_receipt_valid() {
        let mut w = Witness::new("w1").unwrap();
        let event = sample_event();
        let receipt = w.witness_event("test-prefix", &event).unwrap();

        let valid = verify_receipt(&receipt, w.public_key(), w.key_type()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_receipt_wrong_key() {
        let mut w1 = Witness::new("w1").unwrap();
        let w2 = Witness::new("w2").unwrap();
        let event = sample_event();
        let receipt = w1.witness_event("test-prefix", &event).unwrap();

        // Verify with wrong witness's public key.
        let valid = verify_receipt(&receipt, w2.public_key(), w2.key_type()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_receipt_tampered_digest() {
        let mut w = Witness::new("w1").unwrap();
        let event = sample_event();
        let mut receipt = w.witness_event("test-prefix", &event).unwrap();

        // Tamper with the digest.
        receipt.event_digest = "tampered_digest".into();

        let valid = verify_receipt(&receipt, w.public_key(), w.key_type()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_receipt_serialization_roundtrip() {
        let mut w = Witness::new("w1").unwrap();
        let event = sample_event();
        let receipt = w.witness_event("test-prefix", &event).unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, deserialized);
    }

    #[test]
    fn test_witness_secp256k1() {
        let mut w = Witness::with_key_type("w-secp", KeyType::Secp256k1).unwrap();
        let event = sample_event();
        let receipt = w.witness_event("test-prefix", &event).unwrap();

        let valid = verify_receipt(&receipt, w.public_key(), w.key_type()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_multiple_prefixes() {
        let mut w = Witness::new("w1").unwrap();

        let event1 = KeyEvent::Inception {
            prefix: "prefix-a".into(),
            keys: vec![vec![1]],
            next_key_digest: "nkd".into(),
            witnesses: vec![],
            threshold: 1,
        };
        let event2 = KeyEvent::Inception {
            prefix: "prefix-b".into(),
            keys: vec![vec![2]],
            next_key_digest: "nkd".into(),
            witnesses: vec![],
            threshold: 1,
        };

        w.witness_event("prefix-a", &event1).unwrap();
        w.witness_event("prefix-b", &event2).unwrap();

        assert_eq!(w.get_receipts("prefix-a").len(), 1);
        assert_eq!(w.get_receipts("prefix-b").len(), 1);
        assert!(w.get_receipts("prefix-c").is_empty());
    }
}
