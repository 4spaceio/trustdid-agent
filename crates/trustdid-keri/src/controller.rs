//! KERI Controller -- high-level key management with pre-rotation.
//!
//! The controller manages an identifier's lifecycle: inception, signing,
//! verification, and key rotation with pre-rotation commitments.

use crate::event::KeyEvent;
use crate::log::{compute_keys_digest, KeyEventLog};
use sha2::{Digest, Sha256};
use trustdid_crypto::{KeyPair, KeyType};

/// A KERI controller that manages a single identifier's key state.
#[derive(Debug)]
pub struct KeriController {
    /// The self-addressing identifier for this controller.
    prefix: String,
    /// Current active keypair used for signing.
    current_keys: KeyPair,
    /// Pre-committed next keypair (revealed on rotation).
    next_keys: KeyPair,
    /// The key type used by this controller.
    key_type: KeyType,
    /// The Key Event Log for this identifier.
    event_log: KeyEventLog,
}

impl KeriController {
    /// Create a new KERI controller by performing an inception event.
    ///
    /// Generates a current keypair and a next keypair (pre-rotation commitment),
    /// creates the inception event, appends it to the KEL, and returns a ready
    /// controller.
    pub fn incept(key_type: KeyType) -> trustdid_core::Result<Self> {
        let current_keys = trustdid_crypto::generate_keypair(key_type)?;
        let next_keys = trustdid_crypto::generate_keypair(key_type)?;

        // Derive prefix from SHA-256 of the inception public key.
        let prefix = Self::derive_prefix(&current_keys.public_key);

        // Compute pre-rotation commitment = digest of the next public key set.
        let next_key_digest = compute_keys_digest(&[next_keys.public_key.clone()]);

        let icp = KeyEvent::Inception {
            prefix: prefix.clone(),
            keys: vec![current_keys.public_key.clone()],
            next_key_digest,
            witnesses: vec![],
            threshold: 1,
        };

        let mut event_log = KeyEventLog::new(&prefix);
        event_log.append(icp)?;

        Ok(Self {
            prefix,
            current_keys,
            next_keys,
            key_type,
            event_log,
        })
    }

    /// Rotate keys: reveal the pre-committed next keypair, generate a new next keypair,
    /// and append a rotation event to the KEL.
    pub fn rotate(&mut self) -> trustdid_core::Result<KeyEvent> {
        // The new current keys are the previously committed next keys.
        let new_current = self.next_keys.clone();
        // Generate a fresh next keypair for the next rotation.
        let new_next = trustdid_crypto::generate_keypair(self.key_type)?;

        // Compute the new pre-rotation commitment.
        let new_next_key_digest = compute_keys_digest(&[new_next.public_key.clone()]);

        // Build the rotation event.
        let previous_digest = self
            .event_log
            .latest()
            .expect("KEL must have at least the inception event")
            .digest();

        let rot = KeyEvent::Rotation {
            prefix: self.prefix.clone(),
            previous_digest,
            keys: vec![new_current.public_key.clone()],
            next_key_digest: new_next_key_digest,
        };

        // Append -- this validates the pre-rotation commitment.
        self.event_log.append(rot.clone())?;

        // Update internal state.
        self.current_keys = new_current;
        self.next_keys = new_next;

        Ok(rot)
    }

    /// Sign a message with the current signing key.
    pub fn sign(&self, message: &[u8]) -> trustdid_core::Result<Vec<u8>> {
        trustdid_crypto::sign(&self.current_keys.secret_key, message, self.key_type)
    }

    /// Verify a signature against the current public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> trustdid_core::Result<bool> {
        trustdid_crypto::verify(
            &self.current_keys.public_key,
            message,
            signature,
            self.key_type,
        )
    }

    /// Return the current public signing key bytes.
    pub fn current_public_key(&self) -> &[u8] {
        &self.current_keys.public_key
    }

    /// Return the identifier (prefix) for this controller.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Return how many events are in the KEL.
    pub fn event_count(&self) -> usize {
        self.event_log.len()
    }

    /// Borrow the underlying Key Event Log.
    pub fn event_log(&self) -> &KeyEventLog {
        &self.event_log
    }

    /// Derive a prefix from an inception public key using SHA-256.
    fn derive_prefix(public_key: &[u8]) -> String {
        let hash = Sha256::digest(public_key);
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        format!("did:trustdid:keri:{hex}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_incept_ed25519() {
        let ctrl = KeriController::incept(KeyType::Ed25519).unwrap();
        assert!(!ctrl.prefix().is_empty());
        assert!(ctrl.prefix().starts_with("did:trustdid:keri:"));
        assert_eq!(ctrl.event_count(), 1);
        assert!(!ctrl.current_public_key().is_empty());
    }

    #[test]
    fn test_incept_secp256k1() {
        let ctrl = KeriController::incept(KeyType::Secp256k1).unwrap();
        assert!(ctrl.prefix().starts_with("did:trustdid:keri:"));
        assert_eq!(ctrl.event_count(), 1);
    }

    #[test]
    fn test_rotate_once() {
        let mut ctrl = KeriController::incept(KeyType::Ed25519).unwrap();
        let old_pk = ctrl.current_public_key().to_vec();

        let rot_event = ctrl.rotate().unwrap();
        assert_eq!(ctrl.event_count(), 2);
        assert_eq!(rot_event.prefix(), ctrl.prefix());

        // Public key should have changed.
        assert_ne!(ctrl.current_public_key(), old_pk.as_slice());
    }

    #[test]
    fn test_rotate_multiple_times() {
        let mut ctrl = KeriController::incept(KeyType::Ed25519).unwrap();

        for i in 0..5 {
            let prev_pk = ctrl.current_public_key().to_vec();
            ctrl.rotate().unwrap();
            assert_eq!(ctrl.event_count(), 2 + i);
            assert_ne!(ctrl.current_public_key(), prev_pk.as_slice());
        }
        assert_eq!(ctrl.event_count(), 6);
    }

    #[test]
    fn test_sign_and_verify() {
        let ctrl = KeriController::incept(KeyType::Ed25519).unwrap();
        let message = b"hello KERI world";

        let signature = ctrl.sign(message).unwrap();
        assert!(!signature.is_empty());

        let valid = ctrl.verify(message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let ctrl = KeriController::incept(KeyType::Ed25519).unwrap();
        let signature = ctrl.sign(b"correct message").unwrap();
        let valid = ctrl.verify(b"wrong message", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sign_verify_after_rotation() {
        let mut ctrl = KeriController::incept(KeyType::Ed25519).unwrap();

        // Sign before rotation.
        let msg1 = b"before rotation";
        let sig1 = ctrl.sign(msg1).unwrap();
        assert!(ctrl.verify(msg1, &sig1).unwrap());

        // Rotate.
        ctrl.rotate().unwrap();

        // Old signature should NOT verify with new key.
        let valid = ctrl.verify(msg1, &sig1).unwrap();
        assert!(!valid);

        // New signature should verify.
        let msg2 = b"after rotation";
        let sig2 = ctrl.sign(msg2).unwrap();
        assert!(ctrl.verify(msg2, &sig2).unwrap());
    }

    #[test]
    fn test_kel_chain_integrity_after_rotations() {
        let mut ctrl = KeriController::incept(KeyType::Ed25519).unwrap();
        ctrl.rotate().unwrap();
        ctrl.rotate().unwrap();

        assert!(ctrl.event_log().verify_chain().unwrap());
    }

    #[test]
    fn test_prefix_derived_from_inception_key() {
        let ctrl = KeriController::incept(KeyType::Ed25519).unwrap();
        let prefix = ctrl.prefix();
        // Prefix format: did:trustdid:keri:<64-hex-chars>
        assert!(prefix.starts_with("did:trustdid:keri:"));
        let hex_part = prefix.strip_prefix("did:trustdid:keri:").unwrap();
        assert_eq!(hex_part.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_secp256k1_sign_verify() {
        let ctrl = KeriController::incept(KeyType::Secp256k1).unwrap();
        let msg = b"secp256k1 message";
        let sig = ctrl.sign(msg).unwrap();
        assert!(ctrl.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_secp256k1_rotate_and_sign() {
        let mut ctrl = KeriController::incept(KeyType::Secp256k1).unwrap();
        ctrl.rotate().unwrap();
        let msg = b"after secp256k1 rotation";
        let sig = ctrl.sign(msg).unwrap();
        assert!(ctrl.verify(msg, &sig).unwrap());
    }
}
