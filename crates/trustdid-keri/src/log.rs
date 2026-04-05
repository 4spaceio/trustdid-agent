//! Key Event Log (KEL) -- ordered, hash-chained sequence of key events.
//!
//! The KEL maintains the authoritative history for a single KERI identifier.
//! Each event after inception must link to the previous event via `previous_digest`,
//! and rotation events must prove their pre-rotation commitment.

use crate::event::KeyEvent;
use trustdid_core::TrustDIDError;

/// An append-only, hash-chained log of key events for one identifier.
#[derive(Debug, Clone)]
pub struct KeyEventLog {
    /// The identifier (prefix) this log tracks.
    prefix: String,
    /// Ordered events -- index 0 is always the inception event.
    events: Vec<KeyEvent>,
}

impl KeyEventLog {
    /// Create an empty log for a given prefix.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            events: Vec::new(),
        }
    }

    /// Append a validated event to the log.
    ///
    /// Validation rules:
    /// - The first event must be an Inception or Delegated event.
    /// - Subsequent events must carry a `previous_digest` matching the digest of the last event.
    /// - Rotation events must prove the pre-rotation commitment:
    ///   the SHA-256 of the new keys must match the `next_key_digest` stored in the
    ///   most recent establishment event.
    pub fn append(&mut self, event: KeyEvent) -> trustdid_core::Result<()> {
        // Prefix must match.
        if event.prefix() != self.prefix {
            return Err(TrustDIDError::InvalidDocument(format!(
                "event prefix '{}' does not match log prefix '{}'",
                event.prefix(),
                self.prefix
            )));
        }

        if self.events.is_empty() {
            // First event must be an inception-class event.
            match &event {
                KeyEvent::Inception { .. } | KeyEvent::Delegated { .. } => {}
                _ => {
                    return Err(TrustDIDError::InvalidDocument(
                        "first event in KEL must be Inception or Delegated".into(),
                    ));
                }
            }
        } else {
            // Subsequent events must chain via previous_digest.
            let expected_digest = self.events.last().unwrap().digest();
            match event.previous_digest() {
                Some(pd) if pd == expected_digest => {}
                Some(pd) => {
                    return Err(TrustDIDError::InvalidDocument(format!(
                        "previous_digest mismatch: expected '{}', got '{}'",
                        expected_digest, pd
                    )));
                }
                None => {
                    return Err(TrustDIDError::InvalidDocument(
                        "non-inception event must have a previous_digest".into(),
                    ));
                }
            }

            // If this is a rotation, verify the pre-rotation commitment.
            if let KeyEvent::Rotation { keys, .. } = &event {
                self.verify_pre_rotation_commitment(keys)?;
            }
        }

        self.events.push(event);
        Ok(())
    }

    /// Get the event at a specific index.
    pub fn get(&self, index: usize) -> Option<&KeyEvent> {
        self.events.get(index)
    }

    /// Get the most recent event.
    pub fn latest(&self) -> Option<&KeyEvent> {
        self.events.last()
    }

    /// Return the current signing keys from the most recent establishment event.
    pub fn current_keys(&self) -> Vec<Vec<u8>> {
        self.latest_establishment()
            .and_then(|evt| evt.keys().map(|k| k.to_vec()))
            .unwrap_or_default()
    }

    /// Return the pre-rotation commitment (next_key_digest) from the latest establishment event.
    pub fn next_key_digest(&self) -> Option<String> {
        self.latest_establishment()
            .and_then(|evt| evt.next_key_digest().map(String::from))
    }

    /// Verify the integrity of the entire chain.
    ///
    /// Checks:
    /// 1. First event is inception/delegated.
    /// 2. Every subsequent event's `previous_digest` matches the digest of its predecessor.
    /// 3. All rotation events satisfy their pre-rotation commitment relative to the
    ///    preceding establishment event.
    pub fn verify_chain(&self) -> trustdid_core::Result<bool> {
        if self.events.is_empty() {
            return Ok(true);
        }

        // First event must be establishment.
        let first = &self.events[0];
        if !matches!(first, KeyEvent::Inception { .. } | KeyEvent::Delegated { .. }) {
            return Ok(false);
        }

        let mut last_digest = first.digest();
        // Track latest establishment event's next_key_digest for pre-rotation checks.
        let mut last_next_key_digest: Option<String> =
            first.next_key_digest().map(String::from);

        for event in &self.events[1..] {
            // Chain linkage.
            match event.previous_digest() {
                Some(pd) if pd == last_digest => {}
                _ => return Ok(false),
            }

            // Pre-rotation commitment check for rotations.
            if let KeyEvent::Rotation { keys, .. } = event {
                if let Some(ref expected) = last_next_key_digest {
                    let actual = compute_keys_digest(keys);
                    if actual != *expected {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            }

            // Update tracking state.
            last_digest = event.digest();
            if event.is_establishment() {
                last_next_key_digest = event.next_key_digest().map(String::from);
            }
        }

        Ok(true)
    }

    /// Number of events in the log.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log contains no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The prefix this log belongs to.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    // --- private helpers ---

    /// Find the most recent establishment event (walking backward).
    fn latest_establishment(&self) -> Option<&KeyEvent> {
        self.events.iter().rev().find(|e| e.is_establishment())
    }

    /// Verify that the keys in a rotation event satisfy the pre-rotation commitment
    /// from the latest establishment event.
    fn verify_pre_rotation_commitment(&self, new_keys: &[Vec<u8>]) -> trustdid_core::Result<()> {
        let expected = self.next_key_digest().ok_or_else(|| {
            TrustDIDError::PreRotationFailed(
                "no next_key_digest in prior establishment event".into(),
            )
        })?;

        let actual = compute_keys_digest(new_keys);
        if actual != expected {
            return Err(TrustDIDError::PreRotationFailed(format!(
                "pre-rotation commitment mismatch: expected '{}', got '{}'",
                expected, actual
            )));
        }
        Ok(())
    }
}

/// Compute the SHA-256 hex digest over a set of public keys (concatenated).
/// This is the canonical commitment format used for pre-rotation.
pub(crate) fn compute_keys_digest(keys: &[Vec<u8>]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for key in keys {
        hasher.update(key);
    }
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn make_inception(prefix: &str, keys: Vec<Vec<u8>>, nkd: &str) -> KeyEvent {
        KeyEvent::Inception {
            prefix: prefix.into(),
            keys,
            next_key_digest: nkd.into(),
            witnesses: vec![],
            threshold: 1,
        }
    }

    fn make_rotation(prefix: &str, prev: &str, keys: Vec<Vec<u8>>, nkd: &str) -> KeyEvent {
        KeyEvent::Rotation {
            prefix: prefix.into(),
            previous_digest: prev.into(),
            keys,
            next_key_digest: nkd.into(),
        }
    }

    fn make_interaction(prefix: &str, prev: &str) -> KeyEvent {
        KeyEvent::Interaction {
            prefix: prefix.into(),
            previous_digest: prev.into(),
            data: serde_json::json!({"seal": "data"}),
        }
    }

    #[test]
    fn test_empty_log() {
        let log = KeyEventLog::new("prefix");
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.latest().is_none());
        assert!(log.get(0).is_none());
        assert!(log.current_keys().is_empty());
        assert!(log.next_key_digest().is_none());
    }

    #[test]
    fn test_append_inception() {
        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1, 2]], "nkd");
        log.append(icp.clone()).unwrap();
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
        assert_eq!(log.latest().unwrap(), &icp);
        assert_eq!(log.get(0).unwrap(), &icp);
    }

    #[test]
    fn test_first_event_must_be_inception() {
        let mut log = KeyEventLog::new("p");
        let rot = make_rotation("p", "fake", vec![vec![1]], "nkd");
        let result = log.append(rot);
        assert!(result.is_err());
    }

    #[test]
    fn test_prefix_mismatch_rejected() {
        let mut log = KeyEventLog::new("p1");
        let icp = make_inception("p2", vec![vec![1]], "nkd");
        let result = log.append(icp);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_linkage_validated() {
        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1]], "nkd");
        log.append(icp).unwrap();

        // Interaction with wrong previous_digest should fail.
        let ixn = make_interaction("p", "wrong_digest");
        let result = log.append(ixn);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_linkage_correct() {
        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1]], "nkd");
        let icp_digest = icp.digest();
        log.append(icp).unwrap();

        let ixn = make_interaction("p", &icp_digest);
        log.append(ixn).unwrap();
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn test_rotation_pre_rotation_commitment() {
        let next_keys = vec![vec![5, 6, 7]];
        let nkd = compute_keys_digest(&next_keys);

        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1, 2]], &nkd);
        let icp_digest = icp.digest();
        log.append(icp).unwrap();

        // Rotate with the committed-to keys.
        let rot = make_rotation("p", &icp_digest, next_keys, "future_nkd");
        log.append(rot).unwrap();
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn test_rotation_bad_commitment_rejected() {
        let nkd = compute_keys_digest(&[vec![5, 6, 7]]);

        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1]], &nkd);
        let icp_digest = icp.digest();
        log.append(icp).unwrap();

        // Rotate with WRONG keys (don't match the commitment).
        let rot = make_rotation("p", &icp_digest, vec![vec![99, 100]], "nkd2");
        let result = log.append(rot);
        assert!(result.is_err());
    }

    #[test]
    fn test_current_keys_after_rotation() {
        let rot_keys = vec![vec![10, 20, 30]];
        let nkd = compute_keys_digest(&rot_keys);

        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1]], &nkd);
        let icp_digest = icp.digest();
        log.append(icp).unwrap();

        assert_eq!(log.current_keys(), vec![vec![1u8]]);

        let rot = make_rotation("p", &icp_digest, rot_keys.clone(), "future_nkd");
        log.append(rot).unwrap();

        assert_eq!(log.current_keys(), rot_keys);
    }

    #[test]
    fn test_next_key_digest_tracking() {
        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1]], "commitment_1");
        log.append(icp).unwrap();
        assert_eq!(log.next_key_digest().as_deref(), Some("commitment_1"));
    }

    #[test]
    fn test_verify_chain_empty() {
        let log = KeyEventLog::new("p");
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_verify_chain_single_inception() {
        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1]], "nkd");
        log.append(icp).unwrap();
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_verify_chain_full_sequence() {
        let rot1_keys = vec![vec![5, 6]];
        let nkd1 = compute_keys_digest(&rot1_keys);
        let rot2_keys = vec![vec![10, 11]];
        let nkd2 = compute_keys_digest(&rot2_keys);

        let mut log = KeyEventLog::new("p");

        // Inception
        let icp = make_inception("p", vec![vec![1]], &nkd1);
        let d0 = icp.digest();
        log.append(icp).unwrap();

        // Interaction
        let ixn = make_interaction("p", &d0);
        let d1 = ixn.digest();
        log.append(ixn).unwrap();

        // Rotation
        let rot = make_rotation("p", &d1, rot1_keys, &nkd2);
        let d2 = rot.digest();
        log.append(rot).unwrap();

        // Another interaction
        let ixn2 = make_interaction("p", &d2);
        log.append(ixn2).unwrap();

        assert!(log.verify_chain().unwrap());
        assert_eq!(log.len(), 4);
    }

    #[test]
    fn test_delegated_as_first_event() {
        let mut log = KeyEventLog::new("child");
        let dip = KeyEvent::Delegated {
            prefix: "child".into(),
            delegator: "parent".into(),
            keys: vec![vec![1, 2, 3]],
            next_key_digest: "nkd".into(),
        };
        log.append(dip).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log.current_keys(), vec![vec![1u8, 2, 3]]);
    }

    #[test]
    fn test_get_out_of_bounds() {
        let mut log = KeyEventLog::new("p");
        let icp = make_inception("p", vec![vec![1]], "nkd");
        log.append(icp).unwrap();
        assert!(log.get(1).is_none());
        assert!(log.get(100).is_none());
    }
}
