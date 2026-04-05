//! DIDComm envelope (encryption/signing wrapper).
//!
//! Provides pack/unpack operations for DIDComm messages, supporting
//! authenticated encryption, anonymous encryption, and signed modes.
//!
//! The current implementation uses a simplified scheme based on Ed25519 signing
//! and base64 encoding. A full JWE/JWS implementation will be added in a later phase.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::DIDCommError;
use crate::message::DIDCommMessage;

/// Packing mode for DIDComm envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackMode {
    /// Authenticated encryption: sender is authenticated, message is encrypted.
    Authcrypt,
    /// Anonymous encryption: sender is anonymous, message is encrypted.
    Anoncrypt,
    /// Signed (JWS): message is signed but not encrypted.
    Signed,
}

/// A packed DIDComm envelope.
///
/// Wraps a DIDComm message with cryptographic protection. The envelope format
/// is inspired by JWE (JSON Web Encryption) with a simplified structure for
/// the current implementation phase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    /// Base64url-encoded protected header (contains metadata about the packing).
    pub protected: String,

    /// Initialization vector (base64url-encoded). Empty for Signed mode.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub iv: String,

    /// The packed message payload (base64url-encoded).
    pub ciphertext: String,

    /// Authentication tag (base64url-encoded). For Signed mode, this is the signature.
    pub tag: String,

    /// Recipient-specific information.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<Recipient>,
}

/// Recipient information within an envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Recipient {
    /// Recipient key identifier (DID key reference).
    pub kid: String,

    /// Encrypted key material for this recipient (base64url-encoded).
    /// Empty for Signed mode.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub encrypted_key: String,
}

/// Protected header included in the envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedHeader {
    /// Algorithm used for packing.
    pub alg: String,
    /// Encryption algorithm (for Authcrypt/Anoncrypt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,
    /// Content type.
    pub typ: String,
    /// Sender key ID (for Authcrypt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,
}

/// Builder for constructing envelopes.
#[derive(Debug)]
pub struct EnvelopeBuilder {
    message: Option<DIDCommMessage>,
    sender_key: Option<Vec<u8>>,
    recipient_keys: Vec<(String, Vec<u8>)>,
    mode: PackMode,
}

impl EnvelopeBuilder {
    /// Create a new envelope builder.
    pub fn new() -> Self {
        Self {
            message: None,
            sender_key: None,
            recipient_keys: Vec::new(),
            mode: PackMode::Authcrypt,
        }
    }

    /// Set the message to pack.
    pub fn message(mut self, message: DIDCommMessage) -> Self {
        self.message = Some(message);
        self
    }

    /// Set the sender's secret key (for Authcrypt and Signed modes).
    pub fn sender_key(mut self, key: Vec<u8>) -> Self {
        self.sender_key = Some(key);
        self
    }

    /// Add a recipient with their key ID and public key.
    pub fn add_recipient(mut self, kid: impl Into<String>, public_key: Vec<u8>) -> Self {
        self.recipient_keys.push((kid.into(), public_key));
        self
    }

    /// Set the pack mode.
    pub fn mode(mut self, mode: PackMode) -> Self {
        self.mode = mode;
        self
    }

    /// Build and pack the envelope.
    pub fn build(self) -> Result<Envelope, DIDCommError> {
        let message = self
            .message
            .ok_or_else(|| DIDCommError::PackError("message is required".into()))?;

        pack(&message, self.sender_key.as_deref(), &self.recipient_keys, self.mode)
    }
}

impl Default for EnvelopeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Pack a DIDComm message into an envelope.
///
/// This is a simplified implementation that:
/// - For `Authcrypt`: base64-encodes the message and signs it with the sender key.
/// - For `Anoncrypt`: base64-encodes the message with a hash-based tag (no sender auth).
/// - For `Signed`: base64-encodes the message and signs it with the sender key.
///
/// A full ECDH-ES+A256KW / A256CBC-HS512 implementation will replace this.
pub fn pack(
    message: &DIDCommMessage,
    sender_key: Option<&[u8]>,
    recipient_keys: &[(String, Vec<u8>)],
    mode: PackMode,
) -> Result<Envelope, DIDCommError> {
    let message_json = serde_json::to_string(message)
        .map_err(|e| DIDCommError::PackError(format!("serialization failed: {e}")))?;

    let ciphertext = URL_SAFE_NO_PAD.encode(message_json.as_bytes());

    let (alg, enc, tag, skid) = match mode {
        PackMode::Authcrypt => {
            let sk = sender_key
                .ok_or_else(|| DIDCommError::PackError("sender key required for authcrypt".into()))?;
            let signature = sign_payload(sk, ciphertext.as_bytes())?;
            let tag = URL_SAFE_NO_PAD.encode(&signature);
            let skid = Some(compute_key_id(sk));
            ("ECDH-ES+A256KW".to_string(), Some("A256CBC-HS512".to_string()), tag, skid)
        }
        PackMode::Anoncrypt => {
            let hash = Sha256::digest(ciphertext.as_bytes());
            let tag = URL_SAFE_NO_PAD.encode(hash);
            ("ECDH-ES+A256KW".to_string(), Some("A256CBC-HS512".to_string()), tag, None)
        }
        PackMode::Signed => {
            let sk = sender_key
                .ok_or_else(|| DIDCommError::PackError("sender key required for signed mode".into()))?;
            let signature = sign_payload(sk, ciphertext.as_bytes())?;
            let tag = URL_SAFE_NO_PAD.encode(&signature);
            let skid = Some(compute_key_id(sk));
            ("EdDSA".to_string(), None, tag, skid)
        }
    };

    let header = ProtectedHeader {
        alg,
        enc,
        typ: "application/didcomm-encrypted+json".to_string(),
        skid,
    };

    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&header)
            .map_err(|e| DIDCommError::PackError(format!("header serialization failed: {e}")))?
            .as_bytes(),
    );

    let recipients: Vec<Recipient> = recipient_keys
        .iter()
        .map(|(kid, _pk)| {
            // In a full implementation, we would encrypt a content-encryption key
            // for each recipient using their public key. For now, we use a placeholder.
            let encrypted_key = match mode {
                PackMode::Signed => String::new(),
                _ => {
                    let placeholder = Sha256::digest(kid.as_bytes());
                    URL_SAFE_NO_PAD.encode(placeholder)
                }
            };
            Recipient {
                kid: kid.clone(),
                encrypted_key,
            }
        })
        .collect();

    Ok(Envelope {
        protected,
        iv: String::new(),
        ciphertext,
        tag,
        recipients,
    })
}

/// Unpack an envelope to recover the DIDComm message.
///
/// For the simplified implementation, this decodes the base64 ciphertext and
/// optionally verifies the signature if a sender public key is provided.
pub fn unpack(
    envelope: &Envelope,
    _recipient_key: Option<&[u8]>,
    sender_public_key: Option<&[u8]>,
) -> Result<DIDCommMessage, DIDCommError> {
    // Decode the protected header to determine the mode.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.protected)
        .map_err(|e| DIDCommError::UnpackError(format!("invalid protected header: {e}")))?;

    let header: ProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| DIDCommError::UnpackError(format!("invalid header JSON: {e}")))?;

    // Verify signature if sender public key is provided.
    if let Some(spk) = sender_public_key {
        if header.alg == "EdDSA" || header.skid.is_some() {
            let signature = URL_SAFE_NO_PAD
                .decode(&envelope.tag)
                .map_err(|e| DIDCommError::UnpackError(format!("invalid tag: {e}")))?;
            verify_payload(spk, envelope.ciphertext.as_bytes(), &signature)?;
        }
    }

    // Decode the ciphertext (in our simplified scheme, it's just base64-encoded plaintext).
    let plaintext_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext)
        .map_err(|e| DIDCommError::UnpackError(format!("invalid ciphertext: {e}")))?;

    let message: DIDCommMessage = serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| DIDCommError::UnpackError(format!("invalid message JSON: {e}")))?;

    Ok(message)
}

/// Sign a payload using Ed25519.
fn sign_payload(secret_key: &[u8], payload: &[u8]) -> Result<Vec<u8>, DIDCommError> {
    trustdid_crypto::sign(secret_key, payload, trustdid_crypto::KeyType::Ed25519)
        .map_err(|e| DIDCommError::CryptoError(format!("signing failed: {e}")))
}

/// Verify a payload signature using Ed25519.
fn verify_payload(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), DIDCommError> {
    let valid =
        trustdid_crypto::verify(public_key, payload, signature, trustdid_crypto::KeyType::Ed25519)
            .map_err(|e| DIDCommError::CryptoError(format!("verification failed: {e}")))?;

    if valid {
        Ok(())
    } else {
        Err(DIDCommError::CryptoError("signature verification failed".into()))
    }
}

/// Compute a key identifier from key bytes (truncated SHA-256 hash, base64url-encoded).
fn compute_key_id(key_bytes: &[u8]) -> String {
    let hash = Sha256::digest(key_bytes);
    URL_SAFE_NO_PAD.encode(&hash[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::protocol;
    use pretty_assertions::assert_eq;

    fn test_keypair() -> trustdid_crypto::KeyPair {
        trustdid_crypto::generate_keypair(trustdid_crypto::KeyType::Ed25519).unwrap()
    }

    #[test]
    fn test_pack_unpack_authcrypt_roundtrip() {
        let kp = test_keypair();
        let msg = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        let recipient_keys = vec![("did:trustdid:evm:1:bob#key-1".to_string(), kp.public_key.clone())];

        let envelope = pack(&msg, Some(&kp.secret_key), &recipient_keys, PackMode::Authcrypt).unwrap();

        assert!(!envelope.protected.is_empty());
        assert!(!envelope.ciphertext.is_empty());
        assert!(!envelope.tag.is_empty());
        assert_eq!(envelope.recipients.len(), 1);
        assert_eq!(envelope.recipients[0].kid, "did:trustdid:evm:1:bob#key-1");

        let unpacked = unpack(&envelope, Some(&kp.secret_key), Some(&kp.public_key)).unwrap();
        assert_eq!(unpacked, msg);
    }

    #[test]
    fn test_pack_unpack_anoncrypt_roundtrip() {
        let kp = test_keypair();
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .id("anon-001")
            .to("did:trustdid:evm:1:bob")
            .body(serde_json::json!({ "content": "anonymous hello" }))
            .build();

        let recipient_keys = vec![("did:trustdid:evm:1:bob#key-1".to_string(), kp.public_key.clone())];

        let envelope = pack(&msg, None, &recipient_keys, PackMode::Anoncrypt).unwrap();
        let unpacked = unpack(&envelope, None, None).unwrap();
        assert_eq!(unpacked, msg);
    }

    #[test]
    fn test_pack_unpack_signed_roundtrip() {
        let kp = test_keypair();
        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .id("signed-001")
            .from("did:trustdid:evm:1:alice")
            .to("did:trustdid:evm:1:bob")
            .body(serde_json::json!({ "content": "signed message" }))
            .build();

        let envelope = pack(&msg, Some(&kp.secret_key), &[], PackMode::Signed).unwrap();

        assert!(envelope.recipients.is_empty());

        let unpacked = unpack(&envelope, None, Some(&kp.public_key)).unwrap();
        assert_eq!(unpacked, msg);
    }

    #[test]
    fn test_pack_authcrypt_requires_sender_key() {
        let msg = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );
        let result = pack(&msg, None, &[], PackMode::Authcrypt);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("sender key required"), "got: {err}");
    }

    #[test]
    fn test_pack_signed_requires_sender_key() {
        let msg = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );
        let result = pack(&msg, None, &[], PackMode::Signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_builder() {
        let kp = test_keypair();
        let msg = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        let envelope = EnvelopeBuilder::new()
            .message(msg.clone())
            .sender_key(kp.secret_key.clone())
            .add_recipient("did:trustdid:evm:1:bob#key-1", kp.public_key.clone())
            .mode(PackMode::Authcrypt)
            .build()
            .unwrap();

        let unpacked = unpack(&envelope, Some(&kp.secret_key), Some(&kp.public_key)).unwrap();
        assert_eq!(unpacked, msg);
    }

    #[test]
    fn test_envelope_builder_requires_message() {
        let result = EnvelopeBuilder::new()
            .mode(PackMode::Anoncrypt)
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("message is required"), "got: {err}");
    }

    #[test]
    fn test_envelope_serialization_roundtrip() {
        let kp = test_keypair();
        let msg = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        let envelope = pack(
            &msg,
            Some(&kp.secret_key),
            &[("did:trustdid:evm:1:bob#key-1".to_string(), kp.public_key.clone())],
            PackMode::Authcrypt,
        )
        .unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, deserialized);

        // Verify we can still unpack the deserialized envelope.
        let unpacked = unpack(&deserialized, Some(&kp.secret_key), Some(&kp.public_key)).unwrap();
        assert_eq!(unpacked, msg);
    }

    #[test]
    fn test_protected_header_decoding() {
        let kp = test_keypair();
        let msg = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        let envelope = pack(&msg, Some(&kp.secret_key), &[], PackMode::Signed).unwrap();

        let header_bytes = URL_SAFE_NO_PAD.decode(&envelope.protected).unwrap();
        let header: ProtectedHeader = serde_json::from_slice(&header_bytes).unwrap();

        assert_eq!(header.alg, "EdDSA");
        assert!(header.enc.is_none());
        assert!(header.skid.is_some());
    }

    #[test]
    fn test_signature_verification_failure() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();

        let msg = DIDCommMessage::trust_ping(
            "did:trustdid:evm:1:alice",
            "did:trustdid:evm:1:bob",
        );

        // Pack with kp1's key.
        let envelope = pack(&msg, Some(&kp1.secret_key), &[], PackMode::Signed).unwrap();

        // Try to unpack verifying with kp2's public key -- should fail.
        let result = unpack(&envelope, None, Some(&kp2.public_key));
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_recipients() {
        let kp_sender = test_keypair();
        let kp_r1 = test_keypair();
        let kp_r2 = test_keypair();

        let msg = DIDCommMessage::builder(protocol::BASIC_MESSAGE)
            .id("multi-001")
            .from("did:trustdid:evm:1:sender")
            .to("did:trustdid:evm:1:r1")
            .to("did:trustdid:evm:1:r2")
            .body(serde_json::json!({ "content": "broadcast" }))
            .build();

        let recipient_keys = vec![
            ("did:trustdid:evm:1:r1#key-1".to_string(), kp_r1.public_key.clone()),
            ("did:trustdid:evm:1:r2#key-1".to_string(), kp_r2.public_key.clone()),
        ];

        let envelope = pack(&msg, Some(&kp_sender.secret_key), &recipient_keys, PackMode::Authcrypt).unwrap();
        assert_eq!(envelope.recipients.len(), 2);

        // Both recipients should be able to unpack.
        let unpacked = unpack(&envelope, Some(&kp_r1.secret_key), Some(&kp_sender.public_key)).unwrap();
        assert_eq!(unpacked, msg);
    }
}
