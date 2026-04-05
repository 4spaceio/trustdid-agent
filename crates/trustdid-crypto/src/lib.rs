pub mod ed25519;
pub mod jwk;
pub mod multicodec;
pub mod secp256k1;
pub mod traits;

pub use traits::*;

use trustdid_core::TrustDIDError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    Secp256k1,
    P256,
    X25519,
}

impl KeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Secp256k1 => "secp256k1",
            Self::P256 => "P-256",
            Self::X25519 => "X25519",
        }
    }

    pub fn verification_method_type(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519VerificationKey2020",
            Self::Secp256k1 => "EcdsaSecp256k1VerificationKey2019",
            Self::P256 => "JsonWebKey2020",
            Self::X25519 => "X25519KeyAgreementKey2020",
        }
    }
}

/// A keypair containing public and private key material.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl KeyPair {
    pub fn public_key_multibase(&self) -> String {
        multicodec::encode_multibase(&self.public_key, self.key_type)
    }

    pub fn to_jwk_public(&self) -> serde_json::Value {
        jwk::public_key_to_jwk(&self.public_key, self.key_type)
    }

    pub fn to_verification_method(
        &self,
        did_uri: &str,
        key_id: &str,
    ) -> trustdid_core::VerificationMethod {
        trustdid_core::VerificationMethod {
            id: format!("{did_uri}#{key_id}"),
            method_type: self.key_type.verification_method_type().to_string(),
            controller: did_uri.to_string(),
            public_key_multibase: Some(self.public_key_multibase()),
            public_key_jwk: Some(self.to_jwk_public()),
        }
    }
}

/// Generate a keypair of the specified type.
pub fn generate_keypair(key_type: KeyType) -> trustdid_core::Result<KeyPair> {
    match key_type {
        KeyType::Ed25519 => ed25519::generate(),
        KeyType::Secp256k1 => secp256k1::generate(),
        _ => Err(TrustDIDError::CryptoError(format!(
            "key generation not yet implemented for {:?}",
            key_type
        ))),
    }
}

/// Sign data with a secret key.
pub fn sign(secret_key: &[u8], message: &[u8], key_type: KeyType) -> trustdid_core::Result<Vec<u8>> {
    match key_type {
        KeyType::Ed25519 => ed25519::sign(secret_key, message),
        KeyType::Secp256k1 => secp256k1::sign(secret_key, message),
        _ => Err(TrustDIDError::CryptoError(format!(
            "signing not yet implemented for {:?}",
            key_type
        ))),
    }
}

/// Verify a signature against a public key.
pub fn verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    key_type: KeyType,
) -> trustdid_core::Result<bool> {
    match key_type {
        KeyType::Ed25519 => ed25519::verify(public_key, message, signature),
        KeyType::Secp256k1 => secp256k1::verify(public_key, message, signature),
        _ => Err(TrustDIDError::CryptoError(format!(
            "verification not yet implemented for {:?}",
            key_type
        ))),
    }
}

/// Compute the pre-rotation commitment hash for a public key.
pub fn pre_rotation_commitment(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(public_key);
    multibase::encode(multibase::Base::Base58Btc, hash)
}
