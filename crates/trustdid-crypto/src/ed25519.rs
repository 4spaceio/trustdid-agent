use crate::{KeyPair, KeyType};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand::rngs::OsRng;
use trustdid_core::{Result, TrustDIDError};

pub fn generate() -> Result<KeyPair> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    Ok(KeyPair {
        key_type: KeyType::Ed25519,
        public_key: verifying_key.to_bytes().to_vec(),
        secret_key: signing_key.to_bytes().to_vec(),
    })
}

pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let secret_bytes: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| TrustDIDError::CryptoError("invalid Ed25519 secret key length".into()))?;

    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let pub_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| TrustDIDError::CryptoError("invalid Ed25519 public key length".into()))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| TrustDIDError::CryptoError("invalid Ed25519 signature length".into()))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| TrustDIDError::CryptoError(format!("invalid Ed25519 public key: {e}")))?;

    let sig = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Ed25519 signer implementation.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    pub fn new(secret_key: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = secret_key
            .try_into()
            .map_err(|_| TrustDIDError::CryptoError("invalid Ed25519 secret key length".into()))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn from_keypair(keypair: &KeyPair) -> Result<Self> {
        Self::new(&keypair.secret_key)
    }
}

impl crate::traits::Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }
}

/// Ed25519 verifier implementation.
pub struct Ed25519Verifier {
    verifying_key: VerifyingKey,
}

impl Ed25519Verifier {
    pub fn new(public_key: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| TrustDIDError::CryptoError("invalid Ed25519 public key length".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| TrustDIDError::CryptoError(format!("invalid Ed25519 public key: {e}")))?;
        Ok(Self { verifying_key })
    }
}

impl crate::traits::Verifier for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| TrustDIDError::CryptoError("invalid Ed25519 signature length".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        match self.verifying_key.verify(message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = generate().unwrap();
        assert_eq!(kp.key_type, KeyType::Ed25519);
        assert_eq!(kp.public_key.len(), 32);
        assert_eq!(kp.secret_key.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = generate().unwrap();
        let message = b"hello trustdid";
        let sig = sign(&kp.secret_key, message).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify(&kp.public_key, message, &sig).unwrap());
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = generate().unwrap();
        let sig = sign(&kp.secret_key, b"message A").unwrap();
        assert!(!verify(&kp.public_key, b"message B", &sig).unwrap());
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = generate().unwrap();
        let kp2 = generate().unwrap();
        let message = b"hello";
        let sig = sign(&kp1.secret_key, message).unwrap();
        assert!(!verify(&kp2.public_key, message, &sig).unwrap());
    }

    #[test]
    fn test_signer_verifier_structs() {
        use crate::traits::{Signer, Verifier};

        let kp = generate().unwrap();
        let signer = Ed25519Signer::from_keypair(&kp).unwrap();
        let verifier = Ed25519Verifier::new(&kp.public_key).unwrap();

        let message = b"structured signing test";
        let sig = signer.sign(message).unwrap();
        assert!(verifier.verify(message, &sig).unwrap());
    }
}
