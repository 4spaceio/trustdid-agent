use crate::{KeyPair, KeyType};
use k256::ecdsa::{signature::Signer as _, signature::Verifier as _, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use trustdid_core::{Result, TrustDIDError};

pub fn generate() -> Result<KeyPair> {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    Ok(KeyPair {
        key_type: KeyType::Secp256k1,
        public_key: verifying_key.to_sec1_bytes().to_vec(),
        secret_key: signing_key.to_bytes().to_vec(),
    })
}

pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::from_slice(secret_key)
        .map_err(|e| TrustDIDError::CryptoError(format!("invalid secp256k1 secret key: {e}")))?;

    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| TrustDIDError::CryptoError(format!("invalid secp256k1 public key: {e}")))?;

    let sig = Signature::from_slice(signature)
        .map_err(|e| TrustDIDError::CryptoError(format!("invalid secp256k1 signature: {e}")))?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// secp256k1 signer implementation.
pub struct Secp256k1Signer {
    signing_key: SigningKey,
}

impl Secp256k1Signer {
    pub fn new(secret_key: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_slice(secret_key)
            .map_err(|e| TrustDIDError::CryptoError(format!("invalid secp256k1 secret key: {e}")))?;
        Ok(Self { signing_key })
    }
}

impl crate::traits::Signer for Secp256k1Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature: Signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = generate().unwrap();
        assert_eq!(kp.key_type, KeyType::Secp256k1);
        assert_eq!(kp.secret_key.len(), 32);
        // Compressed public key is 33 bytes
        assert_eq!(kp.public_key.len(), 33);
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = generate().unwrap();
        let message = b"hello secp256k1";
        let sig = sign(&kp.secret_key, message).unwrap();
        assert!(verify(&kp.public_key, message, &sig).unwrap());
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = generate().unwrap();
        let sig = sign(&kp.secret_key, b"correct message").unwrap();
        assert!(!verify(&kp.public_key, b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = generate().unwrap();
        let kp2 = generate().unwrap();
        let message = b"test";
        let sig = sign(&kp1.secret_key, message).unwrap();
        assert!(!verify(&kp2.public_key, message, &sig).unwrap());
    }
}
