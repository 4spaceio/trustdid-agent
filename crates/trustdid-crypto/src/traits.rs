use trustdid_core::Result;

pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn public_key_bytes(&self) -> Vec<u8>;
}

pub trait Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool>;
}

pub trait KeyGenerator {
    fn generate(&self) -> Result<crate::KeyPair>;
}
