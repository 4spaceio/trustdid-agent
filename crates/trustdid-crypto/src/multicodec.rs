use crate::KeyType;

// Multicodec prefixes
const ED25519_PUB: [u8; 2] = [0xed, 0x01];
const SECP256K1_PUB: [u8; 2] = [0xe7, 0x01];
const X25519_PUB: [u8; 2] = [0xec, 0x01];
const P256_PUB: [u8; 2] = [0x80, 0x24];

pub fn multicodec_prefix(key_type: KeyType) -> &'static [u8] {
    match key_type {
        KeyType::Ed25519 => &ED25519_PUB,
        KeyType::Secp256k1 => &SECP256K1_PUB,
        KeyType::X25519 => &X25519_PUB,
        KeyType::P256 => &P256_PUB,
    }
}

pub fn encode_multibase(public_key: &[u8], key_type: KeyType) -> String {
    let prefix = multicodec_prefix(key_type);
    let mut encoded = Vec::with_capacity(prefix.len() + public_key.len());
    encoded.extend_from_slice(prefix);
    encoded.extend_from_slice(public_key);
    multibase::encode(multibase::Base::Base58Btc, &encoded)
}

pub fn decode_multibase(encoded: &str) -> trustdid_core::Result<(KeyType, Vec<u8>)> {
    let (_, bytes) = multibase::decode(encoded)
        .map_err(|e| trustdid_core::TrustDIDError::CryptoError(format!("multibase decode: {e}")))?;

    if bytes.len() < 2 {
        return Err(trustdid_core::TrustDIDError::CryptoError(
            "multicodec data too short".into(),
        ));
    }

    let prefix = [bytes[0], bytes[1]];
    let key_data = &bytes[2..];

    let key_type = match prefix {
        p if p == ED25519_PUB => KeyType::Ed25519,
        p if p == SECP256K1_PUB => KeyType::Secp256k1,
        p if p == X25519_PUB => KeyType::X25519,
        p if p == P256_PUB => KeyType::P256,
        _ => {
            return Err(trustdid_core::TrustDIDError::CryptoError(
                "unknown multicodec prefix".into(),
            ))
        }
    };

    Ok((key_type, key_data.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_roundtrip() {
        let key = vec![1u8; 32];
        let encoded = encode_multibase(&key, KeyType::Ed25519);
        assert!(encoded.starts_with('z')); // Base58Btc prefix
        let (kt, decoded) = decode_multibase(&encoded).unwrap();
        assert_eq!(kt, KeyType::Ed25519);
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_secp256k1_roundtrip() {
        let key = vec![2u8; 33];
        let encoded = encode_multibase(&key, KeyType::Secp256k1);
        let (kt, decoded) = decode_multibase(&encoded).unwrap();
        assert_eq!(kt, KeyType::Secp256k1);
        assert_eq!(decoded, key);
    }
}
