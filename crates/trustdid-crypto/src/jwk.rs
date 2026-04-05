use crate::KeyType;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

pub fn public_key_to_jwk(public_key: &[u8], key_type: KeyType) -> serde_json::Value {
    match key_type {
        KeyType::Ed25519 => json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(public_key)
        }),
        KeyType::Secp256k1 => {
            // For compressed key (33 bytes), decompress or store raw
            // For simplicity, store as base64url
            json!({
                "kty": "EC",
                "crv": "secp256k1",
                "x": URL_SAFE_NO_PAD.encode(public_key)
            })
        }
        KeyType::P256 => {
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(public_key)
            })
        }
        KeyType::X25519 => json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": URL_SAFE_NO_PAD.encode(public_key)
        }),
    }
}

pub fn jwk_to_public_key(jwk: &serde_json::Value) -> trustdid_core::Result<(KeyType, Vec<u8>)> {
    let kty = jwk["kty"]
        .as_str()
        .ok_or_else(|| trustdid_core::TrustDIDError::CryptoError("missing kty".into()))?;

    let crv = jwk["crv"]
        .as_str()
        .ok_or_else(|| trustdid_core::TrustDIDError::CryptoError("missing crv".into()))?;

    let x = jwk["x"]
        .as_str()
        .ok_or_else(|| trustdid_core::TrustDIDError::CryptoError("missing x".into()))?;

    let public_key = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| trustdid_core::TrustDIDError::CryptoError(format!("base64 decode: {e}")))?;

    let key_type = match (kty, crv) {
        ("OKP", "Ed25519") => KeyType::Ed25519,
        ("OKP", "X25519") => KeyType::X25519,
        ("EC", "secp256k1") => KeyType::Secp256k1,
        ("EC", "P-256") => KeyType::P256,
        _ => {
            return Err(trustdid_core::TrustDIDError::CryptoError(format!(
                "unsupported JWK type: kty={kty}, crv={crv}"
            )))
        }
    };

    Ok((key_type, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_jwk_roundtrip() {
        let key = vec![42u8; 32];
        let jwk = public_key_to_jwk(&key, KeyType::Ed25519);
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");

        let (kt, decoded) = jwk_to_public_key(&jwk).unwrap();
        assert_eq!(kt, KeyType::Ed25519);
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_secp256k1_jwk_roundtrip() {
        let key = vec![3u8; 33];
        let jwk = public_key_to_jwk(&key, KeyType::Secp256k1);
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "secp256k1");

        let (kt, decoded) = jwk_to_public_key(&jwk).unwrap();
        assert_eq!(kt, KeyType::Secp256k1);
        assert_eq!(decoded, key);
    }
}
