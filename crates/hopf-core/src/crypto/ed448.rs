// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Ed448 signature verification (DNSSEC only).
//!
//! AWS-LC has no Ed448 support; this module wraps `ed448-goldilocks-plus`
//! behind the Hopf crypto facade (RFC 8080 plain Ed448, not Ed448ph).

/// Verify a plain Ed448 signature (`public_key` 57 bytes, `signature` 114 bytes).
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key_bytes) = <[u8; 57]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 114]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = ed448_goldilocks_plus::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(sig) = ed448_goldilocks_plus::Signature::from_bytes(&sig_bytes) else {
        return false;
    };
    key.verify_raw(&sig, message).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed448_goldilocks_plus::crypto_signature::Signer;

    fn test_signing_key(seed_byte: u8) -> ed448_goldilocks_plus::SigningKey {
        let secret = ed448_goldilocks_plus::SecretKey::from([seed_byte; 57]);
        ed448_goldilocks_plus::SigningKey::from_bytes(&secret)
    }

    #[test]
    fn ed448_roundtrip() {
        let private = test_signing_key(0x11);
        let public = private.verifying_key();
        let msg = b"dnssec-test-message";
        let sig: ed448_goldilocks_plus::Signature = private.sign(msg);
        assert!(verify(public.as_bytes(), msg, &sig.to_bytes()));
        assert!(!verify(public.as_bytes(), b"tampered", &sig.to_bytes()));
    }
}
