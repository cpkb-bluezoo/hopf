// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 key schedule (RFC 8446 §7.1) — QUIC-first.

use bytes::Bytes;

use crate::crypto::hkdf::{empty_hash, expand_label, extract, HkdfPrk};

/// Traffic secrets derived after ServerHello (handshake phase).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeTrafficSecrets {
    /// Client handshake traffic secret.
    pub client: [u8; 32],
    /// Server handshake traffic secret.
    pub server: [u8; 32],
}

/// Handshake secret PRK after ECDHE (retained for master-secret derivation).
pub fn handshake_secret(shared_secret: &[u8]) -> HkdfPrk {
    let early = extract(Some(&[0u8; 32]), &[0u8; 32]);
    let derived = early.derive_secret("derived", &empty_hash());
    extract(Some(&derived), shared_secret)
}

/// Derive handshake traffic secrets after ECDHE (PSK-less full handshake).
pub fn derive_handshake_traffic(shared_secret: &[u8], transcript_hash: &[u8; 32]) -> HandshakeTrafficSecrets {
    let hs = handshake_secret(shared_secret);
    HandshakeTrafficSecrets {
        client: hs.derive_secret("c hs traffic", transcript_hash),
        server: hs.derive_secret("s hs traffic", transcript_hash),
    }
}

/// Application traffic secrets after both Finished messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationTrafficSecrets {
    /// Client application traffic secret.
    pub client: [u8; 32],
    /// Server application traffic secret.
    pub server: [u8; 32],
}

/// Finished verify_data for the given traffic secret (RFC 8446 §4.4.4).
pub fn compute_finished_verify_data(traffic_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    use aws_lc_rs::hmac::{self, Key, HMAC_SHA256};
    let finished_key = expand_label(traffic_secret, "finished", &[], 32);
    let key = Key::new(HMAC_SHA256, finished_key.as_ref());
    let tag = hmac::sign(&key, transcript_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Derive 1-RTT application traffic secrets after both Finished messages.
pub fn derive_application_traffic(
    shared_secret: &[u8],
    transcript_hash: &[u8; 32],
) -> ApplicationTrafficSecrets {
    let hs = handshake_secret(shared_secret);
    let derived = hs.derive_secret("derived", &empty_hash());
    let master = extract(Some(&derived), &[] as &[u8]);
    ApplicationTrafficSecrets {
        client: master.derive_secret("c ap traffic", transcript_hash),
        server: master.derive_secret("s ap traffic", transcript_hash),
    }
}

/// Expand traffic secret to AEAD key and IV (RFC 8446 §7.3) — TCP record layer (Phase 4).
#[allow(dead_code)]
pub fn traffic_key_iv(secret: &[u8; 32], key_len: usize, iv_len: usize) -> (Bytes, Bytes) {
    let key = expand_label(secret, "key", &[], key_len);
    let iv = expand_label(secret, "iv", &[], iv_len);
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    #[test]
    fn rfc8448_handshake_traffic_secrets() {
        let shared = hex32("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let transcript = hex32("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let secrets = derive_handshake_traffic(&shared, &transcript);
        assert_eq!(
            secrets.client,
            hex32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
        assert_eq!(
            secrets.server,
            hex32("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );
    }
}
