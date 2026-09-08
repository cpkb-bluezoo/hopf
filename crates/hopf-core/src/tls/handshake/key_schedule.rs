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

/// Application traffic secrets after both Finished messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationTrafficSecrets {
    /// Client application traffic secret.
    pub client: [u8; 32],
    /// Server application traffic secret.
    pub server: [u8; 32],
}

/// Early (0-RTT) traffic secret derived from a PSK (RFC 8446 §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyTrafficSecrets {
    /// Client early traffic secret (`c e traffic`).
    pub client: [u8; 32],
}

/// HKDF-Extract early secret from an optional PSK (zeros IKM when `None`).
pub fn early_secret(psk: Option<&[u8; 32]>) -> HkdfPrk {
    let ikm = psk.map(|p| p.as_slice()).unwrap_or(&[0u8; 32]);
    extract(Some(&[0u8; 32]), ikm)
}

/// Handshake secret PRK after ECDHE (PSK-less full handshake).
pub fn handshake_secret(shared_secret: &[u8]) -> HkdfPrk {
    handshake_secret_with_psk(None, shared_secret)
}

/// Handshake secret after ECDHE, optionally chaining from a resumption PSK.
pub fn handshake_secret_with_psk(psk: Option<&[u8; 32]>, shared_secret: &[u8]) -> HkdfPrk {
    let early = early_secret(psk);
    let derived = early.derive_secret("derived", &empty_hash());
    extract(Some(&derived), shared_secret)
}

/// Derive handshake traffic secrets after ECDHE (PSK-less full handshake).
pub fn derive_handshake_traffic(shared_secret: &[u8], transcript_hash: &[u8; 32]) -> HandshakeTrafficSecrets {
    derive_handshake_traffic_with_psk(None, shared_secret, transcript_hash)
}

/// Derive handshake traffic secrets with optional PSK (PSK-(EC)DHE).
pub fn derive_handshake_traffic_with_psk(
    psk: Option<&[u8; 32]>,
    shared_secret: &[u8],
    transcript_hash: &[u8; 32],
) -> HandshakeTrafficSecrets {
    let hs = handshake_secret_with_psk(psk, shared_secret);
    HandshakeTrafficSecrets {
        client: hs.derive_secret("c hs traffic", transcript_hash),
        server: hs.derive_secret("s hs traffic", transcript_hash),
    }
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

/// Master secret PRK after the handshake secret. RFC 8446 §7.1: `IKM` here is
/// `Hash.length` zero *bytes* (32, for SHA-256) — not an empty string; an
/// empty IKM silently produces a different (wrong) PRK from HKDF-Extract,
/// since HMAC over zero bytes and HMAC over no bytes are different messages.
fn master_secret(psk: Option<&[u8; 32]>, shared_secret: &[u8]) -> HkdfPrk {
    let hs = handshake_secret_with_psk(psk, shared_secret);
    let derived = hs.derive_secret("derived", &empty_hash());
    extract(Some(&derived), &[0u8; 32])
}

/// Derive 1-RTT application traffic secrets after both Finished messages.
pub fn derive_application_traffic(
    shared_secret: &[u8],
    transcript_hash: &[u8; 32],
) -> ApplicationTrafficSecrets {
    derive_application_traffic_with_psk(None, shared_secret, transcript_hash)
}

/// Derive 1-RTT application traffic secrets with optional PSK.
pub fn derive_application_traffic_with_psk(
    psk: Option<&[u8; 32]>,
    shared_secret: &[u8],
    transcript_hash: &[u8; 32],
) -> ApplicationTrafficSecrets {
    let master = master_secret(psk, shared_secret);
    ApplicationTrafficSecrets {
        client: master.derive_secret("c ap traffic", transcript_hash),
        server: master.derive_secret("s ap traffic", transcript_hash),
    }
}

/// Resumption master secret (RFC 8446 §7.1) — input to ticket PSK derivation.
pub fn derive_resumption_master_secret(
    psk: Option<&[u8; 32]>,
    shared_secret: &[u8],
    transcript_hash: &[u8; 32],
) -> [u8; 32] {
    let master = master_secret(psk, shared_secret);
    master.derive_secret("res master", transcript_hash)
}

/// Derive a resumption PSK from the resumption master secret and ticket nonce.
pub fn derive_resumption_psk(resumption_master: &[u8; 32], ticket_nonce: &[u8]) -> [u8; 32] {
    let out = expand_label(resumption_master, "resumption", ticket_nonce, 32);
    let mut psk = [0u8; 32];
    psk.copy_from_slice(out.as_ref());
    psk
}

/// Resumption binder key (`res binder`) from the early secret.
pub fn derive_resumption_binder_key(psk: &[u8; 32]) -> [u8; 32] {
    early_secret(Some(psk)).derive_secret("res binder", &empty_hash())
}

/// Compute a PSK binder (RFC 8446 §4.2.11) over a truncated ClientHello transcript hash.
pub fn compute_psk_binder(psk: &[u8; 32], truncated_ch_hash: &[u8; 32]) -> [u8; 32] {
    let binder_key = derive_resumption_binder_key(psk);
    compute_finished_verify_data(&binder_key, truncated_ch_hash)
}

/// Derive client early traffic secret from PSK and ClientHello transcript hash.
pub fn derive_early_traffic(psk: &[u8; 32], client_hello_hash: &[u8; 32]) -> EarlyTrafficSecrets {
    EarlyTrafficSecrets {
        client: early_secret(Some(psk)).derive_secret("c e traffic", client_hello_hash),
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

    #[test]
    fn early_secret_from_psk_differs_from_zeros() {
        let psk = [0x42u8; 32];
        let with = early_secret(Some(&psk)).derive_secret("c e traffic", &empty_hash());
        let without = early_secret(None).derive_secret("c e traffic", &empty_hash());
        assert_ne!(with, without);
    }

    #[test]
    fn resumption_psk_roundtrip_shape() {
        let rms = [0x11u8; 32];
        let nonce = b"\x01\x02\x03\x04";
        let psk = derive_resumption_psk(&rms, nonce);
        assert_ne!(psk, [0u8; 32]);
        let binder = compute_psk_binder(&psk, &empty_hash());
        assert_ne!(binder, [0u8; 32]);
    }
}
