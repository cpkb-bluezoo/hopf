// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 key schedule (RFC 8446 §7.1) — QUIC-first.

use bytes::Bytes;

use crate::crypto::hkdf::{
    dtls_expand_label, empty_hash, expand_label, extract, extract_derived, extract_derived_dtls,
    extract_dtls, HkdfPrk,
};

/// The running hash of the handshake transcript seen so far (RFC 8446
/// §4.4.1), always `Hash.length` bytes (32, for this codebase's sole TLS
/// 1.3 hash, SHA-256). Distinct from [`PskSecret`]/[`TrafficSecret`] so a
/// transcript hash and a secret can't be transposed at a call site — both
/// are bare 32-byte values with nothing at the type level to stop it
/// otherwise, and a swap wouldn't fail, it would just silently derive
/// wrong-but-plausible-looking keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptHash([u8; 32]);

impl TranscriptHash {
    /// Wrap a 32-byte transcript hash value.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw hash octets.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A pre-shared key (RFC 8446 §4.2.11) — either an external PSK or one
/// derived from a previous session's resumption master secret. See
/// [`TranscriptHash`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PskSecret([u8; 32]);

impl PskSecret {
    /// Wrap a 32-byte PSK value.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw PSK octets.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for PskSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PskSecret(..)")
    }
}

/// The resumption master secret (RFC 8446 §7.1) — input to
/// [`derive_resumption_psk`], never used as a traffic key directly. A
/// distinct type from [`PskSecret`] even though [`derive_resumption_psk`]
/// turns one into the other, since the two mean different things at every
/// other call site.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResumptionMasterSecret([u8; 32]);

impl ResumptionMasterSecret {
    /// Wrap a 32-byte resumption master secret value.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw octets.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ResumptionMasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResumptionMasterSecret(..)")
    }
}

/// One direction's traffic secret (handshake or application phase) —
/// keying material, never to be confused with a [`TranscriptHash`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrafficSecret([u8; 32]);

impl TrafficSecret {
    /// Wrap a 32-byte traffic secret value.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw octets.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for TrafficSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrafficSecret(..)")
    }
}

/// Traffic secrets derived after ServerHello (handshake phase).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeTrafficSecrets {
    /// Client handshake traffic secret.
    pub client: TrafficSecret,
    /// Server handshake traffic secret.
    pub server: TrafficSecret,
}

/// Application traffic secrets after both Finished messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationTrafficSecrets {
    /// Client application traffic secret.
    pub client: TrafficSecret,
    /// Server application traffic secret.
    pub server: TrafficSecret,
}

/// Early (0-RTT) traffic secret derived from a PSK (RFC 8446 §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyTrafficSecrets {
    /// Client early traffic secret (`c e traffic`).
    pub client: TrafficSecret,
}

/// HKDF-Extract early secret from an optional PSK (zeros IKM when `None`).
/// `dtls` selects RFC 9147 §5.9's `"dtls13 "` label prefix throughout this
/// derivation and everything chained from it, instead of TLS 1.3's
/// `"tls13 "` — see [`crate::crypto::hkdf::extract_dtls`]'s doc comment for
/// why this isn't scoped to just a final record-layer step, and for the
/// verification caveat.
pub fn early_secret(psk: Option<&PskSecret>, dtls: bool) -> HkdfPrk {
    let ikm = psk.map(|p| p.as_bytes().as_slice()).unwrap_or(&[0u8; 32]);
    if dtls {
        extract_dtls(Some(&[0u8; 32]), ikm)
    } else {
        extract(Some(&[0u8; 32]), ikm)
    }
}

/// Handshake secret after ECDHE, optionally chaining from a resumption PSK.
pub fn handshake_secret_with_psk(psk: Option<&PskSecret>, shared_secret: &[u8], dtls: bool) -> HkdfPrk {
    let early = early_secret(psk, dtls);
    let derived = early.derive_secret("derived", &empty_hash());
    if dtls {
        extract_derived_dtls(&derived, shared_secret)
    } else {
        extract_derived(&derived, shared_secret)
    }
}

/// Derive handshake traffic secrets with optional PSK (PSK-(EC)DHE).
pub fn derive_handshake_traffic_with_psk(
    psk: Option<&PskSecret>,
    shared_secret: &[u8],
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> HandshakeTrafficSecrets {
    let hs = handshake_secret_with_psk(psk, shared_secret, dtls);
    HandshakeTrafficSecrets {
        client: TrafficSecret::from_bytes(hs.derive_secret("c hs traffic", transcript_hash.as_bytes())),
        server: TrafficSecret::from_bytes(hs.derive_secret("s hs traffic", transcript_hash.as_bytes())),
    }
}

/// Finished verify_data for the given traffic secret (RFC 8446 §4.4.4).
pub fn compute_finished_verify_data(
    traffic_secret: &TrafficSecret,
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> [u8; 32] {
    use aws_lc_rs::hmac::{self, Key, HMAC_SHA256};
    let finished_key = if dtls {
        dtls_expand_label(traffic_secret.as_bytes(), "finished", &[], 32)
    } else {
        expand_label(traffic_secret.as_bytes(), "finished", &[], 32)
    };
    let key = Key::new(HMAC_SHA256, finished_key.as_ref());
    let tag = hmac::sign(&key, transcript_hash.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Master secret PRK after the handshake secret. RFC 8446 §7.1: `IKM` here is
/// `Hash.length` zero *bytes* (32, for SHA-256) — not an empty string; an
/// empty IKM silently produces a different (wrong) PRK from HKDF-Extract,
/// since HMAC over zero bytes and HMAC over no bytes are different messages.
fn master_secret(psk: Option<&PskSecret>, shared_secret: &[u8], dtls: bool) -> HkdfPrk {
    let hs = handshake_secret_with_psk(psk, shared_secret, dtls);
    let derived = hs.derive_secret("derived", &empty_hash());
    if dtls {
        extract_derived_dtls(&derived, &[0u8; 32])
    } else {
        extract_derived(&derived, &[0u8; 32])
    }
}

/// Derive 1-RTT application traffic secrets with optional PSK.
pub fn derive_application_traffic_with_psk(
    psk: Option<&PskSecret>,
    shared_secret: &[u8],
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> ApplicationTrafficSecrets {
    let master = master_secret(psk, shared_secret, dtls);
    ApplicationTrafficSecrets {
        client: TrafficSecret::from_bytes(master.derive_secret("c ap traffic", transcript_hash.as_bytes())),
        server: TrafficSecret::from_bytes(master.derive_secret("s ap traffic", transcript_hash.as_bytes())),
    }
}

/// Resumption master secret (RFC 8446 §7.1) — input to ticket PSK derivation.
pub fn derive_resumption_master_secret(
    psk: Option<&PskSecret>,
    shared_secret: &[u8],
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> ResumptionMasterSecret {
    let master = master_secret(psk, shared_secret, dtls);
    ResumptionMasterSecret::from_bytes(master.derive_secret("res master", transcript_hash.as_bytes()))
}

/// Derive a resumption PSK from the resumption master secret and ticket nonce.
pub fn derive_resumption_psk(resumption_master: &ResumptionMasterSecret, ticket_nonce: &[u8], dtls: bool) -> PskSecret {
    let out = if dtls {
        dtls_expand_label(resumption_master.as_bytes(), "resumption", ticket_nonce, 32)
    } else {
        expand_label(resumption_master.as_bytes(), "resumption", ticket_nonce, 32)
    };
    let mut psk = [0u8; 32];
    psk.copy_from_slice(out.as_ref());
    PskSecret::from_bytes(psk)
}

/// Resumption binder key (`res binder`) from the early secret.
pub fn derive_resumption_binder_key(psk: &PskSecret, dtls: bool) -> TrafficSecret {
    TrafficSecret::from_bytes(early_secret(Some(psk), dtls).derive_secret("res binder", &empty_hash()))
}

/// Compute a PSK binder (RFC 8446 §4.2.11) over a truncated ClientHello transcript hash.
pub fn compute_psk_binder(psk: &PskSecret, truncated_ch_hash: &TranscriptHash, dtls: bool) -> [u8; 32] {
    let binder_key = derive_resumption_binder_key(psk, dtls);
    compute_finished_verify_data(&binder_key, truncated_ch_hash, dtls)
}

/// Derive client early traffic secret from PSK and ClientHello transcript hash.
pub fn derive_early_traffic(psk: &PskSecret, client_hello_hash: &TranscriptHash, dtls: bool) -> EarlyTrafficSecrets {
    EarlyTrafficSecrets {
        client: TrafficSecret::from_bytes(
            early_secret(Some(psk), dtls).derive_secret("c e traffic", client_hello_hash.as_bytes()),
        ),
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

    fn transcript_hash32(s: &str) -> TranscriptHash {
        TranscriptHash::from_bytes(hex32(s))
    }

    #[test]
    fn rfc8448_handshake_traffic_secrets() {
        let shared = hex32("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let transcript = transcript_hash32("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let secrets = derive_handshake_traffic_with_psk(None, &shared, &transcript, false);
        assert_eq!(
            secrets.client.as_bytes(),
            &hex32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
        assert_eq!(
            secrets.server.as_bytes(),
            &hex32("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );
    }

    #[test]
    fn early_secret_from_psk_differs_from_zeros() {
        let psk = PskSecret::from_bytes([0x42u8; 32]);
        let with = early_secret(Some(&psk), false).derive_secret("c e traffic", &empty_hash());
        let without = early_secret(None, false).derive_secret("c e traffic", &empty_hash());
        assert_ne!(with, without);
    }

    #[test]
    fn resumption_psk_roundtrip_shape() {
        let rms = ResumptionMasterSecret::from_bytes([0x11u8; 32]);
        let nonce = b"\x01\x02\x03\x04";
        let psk = derive_resumption_psk(&rms, nonce, false);
        assert_ne!(psk.as_bytes(), &[0u8; 32]);
        let binder = compute_psk_binder(&psk, &TranscriptHash::from_bytes(empty_hash()), false);
        assert_ne!(binder, [0u8; 32]);
    }

    /// The DTLS 1.3 label-prefix variant (RFC 9147 §5.9) must produce
    /// different secrets from the TLS 1.3 path for the same inputs —
    /// cryptographic separation between the two protocols is the entire
    /// point of the prefix change.
    #[test]
    fn dtls_prefix_produces_different_secrets_than_tls() {
        let shared = [0x77u8; 32];
        let transcript = TranscriptHash::from_bytes([0x88u8; 32]);
        let tls = derive_handshake_traffic_with_psk(None, &shared, &transcript, false);
        let dtls = derive_handshake_traffic_with_psk(None, &shared, &transcript, true);
        assert_ne!(tls.client, dtls.client);
        assert_ne!(tls.server, dtls.server);
    }
}
