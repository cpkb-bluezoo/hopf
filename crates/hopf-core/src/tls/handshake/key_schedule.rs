// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 key schedule (RFC 8446 §7.1) — QUIC-first.

use bytes::Bytes;

use crate::crypto::hkdf::{
    dtls_expand_label, empty_hash, expand_label, extract, extract_derived, extract_derived_dtls,
    extract_dtls, HkdfPrk, Secret, Tls13Hash,
};

/// The running hash of the handshake transcript seen so far (RFC 8446
/// §4.4.1), always `Hash.length` bytes of the negotiated suite's hash (32
/// for SHA-256, 48 for SHA-384). Distinct from [`PskSecret`]/[`TrafficSecret`]
/// so a transcript hash and a secret can't be transposed at a call site —
/// both are bare byte strings with nothing at the type level to stop it
/// otherwise, and a swap wouldn't fail, it would just silently derive
/// wrong-but-plausible-looking keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptHash(Secret);

impl TranscriptHash {
    /// Wrap a transcript hash value.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Secret::from_slice(bytes.as_ref()))
    }

    /// Raw hash octets.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A pre-shared key (RFC 8446 §4.2.11) — either an external PSK or one
/// derived from a previous session's resumption master secret. See
/// [`TranscriptHash`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PskSecret(Secret);

impl PskSecret {
    /// Wrap a PSK value.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Secret::from_slice(bytes.as_ref()))
    }

    /// Raw PSK octets.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
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
pub struct ResumptionMasterSecret(Secret);

impl ResumptionMasterSecret {
    /// Wrap a resumption master secret value.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Secret::from_slice(bytes.as_ref()))
    }

    /// Raw octets.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
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
pub struct TrafficSecret(Secret);

impl TrafficSecret {
    /// Wrap a traffic secret value.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Secret::from_slice(bytes.as_ref()))
    }

    /// Raw octets.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
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
pub fn early_secret(hash: Tls13Hash, psk: Option<&PskSecret>, dtls: bool) -> HkdfPrk {
    let zeros = Secret::zeros(hash.len());
    let ikm = psk.map(|p| p.as_bytes()).unwrap_or(zeros.as_bytes());
    if dtls {
        extract_dtls(hash, Some(zeros.as_bytes()), ikm)
    } else {
        extract(hash, Some(zeros.as_bytes()), ikm)
    }
}

/// Handshake secret after ECDHE, optionally chaining from a resumption PSK.
pub fn handshake_secret_with_psk(
    hash: Tls13Hash,
    psk: Option<&PskSecret>,
    shared_secret: &[u8],
    dtls: bool,
) -> HkdfPrk {
    let early = early_secret(hash, psk, dtls);
    let derived = early.derive_secret("derived", empty_hash(hash).as_bytes());
    if dtls {
        extract_derived_dtls(hash, &derived, shared_secret)
    } else {
        extract_derived(hash, &derived, shared_secret)
    }
}

/// Derive handshake traffic secrets with optional PSK (PSK-(EC)DHE).
pub fn derive_handshake_traffic_with_psk(
    hash: Tls13Hash,
    psk: Option<&PskSecret>,
    shared_secret: &[u8],
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> HandshakeTrafficSecrets {
    let hs = handshake_secret_with_psk(hash, psk, shared_secret, dtls);
    HandshakeTrafficSecrets {
        client: TrafficSecret::from_bytes(hs.derive_secret("c hs traffic", transcript_hash.as_bytes())),
        server: TrafficSecret::from_bytes(hs.derive_secret("s hs traffic", transcript_hash.as_bytes())),
    }
}

/// Finished verify_data for the given traffic secret (RFC 8446 §4.4.4).
pub fn compute_finished_verify_data(
    hash: Tls13Hash,
    traffic_secret: &TrafficSecret,
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> Secret {
    use aws_lc_rs::hmac::{self, Key};
    let finished_key = if dtls {
        dtls_expand_label(hash, traffic_secret.as_bytes(), "finished", &[], hash.len())
    } else {
        expand_label(hash, traffic_secret.as_bytes(), "finished", &[], hash.len())
    };
    let key = Key::new(hash.hmac(), finished_key.as_ref());
    let tag = hmac::sign(&key, transcript_hash.as_bytes());
    Secret::from_slice(tag.as_ref())
}

/// Master secret PRK after the handshake secret. RFC 8446 §7.1: `IKM` here is
/// `Hash.length` zero *bytes* (32 for SHA-256, 48 for SHA-384) — not an empty
/// string; an empty IKM silently produces a different (wrong) PRK from
/// HKDF-Extract, since HMAC over zero bytes and HMAC over no bytes are
/// different messages.
fn master_secret(hash: Tls13Hash, psk: Option<&PskSecret>, shared_secret: &[u8], dtls: bool) -> HkdfPrk {
    let hs = handshake_secret_with_psk(hash, psk, shared_secret, dtls);
    let derived = hs.derive_secret("derived", empty_hash(hash).as_bytes());
    let zeros = Secret::zeros(hash.len());
    if dtls {
        extract_derived_dtls(hash, &derived, zeros.as_bytes())
    } else {
        extract_derived(hash, &derived, zeros.as_bytes())
    }
}

/// Derive 1-RTT application traffic secrets with optional PSK.
pub fn derive_application_traffic_with_psk(
    hash: Tls13Hash,
    psk: Option<&PskSecret>,
    shared_secret: &[u8],
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> ApplicationTrafficSecrets {
    let master = master_secret(hash, psk, shared_secret, dtls);
    ApplicationTrafficSecrets {
        client: TrafficSecret::from_bytes(master.derive_secret("c ap traffic", transcript_hash.as_bytes())),
        server: TrafficSecret::from_bytes(master.derive_secret("s ap traffic", transcript_hash.as_bytes())),
    }
}

/// Resumption master secret (RFC 8446 §7.1) — input to ticket PSK derivation.
pub fn derive_resumption_master_secret(
    hash: Tls13Hash,
    psk: Option<&PskSecret>,
    shared_secret: &[u8],
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> ResumptionMasterSecret {
    let master = master_secret(hash, psk, shared_secret, dtls);
    ResumptionMasterSecret::from_bytes(master.derive_secret("res master", transcript_hash.as_bytes()))
}

/// Exporter master secret (RFC 8446 §7.5) through the given transcript hash.
pub fn derive_exporter_master_secret(
    hash: Tls13Hash,
    psk: Option<&PskSecret>,
    shared_secret: &[u8],
    transcript_hash: &TranscriptHash,
    dtls: bool,
) -> Secret {
    let master = master_secret(hash, psk, shared_secret, dtls);
    master.derive_secret("exp master", transcript_hash.as_bytes())
}

/// Derive a resumption PSK from the resumption master secret and ticket nonce.
pub fn derive_resumption_psk(
    hash: Tls13Hash,
    resumption_master: &ResumptionMasterSecret,
    ticket_nonce: &[u8],
    dtls: bool,
) -> PskSecret {
    let out = if dtls {
        dtls_expand_label(hash, resumption_master.as_bytes(), "resumption", ticket_nonce, hash.len())
    } else {
        expand_label(hash, resumption_master.as_bytes(), "resumption", ticket_nonce, hash.len())
    };
    PskSecret::from_bytes(out)
}

/// Resumption binder key (`res binder`) from the early secret.
pub fn derive_resumption_binder_key(hash: Tls13Hash, psk: &PskSecret, dtls: bool) -> TrafficSecret {
    TrafficSecret::from_bytes(early_secret(hash, Some(psk), dtls).derive_secret("res binder", empty_hash(hash).as_bytes()))
}

/// Compute a PSK binder (RFC 8446 §4.2.11) over a truncated ClientHello transcript hash.
pub fn compute_psk_binder(hash: Tls13Hash, psk: &PskSecret, truncated_ch_hash: &TranscriptHash, dtls: bool) -> Secret {
    let binder_key = derive_resumption_binder_key(hash, psk, dtls);
    compute_finished_verify_data(hash, &binder_key, truncated_ch_hash, dtls)
}

/// Derive client early traffic secret from PSK and ClientHello transcript hash.
pub fn derive_early_traffic(
    hash: Tls13Hash,
    psk: &PskSecret,
    client_hello_hash: &TranscriptHash,
    dtls: bool,
) -> EarlyTrafficSecrets {
    EarlyTrafficSecrets {
        client: TrafficSecret::from_bytes(
            early_secret(hash, Some(psk), dtls).derive_secret("c e traffic", client_hello_hash.as_bytes()),
        ),
    }
}

/// Expand traffic secret to AEAD key and IV (RFC 8446 §7.3) — TCP record layer (Phase 4).
#[allow(dead_code)]
pub fn traffic_key_iv(hash: Tls13Hash, secret: &[u8], key_len: usize, iv_len: usize) -> (Bytes, Bytes) {
    let key = expand_label(hash, secret, "key", &[], key_len);
    let iv = expand_label(hash, secret, "iv", &[], iv_len);
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
        let secrets = derive_handshake_traffic_with_psk(Tls13Hash::Sha256, None, &shared, &transcript, false);
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
        let with = early_secret(Tls13Hash::Sha256, Some(&psk), false).derive_secret("c e traffic", empty_hash(Tls13Hash::Sha256).as_bytes());
        let without = early_secret(Tls13Hash::Sha256, None, false).derive_secret("c e traffic", empty_hash(Tls13Hash::Sha256).as_bytes());
        assert_ne!(with, without);
    }

    #[test]
    fn resumption_psk_roundtrip_shape() {
        let rms = ResumptionMasterSecret::from_bytes([0x11u8; 32]);
        let nonce = b"\x01\x02\x03\x04";
        let psk = derive_resumption_psk(Tls13Hash::Sha256, &rms, nonce, false);
        assert_ne!(psk.as_bytes(), &[0u8; 32]);
        let binder = compute_psk_binder(Tls13Hash::Sha256, &psk, &TranscriptHash::from_bytes(empty_hash(Tls13Hash::Sha256)), false);
        assert_ne!(binder.as_bytes(), &[0u8; 32]);
    }

    /// The DTLS 1.3 label-prefix variant (RFC 9147 §5.9) must produce
    /// different secrets from the TLS 1.3 path for the same inputs —
    /// cryptographic separation between the two protocols is the entire
    /// point of the prefix change.
    #[test]
    fn dtls_prefix_produces_different_secrets_than_tls() {
        let shared = [0x77u8; 32];
        let transcript = TranscriptHash::from_bytes([0x88u8; 32]);
        let tls = derive_handshake_traffic_with_psk(Tls13Hash::Sha256, None, &shared, &transcript, false);
        let dtls = derive_handshake_traffic_with_psk(Tls13Hash::Sha256, None, &shared, &transcript, true);
        assert_ne!(tls.client, dtls.client);
        assert_ne!(tls.server, dtls.server);
    }

    fn hex_vec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// SHA-384 key schedule against values computed with an independent
    /// HKDF-Expand-Label implementation (zero PSK, shared secret 0x00..0x2f,
    /// transcript hash = SHA-384("abc")): every secret is `Hash.length` = 48
    /// bytes, the early and master secrets chain from 48 zero bytes, and the
    /// `Finished` HMAC is HMAC-SHA-384.
    #[test]
    fn sha384_key_schedule_matches_independent_reference() {
        let hash = Tls13Hash::Sha384;
        let shared: Vec<u8> = (0..48).collect();
        let th = TranscriptHash::from_bytes(hash.hash(b"abc"));
        assert_eq!(
            th.as_bytes(),
            hex_vec("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        );
        let derived = early_secret(hash, None, false).derive_secret("derived", empty_hash(hash).as_bytes());
        assert_eq!(
            derived.as_bytes(),
            hex_vec("1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b")
        );
        let hs = derive_handshake_traffic_with_psk(hash, None, &shared, &th, false);
        assert_eq!(
            hs.client.as_bytes(),
            hex_vec("b53eb0861399112188fe6f680e44c544e8e4e026e08a97cd83505a2076707d3e5bb1b1153f1dc3a51e41ba487a57f0f7")
        );
        assert_eq!(
            hs.server.as_bytes(),
            hex_vec("0a913fa67639061f64fc62963096163aa0cbad4ed8db5f4179edc241d3de558252e3cd2e08217a3ce963f44c19f480fd")
        );
        let app = derive_application_traffic_with_psk(hash, None, &shared, &th, false);
        assert_eq!(
            app.client.as_bytes(),
            hex_vec("853f37051e8bc3abcc447f8f6a470365e5c7a50ebe44514f751627a8cd4b08e82a1eeba02fe3848ae2e17ae412a9069c")
        );
        let fin = compute_finished_verify_data(hash, &hs.client, &th, false);
        assert_eq!(
            fin.as_bytes(),
            hex_vec("35c8c45a68a73ff00f8d38b02fe516470425e9ced71833f9c84719dd4a63f335a4a694c61aa0cd42f2ca95824113da90")
        );
        let (key, iv) = traffic_key_iv(hash, hs.client.as_bytes(), 32, 12);
        assert_eq!(key.as_ref(), hex_vec("3f86edd1ce8bb943a449269b0cb2d9d4b14823d83d2850e06b52a39d161d6254"));
        assert_eq!(iv.as_ref(), hex_vec("c6a47334ac5995ad216d26fa"));
    }

    /// The hash is part of the derivation: the same inputs under SHA-256 and
    /// SHA-384 give different-length, unrelated secrets.
    #[test]
    fn hash_choice_changes_every_secret() {
        let shared = [0x11u8; 48];
        let t256 = TranscriptHash::from_bytes([0x22u8; 32]);
        let t384 = TranscriptHash::from_bytes([0x22u8; 48]);
        let a = derive_handshake_traffic_with_psk(Tls13Hash::Sha256, None, &shared, &t256, false);
        let b = derive_handshake_traffic_with_psk(Tls13Hash::Sha384, None, &shared, &t384, false);
        assert_eq!(a.client.as_bytes().len(), 32);
        assert_eq!(b.client.as_bytes().len(), 48);
        assert_ne!(&b.client.as_bytes()[..32], a.client.as_bytes());
    }
}
