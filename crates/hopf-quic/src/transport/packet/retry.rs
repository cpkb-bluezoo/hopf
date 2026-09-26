// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Retry packet, integrity tag (RFC 9001 §5.8), and AEAD Retry Token.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::transport::packet::long_header::{HEADER_FORM_LONG, FIXED_BIT, TYPE_RETRY};
use crate::transport::types::ConnectionId;
use crate::transport::version::QuicVersion;

/// Retry Integrity Tag length (RFC 9000 §17.2.5.1).
pub const INTEGRITY_TAG_LEN: usize = 16;

const TOKEN_NONCE_LEN: usize = 12;
const TOKEN_GCM_TAG_LEN: usize = 16;

/// Parsed Retry packet (RFC 9000 §17.2.5).
#[derive(Debug, Clone)]
pub struct RetryPacket {
    /// QUIC version the Retry is in.
    pub version: QuicVersion,
    /// Client's SCID from the Initial that triggered this Retry.
    pub dst_cid: ConnectionId,
    /// Server's newly chosen SCID (client's next Initial DCID).
    pub src_cid: ConnectionId,
    /// Opaque token the client must echo.
    pub token: Vec<u8>,
    /// 16-byte integrity tag.
    pub tag: [u8; INTEGRITY_TAG_LEN],
    /// Packet bytes excluding the trailing tag.
    pub without_tag: Vec<u8>,
}

/// Build Retry header + token (no integrity tag).
pub fn build_without_tag(
    version: QuicVersion,
    dst_cid: &ConnectionId,
    src_cid: &ConnectionId,
    token: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + 2 + dst_cid.len() + src_cid.len() + token.len());
    let first = HEADER_FORM_LONG | FIXED_BIT | (version.wire_type(TYPE_RETRY) << 4);
    out.push(first);
    out.extend_from_slice(&version.wire().to_be_bytes());
    out.push(dst_cid.len() as u8);
    out.extend_from_slice(dst_cid.as_slice());
    out.push(src_cid.len() as u8);
    out.extend_from_slice(src_cid.as_slice());
    out.extend_from_slice(token);
    out
}

/// Parse a Retry packet (must include the trailing integrity tag).
pub fn parse(packet: &[u8]) -> Option<RetryPacket> {
    if packet.len() < 7 + INTEGRITY_TAG_LEN {
        return None;
    }
    let first = packet[0];
    if first & HEADER_FORM_LONG == 0 {
        return None;
    }
    let version = QuicVersion::from_wire(u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]))?;
    if version.logical_type((first >> 4) & 0x03) != TYPE_RETRY {
        return None;
    }
    let mut rest = &packet[5..];
    let dcid_len = *rest.first()? as usize;
    rest = &rest[1..];
    if rest.len() < dcid_len {
        return None;
    }
    let dst_cid = ConnectionId::from_slice(&rest[..dcid_len]);
    rest = &rest[dcid_len..];
    let scid_len = *rest.first()? as usize;
    rest = &rest[1..];
    if rest.len() < scid_len + INTEGRITY_TAG_LEN {
        return None;
    }
    let src_cid = ConnectionId::from_slice(&rest[..scid_len]);
    rest = &rest[scid_len..];
    let token_len = rest.len().checked_sub(INTEGRITY_TAG_LEN)?;
    let token = rest[..token_len].to_vec();
    let mut tag = [0u8; INTEGRITY_TAG_LEN];
    tag.copy_from_slice(&rest[token_len..]);
    let without_tag = packet[..packet.len() - INTEGRITY_TAG_LEN].to_vec();
    Some(RetryPacket {
        version,
        dst_cid,
        src_cid,
        token,
        tag,
        without_tag,
    })
}

/// Compute Retry Integrity Tag (RFC 9001 §5.8).
pub fn integrity_tag(version: QuicVersion, original_dst_cid: &[u8], retry_without_tag: &[u8]) -> [u8; INTEGRITY_TAG_LEN] {
    let mut aad = Vec::with_capacity(1 + original_dst_cid.len() + retry_without_tag.len());
    aad.push(original_dst_cid.len() as u8);
    aad.extend_from_slice(original_dst_cid);
    aad.extend_from_slice(retry_without_tag);

    let key = LessSafeKey::new(
        UnboundKey::new(&AES_128_GCM, &version.retry_key()).expect("integrity key"),
    );
    let mut empty = Vec::new();
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(version.retry_nonce()),
            Aad::from(&aad),
            &mut empty,
        )
        .expect("integrity seal");
    let mut out = [0u8; INTEGRITY_TAG_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Verify a received integrity tag (constant-time).
pub fn verify_integrity(
    version: QuicVersion,
    original_dst_cid: &[u8],
    retry_without_tag: &[u8],
    received_tag: &[u8],
) -> bool {
    if received_tag.len() != INTEGRITY_TAG_LEN {
        return false;
    }
    let expected = integrity_tag(version, original_dst_cid, retry_without_tag);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(received_tag.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Build a complete Retry packet (header + token + integrity tag).
pub fn build_packet(
    version: QuicVersion,
    client_scid: &ConnectionId,
    retry_scid: &ConnectionId,
    original_dst_cid: &[u8],
    token: &[u8],
) -> Vec<u8> {
    let without_tag = build_without_tag(version, client_scid, retry_scid, token);
    let tag = integrity_tag(version, original_dst_cid, &without_tag);
    let mut packet = without_tag;
    packet.extend_from_slice(&tag);
    packet
}

/// Generate a random 32-byte Retry Token sealing key.
pub fn generate_token_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let _ = SystemRandom::new().fill(&mut key);
    key
}

/// Seal a Retry Token (Gumdrop scheme: AES-256-GCM, AAD = client IP).
pub fn seal_token(
    key: &[u8; 32],
    version: QuicVersion,
    original_dst_cid: &[u8],
    client_ip: IpAddr,
    issued_at: SystemTime,
) -> Vec<u8> {
    let mut nonce = [0u8; TOKEN_NONCE_LEN];
    let _ = SystemRandom::new().fill(&mut nonce);

    let issued_ms = issued_at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut plaintext = Vec::with_capacity(1 + original_dst_cid.len() + 8);
    plaintext.push(original_dst_cid.len() as u8);
    plaintext.extend_from_slice(original_dst_cid);
    plaintext.extend_from_slice(&issued_ms.to_be_bytes());
    // The version the Retry was sent in: the returning Initial must use the
    // same one (RFC 9369 section 4.1 lets the server enforce this).
    plaintext.extend_from_slice(&version.wire().to_be_bytes());

    let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("token key"));
    let aad = ip_aad(client_ip);
    let tag = aead
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&aad),
            &mut plaintext,
        )
        .expect("token seal");
    plaintext.extend_from_slice(tag.as_ref());

    let mut token = Vec::with_capacity(TOKEN_NONCE_LEN + plaintext.len());
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&plaintext);
    token
}

/// Unseal and validate a Retry Token. Returns the original Destination CID.
pub fn unseal_token(
    key: &[u8; 32],
    version: QuicVersion,
    token: &[u8],
    client_ip: IpAddr,
    max_age: Duration,
) -> Option<Vec<u8>> {
    if token.len() < TOKEN_NONCE_LEN + TOKEN_GCM_TAG_LEN {
        return None;
    }
    let mut nonce = [0u8; TOKEN_NONCE_LEN];
    nonce.copy_from_slice(&token[..TOKEN_NONCE_LEN]);
    let mut ciphertext = token[TOKEN_NONCE_LEN..].to_vec();
    let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let aad = ip_aad(client_ip);
    aead.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&aad),
        &mut ciphertext,
    )
    .ok()?;
    let plain_len = ciphertext.len().checked_sub(TOKEN_GCM_TAG_LEN)?;
    ciphertext.truncate(plain_len);

    if ciphertext.is_empty() {
        return None;
    }
    let dcid_len = ciphertext[0] as usize;
    if ciphertext.len() < 1 + dcid_len + 8 + 4 {
        return None;
    }
    let dcid = ciphertext[1..1 + dcid_len].to_vec();
    let mut issued_bytes = [0u8; 8];
    issued_bytes.copy_from_slice(&ciphertext[1 + dcid_len..1 + dcid_len + 8]);
    let issued_ms = u64::from_be_bytes(issued_bytes);
    let v = 1 + dcid_len + 8;
    let token_version = u32::from_be_bytes([ciphertext[v], ciphertext[v + 1], ciphertext[v + 2], ciphertext[v + 3]]);
    if token_version != version.wire() {
        return None;
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if now_ms.saturating_sub(issued_ms) > max_age.as_millis() as u64 {
        return None;
    }
    Some(dcid)
}

fn ip_aad(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn retry_wire_round_trip() {
        let dcid = ConnectionId::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let scid = ConnectionId::from_slice(&[9, 10, 11, 12]);
        let token = b"opaque-retry-token";
        let odcid = ConnectionId::from_slice(&[0xaa; 8]);
        let packet = build_packet(QuicVersion::V1, &dcid, &scid, odcid.as_slice(), token);
        let parsed = parse(&packet).unwrap();
        assert_eq!(parsed.dst_cid.as_slice(), dcid.as_slice());
        assert_eq!(parsed.src_cid.as_slice(), scid.as_slice());
        assert_eq!(parsed.token, token);
        assert_eq!(parsed.version, QuicVersion::V1);
        assert!(verify_integrity(
            QuicVersion::V1,
            odcid.as_slice(),
            &parsed.without_tag,
            &parsed.tag
        ));
    }

    #[test]
    fn integrity_rejects_wrong_odcid() {
        let without = build_without_tag(
            QuicVersion::V1,
            &ConnectionId::from_slice(&[1; 8]),
            &ConnectionId::from_slice(&[2; 8]),
            b"tok",
        );
        let tag = integrity_tag(QuicVersion::V1, &[3; 8], &without);
        assert!(!verify_integrity(QuicVersion::V1, &[4; 8], &without, &tag));
    }

    #[test]
    fn token_seal_unseal_round_trip() {
        let key = generate_token_key();
        let odcid = [7u8; 8];
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let token = seal_token(&key, QuicVersion::V1, &odcid, ip, SystemTime::now());
        let recovered = unseal_token(&key, QuicVersion::V1, &token, ip, Duration::from_secs(30)).unwrap();
        assert_eq!(recovered, odcid);
    }

    #[test]
    fn token_rejects_wrong_ip() {
        let key = generate_token_key();
        let odcid = [7u8; 8];
        let token = seal_token(
            &key,
            QuicVersion::V1,
            &odcid,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SystemTime::now(),
        );
        assert!(unseal_token(
            &key,
            QuicVersion::V1,
            &token,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            Duration::from_secs(30)
        )
        .is_none());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// The Retry samples of RFC 9001 A.4 (v1) and RFC 9369 A.4 (v2). The
    /// RFC's integrity tags must verify under our per-version key and nonce.
    /// A packet built here matches the sample apart from the four unused
    /// low bits of the first octet (arbitrary on the wire, and covered by
    /// the tag, so the tag differs too) and verifies under the same rules.
    #[test]
    fn rfc_sample_retry_packets() {
        use crate::transport::packet::{rfc9001_vectors as v1, rfc9369_vectors as v2};
        let odcid = hex(v1::DCID);
        let scid = ConnectionId::from_slice(&hex("f067a5502a4262b5"));
        for (version, sample) in [(QuicVersion::V1, v1::RETRY_PACKET), (QuicVersion::V2, v2::RETRY_PACKET)] {
            let sample = hex(sample);
            let parsed = parse(&sample).unwrap_or_else(|| panic!("{version:?} sample parses"));
            assert_eq!((parsed.version, parsed.token.as_slice()), (version, &b"token"[..]));
            assert_eq!(parsed.src_cid.as_slice(), scid.as_slice());
            assert!(verify_integrity(version, &odcid, &parsed.without_tag, &parsed.tag), "{version:?} RFC tag");
            assert_eq!(integrity_tag(version, &odcid, &parsed.without_tag).to_vec(), parsed.tag.to_vec());

            let built = build_packet(version, &ConnectionId::empty(), &scid, &odcid, b"token");
            assert_eq!(built.len(), sample.len());
            assert_eq!(built[0] & 0xf0, sample[0] & 0xf0, "form, fixed and type bits");
            assert_eq!(built[1..built.len() - INTEGRITY_TAG_LEN], sample[1..sample.len() - INTEGRITY_TAG_LEN]);
            let rebuilt = parse(&built).unwrap();
            assert!(verify_integrity(version, &odcid, &rebuilt.without_tag, &rebuilt.tag));
        }
        // A tag made for one version does not verify under the other.
        let p = parse(&hex(v2::RETRY_PACKET)).unwrap();
        assert!(!verify_integrity(QuicVersion::V1, &odcid, &p.without_tag, &p.tag));
    }

    /// RFC 9369 section 4.1: a server may bind the Retry token to the
    /// version so a client cannot switch versions on the returning Initial.
    #[test]
    fn a_token_is_only_valid_for_the_version_it_was_issued_in() {
        let key = generate_token_key();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let token = seal_token(&key, QuicVersion::V2, &[7; 8], ip, SystemTime::now());
        assert!(unseal_token(&key, QuicVersion::V2, &token, ip, Duration::from_secs(30)).is_some());
        assert!(unseal_token(&key, QuicVersion::V1, &token, ip, Duration::from_secs(30)).is_none());
    }
}
