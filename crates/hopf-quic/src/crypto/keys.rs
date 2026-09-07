// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9001 packet protection keys derived from TLS 1.3 traffic secrets.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use aws_lc_rs::aead::quic::{AES_128, HeaderProtectionKey};
use bytes::BytesMut;
use hopf_core::crypto::quic_expand_label;
use quinn_proto::crypto::{self, CryptoError, HeaderKey, KeyPair, Keys, PacketKey};
use quinn_proto::Side;
use rustls::Side as RustlsSide;
use rustls::quic::{Keys as RustlsKeys, Suite, Version};

const KEY_LEN: usize = 16;
const IV_LEN: usize = 12;
const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
const INTEGRITY_LIMIT: u64 = 1 << 52;

/// TLS_AES_128_GCM_SHA256 initial keys for QUIC v1.
pub fn initial_keys(version: u32, dst_cid: &quinn_proto::ConnectionId, side: Side) -> Result<Keys, crypto::UnsupportedVersion> {
    let v = interpret_version(version)?;
    let suite = default_suite();
    let rustls_side = match side {
        Side::Client => RustlsSide::Client,
        Side::Server => RustlsSide::Server,
    };
    let keys = RustlsKeys::initial(v, suite.suite, suite.quic, dst_cid.as_ref(), rustls_side);
    Ok(to_quinn_keys(keys))
}

/// Derive Handshake or 1-RTT keys from client/server traffic secrets.
pub fn keys_from_traffic_secrets(
    version: u32,
    side: Side,
    client_secret: [u8; 32],
    server_secret: [u8; 32],
) -> Result<Keys, crypto::UnsupportedVersion> {
    let _ = interpret_version(version)?;
    let (local_secret, remote_secret) = match side {
        Side::Client => (client_secret, server_secret),
        Side::Server => (server_secret, client_secret),
    };
    Ok(Keys {
        header: KeyPair {
            local: Box::new(Aes128HeaderKey::new(&local_secret)),
            remote: Box::new(Aes128HeaderKey::new(&remote_secret)),
        },
        packet: KeyPair {
            local: Box::new(Aes128PacketKey::new(&local_secret)),
            remote: Box::new(Aes128PacketKey::new(&remote_secret)),
        },
    })
}

pub(crate) fn default_suite() -> Suite {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => Some(suite.quic_suite()),
            _ => None,
        })
        .flatten()
        .expect("TLS13_AES_128_GCM_SHA256 QUIC suite")
}

fn to_quinn_keys(keys: RustlsKeys) -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(RustlsHeaderKey(keys.local.header)),
            remote: Box::new(RustlsHeaderKey(keys.remote.header)),
        },
        packet: KeyPair {
            local: Box::new(RustlsPacketKey(keys.local.packet)),
            remote: Box::new(RustlsPacketKey(keys.remote.packet)),
        },
    }
}

struct RustlsHeaderKey(Box<dyn rustls::quic::HeaderProtectionKey>);

impl HeaderKey for RustlsHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = pn_offset.min(rest.len().saturating_sub(1)) + 1;
        self.0
            .decrypt_in_place(
                &sample[..self.0.sample_len()],
                &mut first[0],
                &mut rest[pn_offset.saturating_sub(1)..pn_end],
            )
            .expect("header decrypt");
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = pn_offset.min(rest.len().saturating_sub(1)) + 1;
        self.0
            .encrypt_in_place(
                &sample[..self.0.sample_len()],
                &mut first[0],
                &mut rest[pn_offset.saturating_sub(1)..pn_end],
            )
            .expect("header encrypt");
    }

    fn sample_size(&self) -> usize {
        self.0.sample_len()
    }
}

struct RustlsPacketKey(Box<dyn rustls::quic::PacketKey>);

impl PacketKey for RustlsPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        let tag = self
            .0
            .encrypt_in_place(packet, header, payload)
            .expect("encrypt");
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .0
            .decrypt_in_place(packet, header, payload.as_mut())
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

struct Aes128PacketKey {
    key: LessSafeKey,
    iv: [u8; IV_LEN],
}

impl Aes128PacketKey {
    fn new(secret: &[u8; 32]) -> Self {
        let key_bytes = quic_expand_label(secret, "key", &[], KEY_LEN);
        let iv_bytes = quic_expand_label(secret, "iv", &[], IV_LEN);
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(iv_bytes.as_ref());
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_128_GCM, key_bytes.as_ref()).expect("AES-128-GCM key"),
        );
        Self { key, iv }
    }

    fn nonce(&self, packet: u64) -> Nonce {
        let mut seq = [0u8; IV_LEN];
        seq[4..].copy_from_slice(&packet.to_be_bytes());
        for (d, s) in seq.iter_mut().zip(self.iv.iter()) {
            *d ^= s;
        }
        Nonce::assume_unique_for_key(seq)
    }
}

impl PacketKey for Aes128PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let tag_len = self.tag_len();
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - tag_len);
        let tag = self
            .key
            .seal_in_place_separate_tag(self.nonce(packet), Aad::from(header), payload)
            .expect("seal");
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain_len = payload
            .len()
            .checked_sub(self.tag_len())
            .ok_or(CryptoError)?;
        self.key
            .open_in_place(self.nonce(packet), Aad::from(header), payload.as_mut())
            .map_err(|_| CryptoError)?;
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        CONFIDENTIALITY_LIMIT
    }

    fn integrity_limit(&self) -> u64 {
        INTEGRITY_LIMIT
    }
}

struct Aes128HeaderKey {
    hp: HeaderProtectionKey,
}

impl Aes128HeaderKey {
    fn new(secret: &[u8; 32]) -> Self {
        let hp_bytes = quic_expand_label(secret, "hp", &[], KEY_LEN);
        Self {
            hp: HeaderProtectionKey::new(&AES_128, hp_bytes.as_ref()).expect("header protection key"),
        }
    }

    fn apply(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8], masked: bool) {
        let mask = self.hp.new_mask(sample).expect("hp mask");
        let (first_mask, pn_mask) = mask.split_first().expect("mask");
        const LONG_HEADER: u8 = 0x80;
        let bits = if *first & LONG_HEADER == LONG_HEADER {
            0x0f
        } else {
            0x1f
        };
        let first_plain = if masked {
            *first ^ (first_mask & bits)
        } else {
            *first
        };
        let pn_len = (first_plain & 0x03) as usize + 1;
        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }
    }
}

impl HeaderKey for Aes128HeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = pn_offset.min(rest.len().saturating_sub(1)) + 1;
        self.apply(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset.saturating_sub(1)..pn_end],
            true,
        );
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = pn_offset.min(rest.len().saturating_sub(1)) + 1;
        self.apply(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset.saturating_sub(1)..pn_end],
            false,
        );
    }

    fn sample_size(&self) -> usize {
        self.hp.algorithm().sample_len()
    }
}

fn interpret_version(version: u32) -> Result<Version, crypto::UnsupportedVersion> {
    match version {
        0xff00_001d..=0xff00_0020 => Ok(Version::V1Draft),
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(crypto::UnsupportedVersion),
    }
}
