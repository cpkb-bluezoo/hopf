// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9001 packet / header protection (AES-128-GCM).

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128};
use hopf_core::crypto::{extract, quic_expand_label};

use crate::transport::types::Side;

const KEY_LEN: usize = 16;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// QUIC v1 Initial salt (RFC 9001 §5.2).
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Directional AEAD + header protection keys.
pub struct PacketKeys {
    aead: LessSafeKey,
    iv: [u8; IV_LEN],
    hp: HeaderProtectionKey,
}

impl PacketKeys {
    /// Derive from a 32-byte traffic secret.
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let key_bytes = quic_expand_label(secret, "key", &[], KEY_LEN);
        let iv_bytes = quic_expand_label(secret, "iv", &[], IV_LEN);
        let hp_bytes = quic_expand_label(secret, "hp", &[], KEY_LEN);
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(iv_bytes.as_ref());
        Self {
            aead: LessSafeKey::new(
                UnboundKey::new(&AES_128_GCM, key_bytes.as_ref()).expect("AES-128-GCM key"),
            ),
            iv,
            hp: HeaderProtectionKey::new(&AES_128, hp_bytes.as_ref()).expect("hp key"),
        }
    }

    fn nonce(&self, packet: u64) -> Nonce {
        let mut seq = [0u8; IV_LEN];
        seq[4..].copy_from_slice(&packet.to_be_bytes());
        for (d, s) in seq.iter_mut().zip(self.iv.iter()) {
            *d ^= s;
        }
        Nonce::assume_unique_for_key(seq)
    }

    /// Encrypt payload in place; appends 16-byte tag. `header` is AAD.
    pub fn encrypt(&self, packet_number: u64, header: &[u8], payload: &mut Vec<u8>) {
        let tag = self
            .aead
            .seal_in_place_separate_tag(self.nonce(packet_number), Aad::from(header), payload)
            .expect("seal");
        payload.extend_from_slice(tag.as_ref());
    }

    /// Decrypt ciphertext+tag in place; truncates tag on success.
    pub fn decrypt(
        &self,
        packet_number: u64,
        header: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, ()> {
        let plain_len = ciphertext.len().checked_sub(TAG_LEN).ok_or(())?;
        self.aead
            .open_in_place(self.nonce(packet_number), Aad::from(header), ciphertext)
            .map_err(|_| ())?;
        Ok(plain_len)
    }

    /// Apply / remove header protection given sample starting at `pn_offset + 4`.
    pub fn protect_header(&self, pn_offset: usize, packet: &mut [u8], mask: bool) {
        let sample_start = pn_offset + 4;
        let sample_len = self.hp.algorithm().sample_len();
        if packet.len() < sample_start + sample_len {
            return;
        }
        let sample = packet[sample_start..sample_start + sample_len].to_vec();
        let mask_bytes = self.hp.new_mask(&sample).expect("hp mask");
        let (first_mask, pn_mask) = mask_bytes.split_first().expect("mask");
        let long = packet[0] & 0x80 != 0;
        let bits = if long { 0x0f } else { 0x1f };
        // PN length is in the unprotected first-byte low bits. When removing
        // protection those bits are still masked — recover plaintext first.
        let pn_len = if mask {
            (packet[0] & 0x03) as usize + 1
        } else {
            ((packet[0] ^ (first_mask & bits)) & 0x03) as usize + 1
        };
        packet[0] ^= first_mask & bits;
        for (i, m) in pn_mask.iter().take(pn_len).enumerate() {
            if pn_offset + i < packet.len() {
                packet[pn_offset + i] ^= m;
            }
        }
    }

    /// Tag length (AES-GCM).
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }
}

/// Local + remote keys for one encryption level.
pub struct KeyPair {
    /// Keys for packets we send.
    pub local: PacketKeys,
    /// Keys for packets we receive.
    pub remote: PacketKeys,
}

impl KeyPair {
    /// From client/server traffic secrets for `side`.
    pub fn from_traffic_secrets(
        side: Side,
        client_secret: [u8; 32],
        server_secret: [u8; 32],
    ) -> Self {
        let (local_secret, remote_secret) = match side {
            Side::Client => (client_secret, server_secret),
            Side::Server => (server_secret, client_secret),
        };
        Self {
            local: PacketKeys::from_secret(&local_secret),
            remote: PacketKeys::from_secret(&remote_secret),
        }
    }
}

/// Derive Initial client/server secrets from the client's first DCID (RFC 9001 §5.2).
pub fn initial_secrets(dst_cid: &[u8]) -> ([u8; 32], [u8; 32]) {
    let initial = extract(Some(&SALT_V1), dst_cid);
    let client = initial.derive_secret("client in", &[]);
    let server = initial.derive_secret("server in", &[]);
    (client, server)
}

/// Initial key pair for `side`.
pub fn initial_keys(dst_cid: &[u8], side: Side) -> KeyPair {
    let (client, server) = initial_secrets(dst_cid);
    KeyPair::from_traffic_secrets(side, client, server)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9001 Appendix A sample DCID.
    #[test]
    fn rfc9001_initial_secret_client() {
        let dcid = [
            0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        ];
        let (client, _server) = initial_secrets(&dcid);
        // RFC 9001 Appendix A.1 (corrected; see also msquic #4420)
        let expected = [
            0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03,
            0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f,
            0x6c, 0x35, 0x7a, 0xea,
        ];
        assert_eq!(client, expected);
    }

    #[test]
    fn header_protection_round_trip_recovers_pn_length() {
        let keys = PacketKeys::from_secret(&[0x11; 32]);
        // Long header: reserved bits + PN length 2 (encoded as 1 in low bits).
        let mut packet = vec![0xc1u8]; // long form | fixed | type | pn_len=2
        packet.extend_from_slice(&[0u8; 20]); // fake header through pn_offset
        let pn_offset = packet.len();
        packet.extend_from_slice(&[0x12, 0x34]); // PN
        packet.extend_from_slice(&[0x55; 20]); // sample + payload
        let original = packet.clone();
        keys.protect_header(pn_offset, &mut packet, true);
        assert_ne!(packet[0] & 0x0f, original[0] & 0x0f);
        keys.protect_header(pn_offset, &mut packet, false);
        assert_eq!(packet[0] & 0x03, original[0] & 0x03);
        assert_eq!(&packet[pn_offset..pn_offset + 2], &original[pn_offset..pn_offset + 2]);
    }
}
