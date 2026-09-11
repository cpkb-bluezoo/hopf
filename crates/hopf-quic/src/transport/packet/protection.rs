// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9001 packet / header protection — AES-128-GCM (RFC 9001 §5.3/§5.4.3,
//! always used for Initial/Retry per spec) or ChaCha20-Poly1305 (RFC 9001
//! §5.3/§5.4.4) for Handshake/1-RTT/0-RTT, following whichever AEAD the TLS
//! layer negotiated ([`hopf_core::tls::Tls13Aead`]).

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, CHACHA20_POLY1305};
use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, CHACHA20};
use hopf_core::crypto::{extract, quic_expand_label};
use hopf_core::tls::Tls13Aead;

use crate::transport::types::Side;

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
    /// Derive from a 32-byte traffic secret. `aead` selects both the packet
    /// AEAD and its paired header-protection algorithm (RFC 9001 §5.4.3 for
    /// AES, §5.4.4 for ChaCha20) — always [`Tls13Aead::Aes128GcmSha256`] for
    /// Initial/Retry (RFC 9001 §5.2/§5.8 fix the algorithm regardless of
    /// what the handshake negotiates), and whatever the handshake selected
    /// for Handshake/0-RTT/1-RTT.
    pub fn from_secret(aead: Tls13Aead, secret: &[u8; 32]) -> Self {
        let key_len = aead.key_len();
        let key_bytes = quic_expand_label(secret, "key", &[], key_len);
        let iv_bytes = quic_expand_label(secret, "iv", &[], IV_LEN);
        let hp_bytes = quic_expand_label(secret, "hp", &[], key_len);
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(iv_bytes.as_ref());
        let (aead_alg, hp_alg): (&'static aws_lc_rs::aead::Algorithm, &'static aws_lc_rs::aead::quic::Algorithm) =
            match aead {
                Tls13Aead::Aes128GcmSha256 => (&AES_128_GCM, &AES_128),
                Tls13Aead::ChaCha20Poly1305Sha256 => (&CHACHA20_POLY1305, &CHACHA20),
            };
        Self {
            aead: LessSafeKey::new(UnboundKey::new(aead_alg, key_bytes.as_ref()).expect("AEAD key")),
            iv,
            hp: HeaderProtectionKey::new(hp_alg, hp_bytes.as_ref()).expect("hp key"),
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

    /// Tag length (both supported AEADs use a 16-byte tag).
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
    /// From client/server traffic secrets for `side`, under the negotiated `aead`.
    pub fn from_traffic_secrets(
        side: Side,
        aead: Tls13Aead,
        client_secret: [u8; 32],
        server_secret: [u8; 32],
    ) -> Self {
        let (local_secret, remote_secret) = match side {
            Side::Client => (client_secret, server_secret),
            Side::Server => (server_secret, client_secret),
        };
        Self {
            local: PacketKeys::from_secret(aead, &local_secret),
            remote: PacketKeys::from_secret(aead, &remote_secret),
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

/// Initial key pair for `side` — always AES-128-GCM regardless of the
/// handshake's own negotiated suite (RFC 9001 §5.2 fixes the Initial AEAD).
pub fn initial_keys(dst_cid: &[u8], side: Side) -> KeyPair {
    let (client, server) = initial_secrets(dst_cid);
    KeyPair::from_traffic_secrets(side, Tls13Aead::Aes128GcmSha256, client, server)
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

    /// `ChaCha20Poly1305Sha256` (RFC 9001 §5.4.4's paired ChaCha20 header
    /// protection, not the AES-ECB scheme §5.4.3 uses) round-trips both
    /// packet-payload AEAD and header protection through real ciphertext —
    /// proving `PacketKeys::from_secret`'s ChaCha branch actually works, not
    /// just that it type-checks. Real cross-implementation QUIC interop
    /// (quiche/msquic/ngtcp2) isn't wired up in this crate at all yet (see
    /// crypto-migration-plan.md Phase 2's still-unstarted external-peer-interop
    /// item), so this is the strongest proof available today; the TLS-layer
    /// suite *negotiation* itself is proven once, generically, by
    /// `tls::engine`'s `server_selects_chacha20_poly1305_when_its_the_only_offered_suite`
    /// — both TCP and QUIC key installation consume the same `TlsEventSink`
    /// callbacks this crate's own `Sink` forwards into `PacketKeys::from_secret`.
    #[test]
    fn chacha20_poly1305_packet_and_header_protection_round_trip() {
        let keys = PacketKeys::from_secret(Tls13Aead::ChaCha20Poly1305Sha256, &[0x11; 32]);

        // Packet payload AEAD.
        let header = [0xc3u8, 0, 0, 0, 1];
        let mut payload = b"hello quic chacha".to_vec();
        keys.encrypt(0, &header, &mut payload);
        assert_ne!(payload, b"hello quic chacha");
        let n = keys.decrypt(0, &header, &mut payload).unwrap();
        assert_eq!(&payload[..n], b"hello quic chacha");

        // Header protection (RFC 9001 §5.4.4's ChaCha20 mask construction,
        // distinct from AES's — this exercises that specific code path).
        let mut packet = vec![0xc1u8];
        packet.extend_from_slice(&[0u8; 20]);
        let pn_offset = packet.len();
        packet.extend_from_slice(&[0x12, 0x34]);
        packet.extend_from_slice(&[0x55; 20]);
        let original = packet.clone();
        keys.protect_header(pn_offset, &mut packet, true);
        assert_ne!(packet[0] & 0x0f, original[0] & 0x0f);
        keys.protect_header(pn_offset, &mut packet, false);
        assert_eq!(packet[0] & 0x03, original[0] & 0x03);
        assert_eq!(&packet[pn_offset..pn_offset + 2], &original[pn_offset..pn_offset + 2]);
    }

    #[test]
    fn header_protection_round_trip_recovers_pn_length() {
        let keys = PacketKeys::from_secret(Tls13Aead::Aes128GcmSha256, &[0x11; 32]);
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
