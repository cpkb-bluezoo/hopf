// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9001 packet / header protection — AES-128-GCM (RFC 9001 §5.3/§5.4.3,
//! always used for Initial/Retry per spec) or ChaCha20-Poly1305 (RFC 9001
//! §5.3/§5.4.4) for Handshake/1-RTT/0-RTT, following whichever AEAD the TLS
//! layer negotiated ([`hopf_core::tls::Tls13Aead`]).

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, CHACHA20_POLY1305};
use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, CHACHA20};
use hopf_core::crypto::{extract, quic_expand_label_with_prefix};
use hopf_core::tls::Tls13Aead;

use crate::transport::types::Side;
use crate::transport::version::QuicVersion;

const IV_LEN: usize = 12;
/// AEAD tag length shared by every QUIC v1 cipher suite.
pub(crate) const TAG_LEN: usize = 16;

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
    pub fn from_secret(version: QuicVersion, aead: Tls13Aead, secret: &[u8; 32]) -> Self {
        let key_len = aead.key_len();
        // "quic key"/"quic iv"/"quic hp" for version 1, "quicv2 ..." for
        // version 2 (RFC 9369 section 3.3.2).
        let prefix = version.label_prefix();
        let key_bytes = quic_expand_label_with_prefix(prefix, secret, "key", &[], key_len);
        let iv_bytes = quic_expand_label_with_prefix(prefix, secret, "iv", &[], IV_LEN);
        let hp_bytes = quic_expand_label_with_prefix(prefix, secret, "hp", &[], key_len);
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
        version: QuicVersion,
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
            local: PacketKeys::from_secret(version, aead, &local_secret),
            remote: PacketKeys::from_secret(version, aead, &remote_secret),
        }
    }
}

/// Derive Initial client/server secrets from the client's first DCID (RFC 9001
/// §5.2; RFC 9369 §3.3.1 changes only the salt for version 2).
pub fn initial_secrets(version: QuicVersion, dst_cid: &[u8]) -> ([u8; 32], [u8; 32]) {
    let initial = extract(Some(&version.initial_salt()), dst_cid);
    let client = initial.derive_secret("client in", &[]);
    let server = initial.derive_secret("server in", &[]);
    (client, server)
}

/// Initial key pair for `side` — always AES-128-GCM regardless of the
/// handshake's own negotiated suite (RFC 9001 §5.2 fixes the Initial AEAD).
pub fn initial_keys(version: QuicVersion, dst_cid: &[u8], side: Side) -> KeyPair {
    let (client, server) = initial_secrets(version, dst_cid);
    KeyPair::from_traffic_secrets(version, side, Tls13Aead::Aes128GcmSha256, client, server)
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
        let (client, _server) = initial_secrets(QuicVersion::V1, &dcid);
        // RFC 9001 Appendix A.1 (corrected; see also msquic #4420)
        let expected = [
            0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03,
            0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f,
            0x6c, 0x35, 0x7a, 0xea,
        ];
        assert_eq!(client, expected);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// RFC 9001 Appendix A.1: HKDF-Expand-Label's label is `tls13 quic key`
    /// (etc.), i.e. the `tls13 ` prefix is part of every QUIC key derivation.
    /// Regression: the prefix was once omitted, which hopf-to-hopf loopback
    /// cannot see (both ends derive the same wrong keys) but no other QUIC
    /// stack could ever read.
    #[test]
    fn rfc9001_initial_packet_protection_iv() {
        use crate::transport::packet::rfc9001_vectors as v;
        let (client, _) = initial_secrets(QuicVersion::V1, &hex(v::DCID));
        let keys = PacketKeys::from_secret(QuicVersion::V1, Tls13Aead::Aes128GcmSha256, &client);
        assert_eq!(keys.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
    }

    /// RFC 9001 Appendix A.2: the client Initial, byte for byte.
    #[test]
    fn rfc9001_client_initial_packet_protection() {
        use crate::transport::packet::rfc9001_vectors as v;
        let keys = initial_keys(QuicVersion::V1, &hex(v::DCID), Side::Client);
        let packet = protect(&keys.local, &hex(v::CLIENT_INITIAL_HEADER), 2, 4, &hex(v::CLIENT_INITIAL_FRAMES), 1162);
        assert_eq!(packet, hex(v::CLIENT_INITIAL_PACKET));
    }

    /// RFC 9001 Appendix A.3: the server Initial, and the client can open it.
    #[test]
    fn rfc9001_server_initial_packet_protection() {
        use crate::transport::packet::rfc9001_vectors as v;
        let server = initial_keys(QuicVersion::V1, &hex(v::DCID), Side::Server);
        let frames = hex(v::SERVER_INITIAL_FRAMES);
        let packet = protect(&server.local, &hex(v::SERVER_INITIAL_HEADER), 1, 2, &frames, frames.len());
        assert_eq!(packet, hex(v::SERVER_INITIAL_PACKET));
    }

    /// RFC 9369 Appendix A.1: the v2 Initial secrets and the client's
    /// packet protection IV, from the appendix's DCID.
    #[test]
    fn rfc9369_initial_secrets_and_iv() {
        use crate::transport::packet::rfc9369_vectors as v;
        let (client, server) = initial_secrets(QuicVersion::V2, &hex(v::DCID));
        assert_eq!(client.to_vec(), hex("14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"));
        assert_eq!(server.to_vec(), hex("0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1"));
        let keys = PacketKeys::from_secret(QuicVersion::V2, Tls13Aead::Aes128GcmSha256, &client);
        assert_eq!(keys.iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
        // And v1 stays distinct: same DCID, different salt, different secrets.
        assert_ne!(initial_secrets(QuicVersion::V1, &hex(v::DCID)).0, client);
    }

    /// Protect `frames` (zero-padded to `padded_to` octets) under `keys` with
    /// `header` (packet number in its last `pn_len` octets), as a sender does.
    fn protect(keys: &PacketKeys, header: &[u8], pn: u64, pn_len: usize, frames: &[u8], padded_to: usize) -> Vec<u8> {
        let mut payload = frames.to_vec();
        payload.resize(padded_to, 0);
        keys.encrypt(pn, header, &mut payload);
        let mut packet = header.to_vec();
        packet.extend_from_slice(&payload);
        keys.protect_header(header.len() - pn_len, &mut packet, true);
        packet
    }

    /// RFC 9369 Appendix A.2: the client Initial, byte for byte - AEAD with
    /// the `quicv2` key and IV, and header protection with the `quicv2 hp` key.
    #[test]
    fn rfc9369_client_initial_packet_protection() {
        use crate::transport::packet::rfc9369_vectors as v;
        let keys = initial_keys(QuicVersion::V2, &hex(v::DCID), Side::Client);
        let packet = protect(&keys.local, &hex(v::CLIENT_INITIAL_HEADER), 2, 4, &hex(v::CLIENT_INITIAL_FRAMES), 1162);
        assert_eq!(packet, hex(v::CLIENT_INITIAL_PACKET));
    }

    /// RFC 9369 Appendix A.3: the server Initial, and the client can open it.
    #[test]
    fn rfc9369_server_initial_packet_protection_and_open() {
        use crate::transport::packet::rfc9369_vectors as v;
        let server = initial_keys(QuicVersion::V2, &hex(v::DCID), Side::Server);
        let header = hex(v::SERVER_INITIAL_HEADER);
        let frames = hex(v::SERVER_INITIAL_FRAMES);
        let packet = protect(&server.local, &header, 1, 2, &frames, frames.len());
        assert_eq!(packet, hex(v::SERVER_INITIAL_PACKET));

        // The client removes header protection and decrypts with its remote keys.
        let client = initial_keys(QuicVersion::V2, &hex(v::DCID), Side::Client);
        let mut received = packet.clone();
        let pn_offset = header.len() - 2;
        client.remote.protect_header(pn_offset, &mut received, false);
        assert_eq!(&received[..header.len()], header.as_slice());
        let mut body = received[header.len()..].to_vec();
        let n = client.remote.decrypt(1, &received[..header.len()], &mut body).expect("opens");
        assert_eq!(&body[..n], frames.as_slice());
        // Version 1 keys must not open it.
        let v1 = initial_keys(QuicVersion::V1, &hex(v::DCID), Side::Client);
        let mut body = packet[header.len()..].to_vec();
        assert!(v1.remote.decrypt(1, &header, &mut body).is_err());
    }

    /// RFC 9369 Appendix A.5: ChaCha20-Poly1305 with the `quicv2` labels
    /// derives key, IV and header protection key, and protects a short
    /// header packet.
    #[test]
    fn rfc9369_chacha20_short_header_packet() {
        let secret: [u8; 32] = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b").try_into().unwrap();
        let keys = PacketKeys::from_secret(QuicVersion::V2, Tls13Aead::ChaCha20Poly1305Sha256, &secret);
        assert_eq!(keys.iv.to_vec(), hex("a6b5bc6ab7dafce30ffff5dd"));
        let header = hex("4200bff4");
        let mut payload = vec![0x01];
        keys.encrypt(654_360_564, &header, &mut payload);
        assert_eq!(payload, hex("0ae7b6b932bc27d786f4bc2bb20f2162ba"));
        let mut packet = header.clone();
        packet.extend_from_slice(&payload);
        keys.protect_header(1, &mut packet, true);
        assert_eq!(packet, hex("5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"));
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
        let keys = PacketKeys::from_secret(QuicVersion::V1, Tls13Aead::ChaCha20Poly1305Sha256, &[0x11; 32]);

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
        let keys = PacketKeys::from_secret(QuicVersion::V1, Tls13Aead::Aes128GcmSha256, &[0x11; 32]);
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
