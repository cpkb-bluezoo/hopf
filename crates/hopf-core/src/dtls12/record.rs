// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS 1.2 record layer (RFC 6347 §4) — one header shape for everything
//! (`DTLSPlaintext`/`DTLSCiphertext` are structurally identical: `type(1) +
//! version(2) + epoch(2) + sequence_number(6) + length(2)`, unlike DTLS
//! 1.3's later "unified header" split), reusing [`crate::tls::tls12::record`]'s
//! AEAD key/nonce shape (`AesGcmKey`/`ChaCha20Poly1305Key`, RFC 5288 GCM's
//! explicit-nonce-on-the-wire vs RFC 7905 ChaCha20-Poly1305's
//! IV-XOR-sequence-number) with the one substitution RFC 6347 §4.1.2.1
//! specifies: *"the sequence number used to compute the MAC [and, per RFC
//! 6347's blanket "AEAD... exactly as with TLS 1.2", the AEAD
//! `additional_data`/nonce] is the 64-bit value formed by concatenating the
//! epoch and the sequence number in the order they appear on the wire"* —
//! i.e. the header's own `epoch || sequence_number` bytes, not TLS's
//! implicit-only 64-bit counter. Only two epochs exist (0 = cleartext
//! handshake, 1 = post-`ChangeCipherSpec` application data), unlike DTLS
//! 1.3's three — so, unlike [`crate::dtls::record`], there's no sequence-number
//! reconstruction needed either (the full 48-bit value is always sent in
//! cleartext in the header) — anti-replay reuses
//! [`crate::dtls::record::ReplayWindow`] directly.
//!
//! **Unverified against another implementation** at the unit-test level —
//! see `dtls12::engine`'s module doc for the real interop this phase adds
//! (unlike DTLS 1.3, real DTLS 1.2 peers are available and used).

use crate::crypto::aead::{AeadError, AesGcmKey, ChaCha20Poly1305Key};
use crate::dtls::record::ReplayWindow;
use crate::tls::tls12::engine::{CipherKind, DirectionalKeyMaterial};

/// `type(1) + version(2) + epoch(2) + sequence_number(6) + length(2)`.
const HEADER_LEN: usize = 13;
const TAG_LEN: usize = 16;
/// DTLS 1.2's real (not legacy) wire version (RFC 6347 §4.1).
const DTLS12_VERSION: u16 = 0xfefd;

enum DirectionKey {
    Gcm { key: AesGcmKey, fixed_iv: [u8; 4] },
    ChaCha { key: ChaCha20Poly1305Key, fixed_iv: [u8; 12] },
}

impl DirectionKey {
    fn from_material(material: &DirectionalKeyMaterial, cipher: CipherKind) -> Option<Self> {
        Some(match cipher {
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => {
                let mut fixed_iv = [0u8; 4];
                fixed_iv.copy_from_slice(&material.fixed_iv);
                DirectionKey::Gcm { key: AesGcmKey::new(&material.key).ok()?, fixed_iv }
            }
            CipherKind::ChaCha20Poly1305 => {
                let mut fixed_iv = [0u8; 12];
                fixed_iv.copy_from_slice(&material.fixed_iv);
                DirectionKey::ChaCha { key: ChaCha20Poly1305Key::new(&material.key).ok()?, fixed_iv }
            }
        })
    }

    fn has_explicit_nonce(&self) -> bool {
        matches!(self, DirectionKey::Gcm { .. })
    }

    fn seal_in_place_append_tag(&self, nonce: [u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> Result<(), AeadError> {
        match self {
            DirectionKey::Gcm { key, .. } => key.seal_in_place_append_tag(nonce, aad, plaintext),
            DirectionKey::ChaCha { key, .. } => key.seal_in_place_append_tag(nonce, aad, plaintext),
        }
    }

    fn open_in_place(&self, nonce: [u8; 12], aad: &[u8], ciphertext: &mut [u8]) -> Result<usize, AeadError> {
        match self {
            DirectionKey::Gcm { key, .. } => key.open_in_place(nonce, aad, ciphertext),
            DirectionKey::ChaCha { key, .. } => key.open_in_place(nonce, aad, ciphertext),
        }
    }
}

fn nonce_for(key: &DirectionKey, epoch_seq: &[u8; 8]) -> [u8; 12] {
    match key {
        DirectionKey::Gcm { fixed_iv, .. } => {
            let mut n = [0u8; 12];
            n[..4].copy_from_slice(fixed_iv);
            n[4..].copy_from_slice(epoch_seq);
            n
        }
        DirectionKey::ChaCha { fixed_iv, .. } => {
            let mut n = *fixed_iv;
            for i in 0..8 {
                n[4 + i] ^= epoch_seq[i];
            }
            n
        }
    }
}

/// RFC 5288 §3 AEAD `additional_data`, DTLS's `epoch||sequence_number`
/// substitution applied (RFC 6347 §4.1.2.1).
fn additional_data(epoch_seq: [u8; 8], content_type: u8, plaintext_len: usize) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&epoch_seq);
    aad[8] = content_type;
    aad[9..11].copy_from_slice(&DTLS12_VERSION.to_be_bytes());
    aad[11..13].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
    aad
}

/// One direction's write state for one epoch (0 or 1 — see the module doc).
pub struct WriteKeys {
    key: Option<DirectionKey>,
    epoch: u16,
    next_seq: u64,
}

impl WriteKeys {
    /// Epoch 0 — cleartext, no AEAD.
    pub fn cleartext() -> Self {
        Self { key: None, epoch: 0, next_seq: 0 }
    }

    /// Epoch 1 — encrypted, from key material (RFC 6347 §6.3 key-block
    /// expansion, via [`crate::tls::tls12::engine`]).
    pub fn from_material(material: &DirectionalKeyMaterial, cipher: CipherKind) -> Option<Self> {
        Some(Self {
            key: Some(DirectionKey::from_material(material, cipher)?),
            epoch: 1,
            next_seq: 0,
        })
    }
}

/// One direction's read state for one epoch, plus the anti-replay window a
/// write direction doesn't need.
pub struct ReadKeys {
    key: Option<DirectionKey>,
    epoch: u16,
    replay: ReplayWindow,
}

impl ReadKeys {
    /// Epoch 0 — cleartext, no AEAD, no replay tracking (the handshake
    /// FSM's own state machine already rejects out-of-place messages).
    pub fn cleartext() -> Self {
        Self { key: None, epoch: 0, replay: ReplayWindow::new() }
    }

    /// Epoch 1 — encrypted, from key material.
    pub fn from_material(material: &DirectionalKeyMaterial, cipher: CipherKind) -> Option<Self> {
        Some(Self {
            key: Some(DirectionKey::from_material(material, cipher)?),
            epoch: 1,
            replay: ReplayWindow::new(),
        })
    }
}

/// Write one DTLS 1.2 record, appending it to `out`.
pub fn write_record(write: &mut WriteKeys, content_type: u8, payload: &[u8], out: &mut Vec<u8>) {
    let seq = write.next_seq;
    write.next_seq = write.next_seq.wrapping_add(1);
    let mut epoch_seq = [0u8; 8];
    epoch_seq[..2].copy_from_slice(&write.epoch.to_be_bytes());
    epoch_seq[2..].copy_from_slice(&seq.to_be_bytes()[2..]); // low 48 bits

    let Some(key) = write.key.as_ref() else {
        // Epoch 0: cleartext.
        let mut header = [0u8; HEADER_LEN];
        header[0] = content_type;
        header[1..3].copy_from_slice(&DTLS12_VERSION.to_be_bytes());
        header[3..11].copy_from_slice(&epoch_seq);
        header[11..13].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(payload);
        return;
    };

    let aad = additional_data(epoch_seq, content_type, payload.len());
    // RFC 5288 §3: GCM's nonce is `salt || nonce_explicit`, where
    // `nonce_explicit` is whatever value the sender put on the wire — the
    // receiver reads it back rather than independently recomputing it (a
    // real peer's explicit nonce need not equal `epoch_seq` at all; a
    // sender is free to pick any never-reused value, and OpenSSL's is
    // effectively random, confirmed against real interop — see this
    // module's doc). This implementation's own choice, for its own writes,
    // is simply `epoch_seq` itself: deterministic (no RNG needed) and
    // guaranteed unique per direction since `seq` only ever increments.
    let nonce = nonce_for(key, &epoch_seq);
    let mut ciphertext = payload.to_vec();
    key.seal_in_place_append_tag(nonce, &aad, &mut ciphertext)
        .expect("seal with a freshly derived key never fails");
    let has_explicit = key.has_explicit_nonce();
    let explicit_nonce = epoch_seq;
    let record_len = (if has_explicit { 8 } else { 0 } + ciphertext.len()) as u16;

    let mut header = [0u8; HEADER_LEN];
    header[0] = content_type;
    header[1..3].copy_from_slice(&DTLS12_VERSION.to_be_bytes());
    header[3..11].copy_from_slice(&epoch_seq);
    header[11..13].copy_from_slice(&record_len.to_be_bytes());
    out.extend_from_slice(&header);
    if has_explicit {
        out.extend_from_slice(&explicit_nonce);
    }
    out.extend_from_slice(&ciphertext);
}

/// Outcome of reading one record.
pub enum ReadOutcome {
    /// Not enough bytes buffered yet for a complete record.
    Incomplete,
    /// A well-formed record for a different epoch than `read`; `consumed`
    /// bytes should still be dropped from the front of the input buffer.
    WrongEpoch { consumed: usize },
    /// Decrypted (or, at epoch 0, verbatim) `(content_type, payload)`.
    Record { content_type: u8, payload: Vec<u8>, consumed: usize },
    /// Same sequence number already processed this epoch — drop silently.
    Replay { consumed: usize },
    /// Malformed or failed to authenticate.
    Invalid,
}

/// Read one DTLS 1.2 record from the front of `input`, if complete.
pub fn read_record(read: &mut ReadKeys, input: &[u8]) -> ReadOutcome {
    if input.len() < HEADER_LEN {
        return ReadOutcome::Incomplete;
    }
    let content_type = input[0];
    let epoch = u16::from_be_bytes([input[3], input[4]]);
    let mut seq_bytes = [0u8; 8];
    seq_bytes[2..].copy_from_slice(&input[5..11]);
    let seq = u64::from_be_bytes(seq_bytes);
    let length = u16::from_be_bytes([input[11], input[12]]) as usize;
    if input.len() < HEADER_LEN + length {
        return ReadOutcome::Incomplete;
    }
    let consumed = HEADER_LEN + length;
    if epoch != read.epoch {
        return ReadOutcome::WrongEpoch { consumed };
    }

    let Some(key) = read.key.as_ref() else {
        // Epoch 0: cleartext, no replay tracking (see `ReadKeys::cleartext`).
        return ReadOutcome::Record {
            content_type,
            payload: input[HEADER_LEN..consumed].to_vec(),
            consumed,
        };
    };

    if !read.replay.check(seq) {
        return ReadOutcome::Replay { consumed };
    }

    let has_explicit = key.has_explicit_nonce();
    let overhead = if has_explicit { 8 + TAG_LEN } else { TAG_LEN };
    if length < overhead {
        return ReadOutcome::Invalid;
    }
    let ciphertext_start = HEADER_LEN + if has_explicit { 8 } else { 0 };
    let plain_len = length - overhead;
    let epoch_seq = [input[3], input[4], input[5], input[6], input[7], input[8], input[9], input[10]];
    // RFC 6347 §4.1.2.1's `epoch||sequence_number` substitution governs the
    // MAC/AEAD *additional_data* input, not GCM's own explicit-nonce field
    // (RFC 5288 §3) — that's whatever value the sender actually chose (not
    // necessarily `epoch_seq`; confirmed against real OpenSSL interop that
    // it isn't), read back verbatim, exactly as `tls::tls12::record`
    // already does for TCP. ChaCha20-Poly1305 has no such field at all —
    // `nonce_for`'s ChaCha branch uses `epoch_seq` directly instead, same
    // as the write side, since RFC 7905 has no explicit nonce to disagree
    // with in the first place.
    let aad = additional_data(epoch_seq, content_type, plain_len);
    let nonce_seq: [u8; 8] = if has_explicit {
        input[HEADER_LEN..HEADER_LEN + 8].try_into().unwrap()
    } else {
        epoch_seq
    };
    let nonce = nonce_for(key, &nonce_seq);
    let mut buf = input[ciphertext_start..consumed].to_vec();
    let Ok(n) = key.open_in_place(nonce, &aad, &mut buf) else {
        return ReadOutcome::Invalid;
    };
    read.replay.record(seq);
    buf.truncate(n);
    ReadOutcome::Record { content_type, payload: buf, consumed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn material(key: &[u8], iv: &[u8]) -> DirectionalKeyMaterial {
        DirectionalKeyMaterial {
            key: Bytes::copy_from_slice(key),
            fixed_iv: Bytes::copy_from_slice(iv),
        }
    }

    fn pair(cipher: CipherKind) -> (WriteKeys, ReadKeys) {
        let (key, iv) = match cipher {
            CipherKind::ChaCha20Poly1305 => ([0x5au8; 32].to_vec(), [0x22u8; 12].to_vec()),
            _ => ([0x5au8; 16].to_vec(), [0x22u8; 4].to_vec()),
        };
        let m = material(&key, &iv);
        (
            WriteKeys::from_material(&m, cipher).unwrap(),
            ReadKeys::from_material(&m, cipher).unwrap(),
        )
    }

    #[test]
    fn cleartext_round_trips() {
        let mut w = WriteKeys::cleartext();
        let mut r = ReadKeys::cleartext();
        let mut wire = Vec::new();
        write_record(&mut w, 22, b"a client hello", &mut wire);
        match read_record(&mut r, &wire) {
            ReadOutcome::Record { content_type, payload, consumed } => {
                assert_eq!(content_type, 22);
                assert_eq!(payload, b"a client hello");
                assert_eq!(consumed, wire.len());
            }
            _ => panic!("expected a cleartext record"),
        }
    }

    #[test]
    fn encrypted_round_trips_aes_gcm() {
        let (mut w, mut r) = pair(CipherKind::Aes128Gcm);
        let mut wire = Vec::new();
        write_record(&mut w, 23, b"hello dtls12", &mut wire);
        match read_record(&mut r, &wire) {
            ReadOutcome::Record { payload, .. } => assert_eq!(payload, b"hello dtls12"),
            _ => panic!("expected a decrypted record"),
        }
    }

    #[test]
    fn encrypted_round_trips_chacha20poly1305() {
        let (mut w, mut r) = pair(CipherKind::ChaCha20Poly1305);
        let mut wire = Vec::new();
        write_record(&mut w, 23, b"hello chacha", &mut wire);
        match read_record(&mut r, &wire) {
            ReadOutcome::Record { payload, .. } => assert_eq!(payload, b"hello chacha"),
            _ => panic!("expected a decrypted record"),
        }
        // No explicit nonce for ChaCha20-Poly1305: header(13) + ciphertext(12+16).
        assert_eq!(wire.len(), HEADER_LEN + b"hello chacha".len() + TAG_LEN);
    }

    #[test]
    fn replayed_record_is_rejected() {
        let (mut w, mut r) = pair(CipherKind::Aes128Gcm);
        let mut wire = Vec::new();
        write_record(&mut w, 23, b"once", &mut wire);
        assert!(matches!(read_record(&mut r, &wire), ReadOutcome::Record { .. }));
        assert!(matches!(read_record(&mut r, &wire), ReadOutcome::Replay { .. }));
    }

    #[test]
    fn tampered_ciphertext_fails_to_authenticate() {
        let (mut w, mut r) = pair(CipherKind::Aes128Gcm);
        let mut wire = Vec::new();
        write_record(&mut w, 23, b"hello", &mut wire);
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        assert!(matches!(read_record(&mut r, &wire), ReadOutcome::Invalid));
    }

    #[test]
    fn wrong_epoch_record_is_reported_as_such() {
        let (mut w, _r) = pair(CipherKind::Aes128Gcm);
        let mut cleartext_reader = ReadKeys::cleartext();
        let mut wire = Vec::new();
        write_record(&mut w, 22, b"handshake", &mut wire); // epoch 1
        assert!(matches!(
            read_record(&mut cleartext_reader, &wire), // expects epoch 0
            ReadOutcome::WrongEpoch { .. }
        ));
    }
}
