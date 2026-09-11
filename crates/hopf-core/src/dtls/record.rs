// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS 1.3 record layer (RFC 9147 §4) — `DTLSCiphertext` unified-header
//! framing, AEAD, record sequence-number encryption (§4.2.3), and per-epoch
//! anti-replay (§4.2.4/§4.5.1). No record layer exists below this that any
//! other module in this crate shares — TCP's [`crate::tls::record`] and
//! QUIC's packet protection each have their own framing for the same
//! reasons DTLS needs its own here (UDP is unordered and lossy, unlike
//! either).
//!
//! **Unverified against another implementation**: this module's wire shapes
//! (unified-header flag choice, nonce/AAD construction, sequence-number
//! encryption) are a best-effort reading of RFC 9147, cross-checked
//! sentence-by-sentence against the RFC text but not proven against a real
//! DTLS 1.3 peer — none was available when this was written (see
//! `crypto-migration-plan.md` Phase 6). Revisit once one exists.
//!
//! This implementation always uses the unified header's simplest compliant
//! flag combination (RFC 9147 §4, Figure 3): no Connection ID (`C=0`), a
//! 16-bit truncated sequence number (`S=1`), and an explicit length field
//! (`L=1`). Connection IDs and the 8-bit sequence-number form are not
//! implemented (`crypto-migration-plan.md` Phase 6 tracks this as a
//! follow-up). Old-epoch keys are dropped as soon as new ones are
//! installed — RFC 9147 §4.2.1's optional short overlap window (to tolerate
//! reordered datagrams arriving just after a key update) isn't implemented.

use aws_lc_rs::aead::quic::{HeaderProtectionKey, AES_128, CHACHA20};

use crate::crypto::aead::{AeadError, Aes128GcmKey, ChaCha20Poly1305Key};
use crate::crypto::hkdf::dtls_expand_label;
use crate::tls::Tls13Aead;

/// Unified header first byte's fixed bits (RFC 9147 §4): `0b001` fixed,
/// `C=0` (no Connection ID), `S=1` (16-bit sequence number), `L=1` (length
/// present). The low 2 bits are the epoch's low 2 bits, ORed in per record.
const UNIFIED_HEADER_FIXED: u8 = 0b0010_1100;

/// AEAD tag length (both supported suites use a 16-byte tag) — also the
/// minimum ciphertext length RFC 9147 §4.2.3 requires for the sn-encryption
/// sample, which every ciphertext here satisfies automatically (a tag alone
/// is 16 bytes, even sealing zero-length plaintext), so no explicit padding
/// step is needed.
const TAG_LEN: usize = 16;
const SN_SAMPLE_LEN: usize = 16;
/// Truncated sequence-number length on the wire, matching `S=1`.
const SEQ_LEN: usize = 2;
/// Fixed header size before the ciphertext: type-byte(1) + seq(2) + length(2).
const HEADER_LEN: usize = 1 + SEQ_LEN + 2;

/// RFC 8446 §5.5 / RFC 9325 §4.4: an AES-GCM key should be retired after
/// protecting 2^24.5 (≈23,726,566) full-size records. DTLS 1.3's own
/// `KeyUpdate` (RFC 9147's epoch-aware variant) isn't implemented here —
/// this session's TLS 1.3 `KeyUpdate` work is TCP-only — so crossing this
/// limit means closing the connection outright, the same fail-closed
/// treatment TLS 1.2 uses. ChaCha20-Poly1305 has no analogous limit (RFC
/// 8446 §5.5: its sequence number would wrap first). `pub(crate)`, not
/// just private, so `dtls::engine`'s own tests can set a direction's
/// counter right up to the boundary without sending millions of records.
pub(crate) const AES_GCM_CONFIDENTIALITY_LIMIT: u64 = 23_726_566;

enum AeadKeyKind {
    Aes128Gcm(Aes128GcmKey),
    ChaCha20Poly1305(ChaCha20Poly1305Key),
}

impl AeadKeyKind {
    fn seal_in_place_append_tag(&self, nonce: [u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> Result<(), AeadError> {
        match self {
            AeadKeyKind::Aes128Gcm(k) => k.seal_in_place_append_tag(nonce, aad, plaintext),
            AeadKeyKind::ChaCha20Poly1305(k) => k.seal_in_place_append_tag(nonce, aad, plaintext),
        }
    }

    fn open_in_place(&self, nonce: [u8; 12], aad: &[u8], ciphertext: &mut [u8]) -> Result<usize, AeadError> {
        match self {
            AeadKeyKind::Aes128Gcm(k) => k.open_in_place(nonce, aad, ciphertext),
            AeadKeyKind::ChaCha20Poly1305(k) => k.open_in_place(nonce, aad, ciphertext),
        }
    }
}

fn nonce_for(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    // RFC 9147 §4.2.1: "the 64-bit sequence_number is used as the sequence
    // number for the AEAD computation; unlike DTLS 1.2, the epoch is not
    // included" — same IV-XOR-sequence-number shape as TLS 1.3
    // (`crate::tls::record`'s `DirectionalKeys::nonce`), using only the
    // per-epoch sequence number, not epoch||sequence_number.
    let mut n = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= seq_bytes[i];
    }
    n
}

fn keys_for(aead: Tls13Aead, secret: &[u8; 32]) -> (AeadKeyKind, [u8; 12], HeaderProtectionKey) {
    let key_len = aead.key_len();
    let key_bytes = dtls_expand_label(secret, "key", &[], key_len);
    let iv_bytes = dtls_expand_label(secret, "iv", &[], 12);
    let sn_key_bytes = dtls_expand_label(secret, "sn", &[], key_len);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(iv_bytes.as_ref());
    let (key, hp_alg): (AeadKeyKind, &'static aws_lc_rs::aead::quic::Algorithm) = match aead {
        Tls13Aead::Aes128GcmSha256 => (
            AeadKeyKind::Aes128Gcm(Aes128GcmKey::new(key_bytes.as_ref()).expect("16-byte AES-128 key")),
            &AES_128,
        ),
        Tls13Aead::ChaCha20Poly1305Sha256 => (
            AeadKeyKind::ChaCha20Poly1305(ChaCha20Poly1305Key::new(key_bytes.as_ref()).expect("32-byte key")),
            &CHACHA20,
        ),
    };
    let hp = HeaderProtectionKey::new(hp_alg, sn_key_bytes.as_ref()).expect("sn_key");
    (key, iv, hp)
}

/// One direction's write state for one epoch. Epoch numbers follow RFC
/// 9147's fixed meanings (0 = cleartext, 2 = handshake, 3 = application) —
/// this crate skips 1 (0-RTT), which isn't implemented (see the module doc).
pub struct WriteKeys {
    key: AeadKeyKind,
    iv: [u8; 12],
    sn_hp: HeaderProtectionKey,
    epoch: u64,
    next_seq: u64,
}

impl WriteKeys {
    /// Derive from a 32-byte traffic secret for `epoch`.
    pub fn from_secret(aead: Tls13Aead, secret: &[u8; 32], epoch: u64) -> Self {
        let (key, iv, sn_hp) = keys_for(aead, secret);
        Self {
            key,
            iv,
            sn_hp,
            epoch,
            next_seq: 0,
        }
    }

    /// Whether this direction has protected enough records under its
    /// current AES-GCM key to warrant closing the connection (RFC 8446
    /// §5.5) — no DTLS 1.3 rekey mechanism exists here to fall back to.
    pub fn over_confidentiality_limit(&self) -> bool {
        matches!(self.key, AeadKeyKind::Aes128Gcm(_)) && self.next_seq >= AES_GCM_CONFIDENTIALITY_LIMIT
    }

    /// Fast-forward this direction's counter without actually sending
    /// millions of records — for `dtls::engine`'s confidentiality-limit
    /// tests only.
    #[cfg(test)]
    pub(crate) fn set_next_seq_for_test(&mut self, seq: u64) {
        self.next_seq = seq;
    }
}

/// One direction's read state for one epoch — adds the anti-replay window
/// a write direction doesn't need.
pub struct ReadKeys {
    key: AeadKeyKind,
    iv: [u8; 12],
    sn_hp: HeaderProtectionKey,
    epoch: u64,
    replay: ReplayWindow,
}

impl ReadKeys {
    /// Derive from a 32-byte traffic secret for `epoch`.
    pub fn from_secret(aead: Tls13Aead, secret: &[u8; 32], epoch: u64) -> Self {
        let (key, iv, sn_hp) = keys_for(aead, secret);
        Self {
            key,
            iv,
            sn_hp,
            epoch,
            replay: ReplayWindow::new(),
        }
    }

    /// Same as [`WriteKeys::over_confidentiality_limit`], for the read
    /// side — the anti-replay window's `highest` seen sequence number
    /// doubles as this direction's record count.
    pub fn over_confidentiality_limit(&self) -> bool {
        matches!(self.key, AeadKeyKind::Aes128Gcm(_))
            && self.replay.highest().is_some_and(|h| h >= AES_GCM_CONFIDENTIALITY_LIMIT)
    }

    /// Fast-forward this direction's highest-seen sequence number without
    /// actually receiving millions of records — for `dtls::engine`'s
    /// confidentiality-limit tests only.
    #[cfg(test)]
    pub(crate) fn set_replay_highest_for_test(&mut self, seq: u64) {
        self.replay.record(seq);
    }
}

/// Per-epoch anti-replay (RFC 9147 §4.2.4/§4.5.1) — a 64-entry sliding
/// bitmap keyed by the reconstructed full sequence number, same shape as
/// IPsec/QUIC dedup windows. [`Self::check`] is a read-only membership test
/// (cheap early reject before spending an AEAD verify on a known replay);
/// [`Self::record`] marks a sequence number seen and must only be called
/// after that record has actually authenticated — recording on unauthenticated
/// input would let an attacker poison the window with forged sequence
/// numbers and cause a legitimate later record to be misdetected as replayed.
/// `pub(crate)` (not just private to this module) so `hopf-core::dtls12`
/// can reuse it directly for DTLS 1.2's anti-replay — the algorithm is
/// version-agnostic, keyed purely on a reconstructed/on-the-wire 64-bit
/// sequence number regardless of how that number got there.
pub(crate) struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    /// Highest sequence number successfully recorded so far, if any —
    /// doubles as a rough per-key record count for the AES-GCM
    /// confidentiality-limit checks in `dtls::record`/`dtls12::record`.
    pub(crate) fn highest(&self) -> Option<u64> {
        self.highest
    }

    pub(crate) fn new() -> Self {
        Self {
            highest: None,
            bitmap: 0,
        }
    }

    pub(crate) fn check(&self, seq: u64) -> bool {
        match self.highest {
            None => true,
            Some(h) if seq > h => true,
            Some(h) => {
                let diff = h - seq;
                diff < 64 && self.bitmap & (1u64 << diff) == 0
            }
        }
    }

    pub(crate) fn record(&mut self, seq: u64) {
        match self.highest {
            None => {
                self.highest = Some(seq);
                self.bitmap = 1;
            }
            Some(h) if seq > h => {
                let shift = seq - h;
                self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
                self.bitmap |= 1;
                self.highest = Some(seq);
            }
            Some(h) => {
                let diff = h - seq;
                if diff < 64 {
                    self.bitmap |= 1u64 << diff;
                }
            }
        }
    }
}

/// Reconstruct the full sequence number from its truncated on-wire bits
/// (RFC 9147 §4.2.2 — nearest value to one more than the highest
/// successfully deprotected record so far this epoch; the same
/// nearest-in-window algorithm QUIC uses for packet numbers, RFC 9000
/// Appendix A.3). `bits` is the truncated width in bits (16, matching this
/// module's fixed `S=1` choice).
fn reconstruct_sequence_number(highest: Option<u64>, truncated: u64, bits: u32) -> u64 {
    let window = 1u64 << bits;
    let half = window / 2;
    let expected = highest.map(|h| h + 1).unwrap_or(0);
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// Write one DTLSCiphertext record, appending it to `out`.
pub fn write_record(write: &mut WriteKeys, inner_content_type: u8, payload: &[u8], out: &mut Vec<u8>) {
    let seq = write.next_seq;
    write.next_seq = write.next_seq.wrapping_add(1);

    let mut plain = Vec::with_capacity(payload.len() + 1);
    plain.extend_from_slice(payload);
    plain.push(inner_content_type);

    let byte0 = UNIFIED_HEADER_FIXED | ((write.epoch & 0x3) as u8);
    let seq_bytes = (seq as u16).to_be_bytes();
    let cipher_len = (plain.len() + TAG_LEN) as u16;
    let mut aad = [0u8; HEADER_LEN];
    aad[0] = byte0;
    aad[1..3].copy_from_slice(&seq_bytes);
    aad[3..5].copy_from_slice(&cipher_len.to_be_bytes());

    let nonce = nonce_for(&write.iv, seq);
    write
        .key
        .seal_in_place_append_tag(nonce, &aad, &mut plain)
        .expect("seal with a freshly derived key never fails");

    // RFC 9147 §4.2.3: sample the ciphertext (always ≥ 16 bytes — a bare
    // AEAD tag already is), mask the truncated sequence-number bytes only
    // (not the header's first byte, unlike QUIC's own header protection).
    let sample = &plain[..SN_SAMPLE_LEN];
    let mask = write.sn_hp.new_mask(sample).expect("sn mask");
    let masked_seq = [seq_bytes[0] ^ mask[0], seq_bytes[1] ^ mask[1]];

    out.push(byte0);
    out.extend_from_slice(&masked_seq);
    out.extend_from_slice(&cipher_len.to_be_bytes());
    out.extend_from_slice(&plain);
}

/// Outcome of reading one record.
pub enum ReadOutcome {
    /// Not enough bytes buffered yet for a complete record.
    Incomplete,
    /// A well-formed record for a different epoch than `read` — caller
    /// should try a different `ReadKeys` (or drop it; old-epoch overlap
    /// isn't implemented — see the module doc). `consumed` bytes should
    /// still be dropped from the front of the input buffer either way.
    WrongEpoch { consumed: usize },
    /// Decrypted `(inner_content_type, plaintext)`; `consumed` bytes should
    /// be dropped from the front of the input buffer.
    Record {
        inner_content_type: u8,
        plaintext: Vec<u8>,
        consumed: usize,
        /// This record's own (epoch, full 64-bit sequence number) — RFC
        /// 9147 §7's `RecordNumber`, needed by the caller to ACK it.
        record_number: (u64, u64),
    },
    /// Same sequence number already processed this epoch — drop silently
    /// (RFC 9147 §4.5.1), not a protocol error.
    Replay { consumed: usize },
    /// Malformed or failed to authenticate.
    Invalid,
}

/// Read one DTLSCiphertext record from the front of `input`, if a complete
/// one is buffered. Does not mutate `input` — the caller drops
/// `consumed` bytes itself (mirrors [`crate::tls::record`]'s framing, where
/// the caller owns the accumulation buffer).
pub fn read_record(read: &mut ReadKeys, input: &[u8]) -> ReadOutcome {
    if input.len() < HEADER_LEN {
        return ReadOutcome::Incomplete;
    }
    let byte0 = input[0];
    if byte0 & 0b1110_0000 != 0b0010_0000 {
        return ReadOutcome::Invalid;
    }
    let masked_seq = [input[1], input[2]];
    let cipher_len = u16::from_be_bytes([input[3], input[4]]) as usize;
    if cipher_len < TAG_LEN {
        return ReadOutcome::Invalid;
    }
    if input.len() < HEADER_LEN + cipher_len {
        return ReadOutcome::Incomplete;
    }
    let consumed = HEADER_LEN + cipher_len;
    // Epoch checked only now that `consumed` is known, so a caller can skip
    // past a wrong-epoch record and keep parsing the rest of the buffer.
    if (byte0 & 0x3) as u64 != read.epoch & 0x3 {
        return ReadOutcome::WrongEpoch { consumed };
    }
    let ciphertext = &input[HEADER_LEN..consumed];
    if ciphertext.len() < SN_SAMPLE_LEN {
        return ReadOutcome::Invalid;
    }

    let sample = &ciphertext[..SN_SAMPLE_LEN];
    let Ok(mask) = read.sn_hp.new_mask(sample) else {
        return ReadOutcome::Invalid;
    };
    let seq_bytes = [masked_seq[0] ^ mask[0], masked_seq[1] ^ mask[1]];
    let truncated = u16::from_be_bytes(seq_bytes) as u64;
    let seq = reconstruct_sequence_number(read.replay.highest, truncated, 16);

    if !read.replay.check(seq) {
        return ReadOutcome::Replay { consumed };
    }

    let mut aad = [0u8; HEADER_LEN];
    aad[0] = byte0;
    aad[1..3].copy_from_slice(&seq_bytes);
    aad[3..5].copy_from_slice(&(cipher_len as u16).to_be_bytes());

    let nonce = nonce_for(&read.iv, seq);
    let mut buf = ciphertext.to_vec();
    let Ok(n) = read.key.open_in_place(nonce, &aad, &mut buf) else {
        return ReadOutcome::Invalid;
    };
    buf.truncate(n);
    // RFC 9147 §4.2.1 incorporates RFC 8446 §5.4's TLSInnerPlaintext
    // structure unchanged: `content || type || zeros` — a peer may pad
    // with trailing zero bytes before the real (non-zero) content type,
    // which must be stripped first (see `crate::tls::record`'s matching
    // strip, this DTLS record layer's TCP counterpart).
    while buf.last() == Some(&0) {
        buf.pop();
    }
    let Some(inner_content_type) = buf.pop() else {
        return ReadOutcome::Invalid;
    };
    read.replay.record(seq);
    ReadOutcome::Record {
        inner_content_type,
        plaintext: buf,
        consumed,
        record_number: (read.epoch, seq),
    }
}

/// Write one epoch-0 `DTLSPlaintext` record (RFC 9147 §4 — identical to
/// DTLS 1.2's cleartext record format; used only before any keys exist, so
/// only for `ClientHello`/`HelloRetryRequest`/`ServerHello`). `seq` is the
/// caller-owned per-direction epoch-0 sequence counter (48-bit on the wire;
/// this format isn't encrypted or replay-protected — RFC 9147 doesn't
/// require it for epoch 0, since nothing sent there is confidential and the
/// handshake FSM's own state machine already rejects out-of-place messages).
pub fn write_plaintext_record(content_type: u8, seq: &mut u64, payload: &[u8], out: &mut Vec<u8>) {
    out.push(content_type);
    out.extend_from_slice(&0xfefdu16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // epoch = 0
    out.extend_from_slice(&seq.to_be_bytes()[2..8]); // low 48 bits
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    *seq = seq.wrapping_add(1);
}

/// Outcome of [`read_plaintext_record`].
pub enum PlaintextReadOutcome {
    /// Not enough bytes buffered yet for a complete record.
    Incomplete,
    /// The first byte's top 3 bits don't match `DTLSPlaintext`'s pattern —
    /// this is a `DTLSCiphertext` record instead (see [`read_record`]).
    NotPlaintext,
    /// Malformed (bad content type, non-zero epoch).
    Invalid,
    /// One complete cleartext record.
    Record {
        content_type: u8,
        payload: Vec<u8>,
        consumed: usize,
    },
}

/// Read one `DTLSPlaintext` record from the front of `input`, if complete.
pub fn read_plaintext_record(input: &[u8]) -> PlaintextReadOutcome {
    if input.is_empty() {
        return PlaintextReadOutcome::Incomplete;
    }
    if input[0] & 0b1110_0000 != 0 {
        return PlaintextReadOutcome::NotPlaintext;
    }
    if !(20..=23).contains(&input[0]) {
        return PlaintextReadOutcome::Invalid;
    }
    if input.len() < 13 {
        return PlaintextReadOutcome::Incomplete;
    }
    let epoch = u16::from_be_bytes([input[3], input[4]]);
    if epoch != 0 {
        return PlaintextReadOutcome::Invalid;
    }
    let length = u16::from_be_bytes([input[11], input[12]]) as usize;
    if input.len() < 13 + length {
        return PlaintextReadOutcome::Incomplete;
    }
    PlaintextReadOutcome::Record {
        content_type: input[0],
        payload: input[13..13 + length].to_vec(),
        consumed: 13 + length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(aead: Tls13Aead, epoch: u64) -> (WriteKeys, ReadKeys) {
        let secret = [0x5au8; 32];
        (
            WriteKeys::from_secret(aead, &secret, epoch),
            ReadKeys::from_secret(aead, &secret, epoch),
        )
    }

    #[test]
    fn round_trips_a_single_record_aes() {
        let (mut w, mut r) = pair(Tls13Aead::Aes128GcmSha256, 3);
        let mut wire = Vec::new();
        write_record(&mut w, 23, b"hello dtls", &mut wire);
        match read_record(&mut r, &wire) {
            ReadOutcome::Record {
                inner_content_type,
                plaintext,
                consumed,
                ..
            } => {
                assert_eq!(inner_content_type, 23);
                assert_eq!(plaintext, b"hello dtls");
                assert_eq!(consumed, wire.len());
            }
            _ => panic!("expected a decrypted record"),
        }
    }

    #[test]
    fn round_trips_a_single_record_chacha20() {
        let (mut w, mut r) = pair(Tls13Aead::ChaCha20Poly1305Sha256, 2);
        let mut wire = Vec::new();
        write_record(&mut w, 22, b"handshake bytes", &mut wire);
        match read_record(&mut r, &wire) {
            ReadOutcome::Record { plaintext, .. } => assert_eq!(plaintext, b"handshake bytes"),
            _ => panic!("expected a decrypted record"),
        }
    }

    /// RFC 9147 §4.2.1 incorporates RFC 8446 §5.4's `TLSInnerPlaintext`
    /// unchanged (`content || type || zeros`) — a peer is free to pad with
    /// trailing zero bytes before the real content type. `read_record` used
    /// to pop the byte immediately after the AEAD-opened plaintext as the
    /// content type unconditionally, so any padding made it read a zero
    /// (not a real content type) and reject the record as
    /// `ReadOutcome::Invalid` — invisible in hopf-vs-hopf loopback since
    /// this crate's own `write_record` never pads, only caught once a real
    /// peer (wolfSSL) sent a padded application-data record.
    #[test]
    fn trailing_zero_padding_before_the_content_type_is_stripped() {
        let (mut w, mut r) = pair(Tls13Aead::Aes128GcmSha256, 3);
        let mut wire = Vec::new();
        // Manually seal a padded `TLSInnerPlaintext` — `write_record`
        // itself never pads, so this reproduces what a real peer's padded
        // record looks like on the wire.
        let seq = w.next_seq;
        w.next_seq = w.next_seq.wrapping_add(1);
        let mut plain = b"hello dtls".to_vec();
        plain.push(23); // real inner content type: application_data
        plain.extend_from_slice(&[0u8; 8]); // zero padding
        let byte0 = UNIFIED_HEADER_FIXED | ((w.epoch & 0x3) as u8);
        let seq_bytes = (seq as u16).to_be_bytes();
        let cipher_len = (plain.len() + TAG_LEN) as u16;
        let mut aad = [0u8; HEADER_LEN];
        aad[0] = byte0;
        aad[1..3].copy_from_slice(&seq_bytes);
        aad[3..5].copy_from_slice(&cipher_len.to_be_bytes());
        let nonce = nonce_for(&w.iv, seq);
        w.key.seal_in_place_append_tag(nonce, &aad, &mut plain).unwrap();
        let sample = &plain[..SN_SAMPLE_LEN];
        let mask = w.sn_hp.new_mask(sample).unwrap();
        let masked_seq = [seq_bytes[0] ^ mask[0], seq_bytes[1] ^ mask[1]];
        wire.push(byte0);
        wire.extend_from_slice(&masked_seq);
        wire.extend_from_slice(&cipher_len.to_be_bytes());
        wire.extend_from_slice(&plain);

        match read_record(&mut r, &wire) {
            ReadOutcome::Record { inner_content_type, plaintext, .. } => {
                assert_eq!(inner_content_type, 23);
                assert_eq!(plaintext, b"hello dtls");
            }
            _ => panic!("expected a decrypted, unpadded record, got a different outcome"),
        }
    }

    #[test]
    fn sequence_number_is_encrypted_on_the_wire() {
        let (mut w, _r) = pair(Tls13Aead::Aes128GcmSha256, 3);
        let mut first = Vec::new();
        let mut second = Vec::new();
        write_record(&mut w, 23, b"x", &mut first); // seq 0
        write_record(&mut w, 23, b"x", &mut second); // seq 1
        // If sn encryption were a no-op, record 2's on-wire seq bytes would
        // just be record 1's plus 1 — assert that's NOT what's on the wire.
        let seq1 = u16::from_be_bytes([first[1], first[2]]);
        let seq2 = u16::from_be_bytes([second[1], second[2]]);
        assert_ne!(seq2.wrapping_sub(seq1), 1, "truncated seq bytes must not be plaintext-sequential");
    }

    #[test]
    fn out_of_order_records_still_decrypt_and_reconstruct_sequence() {
        let (mut w, mut r) = pair(Tls13Aead::Aes128GcmSha256, 3);
        let mut first = Vec::new();
        let mut second = Vec::new();
        let mut third = Vec::new();
        write_record(&mut w, 23, b"one", &mut first);
        write_record(&mut w, 23, b"two", &mut second);
        write_record(&mut w, 23, b"three", &mut third);

        // Arrival order: 1, 3, 2 — a plausible UDP reordering.
        assert!(matches!(read_record(&mut r, &first), ReadOutcome::Record { .. }));
        assert!(matches!(read_record(&mut r, &third), ReadOutcome::Record { .. }));
        match read_record(&mut r, &second) {
            ReadOutcome::Record { plaintext, .. } => assert_eq!(plaintext, b"two"),
            other => panic!("record 2, arriving late, must still decrypt: {}", match other {
                ReadOutcome::Invalid => "Invalid",
                ReadOutcome::Replay { .. } => "Replay",
                ReadOutcome::Incomplete => "Incomplete",
                ReadOutcome::WrongEpoch { .. } => "WrongEpoch",
                ReadOutcome::Record { .. } => unreachable!(),
            }),
        }
    }

    #[test]
    fn replayed_record_is_rejected_without_re_authenticating() {
        let (mut w, mut r) = pair(Tls13Aead::Aes128GcmSha256, 3);
        let mut wire = Vec::new();
        write_record(&mut w, 23, b"once", &mut wire);
        assert!(matches!(read_record(&mut r, &wire), ReadOutcome::Record { .. }));
        assert!(matches!(read_record(&mut r, &wire), ReadOutcome::Replay { .. }));
    }

    #[test]
    fn tampered_ciphertext_fails_to_authenticate() {
        let (mut w, mut r) = pair(Tls13Aead::Aes128GcmSha256, 3);
        let mut wire = Vec::new();
        write_record(&mut w, 23, b"hello", &mut wire);
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        assert!(matches!(read_record(&mut r, &wire), ReadOutcome::Invalid));
    }

    #[test]
    fn record_from_a_different_epoch_is_reported_as_such() {
        let secret = [0x5au8; 32];
        let mut w = WriteKeys::from_secret(Tls13Aead::Aes128GcmSha256, &secret, 2);
        let mut r = ReadKeys::from_secret(Tls13Aead::Aes128GcmSha256, &secret, 3);
        let mut wire = Vec::new();
        write_record(&mut w, 22, b"handshake", &mut wire);
        assert!(matches!(read_record(&mut r, &wire), ReadOutcome::WrongEpoch { .. }));
    }

    #[test]
    fn reconstruct_sequence_number_handles_forward_and_backward_gaps() {
        assert_eq!(reconstruct_sequence_number(None, 5, 16), 5);
        assert_eq!(reconstruct_sequence_number(Some(100), 101, 16), 101);
        // Wrap forward: truncated value looks smaller than expected's low
        // bits would suggest, so the true value must be one window higher.
        let expected_high = (1u64 << 16) - 1; // 65535
        assert_eq!(reconstruct_sequence_number(Some(expected_high), 0, 16), 1u64 << 16);
    }

    #[test]
    fn plaintext_record_round_trips() {
        let mut seq = 0u64;
        let mut wire = Vec::new();
        write_plaintext_record(22, &mut seq, b"a client hello", &mut wire); // 22 = handshake
        match read_plaintext_record(&wire) {
            PlaintextReadOutcome::Record {
                content_type,
                payload,
                consumed,
            } => {
                assert_eq!(content_type, 22);
                assert_eq!(payload, b"a client hello");
                assert_eq!(consumed, wire.len());
            }
            _ => panic!("expected a plaintext record"),
        }
        assert_eq!(seq, 1, "sequence counter advances");
    }

    /// The unified header's fixed `001` top-3-bit pattern and
    /// `DTLSPlaintext`'s content-type byte range (20-23, top 3 bits always
    /// `000`) never overlap — a receiver can always tell them apart from
    /// the first byte alone, with no epoch/mode context needed. This is
    /// exactly the property `dtls::engine`'s single read loop depends on to
    /// dispatch between [`read_plaintext_record`] and [`read_record`].
    #[test]
    fn plaintext_and_ciphertext_first_bytes_never_collide() {
        for content_type in 20u8..=23 {
            assert_ne!(content_type & 0b1110_0000, 0b0010_0000);
        }
        for epoch_bits in 0u8..4 {
            let ciphertext_byte0 = UNIFIED_HEADER_FIXED | epoch_bits;
            assert!(!(20..=23).contains(&ciphertext_byte0));
        }
    }
}
