// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC-LB server-issued connection IDs
//! ([draft-ietf-quic-load-balancers-21](https://www.ietf.org/archive/id/draft-ietf-quic-load-balancers-21.html)).
//!
//! A load balancer that forwards on the Destination Connection ID needs to
//! find the owning backend from the CID alone, without per-connection state,
//! so that a datagram keeps reaching the same server after the client's
//! address changes (NAT rebinding, migration). A backend configured with the
//! same [`QuicLbConfig`] as its load balancer encodes its *server ID* into
//! every CID it issues; the balancer decodes it back out.
//!
//! Two encodings exist in revision 21: a plaintext one (no key: the server ID
//! is visible on the wire) and an AES-128-ECB one (a single AES block when
//! server ID and nonce total 16 octets, otherwise a four-round Feistel
//! network). Both share the layout
//!
//! ```text
//! First octet: config rotation (3 bits) | length or random bits (5 bits)
//! Server ID (>= 1 octet) || Nonce (>= 4 octets)     // encrypted when keyed
//! ```
//!
//! and both fit QUIC v1's 20-octet CID limit: server ID and nonce total at
//! most 19 octets.
//!
//! Terminating QUIC or TLS at the load balancer is out of scope: this is
//! pass-through routing only. Not implemented: the draft's optional extra
//! server-owned CID bytes, and `NEW_CONNECTION_ID` issuance (this stack does
//! not issue additional CIDs yet, so the Initial and Retry source CIDs are the
//! only server-issued ones).

use std::fmt;
use std::sync::{Arc, Mutex};

use aws_lc_rs::cipher::{
    DecryptionContext, PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, UnboundCipherKey, AES_128,
};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::transport::types::ConnectionId;

/// Source of server-issued connection IDs.
///
/// The default is [`RandomConnectionIdGenerator`]; [`QuicLbConfig::generator`]
/// gives the QUIC-LB one. Every ID from one generator has the same length,
/// because short-header packets carry no CID length field.
pub trait ConnectionIdGenerator: Send + Sync + fmt::Debug {
    /// Length in octets of every ID [`Self::generate`] returns (1-20).
    fn cid_len(&self) -> usize;

    /// A fresh connection ID.
    fn generate(&self) -> ConnectionId;
}

/// Uniformly random connection IDs - the behaviour when QUIC-LB is not
/// configured.
#[derive(Debug, Clone, Copy)]
pub struct RandomConnectionIdGenerator {
    len: usize,
}

impl RandomConnectionIdGenerator {
    /// Random IDs of `len` octets (clamped to 1-20).
    pub fn new(len: usize) -> Self {
        Self { len: len.clamp(1, 20) }
    }
}

impl ConnectionIdGenerator for RandomConnectionIdGenerator {
    fn cid_len(&self) -> usize {
        self.len
    }

    fn generate(&self) -> ConnectionId {
        ConnectionId::random(self.len)
    }
}

/// Why a [`QuicLbConfig`] was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicLbError {
    /// Config ID above 6 (`0b111` is reserved for unroutable CIDs).
    ConfigId,
    /// Server ID empty (it must be at least one octet).
    ServerIdLen,
    /// Nonce shorter than four octets.
    NonceLen,
    /// Server ID and nonce total more than 19 octets, which QUIC v1's
    /// 20-octet connection ID limit cannot hold beside the first octet.
    TotalLen,
    /// The AES key could not be used.
    Key,
}

impl fmt::Display for QuicLbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ConfigId => "QUIC-LB config ID must be 0-6 (0b111 is reserved)",
            Self::ServerIdLen => "QUIC-LB server ID must be at least one octet",
            Self::NonceLen => "QUIC-LB nonce must be at least four octets",
            Self::TotalLen => "QUIC-LB server ID and nonce must total at most 19 octets",
            Self::Key => "QUIC-LB key is unusable",
        })
    }
}

impl std::error::Error for QuicLbError {}

/// AES-128-ECB over single blocks, built on the padded ECB mode `aws-lc-rs`
/// exposes: PKCS#7 padding of a whole block appends one block that depends
/// only on the key, which is reused to undo the padding on decryption.
struct AesEcbBlock {
    enc: PaddedBlockEncryptingKey,
    dec: PaddedBlockDecryptingKey,
    /// `E_K(0x10 * 16)`: the encrypted padding block.
    pad_block: [u8; 16],
}

impl AesEcbBlock {
    fn new(key: &[u8; 16]) -> Result<Self, QuicLbError> {
        let unbound = || UnboundCipherKey::new(&AES_128, key).map_err(|_| QuicLbError::Key);
        let enc = PaddedBlockEncryptingKey::ecb_pkcs7(unbound()?).map_err(|_| QuicLbError::Key)?;
        let dec = PaddedBlockDecryptingKey::ecb_pkcs7(unbound()?).map_err(|_| QuicLbError::Key)?;
        let mut me = Self { enc, dec, pad_block: [0; 16] };
        let mut probe = vec![0u8; 16];
        me.enc.encrypt(&mut probe).map_err(|_| QuicLbError::Key)?;
        me.pad_block.copy_from_slice(&probe[16..32]);
        Ok(me)
    }

    fn encrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut buf = block.to_vec();
        self.enc.encrypt(&mut buf).expect("AES-ECB encrypt of one block");
        buf[..16].try_into().expect("16 octets")
    }

    fn decrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut buf = block.to_vec();
        buf.extend_from_slice(&self.pad_block);
        let plain = self.dec.decrypt(&mut buf, DecryptionContext::None).expect("AES-ECB decrypt of one block");
        plain[..16].try_into().expect("16 octets")
    }
}

/// One QUIC-LB configuration: shared, out of band, between a backend and the
/// load balancers in front of it.
#[derive(Clone)]
pub struct QuicLbConfig {
    config_id: u8,
    server_id: Vec<u8>,
    nonce_len: usize,
    cipher: Option<Arc<AesEcbBlock>>,
    length_self_description: bool,
}

impl fmt::Debug for QuicLbConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the key.
        f.debug_struct("QuicLbConfig")
            .field("config_id", &self.config_id)
            .field("server_id", &self.server_id)
            .field("nonce_len", &self.nonce_len)
            .field("encrypted", &self.cipher.is_some())
            .field("length_self_description", &self.length_self_description)
            .finish()
    }
}

impl QuicLbConfig {
    /// A plaintext configuration: `config_id` (0-6) selects this
    /// configuration among those a load balancer holds, `server_id` names
    /// this backend, `nonce_len` (at least 4) octets of per-CID uniqueness.
    /// Server ID and nonce total at most 19 octets.
    ///
    /// Without [`Self::with_key`] the server ID is readable by anyone on the
    /// path, which makes connection migration linkable.
    pub fn new(config_id: u8, server_id: &[u8], nonce_len: usize) -> Result<Self, QuicLbError> {
        if config_id > 6 {
            return Err(QuicLbError::ConfigId);
        }
        if server_id.is_empty() {
            return Err(QuicLbError::ServerIdLen);
        }
        if nonce_len < 4 {
            return Err(QuicLbError::NonceLen);
        }
        if server_id.len() + nonce_len > 19 {
            return Err(QuicLbError::TotalLen);
        }
        Ok(Self {
            config_id,
            server_id: server_id.to_vec(),
            nonce_len,
            cipher: None,
            length_self_description: false,
        })
    }

    /// Encrypt the server ID and nonce with this 16-octet AES-128 key, shared
    /// with the load balancers. Single AES block when server ID and nonce
    /// total 16 octets, else the four-pass Feistel construction.
    pub fn with_key(mut self, key: [u8; 16]) -> Result<Self, QuicLbError> {
        self.cipher = Some(Arc::new(AesEcbBlock::new(&key)?));
        Ok(self)
    }

    /// Encode the CID length (minus the first octet) in the first octet's low
    /// five bits (draft section 3.3), for deployments whose hardware offload
    /// needs self-describing CIDs. Off by default, when those bits are random.
    pub fn with_length_self_description(mut self, on: bool) -> Self {
        self.length_self_description = on;
        self
    }

    /// Length in octets of every CID this configuration issues.
    pub fn cid_len(&self) -> usize {
        1 + self.server_id.len() + self.nonce_len
    }

    /// A generator issuing CIDs under this configuration, starting from a
    /// random nonce and counting up so that no nonce repeats (section 9.6).
    /// Clone the returned `Arc` (not the config) to share one nonce sequence
    /// between endpoints of the same backend.
    pub fn generator(&self) -> Arc<QuicLbGenerator> {
        Arc::new(QuicLbGenerator::new(self.clone()))
    }

    /// The load balancer's operation: the server ID a CID under this
    /// configuration encodes, or `None` if `cid` is not routable by it (wrong
    /// length, or a different config ID).
    pub fn decode_server_id(&self, cid: &[u8]) -> Option<Vec<u8>> {
        if cid.len() != self.cid_len() || cid[0] >> 5 != self.config_id {
            return None;
        }
        let body = &cid[1..];
        let plaintext = match &self.cipher {
            None => body.to_vec(),
            Some(c) => decrypt_plaintext(c, body),
        };
        Some(plaintext[..self.server_id.len()].to_vec())
    }

    fn first_octet(&self) -> u8 {
        let low = if self.length_self_description {
            (self.cid_len() - 1) as u8
        } else {
            let mut r = [0u8; 1];
            let _ = SystemRandom::new().fill(&mut r);
            r[0] & 0x1f
        };
        (self.config_id << 5) | low
    }

    /// The CID for `nonce` (`nonce_len` octets).
    fn encode(&self, nonce: &[u8]) -> ConnectionId {
        debug_assert_eq!(nonce.len(), self.nonce_len);
        let mut plaintext = self.server_id.clone();
        plaintext.extend_from_slice(nonce);
        let body = match &self.cipher {
            None => plaintext,
            Some(c) => encrypt_plaintext(c, &plaintext),
        };
        let mut cid = Vec::with_capacity(1 + body.len());
        cid.push(self.first_octet());
        cid.extend_from_slice(&body);
        ConnectionId::from_slice(&cid)
    }
}

/// The draft's `expand(length, pass, input_bytes)`: `half` in the leading
/// octets, zero padding, then the total plaintext length and the pass number.
fn expand(len: usize, pass: u8, half: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..half.len()].copy_from_slice(half);
    block[14] = len as u8;
    block[15] = pass;
    block
}

/// Split into the Feistel halves. An odd total shares the middle octet:
/// each half keeps its own nibble of it and zeroes the other.
fn split(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let half = bytes.len().div_ceil(2);
    let mut left = bytes[..half].to_vec();
    let mut right = bytes[bytes.len() - half..].to_vec();
    if bytes.len() % 2 == 1 {
        left[half - 1] &= 0xf0;
        right[0] &= 0x0f;
    }
    (left, right)
}

/// Inverse of [`split`]: merge the shared middle octet of an odd total.
fn join(left: &[u8], right: &[u8], len: usize) -> Vec<u8> {
    if len % 2 == 0 {
        return [left, right].concat();
    }
    let mut out = left[..left.len() - 1].to_vec();
    out.push(left[left.len() - 1] | right[0]);
    out.extend_from_slice(&right[1..]);
    out
}

/// One Feistel round: `target XOR truncate(AES(expand(len, pass, input)))`,
/// with the odd-length nibble cleared on the half being produced
/// (`clear_high` for a right half, else the low nibble of a left half).
fn round(c: &AesEcbBlock, len: usize, pass: u8, input: &[u8], target: &[u8], clear_high: bool) -> Vec<u8> {
    let mask = c.encrypt(&expand(len, pass, input));
    let mut out: Vec<u8> = target.iter().zip(mask.iter()).map(|(t, m)| t ^ m).collect();
    if len % 2 == 1 {
        if clear_high {
            out[0] &= 0x0f;
        } else {
            let last = out.len() - 1;
            out[last] &= 0xf0;
        }
    }
    out
}

/// Encrypt `server_id || nonce` (draft section 5.4): one AES block when the
/// total is exactly 16 octets, else the four-round Feistel network.
fn encrypt_plaintext(cipher: &AesEcbBlock, plaintext: &[u8]) -> Vec<u8> {
    let len = plaintext.len();
    if len == 16 {
        return cipher.encrypt(plaintext.try_into().expect("16 octets")).to_vec();
    }
    let (left0, right0) = split(plaintext);
    let right1 = round(cipher, len, 1, &left0, &right0, true);
    let left1 = round(cipher, len, 2, &right1, &left0, false);
    let right2 = round(cipher, len, 3, &left1, &right1, true);
    let left2 = round(cipher, len, 4, &right2, &left1, false);
    join(&left2, &right2, len)
}

/// Invert [`encrypt_plaintext`] (draft section 5.5). The draft's load
/// balancer pseudo-code stops early when the server ID lies in the left half;
/// all four rounds are undone here so the whole plaintext is available.
fn decrypt_plaintext(cipher: &AesEcbBlock, ciphertext: &[u8]) -> Vec<u8> {
    let len = ciphertext.len();
    if len == 16 {
        return cipher.decrypt(ciphertext.try_into().expect("16 octets")).to_vec();
    }
    let (left2, right2) = split(ciphertext);
    let left1 = round(cipher, len, 4, &right2, &left2, false);
    let right1 = round(cipher, len, 3, &left1, &right2, true);
    let left0 = round(cipher, len, 2, &right1, &left1, false);
    let right0 = round(cipher, len, 1, &left0, &right1, true);
    join(&left0, &right0, len)
}

/// Issues QUIC-LB connection IDs; see [`QuicLbConfig::generator`].
#[derive(Debug)]
pub struct QuicLbGenerator {
    config: QuicLbConfig,
    state: Mutex<NonceState>,
}

#[derive(Debug)]
struct NonceState {
    /// Next nonce to hand out (only the low `8 * nonce_len` bits are used).
    next: u128,
    /// Nonces left before the space is exhausted.
    remaining: u128,
}

impl QuicLbGenerator {
    fn new(config: QuicLbConfig) -> Self {
        let bits = counter_bits(config.nonce_len);
        let mut r = [0u8; 16];
        let _ = SystemRandom::new().fill(&mut r);
        let start = u128::from_be_bytes(r) & mask(bits);
        Self { state: Mutex::new(NonceState { next: start, remaining: space(bits) }), config }
    }

    /// Next nonce, or `None` once every nonce has been used.
    fn next_nonce(&self) -> Option<Vec<u8>> {
        let bits = counter_bits(self.config.nonce_len);
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.remaining == 0 {
            return None;
        }
        let n = st.next;
        st.next = (st.next + 1) & mask(bits);
        st.remaining -= 1;
        // A nonce longer than the 16-octet counter is left-padded with zeros;
        // the nonce is encrypted, so only its uniqueness matters.
        let be = n.to_be_bytes();
        let nonce_len = self.config.nonce_len;
        let mut out = vec![0u8; nonce_len.saturating_sub(16)];
        out.extend_from_slice(&be[16usize.saturating_sub(nonce_len)..]);
        Some(out)
    }

    #[cfg(test)]
    fn set_remaining(&self, n: u128) {
        self.state.lock().unwrap().remaining = n;
    }
}

/// Bits of nonce counter: the whole nonce, up to the 128 a `u128` holds.
fn counter_bits(nonce_len: usize) -> u32 {
    (8 * nonce_len).min(128) as u32
}

fn mask(bits: u32) -> u128 {
    if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 }
}

fn space(bits: u32) -> u128 {
    if bits >= 128 { u128::MAX } else { 1u128 << bits }
}

impl ConnectionIdGenerator for QuicLbGenerator {
    fn cid_len(&self) -> usize {
        self.config.cid_len()
    }

    fn generate(&self) -> ConnectionId {
        match self.config.cipher {
            Some(_) => match self.next_nonce() {
                Some(nonce) => self.config.encode(&nonce),
                None => self.unroutable(),
            },
            // Without a key the nonce is a plain field: it must have no
            // observable relationship between CIDs (section 5.4), so random
            // rather than a counter. Uniqueness is the endpoint's to enforce.
            None => {
                let mut nonce = vec![0u8; self.config.nonce_len];
                let _ = SystemRandom::new().fill(&mut nonce);
                self.config.encode(&nonce)
            }
        }
    }
}

impl QuicLbGenerator {
    /// Section 9.6: a server that has run out of nonces must stop using the
    /// configuration and fall back to the "unroutable" codepoint `0b111`,
    /// whose CIDs self-describe their length (section 3.2).
    fn unroutable(&self) -> ConnectionId {
        let len = self.config.cid_len();
        let mut bytes = vec![0u8; len];
        let _ = SystemRandom::new().fill(&mut bytes);
        bytes[0] = 0xe0 | ((len - 1) as u8 & 0x1f);
        ConnectionId::from_slice(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn key(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }

    /// The draft's own worked example (section 5.4.2.4): seven octets of
    /// server ID and nonce, so the four-pass construction with an odd split.
    #[test]
    fn matches_the_drafts_four_pass_test_vector() {
        let cfg = QuicLbConfig::new(0, &hex("31441a"), 4)
            .unwrap()
            .with_key(key("fdf726a9893ec05c0632d3956680baf0"))
            .unwrap()
            .with_length_self_description(true);
        let cid = cfg.encode(&hex("9c69c275"));
        assert_eq!(cid.as_slice(), hex("0767947d29be054a").as_slice());
        assert_eq!(cfg.decode_server_id(cid.as_slice()), Some(hex("31441a")));
    }

    /// Server ID and nonce totalling 16 octets take the single-pass path: the
    /// whole plaintext block is one AES-128-ECB encryption. Known answer for
    /// AES-128 (FIPS 197 appendix B key) so the primitive is independently checked.
    #[test]
    fn single_pass_is_one_aes_ecb_block() {
        let k = key("2b7e151628aed2a6abf7158809cf4f3c");
        let cfg = QuicLbConfig::new(2, &hex("3243f6a8885a308d"), 8).unwrap().with_key(k).unwrap();
        // FIPS 197 example: plaintext 3243f6a8885a308d313198a2e0370734.
        let cid = cfg.encode(&hex("313198a2e0370734"));
        assert_eq!(&cid.as_slice()[1..], hex("3925841d02dc09fbdc118597196a0b32").as_slice());
        assert_eq!(cid.as_slice()[0] >> 5, 2);
        assert_eq!(cfg.decode_server_id(cid.as_slice()), Some(hex("3243f6a8885a308d")));
    }

    /// Every server-ID / nonce split, odd and even totals, with and without
    /// a key, decodes back to the server ID (and only under the right config).
    #[test]
    fn every_length_combination_round_trips() {
        let k = key("000102030405060708090a0b0c0d0e0f");
        for sid_len in 1..=15usize {
            for nonce_len in 4..=(19 - sid_len) {
                let sid: Vec<u8> = (0..sid_len as u8).map(|b| b.wrapping_mul(37).wrapping_add(11)).collect();
                for keyed in [false, true] {
                    let mut cfg = QuicLbConfig::new(3, &sid, nonce_len).unwrap();
                    if keyed {
                        cfg = cfg.with_key(k).unwrap();
                    }
                    let generator = cfg.generator();
                    for _ in 0..8 {
                        let cid = generator.generate();
                        assert_eq!(cid.len(), 1 + sid_len + nonce_len);
                        assert_eq!(
                            cfg.decode_server_id(cid.as_slice()).as_deref(),
                            Some(sid.as_slice()),
                            "sid {sid_len} nonce {nonce_len} keyed {keyed}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn plaintext_mode_puts_the_server_id_on_the_wire() {
        let cfg = QuicLbConfig::new(1, &[0xaa, 0xbb], 6).unwrap();
        let cid = cfg.generator().generate();
        assert_eq!(&cid.as_slice()[1..3], &[0xaa, 0xbb]);
        assert_eq!(cid.as_slice()[0] >> 5, 1);
    }

    #[test]
    fn encrypted_mode_hides_the_server_id() {
        let cfg = QuicLbConfig::new(1, &[0xaa, 0xbb], 6).unwrap().with_key([7; 16]).unwrap();
        let g = cfg.generator();
        // Not in the clear, and two CIDs from one server share no fixed field.
        let (a, b) = (g.generate(), g.generate());
        assert_ne!(&a.as_slice()[1..3], &[0xaa, 0xbb]);
        assert_ne!(&a.as_slice()[1..3], &b.as_slice()[1..3]);
    }

    /// Different key, config ID or length: not routable, never a wrong answer
    /// from the wrong config.
    #[test]
    fn a_cid_is_only_routable_under_its_own_config() {
        let cfg = QuicLbConfig::new(2, &[1, 2, 3], 5).unwrap().with_key([9; 16]).unwrap();
        let cid = cfg.generator().generate();
        let other_id = QuicLbConfig::new(3, &[1, 2, 3], 5).unwrap().with_key([9; 16]).unwrap();
        assert_eq!(other_id.decode_server_id(cid.as_slice()), None);
        let other_len = QuicLbConfig::new(2, &[1, 2, 3], 6).unwrap().with_key([9; 16]).unwrap();
        assert_eq!(other_len.decode_server_id(cid.as_slice()), None);
        let other_key = QuicLbConfig::new(2, &[1, 2, 3], 5).unwrap().with_key([8; 16]).unwrap();
        assert_ne!(other_key.decode_server_id(cid.as_slice()), Some(vec![1, 2, 3]));
    }

    #[test]
    fn length_self_description_encodes_the_length_minus_one() {
        let cfg = QuicLbConfig::new(5, &[1, 2, 3], 9).unwrap().with_length_self_description(true);
        for _ in 0..16 {
            let cid = cfg.generator().generate();
            assert_eq!(cid.as_slice()[0] & 0x1f, (cfg.cid_len() - 1) as u8);
            assert_eq!(cid.as_slice()[0] >> 5, 5);
        }
    }

    /// Without self-description the low five bits are random, not a constant
    /// an observer could use to fingerprint the deployment.
    #[test]
    fn low_first_octet_bits_vary_without_length_self_description() {
        let cfg = QuicLbConfig::new(0, &[1], 4).unwrap();
        let g = cfg.generator();
        let seen: std::collections::HashSet<u8> = (0..200).map(|_| g.generate().as_slice()[0] & 0x1f).collect();
        assert!(seen.len() > 8, "{seen:?}");
    }

    /// Section 9.6: a nonce is never reused. A counter from a random start
    /// yields distinct nonces, hence distinct ciphertexts.
    #[test]
    fn keyed_cids_never_repeat() {
        let g = QuicLbConfig::new(0, &[1, 2], 4).unwrap().with_key([3; 16]).unwrap().generator();
        let all: std::collections::HashSet<Vec<u8>> = (0..20_000).map(|_| g.generate().as_slice().to_vec()).collect();
        assert_eq!(all.len(), 20_000);
    }

    /// Section 9.6: with the nonce space used up the server must stop issuing
    /// routable CIDs and use the reserved 0b111 codepoint, self-describing
    /// its length.
    #[test]
    fn exhausted_nonce_space_falls_back_to_the_unroutable_codepoint() {
        let cfg = QuicLbConfig::new(0, &[1, 2], 4).unwrap().with_key([3; 16]).unwrap();
        let g = cfg.generator();
        g.set_remaining(2);
        assert_eq!(cfg.decode_server_id(g.generate().as_slice()), Some(vec![1, 2]));
        assert_eq!(cfg.decode_server_id(g.generate().as_slice()), Some(vec![1, 2]));
        for _ in 0..4 {
            let cid = g.generate();
            assert_eq!(cid.len(), cfg.cid_len());
            assert_eq!(cid.as_slice()[0] >> 5, 0b111);
            assert_eq!(cid.as_slice()[0] & 0x1f, (cfg.cid_len() - 1) as u8);
            assert_eq!(cfg.decode_server_id(cid.as_slice()), None);
        }
    }

    #[test]
    fn invalid_configurations_are_rejected() {
        assert_eq!(QuicLbConfig::new(7, &[1], 4).unwrap_err(), QuicLbError::ConfigId);
        assert_eq!(QuicLbConfig::new(0, &[], 4).unwrap_err(), QuicLbError::ServerIdLen);
        assert_eq!(QuicLbConfig::new(0, &[1], 3).unwrap_err(), QuicLbError::NonceLen);
        assert_eq!(QuicLbConfig::new(0, &[1; 8], 12).unwrap_err(), QuicLbError::TotalLen);
        assert!(QuicLbConfig::new(0, &[1; 8], 11).is_ok(), "19 octets is the maximum");
        assert!(QuicLbConfig::new(6, &[1], 4).is_ok());
    }

    #[test]
    fn debug_output_never_shows_the_key() {
        let cfg = QuicLbConfig::new(0, &[1], 4).unwrap().with_key([0x5a; 16]).unwrap();
        let dbg = format!("{cfg:?} {:?}", cfg.generator());
        assert!(!dbg.to_lowercase().contains("5a5a") && !dbg.contains("0x5a"), "{dbg}");
        assert!(dbg.contains("encrypted: true"));
    }

    #[test]
    fn random_generator_yields_fixed_length_random_ids() {
        let g = RandomConnectionIdGenerator::new(8);
        assert_eq!(g.cid_len(), 8);
        let (a, b) = (g.generate(), g.generate());
        assert_eq!(a.len(), 8);
        assert_ne!(a, b);
    }
}
