// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TSIG transaction signatures (RFC 8945): shared-secret HMAC authentication
//! of DNS messages, used for zone transfers and dynamic updates.
//!
//! Operates on wire bytes, because the MAC covers the message exactly as it
//! was sent, and a parse-then-reserialise round trip would not reproduce
//! another implementation's name compression.
//!
//! Algorithms: HMAC-SHA256 (mandatory, RFC 8945 §6), SHA384 and SHA512.
//! HMAC-MD5 and HMAC-SHA1 are deliberately not offered.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use crate::wire::{decode_name, encode_name, normalize_name};

/// TSIG RR type (RFC 8945 §3).
pub const TYPE_TSIG: u16 = 250;
const CLASS_ANY: u16 = 255;
/// Default permitted clock skew in seconds (RFC 8945 §5.2.3 recommends 300).
pub const DEFAULT_FUDGE: u16 = 300;

/// TSIG extended RCODEs (RFC 8945 §3.2).
pub const TSIG_BADSIG: u16 = 16;
/// Unknown key or algorithm.
pub const TSIG_BADKEY: u16 = 17;
/// Time outside the fudge window.
pub const TSIG_BADTIME: u16 = 18;

/// HMAC algorithm of a [`TsigKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    /// `hmac-sha256`
    HmacSha256,
    /// `hmac-sha384`
    HmacSha384,
    /// `hmac-sha512`
    HmacSha512,
}

impl TsigAlgorithm {
    /// Name as carried on the wire (without a trailing dot).
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
        }
    }

    /// Parse a wire or configuration name, case-insensitively, with or
    /// without the trailing dot.
    pub fn from_name(name: &str) -> Option<Self> {
        match normalize_name(name).as_str() {
            "hmac-sha256" => Some(Self::HmacSha256),
            "hmac-sha384" => Some(Self::HmacSha384),
            "hmac-sha512" => Some(Self::HmacSha512),
            _ => None,
        }
    }

    fn compute(self, secret: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        fn run<M: Mac + hmac::digest::KeyInit>(secret: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut m = <M as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }
        match self {
            Self::HmacSha256 => run::<Hmac<Sha256>>(secret, parts),
            Self::HmacSha384 => run::<Hmac<Sha384>>(secret, parts),
            Self::HmacSha512 => run::<Hmac<Sha512>>(secret, parts),
        }
    }
}

/// A shared secret.
#[derive(Clone, PartialEq, Eq)]
pub struct TsigKey {
    name: String,
    algorithm: TsigAlgorithm,
    secret: Vec<u8>,
}

impl std::fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl TsigKey {
    /// A key from raw secret bytes.
    pub fn new(name: &str, algorithm: TsigAlgorithm, secret: Vec<u8>) -> Self {
        Self {
            name: normalize_name(name),
            algorithm,
            secret,
        }
    }

    /// A key from the base64 secret found in BIND key files.
    pub fn from_base64(name: &str, algorithm: TsigAlgorithm, secret: &str) -> Result<Self, String> {
        Ok(Self::new(name, algorithm, base64_decode(secret)?))
    }

    /// Key name (lower-case, no trailing dot).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The HMAC algorithm.
    pub fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }
}

/// Keys a server accepts, by name.
#[derive(Debug, Clone, Default)]
pub struct TsigKeyring {
    keys: HashMap<String, TsigKey>,
}

impl TsigKeyring {
    /// Empty keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or replace) a key.
    pub fn with_key(mut self, key: TsigKey) -> Self {
        self.keys.insert(key.name.clone(), key);
        self
    }

    /// Whether any key is configured.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub(crate) fn get(&self, name: &str) -> Option<&TsigKey> {
        self.keys.get(&normalize_name(name))
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.trim().bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return Err(format!("invalid base64 character {:?}", c as char)),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err("empty TSIG secret".into());
    }
    Ok(out)
}

/// Why a TSIG failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TsigError {
    /// Not a well-formed TSIG-carrying message.
    Format,
    /// Unknown key or mismatched algorithm (BADKEY).
    BadKey,
    /// MAC mismatch (BADSIG).
    BadSig,
    /// Clock outside the fudge window (BADTIME).
    BadTime,
}

impl TsigError {
    pub(crate) fn code(&self) -> u16 {
        match self {
            Self::Format | Self::BadKey => TSIG_BADKEY,
            Self::BadSig => TSIG_BADSIG,
            Self::BadTime => TSIG_BADTIME,
        }
    }
}

/// A TSIG record located in a wire message.
#[derive(Debug, Clone)]
pub(crate) struct TsigRecord {
    /// Offset of the record's owner name: the message without TSIG ends here.
    pub(crate) start: usize,
    pub(crate) key_name: String,
    pub(crate) algorithm: String,
    pub(crate) time_signed: u64,
    pub(crate) fudge: u16,
    pub(crate) mac: Vec<u8>,
    pub(crate) original_id: u16,
    pub(crate) error: u16,
    pub(crate) other: Vec<u8>,
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

/// Advance past a (possibly compressed) name.
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *b.get(i)?;
        match len {
            0 => return Some(i + 1),
            l if l & 0xC0 == 0xC0 => return Some(i + 2),
            l if l & 0xC0 == 0 => i += 1 + l as usize,
            _ => return None,
        }
    }
}

/// Find the TSIG record, which must be the last record of the message
/// (RFC 8945 §5.1).
pub(crate) fn locate(raw: &[u8]) -> Option<TsigRecord> {
    let counts: Vec<usize> = (0..4).map(|i| u16_at(raw, 4 + 2 * i).map(usize::from)).collect::<Option<_>>()?;
    let (qd, rrs, ar) = (counts[0], counts[1] + counts[2] + counts[3], counts[3]);
    if ar == 0 {
        return None;
    }
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(raw, i)? + 4;
    }
    let mut last = None;
    for _ in 0..rrs {
        let start = i;
        i = skip_name(raw, i)?;
        let rdlen = u16_at(raw, i + 8)? as usize;
        last = Some((start, i));
        i += 10 + rdlen;
    }
    if i != raw.len() {
        return None;
    }
    let (start, after_name) = last?;
    if u16_at(raw, after_name)? != TYPE_TSIG || u16_at(raw, after_name + 2)? != CLASS_ANY {
        return None;
    }
    let mut c = start;
    let key_name = normalize_name(&decode_name(raw, &mut c).ok()?);
    let mut c = after_name + 10;
    let algorithm = normalize_name(&decode_name(raw, &mut c).ok()?);
    let time_signed = u64::from_be_bytes([0, 0, *raw.get(c)?, raw[c + 1], raw[c + 2], raw[c + 3], raw[c + 4], raw[c + 5]]);
    let fudge = u16_at(raw, c + 6)?;
    let mac_len = u16_at(raw, c + 8)? as usize;
    let mac = raw.get(c + 10..c + 10 + mac_len)?.to_vec();
    let c = c + 10 + mac_len;
    let original_id = u16_at(raw, c)?;
    let error = u16_at(raw, c + 2)?;
    let other_len = u16_at(raw, c + 4)? as usize;
    let other = raw.get(c + 6..c + 6 + other_len)?.to_vec();
    if c + 6 + other_len != raw.len() {
        return None;
    }
    Some(TsigRecord {
        start,
        key_name,
        algorithm,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
        other,
    })
}

/// RFC 8945 §4.3.3 TSIG variables (or, for a continuation message, only the
/// timers, §5.3.1).
fn variables(key_name: &str, algorithm: &str, time: u64, fudge: u16, error: u16, other: &[u8], timers_only: bool) -> Vec<u8> {
    let mut v = Vec::new();
    if !timers_only {
        v.extend_from_slice(&encode_name(key_name).expect("valid key name"));
        v.extend_from_slice(&CLASS_ANY.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&encode_name(algorithm).expect("valid algorithm name"));
    }
    v.extend_from_slice(&time.to_be_bytes()[2..]);
    v.extend_from_slice(&fudge.to_be_bytes());
    if !timers_only {
        v.extend_from_slice(&error.to_be_bytes());
        v.extend_from_slice(&(other.len() as u16).to_be_bytes());
        v.extend_from_slice(other);
    }
    v
}

/// What precedes the message in the digest: the MAC being answered or
/// continued, and any unsigned messages since it (RFC 8945 §5.3.1).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Chain<'a> {
    pub(crate) prior_mac: Option<&'a [u8]>,
    pub(crate) unsigned_since: &'a [u8],
}

fn digest(key: &TsigKey, chain: Chain<'_>, message: &[u8], vars: &[u8]) -> Vec<u8> {
    let prior_len = chain.prior_mac.map(|m| (m.len() as u16).to_be_bytes());
    let mut parts: Vec<&[u8]> = Vec::new();
    if let (Some(m), Some(l)) = (chain.prior_mac, prior_len.as_ref()) {
        parts.push(l);
        parts.push(m);
    }
    parts.push(chain.unsigned_since);
    parts.push(message);
    parts.push(vars);
    key.algorithm.compute(&key.secret, &parts)
}

fn tsig_rr(key_name: &str, algorithm: &str, time: u64, fudge: u16, mac: &[u8], id: u16, error: u16, other: &[u8]) -> Vec<u8> {
    let mut rdata = encode_name(algorithm).expect("valid algorithm name");
    rdata.extend_from_slice(&time.to_be_bytes()[2..]);
    rdata.extend_from_slice(&fudge.to_be_bytes());
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(mac);
    rdata.extend_from_slice(&id.to_be_bytes());
    rdata.extend_from_slice(&error.to_be_bytes());
    rdata.extend_from_slice(&(other.len() as u16).to_be_bytes());
    rdata.extend_from_slice(other);
    let mut rr = encode_name(key_name).expect("valid key name");
    rr.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    rr.extend_from_slice(&CLASS_ANY.to_be_bytes());
    rr.extend_from_slice(&0u32.to_be_bytes());
    rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    rr.extend_from_slice(&rdata);
    rr
}

fn append_rr(message: &[u8], rr: &[u8]) -> Vec<u8> {
    let mut out = message.to_vec();
    let ar = u16::from_be_bytes([out[10], out[11]]).wrapping_add(1);
    out[10..12].copy_from_slice(&ar.to_be_bytes());
    out.extend_from_slice(rr);
    out
}

/// Sign a serialised message. Returns the message with its TSIG appended and
/// the MAC (which a response or continuation is chained to).
pub(crate) fn sign(message: &[u8], key: &TsigKey, chain: Chain<'_>, timers_only: bool, now: u64) -> (Vec<u8>, Vec<u8>) {
    let alg = key.algorithm.wire_name();
    let vars = variables(&key.name, alg, now, DEFAULT_FUDGE, 0, &[], timers_only);
    let mac = digest(key, chain, message, &vars);
    let id = u16::from_be_bytes([message[0], message[1]]);
    let rr = tsig_rr(&key.name, alg, now, DEFAULT_FUDGE, &mac, id, 0, &[]);
    (append_rr(message, &rr), mac)
}

/// An unsigned TSIG error reply (RFC 8945 §5.3): no MAC, the error code,
/// and for BADTIME the server's clock.
pub(crate) fn error_reply(message: &[u8], request: &TsigRecord, error: u16, now: u64) -> Vec<u8> {
    let other = if error == TSIG_BADTIME { now.to_be_bytes()[2..].to_vec() } else { Vec::new() };
    let id = u16::from_be_bytes([message[0], message[1]]);
    let rr = tsig_rr(&request.key_name, &request.algorithm, now, request.fudge, &[], id, error, &other);
    append_rr(message, &rr)
}

/// A verified TSIG.
#[derive(Debug)]
pub(crate) struct Verified {
    /// The key that signed it.
    pub(crate) key_name: String,
    pub(crate) mac: Vec<u8>,
    /// The message with the TSIG removed (ARCOUNT adjusted, ID as received).
    pub(crate) unsigned: Vec<u8>,
}

/// Verify the TSIG on `raw` against `keyring` at time `now`.
pub(crate) fn verify(raw: &[u8], keyring: &TsigKeyring, chain: Chain<'_>, timers_only: bool, now: u64) -> Result<Verified, TsigError> {
    let rec = locate(raw).ok_or(TsigError::Format)?;
    let key = keyring.get(&rec.key_name).ok_or(TsigError::BadKey)?;
    if TsigAlgorithm::from_name(&rec.algorithm) != Some(key.algorithm) {
        return Err(TsigError::BadKey);
    }
    let mut unsigned = raw[..rec.start].to_vec();
    let ar = u16::from_be_bytes([unsigned[10], unsigned[11]]).wrapping_sub(1);
    unsigned[10..12].copy_from_slice(&ar.to_be_bytes());
    // The MAC covers the message under its original ID.
    let mut signed_form = unsigned.clone();
    signed_form[0..2].copy_from_slice(&rec.original_id.to_be_bytes());
    let vars = variables(&rec.key_name, &rec.algorithm, rec.time_signed, rec.fudge, rec.error, &rec.other, timers_only);
    let expected = digest(key, chain, &signed_form, &vars);
    if expected.len() != rec.mac.len() || expected.ct_eq(&rec.mac).unwrap_u8() != 1 {
        return Err(TsigError::BadSig);
    }
    if now.abs_diff(rec.time_signed) > u64::from(rec.fudge) {
        return Err(TsigError::BadTime);
    }
    Ok(Verified {
        key_name: rec.key_name,
        mac: rec.mac,
        unsigned,
    })
}

/// Seconds since the Unix epoch.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsMessage, DnsQuestion, DnsResourceRecord, DnsType};

    fn key() -> TsigKey {
        TsigKey::new("Key.Example.", TsigAlgorithm::HmacSha256, b"0123456789abcdef".to_vec())
    }

    fn ring() -> TsigKeyring {
        TsigKeyring::new().with_key(key())
    }

    fn msg(id: u16) -> Vec<u8> {
        let mut m = DnsMessage::query(id, DnsQuestion::in_class("example.com", DnsType::Soa), false);
        m.additionals.push(DnsResourceRecord::opt(1232, false, &[]));
        m.serialize().unwrap()
    }

    #[test]
    fn a_signed_request_verifies_and_the_unsigned_form_is_recovered() {
        let plain = msg(7);
        let (signed, mac) = sign(&plain, &key(), Chain::default(), false, 1_000_000);
        let v = verify(&signed, &ring(), Chain::default(), false, 1_000_100).unwrap();
        assert_eq!(v.key_name, "key.example");
        assert_eq!(v.mac, mac);
        assert_eq!(v.unsigned, plain, "TSIG removed and ARCOUNT restored");
        assert_eq!(DnsMessage::parse(&signed).unwrap().additionals.len(), 2, "OPT + TSIG");
    }

    #[test]
    fn tampering_wrong_keys_and_clock_skew_are_rejected_with_the_right_error() {
        let (signed, _) = sign(&msg(7), &key(), Chain::default(), false, 1_000_000);
        let mut bad = signed.clone();
        bad[13] ^= 0xFF; // inside the question name
        assert_eq!(verify(&bad, &ring(), Chain::default(), false, 1_000_000).unwrap_err(), TsigError::BadSig);

        let other = TsigKeyring::new().with_key(TsigKey::new("other", TsigAlgorithm::HmacSha256, vec![1; 16]));
        assert_eq!(verify(&signed, &other, Chain::default(), false, 1_000_000).unwrap_err(), TsigError::BadKey);

        let wrong_secret = TsigKeyring::new().with_key(TsigKey::new("key.example", TsigAlgorithm::HmacSha256, vec![9; 16]));
        assert_eq!(verify(&signed, &wrong_secret, Chain::default(), false, 1_000_000).unwrap_err(), TsigError::BadSig);

        let wrong_alg = TsigKeyring::new().with_key(TsigKey::new("key.example", TsigAlgorithm::HmacSha512, b"0123456789abcdef".to_vec()));
        assert_eq!(verify(&signed, &wrong_alg, Chain::default(), false, 1_000_000).unwrap_err(), TsigError::BadKey);

        assert_eq!(verify(&signed, &ring(), Chain::default(), false, 1_000_000 + 301).unwrap_err(), TsigError::BadTime);
        assert!(verify(&signed, &ring(), Chain::default(), false, 1_000_000 + 300).is_ok());
        assert_eq!(verify(&msg(1), &ring(), Chain::default(), false, 0).unwrap_err(), TsigError::Format);
    }

    #[test]
    fn a_response_is_bound_to_its_request_mac() {
        let (req, req_mac) = sign(&msg(3), &key(), Chain::default(), false, 500);
        let _ = req;
        let resp = msg(3);
        let chain = Chain { prior_mac: Some(&req_mac), unsigned_since: &[] };
        let (signed, mac) = sign(&resp, &key(), chain, false, 500);
        assert!(verify(&signed, &ring(), chain, false, 500).is_ok());
        // Verified against a different request it fails.
        let other = Chain { prior_mac: Some(&[0u8; 32]), unsigned_since: &[] };
        assert_eq!(verify(&signed, &ring(), other, false, 500).unwrap_err(), TsigError::BadSig);
        // A continuation chained to that response, timers only.
        let cont_chain = Chain { prior_mac: Some(&mac), unsigned_since: &[] };
        let (cont, _) = sign(&msg(3), &key(), cont_chain, true, 501);
        assert!(verify(&cont, &ring(), cont_chain, true, 501).is_ok());
        assert!(verify(&cont, &ring(), cont_chain, false, 501).is_err(), "timers-only digest differs");
    }

    #[test]
    fn unsigned_messages_since_the_last_signature_are_covered() {
        let (_, prior) = sign(&msg(1), &key(), Chain::default(), false, 10);
        let middle = msg(2);
        let chain = Chain { prior_mac: Some(&prior), unsigned_since: &middle };
        let (signed, _) = sign(&msg(3), &key(), chain, true, 11);
        assert!(verify(&signed, &ring(), chain, true, 11).is_ok());
        let without = Chain { prior_mac: Some(&prior), unsigned_since: &[] };
        assert!(verify(&signed, &ring(), without, true, 11).is_err());
    }

    #[test]
    fn error_replies_carry_the_code_and_no_mac() {
        let (signed, _) = sign(&msg(9), &key(), Chain::default(), false, 42);
        let rec = locate(&signed).unwrap();
        let reply = error_reply(&msg(9), &rec, TSIG_BADTIME, 99);
        let r = locate(&reply).unwrap();
        assert_eq!((r.error, r.mac.len(), r.other.len()), (TSIG_BADTIME, 0, 6));
        assert_eq!(r.time_signed, 99, "the reply carries the server's clock");
    }

    #[test]
    fn base64_secrets_decode() {
        assert_eq!(base64_decode("aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert!(base64_decode("!!!").is_err());
        assert!(base64_decode("").is_err());
        assert_eq!(TsigAlgorithm::from_name("HMAC-SHA256."), Some(TsigAlgorithm::HmacSha256));
        assert_eq!(TsigAlgorithm::from_name("hmac-md5.sig-alg.reg.int"), None);
        assert!(!format!("{:?}", key()).contains("0123"), "secret never printed");
    }
}
