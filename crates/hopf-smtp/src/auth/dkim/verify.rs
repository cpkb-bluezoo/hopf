// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DKIM signature verification (RFC 6376 §6, Ed25519 per RFC 8463).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rmimeparser::dkim::RawHeader;

use super::canon::{self, Canonicalization};
use super::rsa_der;
use crate::auth::dns_lookup::{DnsLookup, Lookup};

/// RFC 6376 §6.3 verification result (values mirror Gumdrop's `DKIMResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimResult {
    /// Signature verified.
    Pass,
    /// Signature present but did not verify (bad crypto, revoked/expired key, body/header hash mismatch).
    Fail,
    /// No DKIM-Signature header present.
    None,
    /// Transient error (DNS timeout/SERVFAIL).
    TempError,
    /// Permanent error (malformed signature or key record, unsupported algorithm).
    PermError,
    /// Signing domain's key record restricts use in a way that fails policy but not crypto.
    Policy,
    /// Reserved for parity with Gumdrop's enum; not produced by this verifier.
    Neutral,
}

impl DkimResult {
    /// `Authentication-Results`-style lowercase token.
    pub fn as_str(&self) -> &'static str {
        match self {
            DkimResult::Pass => "pass",
            DkimResult::Fail => "fail",
            DkimResult::None => "none",
            DkimResult::TempError => "temperror",
            DkimResult::PermError => "permerror",
            DkimResult::Policy => "policy",
            DkimResult::Neutral => "neutral",
        }
    }
}

/// Outcome of verifying one `DKIM-Signature` header.
#[derive(Debug, Clone)]
pub struct DkimSignatureResult {
    /// Verification result.
    pub result: DkimResult,
    /// `d=` signing domain, when the signature parsed far enough to have one.
    pub signing_domain: Option<String>,
    /// `s=` selector, when the signature parsed far enough to have one.
    pub selector: Option<String>,
}

/// Callback receiving one [`DkimSignatureResult`].
pub type DkimCallback = Box<dyn FnOnce(DkimSignatureResult) + Send>;
/// Callback receiving results for every `DKIM-Signature` header found.
pub type DkimAllCallback = Box<dyn FnOnce(Vec<DkimSignatureResult>) + Send>;

const MAX_SIGNATURES: usize = 10;

/// Body hashes keyed by the `(c=body-side, l=)` pair that produced them —
/// enough to answer every `DKIM-Signature` header's body-hash need, since
/// signatures sharing a `(c, l)` pair also share a body hash. Populate via
/// [`super::canon::IncrementalBodyCanon`], one instance per key returned by
/// [`required_body_hash_keys`], fed while the message streams in.
pub type BodyHashMap = HashMap<(Canonicalization, Option<u64>), Vec<u8>>;

/// The distinct `(c=body-side, l=)` pairs across every `DKIM-Signature`
/// header in `headers` (bounded to [`MAX_SIGNATURES`], matching
/// [`verify_all`]/[`verify_all_with_body_hashes`]) — i.e. exactly the set
/// of [`super::canon::IncrementalBodyCanon`] instances a streaming caller
/// needs to run the message body through before calling
/// [`verify_all_with_body_hashes`]. Malformed `DKIM-Signature` headers are
/// silently skipped here (they'll surface as `PermError` during actual
/// verification instead).
pub fn required_body_hash_keys(headers: &[RawHeader]) -> Vec<(Canonicalization, Option<u64>)> {
    let mut keys: Vec<(Canonicalization, Option<u64>)> = Vec::new();
    for h in headers
        .iter()
        .filter(|h| h.name().eq_ignore_ascii_case("DKIM-Signature"))
        .take(MAX_SIGNATURES)
    {
        if let Ok(tags) = parse_signature_tags(&h.as_string_unfolded()) {
            let key = (tags.c.1, tags.l);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

/// Streaming counterpart to [`verify_all`]: verifies every `DKIM-Signature`
/// header using body hashes computed ahead of time (see
/// [`required_body_hash_keys`] / [`BodyHashMap`]) instead of a
/// fully-materialized message body — issue #86.
pub fn verify_all_with_body_hashes(
    dns: Arc<dyn DnsLookup>,
    headers: Arc<Vec<RawHeader>>,
    body_hashes: Arc<BodyHashMap>,
    cb: DkimAllCallback,
) {
    let sigs: Vec<RawHeader> = headers
        .iter()
        .filter(|h| h.name().eq_ignore_ascii_case("DKIM-Signature"))
        .take(MAX_SIGNATURES)
        .cloned()
        .collect();
    step_streaming(dns, headers, body_hashes, sigs, 0, Vec::new(), cb);
}

fn step_streaming(
    dns: Arc<dyn DnsLookup>,
    headers: Arc<Vec<RawHeader>>,
    body_hashes: Arc<BodyHashMap>,
    sigs: Vec<RawHeader>,
    i: usize,
    mut acc: Vec<DkimSignatureResult>,
    cb: DkimAllCallback,
) {
    if i >= sigs.len() {
        cb(acc);
        return;
    }
    let sig = sigs[i].clone();
    verify_one_streaming(
        Arc::clone(&dns),
        Arc::clone(&headers),
        Arc::clone(&body_hashes),
        sig,
        Box::new(move |result| {
            acc.push(result);
            step_streaming(dns, headers, body_hashes, sigs, i + 1, acc, cb);
        }),
    );
}

fn verify_one_streaming(
    dns: Arc<dyn DnsLookup>,
    headers: Arc<Vec<RawHeader>>,
    body_hashes: Arc<BodyHashMap>,
    sig_header: RawHeader,
    cb: DkimCallback,
) {
    let tags = match parse_signature_tags(&sig_header.as_string_unfolded()) {
        Ok(t) => t,
        Err(()) => {
            cb(DkimSignatureResult {
                result: DkimResult::PermError,
                signing_domain: None,
                selector: None,
            });
            return;
        }
    };
    let computed_bh = match body_hashes.get(&(tags.c.1, tags.l)) {
        Some(h) => h.clone(),
        // The caller didn't run a canonicalization this signature needs —
        // a caller bug (didn't consult required_body_hash_keys first), not
        // anything about the message itself. Fail closed rather than
        // silently treating it as a body-hash mismatch.
        None => {
            cb(DkimSignatureResult {
                result: DkimResult::PermError,
                signing_domain: Some(tags.d.clone()),
                selector: Some(tags.s.clone()),
            });
            return;
        }
    };
    verify_tags_and_hash(dns, headers, tags, computed_bh, sig_header, cb);
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared tail of [`verify_one_streaming`] once it has a `computed_bh` in
/// hand: algo/expiry checks, body-hash comparison, signature decode,
/// `h=`-selected header canon, and the DNS key fetch + crypto verify.
fn verify_tags_and_hash(
    dns: Arc<dyn DnsLookup>,
    headers: Arc<Vec<RawHeader>>,
    tags: SigTags,
    computed_bh: Vec<u8>,
    sig_header: RawHeader,
    cb: DkimCallback,
) {
    let algo = match tags.a.as_str() {
        "rsa-sha256" => Algorithm::RsaSha256,
        "ed25519-sha256" => Algorithm::Ed25519Sha256,
        _ => {
            // Includes the RFC 8301-deprecated `rsa-sha1`.
            cb(DkimSignatureResult {
                result: DkimResult::PermError,
                signing_domain: Some(tags.d.clone()),
                selector: Some(tags.s.clone()),
            });
            return;
        }
    };

    if let Some(x) = tags.x {
        if now_unix() > x {
            cb(DkimSignatureResult {
                result: DkimResult::Fail,
                signing_domain: Some(tags.d.clone()),
                selector: Some(tags.s.clone()),
            });
            return;
        }
    }

    let given_bh = match base64_decode(&tags.bh) {
        Some(b) => b,
        None => {
            cb(DkimSignatureResult {
                result: DkimResult::PermError,
                signing_domain: Some(tags.d.clone()),
                selector: Some(tags.s.clone()),
            });
            return;
        }
    };
    if computed_bh != given_bh {
        cb(DkimSignatureResult {
            result: DkimResult::Fail,
            signing_domain: Some(tags.d.clone()),
            selector: Some(tags.s.clone()),
        });
        return;
    }

    let signature = match base64_decode(&tags.b) {
        Some(b) => b,
        None => {
            cb(DkimSignatureResult {
                result: DkimResult::PermError,
                signing_domain: Some(tags.d.clone()),
                selector: Some(tags.s.clone()),
            });
            return;
        }
    };

    let signed_data = build_signed_data(&headers, &tags, &sig_header);

    let key_name = format!("{}._domainkey.{}", tags.s, tags.d);
    let d = tags.d.clone();
    let s = tags.s.clone();
    dns.query_txt(
        &key_name,
        Box::new(move |lookup| {
            let outcome = match lookup {
                Lookup::TempError => DkimResult::TempError,
                Lookup::NxDomain | Lookup::NoData => DkimResult::PermError,
                Lookup::Answers(txts) => {
                    if txts.len() != 1 {
                        DkimResult::PermError
                    } else {
                        match parse_key_record(&txts[0]) {
                            Err(()) => DkimResult::PermError,
                            Ok(key) => evaluate_key(&key, algo, &signature, &signed_data),
                        }
                    }
                }
            };
            cb(DkimSignatureResult {
                result: outcome,
                signing_domain: Some(d),
                selector: Some(s),
            });
        }),
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    RsaSha256,
    Ed25519Sha256,
}

fn evaluate_key(
    key: &KeyTags,
    algo: Algorithm,
    signature: &[u8],
    signed_data: &[u8],
) -> DkimResult {
    let key_algo_rsa = key.k.eq_ignore_ascii_case("rsa") || key.k.is_empty();
    let key_algo_ed25519 = key.k.eq_ignore_ascii_case("ed25519");
    match algo {
        Algorithm::RsaSha256 if !key_algo_rsa => return DkimResult::PermError,
        Algorithm::Ed25519Sha256 if !key_algo_ed25519 => return DkimResult::PermError,
        _ => {}
    }
    if let Some(allowed_hashes) = &key.h {
        if !allowed_hashes
            .iter()
            .any(|h| h.eq_ignore_ascii_case("sha256"))
        {
            return DkimResult::PermError;
        }
    }
    if let Some(service) = &key.s {
        if !service
            .iter()
            .any(|s| s == "*" || s.eq_ignore_ascii_case("email"))
        {
            return DkimResult::PermError;
        }
    }
    let p = match &key.p {
        None => return DkimResult::PermError, // p= tag missing entirely
        Some(p) if p.is_empty() => return DkimResult::Fail, // revoked (RFC 6376 §3.6.1)
        Some(p) => p,
    };

    match algo {
        Algorithm::RsaSha256 => {
            let (n, e) = match rsa_der::parse_rsa_spki(p) {
                Ok(v) => v,
                Err(()) => return DkimResult::PermError,
            };
            let key = ring::signature::RsaPublicKeyComponents { n: &n, e: &e };
            match key.verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                signed_data,
                signature,
            ) {
                Ok(()) => DkimResult::Pass,
                Err(_) => DkimResult::Fail,
            }
        }
        Algorithm::Ed25519Sha256 => {
            if p.len() != 32 {
                return DkimResult::PermError;
            }
            let key =
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, p.as_slice());
            match key.verify(signed_data, signature) {
                Ok(()) => DkimResult::Pass,
                Err(_) => DkimResult::Fail,
            }
        }
    }
}

/// Build the bytes that are actually signed: the selected `h=` headers
/// canonicalized in order, followed by the (b=-blanked) signature header
/// itself, per RFC 6376 §3.7 / §5.4.
fn build_signed_data(headers: &[RawHeader], tags: &SigTags, sig_header: &RawHeader) -> Vec<u8> {
    let selected = select_headers(headers, &tags.h);
    let mut out = Vec::new();
    for h in selected {
        out.extend_from_slice(&canon::canon_header(h, tags.c.0));
    }
    out.extend_from_slice(&canon::canon_signature_header(
        sig_header.name(),
        &sig_header.bytes_unfolded(),
        tags.c.0,
    ));
    out
}

/// RFC 6376 §5.4: for each name in `h=`, take the next-from-the-bottom
/// unused header field instance with that name; if fewer instances exist
/// than references, the extra references are simply omitted.
fn select_headers<'a>(all: &'a [RawHeader], h_list: &[String]) -> Vec<&'a RawHeader> {
    let mut used: HashMap<String, usize> = HashMap::new();
    let mut selected = Vec::with_capacity(h_list.len());
    for name in h_list {
        let matches: Vec<&RawHeader> = all
            .iter()
            .filter(|h| h.name().eq_ignore_ascii_case(name))
            .collect();
        let count = used.entry(name.clone()).or_insert(0);
        if *count < matches.len() {
            let idx = matches.len() - 1 - *count;
            selected.push(matches[idx]);
            *count += 1;
        }
    }
    selected
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(stripped)
        .ok()
}

fn domain_eq_or_subdomain(sub: &str, base: &str) -> bool {
    let sub = sub.trim_end_matches('.').to_ascii_lowercase();
    let base = base.trim_end_matches('.').to_ascii_lowercase();
    sub == base || sub.ends_with(&format!(".{base}"))
}

// --- DKIM-Signature tag parsing (RFC 6376 §3.5) ---------------------------

struct SigTags {
    a: String,
    b: String,
    bh: String,
    c: (Canonicalization, Canonicalization),
    d: String,
    h: Vec<String>,
    l: Option<u64>,
    s: String,
    x: Option<u64>,
}

fn parse_tag_list(value: &str) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            tags.insert(name.trim().to_string(), val.trim().to_string());
        }
    }
    tags
}

fn parse_signature_tags(header_line: &str) -> Result<SigTags, ()> {
    let value = header_line.split_once(':').map(|(_, v)| v).unwrap_or("");
    let tags = parse_tag_list(value);

    if tags.get("v").map(|v| v.as_str()) != Some("1") {
        return Err(());
    }
    let a = tags.get("a").ok_or(())?.clone();
    let b = tags.get("b").ok_or(())?.clone();
    let bh = tags.get("bh").ok_or(())?.clone();
    let d = tags.get("d").ok_or(())?.clone();
    let h_raw = tags.get("h").ok_or(())?.clone();
    let s = tags.get("s").ok_or(())?.clone();
    if d.is_empty() || s.is_empty() {
        return Err(());
    }

    let c_raw = tags
        .get("c")
        .cloned()
        .unwrap_or_else(|| "simple/simple".to_string());
    let mut c_parts = c_raw.splitn(2, '/');
    let ch = Canonicalization::parse(c_parts.next().unwrap_or("simple")).ok_or(())?;
    let cb = Canonicalization::parse(c_parts.next().unwrap_or("simple")).ok_or(())?;

    let h: Vec<String> = h_raw
        .split(':')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !h.iter().any(|n| n.eq_ignore_ascii_case("from")) {
        return Err(());
    }

    if let Some(i) = tags.get("i") {
        let idom = i.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
        if !domain_eq_or_subdomain(idom, &d) {
            return Err(());
        }
    }

    let l = match tags.get("l") {
        Some(v) => Some(v.parse::<u64>().map_err(|_| ())?),
        None => None,
    };
    let x = match tags.get("x") {
        Some(v) => Some(v.parse::<u64>().map_err(|_| ())?),
        None => None,
    };

    Ok(SigTags {
        a,
        b,
        bh,
        c: (ch, cb),
        d,
        h,
        l,
        s,
        x,
    })
}

// --- DKIM key record parsing (RFC 6376 §3.6.1) ----------------------------

struct KeyTags {
    k: String,
    p: Option<Vec<u8>>,
    h: Option<Vec<String>>,
    s: Option<Vec<String>>,
}

fn parse_key_record(txt: &str) -> Result<KeyTags, ()> {
    let tags = parse_tag_list(txt);
    if let Some(v) = tags.get("v") {
        if !v.eq_ignore_ascii_case("DKIM1") {
            return Err(());
        }
    }
    let k = tags.get("k").cloned().unwrap_or_else(|| "rsa".to_string());
    let p = match tags.get("p") {
        None => None,
        Some(p) if p.is_empty() => Some(Vec::new()),
        Some(p) => Some(base64_decode(p).ok_or(())?),
    };
    let h = tags
        .get("h")
        .map(|v| v.split(':').map(|s| s.trim().to_string()).collect());
    let s = tags
        .get("s")
        .map(|v| v.split(':').map(|s| s.trim().to_string()).collect());
    Ok(KeyTags { k, p, h, s })
}

#[cfg(test)]
mod tests;
