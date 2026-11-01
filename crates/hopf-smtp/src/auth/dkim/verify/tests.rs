use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use rmimeparser::dkim::RawHeader;

use super::super::sign::{DkimPrivateKey, DkimSigner};
use super::*;
use crate::auth::dns_lookup::DnsLookup;

// Freshly generated for this test only — not used anywhere else.
const RSA_PKCS8_B64: &str = concat!(
    "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCp26EPB8wIigJ0",
    "Jz4ZH36rOTnmUxWdN9dr6iMnunwBZB2k5pmLxYyh6GAGnfVt/uW+0AQngLlIo1R3",
    "Ky1IC3FZX1n+Y3GkKW9Y7ulKvFe02Q14TbIG3gXFx99PrqL+Tq8HiNeOXtYcW742",
    "/NW/uPFyWPvyV/aQeR5muKBI27hibSILxyltOjOlCAE5F8bM67YA8eDRAsgXqdec",
    "z75ANeOI3vGVodK1Hg6UFHjN6te98KDvrscTDWHtSF9SxJB98aWeuplFkQgvsmlc",
    "Dx8V3iXqgQeOx+aLgKDF8ZCzshHR5K9avR9fU7kwqaPmvA/wJSuvP0cHXyXTq/xg",
    "mi3LvyNJAgMBAAECggEADhltBRJgnVTXX0zimrNCkHPvmm7LHIHGH+8Pe/y+zl7B",
    "Fy8ND80WH1pqniH+fWLrLyuVLLJCrwTfvgSXfaN1hTWlAri+diH6XCd4tftsTFa4",
    "B4RrgqZrVD+DCdo1LWbaoIV7XxYAL9ptr6LNG1z+rb81Kqiijtt+6ofoxiN26rSB",
    "wHaLMSBj8c8bfuOkK5j87nh/GucT0CtRoxCs4fDPURJRU+atrdejeFybdRF+oElH",
    "anCOQh2KpkI2rwF/zgEg345RwE8WMc9fJjpTvHyQLF5Od9a+Q3o67BmGIsDIMKzu",
    "M4kC2SxSVd5uJSULRywgF/3bo/eeIs5JY7NFkzaEAQKBgQDRgr2tovvSBV6ixqgE",
    "cVTJllZEV9po2rHsCAbzYdSmfSAE0JZUcsxEKd16J5jXBGwNvpdfSdGXAW79lpSg",
    "+wKvB7U3bJzdfMxYkfLpE5I7K7F1hpa4OnE0pj2cDeMdlrtlry1+D9MCh1YiB2Zr",
    "HiMiEix5P3dIFVsXko9/UErIBQKBgQDPjGlPwitRtVpv2+ORc9FAZRTy5svSGN48",
    "ONETx+ZzK0rb6Y/vvY02FeG7jx9hxTFjlNuDhOnf0yZTXzC+l/jN5h4q8oOsKZn5",
    "L0+x7HJ5YkVFshyQeJEA6IdtSyFDOKlXM4EGGhVBGXp4qztFX/cniZfnS4RhBIID",
    "lPmuLVUldQKBgQCvOyimN/FjIbabcohI3vlJegJBOzGkDXZOshAOND8F2RWUsVlq",
    "3HFYeaOSbdf5zusJO+WjfzxbjolkdDNvyUHfXxUEfEVfQugvFDMVGpduAgd1AtLA",
    "17Cjln9lLIBO2Sl3zOLB0z5rmQJDh+jzostDzeuApcKAecwslRqMI33IeQKBgQDB",
    "nTns5rTkn2qDaTysxr9Q9DsLsdQ35W0D/vjEHDpV++/0oLjerBRcfSM8hfJ/kaZW",
    "QFpbIZXPcDmTkvx1AG5hHafM5rmA1LpHpCQTVgEgTVVUBCjzeRXEJCeaBHk+LVCE",
    "AY7+czyaozsF8K71M+Xro0bqxR70JnFnCAW3v6BrtQKBgQCgAv5JMQIf7daIxl50",
    "lqdARsxkwdTl/EYFrKAMIHTFcVLKtKuUeTZuuycKF+aScoXzzzq6h2H61izgrY2o",
    "k0YUUWxULwPdi0FsGFvOErZFZzhRqf8fO1LdzbVL5Iz12RyP2vhrbRevoSLAh2mn",
    "7QzaD9kUujSxarQY4s3G5D0sGQ==",
);
const RSA_SPKI_B64: &str = concat!(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqduhDwfMCIoCdCc+GR9+",
    "qzk55lMVnTfXa+ojJ7p8AWQdpOaZi8WMoehgBp31bf7lvtAEJ4C5SKNUdystSAtx",
    "WV9Z/mNxpClvWO7pSrxXtNkNeE2yBt4FxcffT66i/k6vB4jXjl7WHFu+NvzVv7jx",
    "clj78lf2kHkeZrigSNu4Ym0iC8cpbTozpQgBORfGzOu2APHg0QLIF6nXnM++QDXj",
    "iN7xlaHStR4OlBR4zerXvfCg767HEw1h7UhfUsSQffGlnrqZRZEIL7JpXA8fFd4l",
    "6oEHjsfmi4CgxfGQs7IR0eSvWr0fX1O5MKmj5rwP8CUrrz9HB18l06v8YJoty78j",
    "SQIDAQAB",
);
const ED25519_PKCS8_B64: &str = "MC4CAQAwBQYDK2VwBCIEIJOr3cUYESkwGr3t08+NHi5fO++QEUtI7YDNn9ruV59R";
const ED25519_RAW_PUB_B64: &str = "7qcUfZUf3KQSvsFseKVzOm5hlukTWGugsb87LtL2Wuo=";

fn b64_decode(s: &str) -> Vec<u8> {
    rmimeparser::charset::base64::decode(s).unwrap()
}

fn rsa_key() -> DkimPrivateKey {
    DkimPrivateKey::rsa_from_pkcs8(&b64_decode(RSA_PKCS8_B64)).unwrap()
}

fn ed25519_key() -> DkimPrivateKey {
    DkimPrivateKey::ed25519_from_pkcs8(&b64_decode(ED25519_PKCS8_B64)).unwrap()
}

fn sample_headers() -> Vec<RawHeader> {
    vec![
        RawHeader::new("From", b"From: alice@example.com\r\n".to_vec()),
        RawHeader::new("To", b"To: bob@example.net\r\n".to_vec()),
        RawHeader::new("Subject", b"Subject: Hello\r\n".to_vec()),
        RawHeader::new(
            "Date",
            b"Date: Tue, 28 Jul 2026 10:00:00 +0000\r\n".to_vec(),
        ),
        RawHeader::new(
            "Message-ID",
            b"Message-ID: <abc123@example.com>\r\n".to_vec(),
        ),
    ]
}

#[derive(Default)]
struct FakeDns {
    txt: HashMap<String, Vec<String>>,
    temp: std::collections::HashSet<String>,
}

impl FakeDns {
    fn with_temp_error(mut self, name: &str) -> Self {
        self.temp.insert(name.to_ascii_lowercase());
        self
    }
    fn with_txt(mut self, name: &str, record: &str) -> Self {
        self.txt
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(record.to_string());
        self
    }
}

impl DnsLookup for FakeDns {
    fn query_txt(&self, name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
        if self.temp.contains(&name.to_ascii_lowercase()) {
            return cb(Lookup::TempError);
        }
        match self.txt.get(&name.to_ascii_lowercase()) {
            None => cb(Lookup::NxDomain),
            Some(v) if v.is_empty() => cb(Lookup::NoData),
            Some(v) => cb(Lookup::Answers(v.clone())),
        }
    }
    fn query_a(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<Ipv4Addr>) + Send>) {
        cb(Lookup::NxDomain);
    }
    fn query_aaaa(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<Ipv6Addr>) + Send>) {
        cb(Lookup::NxDomain);
    }
    fn query_mx(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<(u16, String)>) + Send>) {
        cb(Lookup::NxDomain);
    }
    fn query_ptr(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
        cb(Lookup::NxDomain);
    }
}

fn sign_and_assemble(key: &DkimPrivateKey, body: &[u8]) -> Vec<RawHeader> {
    let mut headers = sample_headers();
    let signer = DkimSigner::new(key, "example.com", "selector1").timestamp(1_753_700_000);
    let mut stream = signer.start(&headers);
    stream.feed(body);
    let value = stream.finish().unwrap();
    let mut bytes = b"DKIM-Signature: ".to_vec();
    bytes.extend_from_slice(value.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    headers.insert(0, RawHeader::new("DKIM-Signature", bytes));
    headers
}

/// Drives the same streaming verification path `run_all_streaming` does,
/// but returns only the first signature's result — the behavior these
/// tests originally exercised via the now-removed whole-buffer
/// `verify_first` (deleted: zero production callers, `verify_all_with_body_hashes`
/// is the real path `AuthPipeline` uses). A message with no `DKIM-Signature`
/// header at all yields an empty result list from the streaming verifier
/// (nothing to iterate), so that case is synthesized here to match
/// `verify_first`'s old explicit `DkimResult::None` behavior.
fn run_first(dns: FakeDns, headers: Vec<RawHeader>, body: &[u8]) -> DkimSignatureResult {
    let results = run_all_streaming(dns, headers, body, 64);
    results.into_iter().next().unwrap_or(DkimSignatureResult {
        result: DkimResult::None,
        signing_domain: None,
        selector: None,
    })
}

#[test]
fn rsa_round_trip_passes() {
    let key = rsa_key();
    let body = b"Hello, world!\r\n".to_vec();
    let headers = sign_and_assemble(&key, &body);
    let dns = FakeDns::default().with_txt(
        "selector1._domainkey.example.com",
        &format!("v=DKIM1; k=rsa; p={RSA_SPKI_B64}"),
    );
    let result = run_first(dns, headers, &body);
    assert_eq!(result.result, DkimResult::Pass);
    assert_eq!(result.signing_domain.as_deref(), Some("example.com"));
    assert_eq!(result.selector.as_deref(), Some("selector1"));
}

#[test]
fn ed25519_round_trip_passes() {
    let key = ed25519_key();
    let body = b"Hello, Ed25519!\r\n".to_vec();
    let headers = sign_and_assemble(&key, &body);
    let dns = FakeDns::default().with_txt(
        "selector1._domainkey.example.com",
        &format!("v=DKIM1; k=ed25519; p={ED25519_RAW_PUB_B64}"),
    );
    let result = run_first(dns, headers, &body);
    assert_eq!(result.result, DkimResult::Pass);
}

#[test]
fn tampered_body_fails() {
    let key = rsa_key();
    let body = b"Original body\r\n".to_vec();
    let headers = sign_and_assemble(&key, &body);
    let dns = FakeDns::default().with_txt(
        "selector1._domainkey.example.com",
        &format!("v=DKIM1; k=rsa; p={RSA_SPKI_B64}"),
    );
    let tampered = b"Tampered body\r\n".to_vec();
    let result = run_first(dns, headers, &tampered);
    assert_eq!(result.result, DkimResult::Fail);
}

#[test]
fn revoked_key_fails() {
    let key = rsa_key();
    let body = b"Hello\r\n".to_vec();
    let headers = sign_and_assemble(&key, &body);
    let dns = FakeDns::default().with_txt("selector1._domainkey.example.com", "v=DKIM1; k=rsa; p=");
    let result = run_first(dns, headers, &body);
    assert_eq!(result.result, DkimResult::Fail);
}

#[test]
fn missing_selector_is_permerror() {
    let key = rsa_key();
    let body = b"Hello\r\n".to_vec();
    let headers = sign_and_assemble(&key, &body);
    let dns = FakeDns::default();
    let result = run_first(dns, headers, &body);
    assert_eq!(result.result, DkimResult::PermError);
}

#[test]
fn no_signature_header_is_none() {
    let headers = sample_headers();
    let dns = FakeDns::default();
    let result = run_first(dns, headers, b"body");
    assert_eq!(result.result, DkimResult::None);
}

/// Runs the streaming path exactly the way `AuthPipeline` will: determine
/// the required `(c, l)` canonicalizations from the (already-buffered,
/// small) headers, feed the body through one [`super::super::canon::IncrementalBodyCanon`]
/// per canonicalization in arbitrarily-sized chunks, then verify against
/// the precomputed hashes instead of a whole-buffer body.
fn run_all_streaming(
    dns: FakeDns,
    headers: Vec<RawHeader>,
    body: &[u8],
    chunk_size: usize,
) -> Vec<DkimSignatureResult> {
    let keys = required_body_hash_keys(&headers);
    let mut canons: Vec<_> = keys
        .iter()
        .map(|&(c, l)| (c, l, super::super::canon::IncrementalBodyCanon::new(c, l)))
        .collect();
    for chunk in body.chunks(chunk_size.max(1)) {
        for (_, _, canon) in canons.iter_mut() {
            canon.feed(chunk);
        }
    }
    let mut body_hashes = BodyHashMap::new();
    for (c, l, canon) in canons {
        body_hashes.insert((c, l), canon.finish().as_ref().to_vec());
    }

    let out = Arc::new(Mutex::new(None));
    let out2 = Arc::clone(&out);
    verify_all_with_body_hashes(
        Arc::new(dns),
        Arc::new(headers),
        Arc::new(body_hashes),
        Box::new(move |r| *out2.lock().unwrap() = Some(r)),
    );
    let result = out.lock().unwrap().take().unwrap();
    result
}

#[test]
fn streaming_verification_matches_whole_buffer_for_pass_and_fail() {
    let key = rsa_key();
    let body = b"Hello, streaming world!\r\nSecond line.\r\n".to_vec();
    let headers = sign_and_assemble(&key, &body);
    let dns = || {
        FakeDns::default().with_txt(
            "selector1._domainkey.example.com",
            &format!("v=DKIM1; k=rsa; p={RSA_SPKI_B64}"),
        )
    };

    for chunk_size in [1usize, 3, 7, 64, 4096] {
        let results = run_all_streaming(dns(), headers.clone(), &body, chunk_size);
        assert_eq!(results.len(), 1, "chunk_size={chunk_size}");
        assert_eq!(
            results[0].result,
            DkimResult::Pass,
            "chunk_size={chunk_size}"
        );
    }

    // A tampered body must still fail streamed, exactly like whole-buffer.
    let tampered = b"Hello, tampered world!\r\nSecond line.\r\n".to_vec();
    let results = run_all_streaming(dns(), headers, &tampered, 5);
    assert_eq!(results[0].result, DkimResult::Fail);
}

#[test]
fn algorithm_family_mismatch_is_permerror() {
    let key = rsa_key();
    let body = b"Hello\r\n".to_vec();
    let headers = sign_and_assemble(&key, &body);
    // Key record claims ed25519 but signature says rsa-sha256.
    let dns = FakeDns::default().with_txt(
        "selector1._domainkey.example.com",
        &format!("v=DKIM1; k=ed25519; p={ED25519_RAW_PUB_B64}"),
    );
    let result = run_first(dns, headers, &body);
    assert_eq!(result.result, DkimResult::PermError);
}


// ── helpers for the cases below ──────────────────────────────────────────

const KEY_NAME: &str = "selector1._domainkey.example.com";

fn rsa_dns() -> FakeDns {
    FakeDns::default().with_txt(KEY_NAME, &format!("v=DKIM1; k=rsa; p={RSA_SPKI_B64}"))
}

fn ed_dns() -> FakeDns {
    FakeDns::default().with_txt(KEY_NAME, &format!("v=DKIM1; k=ed25519; p={ED25519_RAW_PUB_B64}"))
}

fn signed_rsa(body: &[u8]) -> Vec<RawHeader> {
    sign_and_assemble(&rsa_key(), body)
}

/// The signature header's value, without the field name.
fn sig_value(headers: &[RawHeader]) -> String {
    headers[0].as_string_unfolded().split_once(':').unwrap().1.trim().to_string()
}

/// Replace the signature header with one whose value is `f(old value)`.
fn edit_sig(headers: &[RawHeader], f: impl Fn(&str) -> String) -> Vec<RawHeader> {
    let mut out = headers.to_vec();
    out[0] = RawHeader::new("DKIM-Signature", format!("DKIM-Signature: {}\r\n", f(&sig_value(headers))).into_bytes());
    out
}

fn verdict(dns: FakeDns, headers: Vec<RawHeader>, body: &[u8]) -> DkimResult {
    run_first(dns, headers, body).result
}

const BODY: &[u8] = b"Hello, world!\r\n";

// ── the signature header ─────────────────────────────────────────────────

#[test]
fn results_have_their_authentication_results_names() {
    for (r, name) in [
        (DkimResult::Pass, "pass"),
        (DkimResult::Fail, "fail"),
        (DkimResult::None, "none"),
        (DkimResult::TempError, "temperror"),
        (DkimResult::PermError, "permerror"),
        (DkimResult::Policy, "policy"),
        (DkimResult::Neutral, "neutral"),
    ] {
        assert_eq!(r.as_str(), name);
    }
}

#[test]
fn a_signature_that_is_missing_a_required_tag_is_a_permerror() {
    for tag in ["v", "a", "b", "bh", "d", "h", "s"] {
        let headers = edit_sig(&signed_rsa(BODY), |v| {
            v.split(';')
                .map(str::trim)
                .filter(|part| !part.starts_with(&format!("{tag}=")))
                .collect::<Vec<_>>()
                .join("; ")
        });
        assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError, "without {tag}=");
    }
}

#[test]
fn only_version_one_is_understood() {
    let headers = edit_sig(&signed_rsa(BODY), |v| v.replacen("v=1", "v=2", 1));
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError);
}

#[test]
fn a_signature_that_does_not_cover_the_from_header_is_a_permerror() {
    let headers = edit_sig(&signed_rsa(BODY), |v| v.replace("h=From:", "h=").replace("From", "Sender"));
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError);
}

#[test]
fn rsa_sha1_and_unknown_algorithms_are_not_verified() {
    for algo in ["rsa-sha1", "md5-rsa", "ed25519-sha1"] {
        let headers = edit_sig(&signed_rsa(BODY), |v| v.replacen("a=rsa-sha256", &format!("a={algo}"), 1));
        assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError, "{algo}");
    }
}

#[test]
fn an_identity_outside_the_signing_domain_is_a_permerror() {
    let headers = edit_sig(&signed_rsa(BODY), |v| format!("{v}; i=user@evil.example"));
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError);
    // A subdomain of d= is allowed in the syntax (the signature then fails only because i= was added after signing).
    let headers = edit_sig(&signed_rsa(BODY), |v| format!("{v}; i=@sub.example.com"));
    assert_ne!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError);
}

#[test]
fn a_tag_given_twice_is_a_permerror() {
    // RFC 6376 section 3.2: a tag name must not occur more than once.
    // Same value again, so only the repetition itself is wrong.
    let headers = edit_sig(&signed_rsa(BODY), |v| format!("{v}; s=selector1"));
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError);
}

#[test]
fn unreadable_numbers_and_base64_are_permerrors() {
    for edit in [
        (" l=abc", "l"),
        (" x=soon", "x"),
    ] {
        let headers = edit_sig(&signed_rsa(BODY), |v| format!("{v};{}", edit.0.replace(' ', " ")));
        assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError, "{}", edit.1);
    }
    let headers = edit_sig(&signed_rsa(BODY), |v| v.replacen("bh=", "bh=!!!", 1));
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError);
}

#[test]
fn a_bad_canonicalization_is_a_permerror() {
    let headers = edit_sig(&signed_rsa(BODY), |v| v.replacen("c=relaxed/relaxed", "c=fancy/relaxed", 1));
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::PermError);
}

#[test]
fn an_expired_signature_fails_and_a_current_one_passes() {
    let key = rsa_key();
    let mut headers = sample_headers();
    let sign = |expires: u64, headers: &mut Vec<RawHeader>| {
        let signer = DkimSigner::new(&key, "example.com", "selector1").timestamp(1_753_700_000).expiration(expires);
        let mut stream = signer.start(headers);
        stream.feed(BODY);
        let value = stream.finish().unwrap();
        headers.insert(0, RawHeader::new("DKIM-Signature", format!("DKIM-Signature: {value}\r\n").into_bytes()));
    };
    sign(1_753_700_100, &mut headers);
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::Fail, "x= is long past");

    let mut headers = sample_headers();
    sign(u64::MAX / 2, &mut headers);
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::Pass);
}

// ── what is signed ───────────────────────────────────────────────────────

#[test]
fn changing_a_signed_header_fails() {
    let mut headers = signed_rsa(BODY);
    let subject = headers.iter().position(|h| h.name() == "Subject").unwrap();
    headers[subject] = RawHeader::new("Subject", b"Subject: Hijacked\r\n".to_vec());
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::Fail);
}

#[test]
fn changing_a_header_that_was_not_signed_passes() {
    let mut headers = signed_rsa(BODY);
    headers.push(RawHeader::new("X-Trace", b"X-Trace: added later\r\n".to_vec()));
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::Pass);
}

#[test]
fn removing_a_signed_header_fails() {
    let headers: Vec<RawHeader> = signed_rsa(BODY).into_iter().filter(|h| h.name() != "Subject").collect();
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::Fail);
}

#[test]
fn a_flipped_signature_bit_fails() {
    let headers = edit_sig(&signed_rsa(BODY), |v| {
        let b = v.rfind("b=").unwrap() + 2;
        let mut out = v.to_string();
        let c = if &out[b..b + 1] == "A" { "B" } else { "A" };
        out.replace_range(b..b + 1, c);
        out
    });
    assert_eq!(verdict(rsa_dns(), headers, BODY), DkimResult::Fail);
}

#[test]
fn every_canonicalization_pair_round_trips() {
    use super::super::canon::Canonicalization::{Relaxed, Simple};
    for (ch, cb) in [(Simple, Simple), (Simple, Relaxed), (Relaxed, Simple), (Relaxed, Relaxed)] {
        let key = ed25519_key();
        let mut headers = sample_headers();
        let signer = DkimSigner::new(&key, "example.com", "selector1")
            .header_canonicalization(ch)
            .body_canonicalization(cb)
            .timestamp(1_753_700_000);
        let mut stream = signer.start(&headers);
        stream.feed(b"Line one  with   spaces\r\n\r\nafter blank\r\n");
        let value = stream.finish().unwrap();
        headers.insert(0, RawHeader::new("DKIM-Signature", format!("DKIM-Signature: {value}\r\n").into_bytes()));
        assert_eq!(
            verdict(ed_dns(), headers, b"Line one  with   spaces\r\n\r\nafter blank\r\n"),
            DkimResult::Pass,
            "{ch:?}/{cb:?}"
        );
    }
}

#[test]
fn relaxed_body_canonicalization_tolerates_whitespace_changes_but_simple_does_not() {
    let key = ed25519_key();
    for (cb, expect) in [
        (super::super::canon::Canonicalization::Relaxed, DkimResult::Pass),
        (super::super::canon::Canonicalization::Simple, DkimResult::Fail),
    ] {
        let mut headers = sample_headers();
        let signer = DkimSigner::new(&key, "example.com", "selector1").body_canonicalization(cb).timestamp(1);
        let mut stream = signer.start(&headers);
        stream.feed(b"a b\r\n");
        let value = stream.finish().unwrap();
        headers.insert(0, RawHeader::new("DKIM-Signature", format!("DKIM-Signature: {value}\r\n").into_bytes()));
        assert_eq!(verdict(ed_dns(), headers, b"a   b  \r\n"), expect, "{cb:?}");
    }
}

#[test]
fn a_header_name_repeated_in_h_with_different_case_selects_two_different_headers() {
    // RFC 6376 section 5.4: names match without regard to case, so
    // `h=from:From` takes the bottom From and then the one above it.
    let key = ed25519_key();
    let mut headers = vec![
        RawHeader::new("From", b"From: first@example.com\r\n".to_vec()),
        RawHeader::new("From", b"From: second@example.com\r\n".to_vec()),
        RawHeader::new("Subject", b"Subject: s\r\n".to_vec()),
    ];
    let signer = DkimSigner::new(&key, "example.com", "selector1")
        .signed_headers(vec!["from".into(), "From".into(), "Subject".into()])
        .timestamp(1);
    let mut stream = signer.start(&headers);
    stream.feed(BODY);
    let value = stream.finish().unwrap();
    headers.insert(0, RawHeader::new("DKIM-Signature", format!("DKIM-Signature: {value}\r\n").into_bytes()));
    assert_eq!(verdict(ed_dns(), headers.clone(), BODY), DkimResult::Pass);
    // Both From headers are covered: changing the upper one must break it.
    let upper = headers.iter().position(|h| h.name() == "From").unwrap();
    headers[upper] = RawHeader::new("From", b"From: forged@example.com\r\n".to_vec());
    assert_eq!(verdict(ed_dns(), headers, BODY), DkimResult::Fail);
}

#[test]
fn naming_a_header_more_often_than_it_exists_covers_its_absence() {
    // Oversigning: an extra reference to a missing header means adding one later breaks the signature.
    let key = ed25519_key();
    let mut headers = sample_headers();
    let signer = DkimSigner::new(&key, "example.com", "selector1")
        .signed_headers(vec!["From".into(), "To".into(), "Subject".into(), "Subject".into()])
        .timestamp(1);
    let mut stream = signer.start(&headers);
    stream.feed(BODY);
    let value = stream.finish().unwrap();
    headers.insert(0, RawHeader::new("DKIM-Signature", format!("DKIM-Signature: {value}\r\n").into_bytes()));
    assert_eq!(verdict(ed_dns(), headers.clone(), BODY), DkimResult::Pass);
    headers.push(RawHeader::new("Subject", b"Subject: injected\r\n".to_vec()));
    assert_eq!(verdict(ed_dns(), headers, BODY), DkimResult::Fail);
}

// ── the key record ───────────────────────────────────────────────────────

fn with_key_record(record: &str) -> DkimResult {
    let dns = FakeDns::default().with_txt(KEY_NAME, record);
    verdict(dns, signed_rsa(BODY), BODY)
}

#[test]
fn a_key_record_may_leave_out_the_version_and_the_key_type() {
    assert_eq!(with_key_record(&format!("p={RSA_SPKI_B64}")), DkimResult::Pass);
    assert_eq!(with_key_record(&format!("v=dkim1; p={RSA_SPKI_B64}")), DkimResult::Pass, "DKIM1 in any case");
}

#[test]
fn a_key_record_for_another_version_or_without_a_key_is_a_permerror() {
    assert_eq!(with_key_record(&format!("v=DKIM2; p={RSA_SPKI_B64}")), DkimResult::PermError);
    assert_eq!(with_key_record("v=DKIM1; k=rsa"), DkimResult::PermError, "no p= at all");
    assert_eq!(with_key_record("v=DKIM1; k=rsa; p=!!!"), DkimResult::PermError);
    assert_eq!(with_key_record("v=DKIM1; k=rsa; p=AAAA"), DkimResult::PermError, "not a public key");
}

#[test]
fn a_key_that_does_not_allow_sha256_or_email_is_a_permerror() {
    assert_eq!(with_key_record(&format!("v=DKIM1; h=sha1; p={RSA_SPKI_B64}")), DkimResult::PermError);
    assert_eq!(with_key_record(&format!("v=DKIM1; h=sha1:sha256; p={RSA_SPKI_B64}")), DkimResult::Pass);
    assert_eq!(with_key_record(&format!("v=DKIM1; s=other; p={RSA_SPKI_B64}")), DkimResult::PermError);
    assert_eq!(with_key_record(&format!("v=DKIM1; s=*; p={RSA_SPKI_B64}")), DkimResult::Pass);
    assert_eq!(with_key_record(&format!("v=DKIM1; s=email; p={RSA_SPKI_B64}")), DkimResult::Pass);
}

#[test]
fn a_key_tag_given_twice_is_a_permerror() {
    assert_eq!(with_key_record(&format!("v=DKIM1; p={RSA_SPKI_B64}; p=")), DkimResult::PermError);
}

#[test]
fn a_strict_key_wants_the_identity_to_be_the_signing_domain_itself() {
    // t=s (RFC 6376 section 3.6.1): i= may not name a subdomain of d=.
    let key = rsa_key();
    let mut headers = sample_headers();
    let signer = DkimSigner::new(&key, "example.com", "selector1").identity("user@sub.example.com").timestamp(1);
    let mut stream = signer.start(&headers);
    stream.feed(BODY);
    let value = stream.finish().unwrap();
    headers.insert(0, RawHeader::new("DKIM-Signature", format!("DKIM-Signature: {value}\r\n").into_bytes()));
    let lax = FakeDns::default().with_txt(KEY_NAME, &format!("v=DKIM1; p={RSA_SPKI_B64}"));
    assert_eq!(verdict(lax, headers.clone(), BODY), DkimResult::Pass);
    let strict = FakeDns::default().with_txt(KEY_NAME, &format!("v=DKIM1; t=s; p={RSA_SPKI_B64}"));
    assert_eq!(verdict(strict, headers, BODY), DkimResult::Fail);
}

#[test]
fn an_ed25519_key_of_the_wrong_length_is_a_permerror() {
    let key = ed25519_key();
    let headers = sign_and_assemble(&key, BODY);
    let dns = FakeDns::default().with_txt(KEY_NAME, "v=DKIM1; k=ed25519; p=AAAA");
    assert_eq!(verdict(dns, headers, BODY), DkimResult::PermError);
}

#[test]
fn a_different_ed25519_key_fails() {
    let key = ed25519_key();
    let headers = sign_and_assemble(&key, BODY);
    let other = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    let dns = FakeDns::default().with_txt(KEY_NAME, &format!("v=DKIM1; k=ed25519; p={other}"));
    assert_eq!(verdict(dns, headers, BODY), DkimResult::Fail);
}

#[test]
fn two_key_records_or_a_failing_lookup_are_not_a_pass() {
    let dns = rsa_dns().with_txt(KEY_NAME, &format!("v=DKIM1; p={RSA_SPKI_B64}"));
    assert_eq!(verdict(dns, signed_rsa(BODY), BODY), DkimResult::PermError);
    let dns = FakeDns::default().with_temp_error(KEY_NAME);
    assert_eq!(verdict(dns, signed_rsa(BODY), BODY), DkimResult::TempError);
}

// ── several signatures ───────────────────────────────────────────────────

#[test]
fn every_signature_is_reported_in_order() {
    let headers = signed_rsa(BODY);
    let mut headers_two = headers.clone();
    headers_two.insert(
        0,
        RawHeader::new("DKIM-Signature", format!("DKIM-Signature: {}\r\n", sig_value(&headers).replace("a=rsa-sha256", "a=rsa-sha1")).into_bytes()),
    );
    let results = run_all_streaming(rsa_dns(), headers_two, BODY, 16);
    let verdicts: Vec<DkimResult> = results.iter().map(|r| r.result).collect();
    assert_eq!(verdicts, [DkimResult::PermError, DkimResult::Pass]);
}

#[test]
fn only_the_first_ten_signatures_are_looked_at() {
    let headers = signed_rsa(BODY);
    let one = headers[0].clone();
    let mut many = headers.clone();
    for _ in 0..14 {
        many.insert(0, one.clone());
    }
    assert_eq!(run_all_streaming(rsa_dns(), many.clone(), BODY, 64).len(), 10);
    assert_eq!(required_body_hash_keys(&many).len(), 1, "the same canonicalization needs one hash");
}

#[test]
fn the_body_hashes_needed_are_one_per_canonicalization_and_length() {
    let headers = signed_rsa(BODY);
    let simple = edit_sig(&headers, |v| v.replacen("c=relaxed/relaxed", "c=relaxed/simple", 1));
    let mut both = headers.clone();
    both.insert(0, simple[0].clone());
    let keys = required_body_hash_keys(&both);
    assert_eq!(keys.len(), 2);
    // A malformed signature adds nothing.
    let broken = edit_sig(&headers, |v| v.replacen("v=1", "v=9", 1));
    assert!(required_body_hash_keys(&broken).is_empty());
}

#[test]
fn a_body_hash_the_caller_did_not_compute_is_a_permerror_not_a_mismatch() {
    let headers = signed_rsa(BODY);
    let out = Arc::new(Mutex::new(None));
    let out2 = Arc::clone(&out);
    verify_all_with_body_hashes(
        Arc::new(rsa_dns()),
        Arc::new(headers),
        Arc::new(BodyHashMap::new()),
        Box::new(move |r| *out2.lock().unwrap() = Some(r)),
    );
    let results = out.lock().unwrap().take().unwrap();
    assert_eq!(results[0].result, DkimResult::PermError);
    assert_eq!(results[0].signing_domain.as_deref(), Some("example.com"));
}

#[test]
fn a_signature_that_does_not_parse_has_no_domain_to_report() {
    let headers = edit_sig(&signed_rsa(BODY), |v| v.replacen("v=1", "v=9", 1));
    let r = run_first(rsa_dns(), headers, BODY);
    assert_eq!((r.result, r.signing_domain, r.selector), (DkimResult::PermError, None, None));
}
