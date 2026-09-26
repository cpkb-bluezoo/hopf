use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use rmimeparser::dkim::RawHeader;

use super::*;
use crate::auth::dkim::canon::{Canonicalization, IncrementalBodyCanon};
use crate::auth::dkim::{BodyHashMap, DkimPrivateKey};
use crate::auth::dns_lookup::{DnsLookup, Lookup};

// Freshly generated for these tests only - not used anywhere else.
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

#[derive(Default)]
struct FakeDns {
    txt: HashMap<String, Vec<String>>,
}

impl FakeDns {
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

const RELAXED: Canonicalization = Canonicalization::Relaxed;

fn rsa_key() -> Arc<DkimPrivateKey> {
    Arc::new(DkimPrivateKey::rsa_from_pkcs8(&b64_decode(RSA_PKCS8_B64)).unwrap())
}

fn ed25519_key() -> Arc<DkimPrivateKey> {
    Arc::new(DkimPrivateKey::ed25519_from_pkcs8(&b64_decode(ED25519_PKCS8_B64)).unwrap())
}

fn dns() -> Arc<dyn DnsLookup> {
    Arc::new(
        FakeDns::default()
            .with_txt(
                "arc._domainkey.list.example",
                &format!("v=DKIM1; k=rsa; p={RSA_SPKI_B64}"),
            )
            .with_txt(
                "arc._domainkey.fwd.example",
                &format!("v=DKIM1; k=ed25519; p={ED25519_RAW_PUB_B64}"),
            ),
    )
}

fn base_headers() -> Vec<RawHeader> {
    vec![
        RawHeader::new("From", b"From: alice@example.com\r\n".to_vec()),
        RawHeader::new("To", b"To: bob@example.net\r\n".to_vec()),
        RawHeader::new("Subject", b"Subject: Hello\r\n".to_vec()),
        RawHeader::new("Date", b"Date: Tue, 28 Jul 2026 10:00:00 +0000\r\n".to_vec()),
        RawHeader::new("Message-ID", b"Message-ID: <abc123@example.com>\r\n".to_vec()),
    ]
}

const AR: &str = "Authentication-Results: list.example;\r\n\tspf=pass smtp.mailfrom=example.com;\r\n\tdkim=pass header.d=example.com;\r\n\tdmarc=pass header.from=example.com";

fn body_hashes(keys: &[(Canonicalization, Option<u64>)], body: &[u8]) -> BodyHashMap {
    keys.iter()
        .map(|&(c, l)| {
            let mut canon = IncrementalBodyCanon::new(c, l);
            canon.feed(body);
            ((c, l), canon.finish().as_ref().to_vec())
        })
        .collect()
}

fn run_validate(headers: &[RawHeader], body: &[u8]) -> ArcValidationResult {
    let keys = required_body_hash_keys(headers);
    let out = Arc::new(Mutex::new(None));
    let out2 = Arc::clone(&out);
    validate(
        dns(),
        Arc::new(headers.to_vec()),
        Arc::new(body_hashes(&keys, body)),
        Box::new(move |r| *out2.lock().unwrap() = Some(r)),
    );
    let r = out.lock().unwrap().take().expect("FakeDns completes synchronously");
    r
}

/// Validate `headers`/`body` as a hop would on receipt, then seal.
fn hop(
    sealer: &ArcSealer,
    headers: &[RawHeader],
    body: &[u8],
) -> (ArcValidationResult, Result<ArcSetHeaders, ArcSealError>) {
    let existing = run_validate(headers, body);
    let hashes = body_hashes(&[sealer.body_canonicalization_key()], body);
    let sealed = sealer.seal(headers, &hashes, &existing, AR);
    (existing, sealed)
}

/// Prepend a sealed set to the headers the way a relay would.
fn with_set(headers: &[RawHeader], set: &ArcSetHeaders) -> Vec<RawHeader> {
    let mut out = vec![
        RawHeader::new("ARC-Seal", set.seal.clone().into_bytes()),
        RawHeader::new("ARC-Message-Signature", set.message_signature.clone().into_bytes()),
        RawHeader::new(
            "ARC-Authentication-Results",
            set.authentication_results.clone().into_bytes(),
        ),
    ];
    out.extend_from_slice(headers);
    out
}

fn list_sealer() -> ArcSealer {
    ArcSealer::new(rsa_key(), "list.example", "arc", "list.example").timestamp(1_753_700_000)
}

fn fwd_sealer() -> ArcSealer {
    ArcSealer::new(ed25519_key(), "fwd.example", "arc", "fwd.example").timestamp(1_753_700_100)
}

const BODY: &[u8] = b"Hello, world!\r\n";

fn one_hop() -> Vec<RawHeader> {
    let (_, sealed) = hop(&list_sealer(), &base_headers(), BODY);
    with_set(&base_headers(), &sealed.unwrap())
}

fn two_hops() -> Vec<RawHeader> {
    let h1 = one_hop();
    let (_, sealed) = hop(&fwd_sealer(), &h1, BODY);
    with_set(&h1, &sealed.unwrap())
}

fn replace_header(headers: &[RawHeader], name: &str, f: impl Fn(&str) -> String) -> Vec<RawHeader> {
    headers
        .iter()
        .map(|h| {
            if h.name().eq_ignore_ascii_case(name) {
                RawHeader::new(h.name(), f(&String::from_utf8_lossy(h.bytes())).into_bytes())
            } else {
                h.clone()
            }
        })
        .collect()
}

// --- chain grouping ---------------------------------------------------------

#[test]
fn no_arc_headers_is_an_empty_chain() {
    let chain = ArcChain::from_headers(&base_headers()).unwrap();
    assert!(chain.sets.is_empty());
    assert_eq!(run_validate(&base_headers(), BODY).cv, ArcCv::None);
}

#[test]
fn sets_are_grouped_and_ordered_by_instance() {
    let chain = ArcChain::from_headers(&two_hops()).unwrap();
    let instances: Vec<u32> = chain.sets.iter().map(|s| s.instance).collect();
    assert_eq!(instances, vec![1, 2]);
    assert_eq!(chain.sets[0].seal_cv, ArcCv::None);
    assert_eq!(chain.sets[1].seal_cv, ArcCv::Pass);
    assert_eq!(chain.sets[0].sealer_domain().as_deref(), Some("list.example"));
    assert_eq!(chain.sets[1].sealer_domain().as_deref(), Some("fwd.example"));
}

#[test]
fn missing_header_in_a_set_is_malformed() {
    let mut h = one_hop();
    h.retain(|x| !x.name().eq_ignore_ascii_case("ARC-Message-Signature"));
    assert_eq!(ArcChain::from_headers(&h).unwrap_err(), ArcMalformed::IncompleteSet);
    let r = run_validate(&h, BODY);
    assert_eq!(r.cv, ArcCv::Fail);
    assert_eq!(r.malformed, Some(ArcMalformed::IncompleteSet));
}

#[test]
fn gap_in_instances_is_malformed() {
    let h = replace_header(&two_hops(), "ARC-Seal", |s| s.replace("i=1;", "i=3;"));
    assert_eq!(ArcChain::from_headers(&h).unwrap_err(), ArcMalformed::IncompleteSet);
}

#[test]
fn duplicate_header_for_an_instance_is_malformed() {
    let mut h = one_hop();
    let dup = h[0].clone();
    h.insert(0, dup);
    assert_eq!(ArcChain::from_headers(&h).unwrap_err(), ArcMalformed::DuplicateHeader);
}

#[test]
fn bad_instance_and_bad_cv_are_malformed() {
    let h = replace_header(&one_hop(), "ARC-Seal", |s| s.replace("i=1;", "i=0;"));
    assert_eq!(ArcChain::from_headers(&h).unwrap_err(), ArcMalformed::BadInstance);
    let h = replace_header(&one_hop(), "ARC-Seal", |s| s.replace("i=1;", "i=51;"));
    assert_eq!(ArcChain::from_headers(&h).unwrap_err(), ArcMalformed::BadInstance);
    let h = replace_header(&one_hop(), "ARC-Seal", |s| s.replace("cv=none", "cv=maybe"));
    assert_eq!(ArcChain::from_headers(&h).unwrap_err(), ArcMalformed::BadSealCv);
}

// --- seal + validate round trips ---------------------------------------------

#[test]
fn first_hop_seals_with_cv_none_and_validates() {
    let (existing, sealed) = hop(&list_sealer(), &base_headers(), BODY);
    assert_eq!(existing.cv, ArcCv::None);
    let set = sealed.unwrap();
    assert!(set.seal.starts_with("ARC-Seal: i=1; a=rsa-sha256; t=1753700000; cv=none; d=list.example; s=arc; b="));
    assert!(set.message_signature.starts_with("ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=list.example; s=arc;"));
    assert!(set.authentication_results.starts_with("ARC-Authentication-Results: i=1; list.example;"));

    let r = run_validate(&with_set(&base_headers(), &set), BODY);
    assert_eq!(r.cv, ArcCv::Pass, "{:?}", r.failed_instance);
    assert_eq!(r.chain.sets.len(), 1);
}

#[test]
fn two_hop_chain_with_mixed_algorithms_validates() {
    let r = run_validate(&two_hops(), BODY);
    assert_eq!(r.cv, ArcCv::Pass, "failed at {:?}", r.failed_instance);
    assert_eq!(r.chain.sets.len(), 2);
    assert_eq!(r.chain.sets[1].seal_cv, ArcCv::Pass);
}

#[test]
fn body_modified_by_a_later_hop_still_validates() {
    // Hop 2 (a mailing list, say) rewrites the body and seals what it now
    // has. Hop 1's message signature no longer matches, which is expected:
    // only the newest AMS must verify (RFC 8617 section 5.2).
    let h1 = one_hop();
    let modified = b"Hello, world!\r\n\r\n-- \r\nlist footer\r\n";
    // Hop 2 received the original body, so its own chain check passes...
    let existing = run_validate(&h1, BODY);
    assert_eq!(existing.cv, ArcCv::Pass);
    // ...then it forwards the modified body, sealing over that.
    let hashes = body_hashes(&[fwd_sealer().body_canonicalization_key()], modified);
    let sealed2 = fwd_sealer().seal(&h1, &hashes, &existing, AR).unwrap();
    let final_headers = with_set(&h1, &sealed2);
    let r = run_validate(&final_headers, modified);
    assert_eq!(r.cv, ArcCv::Pass, "failed at {:?}", r.failed_instance);
}

#[test]
fn tampered_body_fails_the_newest_message_signature() {
    let r = run_validate(&two_hops(), b"Tampered\r\n");
    assert_eq!(r.cv, ArcCv::Fail);
    assert_eq!(r.failed_instance, Some(2));
}

#[test]
fn tampered_older_authentication_results_fails_a_seal() {
    let h = replace_header(&two_hops(), "ARC-Authentication-Results", |s| {
        s.replace("spf=pass", "spf=fail")
    });
    // Both sets' AARs were altered by this blunt replace; the newest seal
    // covers them all so validation fails at i=2 (newest first).
    let r = run_validate(&h, BODY);
    assert_eq!(r.cv, ArcCv::Fail);
    assert!(r.failed_instance.is_some());
}

#[test]
fn tampering_only_the_oldest_set_fails_at_that_seal() {
    let mut first = true;
    let h: Vec<RawHeader> = two_hops()
        .into_iter()
        .rev()
        .map(|h| {
            if first && h.name().eq_ignore_ascii_case("ARC-Authentication-Results") {
                first = false; // reversed: the first AAR seen is i=1's
                let s = String::from_utf8_lossy(h.bytes()).replace("spf=pass", "spf=fail");
                RawHeader::new(h.name(), s.into_bytes())
            } else {
                h
            }
        })
        .rev()
        .collect();
    let r = run_validate(&h, BODY);
    assert_eq!(r.cv, ArcCv::Fail);
}

#[test]
fn unknown_signing_key_fails() {
    let sealer = ArcSealer::new(rsa_key(), "nokey.example", "arc", "nokey.example");
    let (_, sealed) = hop(&sealer, &base_headers(), BODY);
    let r = run_validate(&with_set(&base_headers(), &sealed.unwrap()), BODY);
    assert_eq!(r.cv, ArcCv::Fail);
    assert_eq!(r.failed_instance, Some(1));
}

#[test]
fn first_seal_must_be_cv_none_and_later_seals_cv_pass() {
    let h = replace_header(&one_hop(), "ARC-Seal", |s| s.replace("cv=none", "cv=pass"));
    assert_eq!(run_validate(&h, BODY).cv, ArcCv::Fail);
    let h = replace_header(&two_hops(), "ARC-Seal", |s| s.replace("cv=pass", "cv=none"));
    assert_eq!(run_validate(&h, BODY).cv, ArcCv::Fail);
}

#[test]
fn failed_chain_is_sealed_with_cv_fail_and_cannot_be_extended() {
    // Hop 2 receives a chain that fails (body tampered after hop 1) and
    // records that with cv=fail, covering only its own set.
    let h1 = one_hop();
    let tampered = b"Tampered\r\n";
    let (existing, sealed) = hop(&fwd_sealer(), &h1, tampered);
    assert_eq!(existing.cv, ArcCv::Fail);
    let set = sealed.unwrap();
    assert!(set.seal.contains("cv=fail;"));

    let h2 = with_set(&h1, &set);
    let r = run_validate(&h2, tampered);
    assert_eq!(r.cv, ArcCv::Fail);

    // A third hop must not extend a chain a previous sealer declared dead.
    let (_, third) = hop(&list_sealer(), &h2, tampered);
    assert_eq!(third.unwrap_err(), ArcSealError::ChainAlreadyFailed);
}

#[test]
fn malformed_chain_is_never_sealed() {
    let mut h = one_hop();
    h.retain(|x| !x.name().eq_ignore_ascii_case("ARC-Seal"));
    let (existing, sealed) = hop(&list_sealer(), &h, BODY);
    assert!(existing.malformed.is_some());
    assert_eq!(sealed.unwrap_err(), ArcSealError::MalformedChain);
}

#[test]
fn seal_requires_the_body_hash_for_its_canonicalization() {
    let existing = run_validate(&base_headers(), BODY);
    let err = list_sealer()
        .seal(&base_headers(), &BodyHashMap::new(), &existing, AR)
        .unwrap_err();
    assert_eq!(err, ArcSealError::MissingBodyHash);
}

#[test]
fn fifty_sets_is_the_limit() {
    let mut chain = ArcChain::default();
    let template = ArcChain::from_headers(&one_hop()).unwrap().sets.remove(0);
    for i in 1..=MAX_INSTANCE {
        chain.sets.push(ArcSet { instance: i, ..template.clone() });
    }
    let existing = ArcValidationResult {
        cv: ArcCv::Pass,
        malformed: None,
        chain,
        failed_instance: None,
    };
    let hashes = body_hashes(&[(RELAXED, None)], BODY);
    // seal_cv of the template is None (not Fail), so only the limit applies.
    let err = list_sealer().seal(&base_headers(), &hashes, &existing, AR).unwrap_err();
    assert_eq!(err, ArcSealError::TooManyInstances);
}

#[test]
fn simple_canonicalization_round_trips() {
    let sealer = ArcSealer::new(rsa_key(), "list.example", "arc", "list.example")
        .header_canonicalization(Canonicalization::Simple)
        .body_canonicalization(Canonicalization::Simple);
    let (_, sealed) = hop(&sealer, &base_headers(), BODY);
    let r = run_validate(&with_set(&base_headers(), &sealed.unwrap()), BODY);
    assert_eq!(r.cv, ArcCv::Pass, "{:?}", r.failed_instance);
}

// --- recorded results ---------------------------------------------------------

#[test]
fn recorded_results_expose_spf_and_dkim_verdicts() {
    let chain = ArcChain::from_headers(&one_hop()).unwrap();
    let rec = chain.sets[0].recorded_results();
    assert_eq!(rec.spf, Some((SpfResult::Pass, Some("example.com".to_string()))));
    assert_eq!(rec.dkim, vec![(DkimResult::Pass, Some("example.com".to_string()))]);
}
