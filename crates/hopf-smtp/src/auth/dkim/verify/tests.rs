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
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
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

fn sign_and_assemble(key: &DkimPrivateKey, body: &[u8]) -> Vec<RawHeader> {
    let mut headers = sample_headers();
    let value = DkimSigner::new(key, "example.com", "selector1")
        .timestamp(1_753_700_000)
        .sign(&headers, body)
        .unwrap();
    let mut bytes = b"DKIM-Signature: ".to_vec();
    bytes.extend_from_slice(value.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    headers.insert(0, RawHeader::new("DKIM-Signature", bytes));
    headers
}

fn run_first(dns: FakeDns, headers: Vec<RawHeader>, body: &[u8]) -> DkimSignatureResult {
    let out = Arc::new(Mutex::new(None));
    let out2 = Arc::clone(&out);
    verify_first(
        Arc::new(dns),
        Arc::new(headers),
        Arc::new(body.to_vec()),
        Box::new(move |r| *out2.lock().unwrap() = Some(r)),
    );
    let r = out.lock().unwrap().take().unwrap();
    r
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
