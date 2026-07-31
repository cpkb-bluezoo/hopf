use rmimeparser::dkim::RawHeader;

use super::*;

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
const ED25519_PKCS8_B64: &str = "MC4CAQAwBQYDK2VwBCIEIJOr3cUYESkwGr3t08+NHi5fO++QEUtI7YDNn9ruV59R";

fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn headers() -> Vec<RawHeader> {
    vec![
        RawHeader::new("From", b"From: alice@example.com\r\n".to_vec()),
        RawHeader::new("Subject", b"Subject: Hi\r\n".to_vec()),
    ]
}

#[test]
fn rsa_signature_has_expected_shape() {
    let key = DkimPrivateKey::rsa_from_pkcs8(&b64_decode(RSA_PKCS8_B64)).unwrap();
    let signer = DkimSigner::new(&key, "example.com", "sel1")
        .signed_headers(vec!["From".to_string(), "Subject".to_string()])
        .timestamp(1_753_700_000);
    let mut stream = signer.start(&headers());
    stream.feed(b"body\r\n");
    let value = stream.finish().unwrap();
    assert!(value
        .starts_with("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; t=1753700000"));
    assert!(value.contains("h=From:Subject;"));
    assert!(value.contains("bh="));
    assert!(value.ends_with(|c: char| c != ';')); // b= value present after final "b="
    assert!(value.contains("; b="));
}

#[test]
fn ed25519_signature_uses_correct_algorithm_tag() {
    let key = DkimPrivateKey::ed25519_from_pkcs8(&b64_decode(ED25519_PKCS8_B64)).unwrap();
    let signer = DkimSigner::new(&key, "example.com", "sel1").timestamp(1_753_700_000);
    let mut stream = signer.start(&headers());
    stream.feed(b"body\r\n");
    let value = stream.finish().unwrap();
    assert!(value.starts_with("v=1; a=ed25519-sha256;"));
}

#[test]
fn expiration_and_identity_tags_included() {
    let key = DkimPrivateKey::rsa_from_pkcs8(&b64_decode(RSA_PKCS8_B64)).unwrap();
    let signer = DkimSigner::new(&key, "example.com", "sel1")
        .timestamp(1_753_700_000)
        .expiration(1_753_800_000)
        .identity("user@sub.example.com");
    let mut stream = signer.start(&headers());
    stream.feed(b"body\r\n");
    let value = stream.finish().unwrap();
    assert!(value.contains("x=1753800000"));
    assert!(value.contains("i=user@sub.example.com"));
}
