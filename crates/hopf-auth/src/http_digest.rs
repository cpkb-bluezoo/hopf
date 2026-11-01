// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP Digest authentication (RFC 7616): SHA-256 by default, MD5 for
//! clients that know nothing better, `qop=auth`, and the `-sess` variants.

use std::collections::HashMap;

use crate::crypto::{ct_eq_hex, generate_nonce_hex, md5_hex, sha256, to_hex};

/// The hash a Digest exchange is computed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// `MD5` (RFC 7616 keeps it for backward compatibility only).
    Md5,
    /// `SHA-256`.
    Sha256,
}

impl DigestAlgorithm {
    /// The wire name (`algorithm=` value, without any `-sess`).
    pub fn name(self) -> &'static str {
        match self {
            DigestAlgorithm::Md5 => "MD5",
            DigestAlgorithm::Sha256 => "SHA-256",
        }
    }

    /// The hash of `data` as lowercase hex.
    pub fn hash_hex(self, data: &[u8]) -> String {
        match self {
            DigestAlgorithm::Md5 => md5_hex(data),
            DigestAlgorithm::Sha256 => to_hex(&sha256(data)),
        }
    }

    /// Parse an `algorithm=` value (case-insensitive) into the hash and
    /// whether it is the `-sess` variant.
    pub fn parse(value: &str) -> Option<(DigestAlgorithm, bool)> {
        let upper = value.trim().to_ascii_uppercase();
        let (base, sess) = match upper.strip_suffix("-SESS") {
            Some(base) => (base, true),
            None => (upper.as_str(), false),
        };
        match base {
            "MD5" => Some((DigestAlgorithm::Md5, sess)),
            "SHA-256" => Some((DigestAlgorithm::Sha256, sess)),
            _ => None,
        }
    }
}

/// `H(username:realm:password)` - the value a credential store keeps so it
/// never has to hold the password.
pub fn compute_ha1(algorithm: DigestAlgorithm, username: &str, realm: &str, password: &str) -> String {
    algorithm.hash_hex(format!("{username}:{realm}:{password}").as_bytes())
}

/// Parse a `key=value, key="quoted value"` parameter list.
pub fn parse_params(list: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_quote = false;
    let mut in_value = false;
    let chars: Vec<char> = list.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_quote {
            if c == '"' {
                in_quote = false;
            } else if c == '\\' && i + 1 < chars.len() {
                i += 1;
                value.push(chars[i]);
            } else {
                value.push(c);
            }
        } else if c == '"' {
            in_quote = true;
        } else if c == '=' && !in_value {
            in_value = true;
        } else if c == ',' {
            params.insert(key.trim().to_string(), value.clone());
            key.clear();
            value.clear();
            in_value = false;
        } else if in_value {
            value.push(c);
        } else {
            key.push(c);
        }
        i += 1;
    }
    if !key.is_empty() {
        params.insert(key.trim().to_string(), value.trim().to_string());
    }
    params
}

/// Build the `WWW-Authenticate: Digest ...` challenge value (without the
/// scheme word) for `algorithm`. A server offering several sends one
/// challenge each, strongest first (RFC 7616 section 3.7).
pub fn challenge_header(realm: &str, nonce: &str, algorithm: DigestAlgorithm) -> String {
    format!(
        "realm=\"{realm}\", nonce=\"{nonce}\", qop=\"auth\", algorithm={}",
        algorithm.name()
    )
}

/// Fresh, unpredictable nonce.
pub fn new_nonce() -> String {
    generate_nonce_hex(16)
}

/// The algorithm a client's credentials were computed with, and whether it
/// is a `-sess` one. An absent `algorithm` means MD5 (RFC 7616 section
/// 3.3); an unrecognised one is `None`.
pub fn credentials_algorithm(credentials: &str) -> Option<(DigestAlgorithm, bool)> {
    match parse_params(credentials).get("algorithm") {
        Some(a) => DigestAlgorithm::parse(a),
        None => Some((DigestAlgorithm::Md5, false)),
    }
}

/// Verify an HTTP Digest Authorization credential string (after `Digest `).
///
/// `ha1_hex` is `H(username:realm:password)` for `algorithm`, from the
/// credential store. Credentials computed with a different algorithm are
/// refused. `method` and `uri` are the request method and digest-uri.
pub fn verify_authorization(
    credentials: &str,
    ha1_hex: &str,
    algorithm: DigestAlgorithm,
    method: &str,
    uri: &str,
    expected_nonce: Option<&str>,
) -> bool {
    let params = parse_params(credentials);
    let Some(nonce) = params.get("nonce") else {
        return false;
    };
    if let Some(exp) = expected_nonce {
        if nonce != exp {
            return false;
        }
    }
    let Some(response) = params.get("response") else {
        return false;
    };
    let Some((claimed, sess)) = credentials_algorithm(credentials) else {
        return false;
    };
    if claimed != algorithm {
        return false;
    }
    let qop = params.get("qop").map(|s| s.as_str());
    let cnonce = params.get("cnonce").map(|s| s.as_str());
    let nc = params.get("nc").map(|s| s.as_str());
    let req_uri = params.get("uri").map(|s| s.as_str()).unwrap_or(uri);

    let final_ha1 = if sess {
        let Some(cnonce) = cnonce else {
            return false;
        };
        algorithm.hash_hex(format!("{ha1_hex}:{nonce}:{cnonce}").as_bytes())
    } else {
        ha1_hex.to_string()
    };

    let ha2 = algorithm.hash_hex(format!("{method}:{req_uri}").as_bytes());

    let computed = if qop == Some("auth") {
        let (Some(cnonce), Some(nc)) = (cnonce, nc) else {
            return false;
        };
        algorithm.hash_hex(format!("{final_ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes())
    } else if algorithm == DigestAlgorithm::Md5 {
        // The RFC 2069 form, for old MD5 clients only.
        algorithm.hash_hex(format!("{final_ha1}:{nonce}:{ha2}").as_bytes())
    } else {
        return false;
    };

    ct_eq_hex(response, &computed)
}

/// Client helper: build Digest Authorization credentials (`qop=auth`).
pub fn client_authorization(
    algorithm: DigestAlgorithm,
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    let cnonce = generate_nonce_hex(8);
    let nc = "00000001";
    let ha1 = compute_ha1(algorithm, username, realm, password);
    let ha2 = algorithm.hash_hex(format!("{method}:{uri}").as_bytes());
    let response =
        algorithm.hash_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes());
    let name = algorithm.name();
    format!(
        "username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", \
         algorithm={name}, qop=auth, nc={nc}, cnonce=\"{cnonce}\", response={response}"
    )
}

/// A parsed `WWW-Authenticate: Digest` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChallenge {
    /// The `realm`.
    pub realm: String,
    /// The `nonce`.
    pub nonce: String,
    /// The algorithm it asks for (MD5 when it names none).
    pub algorithm: DigestAlgorithm,
}

/// Parse one `WWW-Authenticate` field value. `None` unless it is a Digest
/// challenge with a realm and a nonce, for an algorithm and `qop=auth` we
/// can answer (`-sess` variants are not offered by [`client_authorization`]).
pub fn parse_challenge(value: &str) -> Option<DigestChallenge> {
    let value = value.trim();
    let head = value.get(..6)?;
    let rest = value.get(6..)?;
    if !head.eq_ignore_ascii_case("digest") || !rest.starts_with([' ', '\t']) {
        return None;
    }
    let params = parse_params(rest.trim_start());
    let (algorithm, sess) = match params.get("algorithm") {
        Some(a) => DigestAlgorithm::parse(a)?,
        None => (DigestAlgorithm::Md5, false),
    };
    if sess {
        return None;
    }
    let qops = params.get("qop").map(|q| q.as_str()).unwrap_or("auth");
    if !qops.split(',').any(|q| q.trim().eq_ignore_ascii_case("auth")) {
        return None;
    }
    Some(DigestChallenge {
        realm: params.get("realm")?.clone(),
        nonce: params.get("nonce")?.clone(),
        algorithm,
    })
}

/// Of several `WWW-Authenticate` values, the Digest challenge to answer:
/// SHA-256 over MD5 (RFC 7616 section 3.7 puts the server's preference
/// first, but a client should still not choose the weaker when it can pick).
pub fn preferred_challenge<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<DigestChallenge> {
    let mut best: Option<DigestChallenge> = None;
    for c in values.into_iter().filter_map(parse_challenge) {
        let better = match &best {
            None => true,
            Some(b) => b.algorithm == DigestAlgorithm::Md5 && c.algorithm == DigestAlgorithm::Sha256,
        };
        if better {
            best = Some(c);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGS: [DigestAlgorithm; 2] = [DigestAlgorithm::Md5, DigestAlgorithm::Sha256];

    #[test]
    fn roundtrip_for_each_algorithm() {
        for alg in ALGS {
            let nonce = new_nonce();
            let creds = client_authorization(alg, "alice", "s3cret", "test", &nonce, "GET", "/");
            let ha1 = compute_ha1(alg, "alice", "test", "s3cret");
            assert!(verify_authorization(&creds, &ha1, alg, "GET", "/", Some(&nonce)), "{alg:?}");
            assert!(!verify_authorization(&creds, &ha1, alg, "POST", "/", Some(&nonce)), "{alg:?} method");
            assert!(!verify_authorization(&creds, &ha1, alg, "GET", "/", Some("other")), "{alg:?} nonce");
            let wrong = compute_ha1(alg, "alice", "test", "nope");
            assert!(!verify_authorization(&creds, &wrong, alg, "GET", "/", Some(&nonce)), "{alg:?} password");
        }
    }

    #[test]
    fn credentials_for_one_algorithm_are_not_accepted_as_another() {
        let nonce = new_nonce();
        let creds = client_authorization(DigestAlgorithm::Md5, "alice", "s3cret", "test", &nonce, "GET", "/");
        let ha1 = compute_ha1(DigestAlgorithm::Sha256, "alice", "test", "s3cret");
        assert!(!verify_authorization(&creds, &ha1, DigestAlgorithm::Sha256, "GET", "/", Some(&nonce)));
    }

    #[test]
    fn sha256_digests_are_sha256() {
        // RFC 7616 section 3.9.1 example: H("Mufasa:http-auth@example.org:Circle of Life").
        let ha1 = compute_ha1(DigestAlgorithm::Sha256, "Mufasa", "http-auth@example.org", "Circle of Life");
        assert_eq!(ha1.len(), 64);
        assert_eq!(ha1, to_hex(&sha256(b"Mufasa:http-auth@example.org:Circle of Life")));
    }

    #[test]
    fn the_rfc_7616_sha256_example_verifies() {
        // RFC 7616 section 3.9.1.
        let creds = "username=\"Mufasa\", realm=\"http-auth@example.org\", \
                     uri=\"/dir/index.html\", algorithm=SHA-256, \
                     nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                     nc=00000001, cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", \
                     qop=auth, \
                     response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\"";
        let ha1 = compute_ha1(DigestAlgorithm::Sha256, "Mufasa", "http-auth@example.org", "Circle of Life");
        assert!(verify_authorization(
            creds,
            &ha1,
            DigestAlgorithm::Sha256,
            "GET",
            "/dir/index.html",
            Some("7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"),
        ));
    }

    #[test]
    fn sha256_needs_qop() {
        let ha1 = compute_ha1(DigestAlgorithm::Sha256, "u", "r", "p");
        let ha2 = DigestAlgorithm::Sha256.hash_hex(b"GET:/");
        let response = DigestAlgorithm::Sha256.hash_hex(format!("{ha1}:n:{ha2}").as_bytes());
        let creds = format!("username=\"u\", realm=\"r\", nonce=\"n\", uri=\"/\", algorithm=SHA-256, response={response}");
        assert!(!verify_authorization(&creds, &ha1, DigestAlgorithm::Sha256, "GET", "/", Some("n")));
    }

    #[test]
    fn an_absent_algorithm_means_md5_and_an_unknown_one_is_refused() {
        assert_eq!(credentials_algorithm("username=\"u\""), Some((DigestAlgorithm::Md5, false)));
        assert_eq!(credentials_algorithm("algorithm=sha-256"), Some((DigestAlgorithm::Sha256, false)));
        assert_eq!(credentials_algorithm("algorithm=SHA-256-sess"), Some((DigestAlgorithm::Sha256, true)));
        assert_eq!(credentials_algorithm("algorithm=MD5-sess"), Some((DigestAlgorithm::Md5, true)));
        assert_eq!(credentials_algorithm("algorithm=SHA-512-256"), None);
    }

    #[test]
    fn session_variants_verify() {
        for alg in ALGS {
            let ha1 = compute_ha1(alg, "u", "r", "p");
            let sess_ha1 = alg.hash_hex(format!("{ha1}:n:c").as_bytes());
            let ha2 = alg.hash_hex(b"GET:/");
            let response = alg.hash_hex(format!("{sess_ha1}:n:00000001:c:auth:{ha2}").as_bytes());
            let creds = format!(
                "username=\"u\", realm=\"r\", nonce=\"n\", uri=\"/\", algorithm={}-sess, qop=auth, nc=00000001, cnonce=\"c\", response={response}",
                alg.name()
            );
            assert!(verify_authorization(&creds, &ha1, alg, "GET", "/", Some("n")), "{alg:?}");
        }
    }

    #[test]
    fn challenges_name_their_algorithm() {
        let c = challenge_header("files", "abc", DigestAlgorithm::Sha256);
        assert_eq!(c, "realm=\"files\", nonce=\"abc\", qop=\"auth\", algorithm=SHA-256");
        let c = challenge_header("files", "abc", DigestAlgorithm::Md5);
        assert!(c.ends_with("algorithm=MD5"));
    }

    #[test]
    fn challenges_parse_and_the_stronger_is_chosen() {
        let md5 = "Digest realm=\"r\", nonce=\"n1\", qop=\"auth\", algorithm=MD5";
        let sha = "digest realm=\"r\", nonce=\"n2\", qop=\"auth, auth-int\", algorithm=SHA-256";
        let c = parse_challenge(sha).unwrap();
        assert_eq!((c.realm.as_str(), c.nonce.as_str(), c.algorithm), ("r", "n2", DigestAlgorithm::Sha256));
        assert_eq!(parse_challenge(md5).unwrap().algorithm, DigestAlgorithm::Md5);
        assert_eq!(preferred_challenge([md5, sha]).unwrap().nonce, "n2");
        assert_eq!(preferred_challenge([sha, md5]).unwrap().nonce, "n2");
        assert_eq!(preferred_challenge([md5]).unwrap().nonce, "n1");
        assert!(parse_challenge("Basic realm=\"r\"").is_none());
        assert!(parse_challenge("Digest realm=\"r\"").is_none(), "no nonce");
        assert!(parse_challenge("Digest realm=\"r\", nonce=\"n\", algorithm=SHA-512-256").is_none());
        assert!(parse_challenge("Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\"").is_none());
        assert!(preferred_challenge(["Basic x"]).is_none());
    }

    #[test]
    fn parameter_lists_handle_quotes_commas_and_escapes() {
        let p = parse_params("a=1, b=\"two, with comma\", c=\"q\\\"uote\", d=x=y");
        assert_eq!(p["a"], "1");
        assert_eq!(p["b"], "two, with comma");
        assert_eq!(p["c"], "q\"uote");
        assert_eq!(p["d"], "x=y");
    }
}
