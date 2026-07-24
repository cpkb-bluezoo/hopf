// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP Digest (RFC 7616) helpers — MD5 / MD5-sess, qop=auth.

use crate::crypto::{ct_eq_hex, from_hex, generate_nonce_hex, md5, md5_hex, to_hex};
use crate::digest_md5::{compute_ha1, parse_params};

/// Build `WWW-Authenticate: Digest …` challenge value (without the scheme word).
pub fn challenge_header(realm: &str, nonce: &str) -> String {
    format!("realm=\"{realm}\", nonce=\"{nonce}\", qop=\"auth\", algorithm=MD5")
}

/// Fresh nonce suitable for HTTP Digest.
pub fn new_nonce() -> String {
    // Mix time into MD5 like Gumdrop for unpredictability.
    let rnd = generate_nonce_hex(16);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    md5_hex(format!("{t}:{rnd}").as_bytes())
}

/// Verify an HTTP Digest Authorization credential string (after `Digest `).
///
/// `ha1_hex` is `MD5(username:realm:password)` from the credential store.
/// `method` and `uri` are the request method and digest-uri.
pub fn verify_authorization(
    credentials: &str,
    ha1_hex: &str,
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
    let algorithm = params
        .get("algorithm")
        .map(|s| s.as_str())
        .unwrap_or("MD5");
    let qop = params.get("qop").map(|s| s.as_str());
    let cnonce = params.get("cnonce").map(|s| s.as_str());
    let nc = params.get("nc").map(|s| s.as_str());
    let req_uri = params.get("uri").map(|s| s.as_str()).unwrap_or(uri);

    let final_ha1 = if algorithm.eq_ignore_ascii_case("MD5-sess") {
        let Some(cnonce) = cnonce else {
            return false;
        };
        let Some(ha1_bin) = from_hex(ha1_hex) else {
            return false;
        };
        let mut data = ha1_bin;
        data.push(b':');
        data.extend_from_slice(nonce.as_bytes());
        data.push(b':');
        data.extend_from_slice(cnonce.as_bytes());
        to_hex(&md5(&data))
    } else {
        ha1_hex.to_string()
    };

    let a2 = format!("{method}:{req_uri}");
    let ha2 = md5_hex(a2.as_bytes());

    let computed = if qop == Some("auth") {
        let (Some(cnonce), Some(nc)) = (cnonce, nc) else {
            return false;
        };
        md5_hex(
            format!("{final_ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes(),
        )
    } else {
        md5_hex(format!("{final_ha1}:{nonce}:{ha2}").as_bytes())
    };

    ct_eq_hex(response, &computed)
}

/// Client helper: build Digest Authorization credentials (MD5, qop=auth).
pub fn client_authorization(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    let cnonce = generate_nonce_hex(8);
    let nc = "00000001";
    let ha1 = compute_ha1(username, realm, password);
    let ha2 = md5_hex(format!("{method}:{uri}").as_bytes());
    let response = md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes());
    format!(
        "username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", \
         algorithm=MD5, qop=auth, nc={nc}, cnonce=\"{cnonce}\", response={response}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_digest_auth() {
        let realm = "test";
        let user = "alice";
        let pass = "s3cret";
        let nonce = new_nonce();
        let creds = client_authorization(user, pass, realm, &nonce, "GET", "/");
        let ha1 = compute_ha1(user, realm, pass);
        assert!(verify_authorization(&creds, &ha1, "GET", "/", Some(&nonce)));
    }
}
