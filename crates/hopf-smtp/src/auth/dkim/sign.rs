// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DKIM signing (RFC 6376 §5, Ed25519 per RFC 8463).

use std::time::{SystemTime, UNIX_EPOCH};

use rmimeparser::dkim::RawHeader;

use super::canon::{self, Canonicalization};

/// A private key usable for DKIM signing.
pub enum DkimPrivateKey {
    /// RSA key pair (`a=rsa-sha256`), PKCS#8 DER.
    Rsa(ring::signature::RsaKeyPair),
    /// Ed25519 key pair (`a=ed25519-sha256`, RFC 8463), PKCS#8 DER.
    Ed25519(ring::signature::Ed25519KeyPair),
}

impl DkimPrivateKey {
    /// Load an RSA private key from PKCS#8 DER (e.g. `openssl genpkey
    /// -algorithm RSA ... | openssl pkcs8 -topk8 -nocrypt`).
    pub fn rsa_from_pkcs8(der: &[u8]) -> Result<Self, ()> {
        ring::signature::RsaKeyPair::from_pkcs8(der)
            .map(DkimPrivateKey::Rsa)
            .map_err(|_| ())
    }

    /// Load an Ed25519 private key from PKCS#8 (v1 or v2) DER. Accepts the
    /// PKCS#8 v1 form `openssl genpkey -algorithm ED25519` produces (seed
    /// only, no embedded public key) as well as v2 (seed + public key,
    /// consistency-checked).
    pub fn ed25519_from_pkcs8(der: &[u8]) -> Result<Self, ()> {
        ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map(DkimPrivateKey::Ed25519)
            .map_err(|_| ())
    }

    fn algorithm_tag(&self) -> &'static str {
        match self {
            DkimPrivateKey::Rsa(_) => "rsa-sha256",
            DkimPrivateKey::Ed25519(_) => "ed25519-sha256",
        }
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            DkimPrivateKey::Rsa(kp) => {
                let rng = ring::rand::SystemRandom::new();
                let mut sig = vec![0u8; kp.public().modulus_len()];
                kp.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, data, &mut sig)
                    .map_err(|_| ())?;
                Ok(sig)
            }
            DkimPrivateKey::Ed25519(kp) => Ok(kp.sign(data).as_ref().to_vec()),
        }
    }
}

/// Builds a `DKIM-Signature:` header value (RFC 6376 §5).
pub struct DkimSigner<'a> {
    key: &'a DkimPrivateKey,
    domain: String,
    selector: String,
    header_canon: Canonicalization,
    body_canon: Canonicalization,
    signed_headers: Vec<String>,
    timestamp: Option<u64>,
    expiration: Option<u64>,
    identity: Option<String>,
}

impl<'a> DkimSigner<'a> {
    /// New signer for `domain`/`selector`, defaulting to relaxed/relaxed
    /// canonicalization and signing `From`, `To`, `Subject`, `Date`,
    /// `Message-ID` (a conservative, commonly-used default header set).
    pub fn new(
        key: &'a DkimPrivateKey,
        domain: impl Into<String>,
        selector: impl Into<String>,
    ) -> Self {
        Self {
            key,
            domain: domain.into(),
            selector: selector.into(),
            header_canon: Canonicalization::Relaxed,
            body_canon: Canonicalization::Relaxed,
            signed_headers: vec![
                "From".to_string(),
                "To".to_string(),
                "Subject".to_string(),
                "Date".to_string(),
                "Message-ID".to_string(),
            ],
            timestamp: None,
            expiration: None,
            identity: None,
        }
    }

    /// Set header canonicalization (`c=` first component).
    pub fn header_canonicalization(mut self, c: Canonicalization) -> Self {
        self.header_canon = c;
        self
    }

    /// Set body canonicalization (`c=` second component).
    pub fn body_canonicalization(mut self, c: Canonicalization) -> Self {
        self.body_canon = c;
        self
    }

    /// Set the exact ordered list of headers to sign (`h=`). Must include
    /// `From`; headers absent from the message are simply skipped at sign
    /// time the same way a verifier skips them (RFC 6376 §5.4).
    pub fn signed_headers(mut self, headers: Vec<String>) -> Self {
        self.signed_headers = headers;
        self
    }

    /// Explicit `t=` signing timestamp; defaults to "now" at [`Self::sign`] time.
    pub fn timestamp(mut self, t: u64) -> Self {
        self.timestamp = Some(t);
        self
    }

    /// `x=` expiration timestamp.
    pub fn expiration(mut self, x: u64) -> Self {
        self.expiration = Some(x);
        self
    }

    /// `i=` Agent-or-User-Identifier; must be `domain` or a subdomain of it.
    pub fn identity(mut self, i: impl Into<String>) -> Self {
        self.identity = Some(i.into());
        self
    }

    /// Produce the `DKIM-Signature:` header value (without the trailing
    /// CRLF, without the `DKIM-Signature:` field name) for `headers` +
    /// `body`. Returns the same string Gumdrop's `DKIMSigner.sign()` returns
    /// modulo formatting: `"DKIM-Signature: " + this`.
    pub fn sign(&self, headers: &[RawHeader], body: &[u8]) -> Result<String, ()> {
        let t = self.timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

        let canon_body_bytes = canon::canon_body(body, self.body_canon, None);
        let bh = base64_encode(ring::digest::digest(
            &ring::digest::SHA256,
            &canon_body_bytes,
        ));

        let h_joined = self.signed_headers.join(":");
        let mut unsigned_value = format!(
            "v=1; a={}; c={}/{}; d={}; s={}; t={}",
            self.key.algorithm_tag(),
            canon_name(self.header_canon),
            canon_name(self.body_canon),
            self.domain,
            self.selector,
            t,
        );
        if let Some(x) = self.expiration {
            unsigned_value.push_str(&format!("; x={x}"));
        }
        if let Some(i) = &self.identity {
            unsigned_value.push_str(&format!("; i={i}"));
        }
        unsigned_value.push_str(&format!("; h={h_joined}; bh={bh}; b="));

        let sig_header_bytes = {
            let mut b = Vec::new();
            b.extend_from_slice(b"DKIM-Signature:");
            b.extend_from_slice(unsigned_value.as_bytes());
            b
        };

        let selected = select_headers(headers, &self.signed_headers);
        let mut signed_data = Vec::new();
        for h in selected {
            signed_data.extend_from_slice(&canon::canon_header(h, self.header_canon));
        }
        signed_data.extend_from_slice(&canon::canon_signature_header(
            "DKIM-Signature",
            &sig_header_bytes,
            self.header_canon,
        ));

        let signature = self.key.sign(&signed_data)?;
        let b = base64_encode(&signature);
        Ok(format!("{unsigned_value}{b}"))
    }
}

/// Same bottom-up-per-name selection algorithm the verifier uses (RFC 6376
/// §5.4) — a signer using a repeated header name in `h=` must select
/// instances the same way a verifier will.
fn select_headers<'a>(all: &'a [RawHeader], h_list: &[String]) -> Vec<&'a RawHeader> {
    let mut used: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
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

fn canon_name(c: Canonicalization) -> &'static str {
    match c {
        Canonicalization::Simple => "simple",
        Canonicalization::Relaxed => "relaxed",
    }
}

fn base64_encode(data: impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data.as_ref())
}

#[cfg(test)]
mod tests;
