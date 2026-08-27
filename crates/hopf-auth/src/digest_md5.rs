// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL DIGEST-MD5 (RFC 2831) — deprecated but retained for Gumdrop parity.

use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::{ct_eq_hex, generate_nonce_hex, md5_hex};
use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::CredentialStore;

/// Parse `key=value` DIGEST parameter list.
pub fn parse_params(response: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_quote = false;
    let mut in_value = false;
    let chars: Vec<char> = response.chars().collect();
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
        } else if c == '=' {
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
        params.insert(key.trim().to_string(), value);
    }
    params
}

/// `MD5(username:realm:password)` hex.
pub fn compute_ha1(username: &str, realm: &str, password: &str) -> String {
    md5_hex(format!("{username}:{realm}:{password}").as_bytes())
}

/// Verify client response; returns `rspauth` hex on success (Gumdrop parity: md5-sess with hex HA1).
pub fn verify_client_response(
    ha1_hex: &str,
    server_nonce: &str,
    params: &HashMap<String, String>,
) -> Option<String> {
    let client_nonce = params.get("nonce")?;
    let nc = params.get("nc")?;
    let cnonce = params.get("cnonce")?;
    let qop = params.get("qop")?;
    let digest_uri = params.get("digest-uri")?;
    let client_response = params.get("response")?;
    if client_nonce != server_nonce {
        return None;
    }
    // Gumdrop: session HA1 = MD5( hex(HA1) + ":" + nonce + ":" + cnonce )
    let session_ha1 = md5_hex(format!("{ha1_hex}:{server_nonce}:{cnonce}").as_bytes());
    let ha2 = md5_hex(format!("AUTHENTICATE:{digest_uri}").as_bytes());
    let expected = md5_hex(
        format!("{session_ha1}:{server_nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes(),
    );
    if !ct_eq_hex(client_response, &expected) {
        return None;
    }
    let rsp_ha2 = md5_hex(format!(":{digest_uri}").as_bytes());
    Some(md5_hex(
        format!("{session_ha1}:{server_nonce}:{nc}:{cnonce}:{qop}:{rsp_ha2}").as_bytes(),
    ))
}

/// Generate DIGEST-MD5 server challenge (ready for Base64 on the wire).
pub fn generate_challenge(realm: &str, nonce: &str) -> String {
    format!("realm=\"{realm}\",nonce=\"{nonce}\",qop=\"auth\",charset=utf-8,algorithm=md5-sess")
}

pub(crate) struct DigestMd5Server {
    store: Arc<dyn CredentialStore>,
    realm: String,
    nonce: String,
    sent: bool,
}

impl DigestMd5Server {
    pub fn new(store: Arc<dyn CredentialStore>, realm: String) -> Self {
        Self {
            store,
            realm,
            nonce: generate_nonce_hex(16),
            sent: false,
        }
    }
}

impl SaslServer for DigestMd5Server {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::DigestMd5
    }

    fn server_first(&self) -> bool {
        true
    }

    fn step(&mut self, client_response: Option<&[u8]>, cb: crate::session::Cb<SaslServerStep>) {
        if !self.sent {
            self.sent = true;
            let ch = generate_challenge(&self.realm, &self.nonce);
            return cb(SaslServerStep::Challenge(ch.into_bytes()));
        }
        let Some(raw) = client_response else {
            return cb(SaslServerStep::Failure);
        };
        let text = String::from_utf8_lossy(raw);
        let params = parse_params(&text);
        let Some(username) = params.get("username").cloned() else {
            return cb(SaslServerStep::Failure);
        };
        let Some(ha1) = self.store.digest_ha1(&username, &self.realm) else {
            return cb(SaslServerStep::Failure);
        };
        cb(match verify_client_response(&ha1, &self.nonce, &params) {
            Some(rspauth) => SaslServerStep::Complete {
                username,
                final_message: Some(format!("rspauth={rspauth}").into_bytes()),
            },
            None => SaslServerStep::Failure,
        });
    }
}

pub(crate) struct DigestMd5Client {
    username: String,
    password: String,
    host: String,
    /// `serv-type` half of the `digest-uri` (RFC 2831 §2.1.2), e.g. `"imap"`,
    /// `"pop"`, `"smtp"` — the protocol the caller is authenticating for.
    service: String,
    complete: bool,
    /// Values from the first step, retained to verify the server's
    /// `rspauth` in its final message (RFC 2831 §2.1.3) — `None` until the
    /// first step has run.
    session: Option<ClientSession>,
}

struct ClientSession {
    session_ha1: String,
    nonce: String,
    cnonce: String,
    digest_uri: String,
}

impl DigestMd5Client {
    pub fn new(username: &str, password: &str, host: &str, service: &str) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            host: host.into(),
            service: service.into(),
            complete: false,
            session: None,
        }
    }
}

impl SaslClient for DigestMd5Client {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::DigestMd5
    }

    fn has_initial_response(&self) -> bool {
        false
    }

    fn evaluate(&mut self, challenge: Option<&[u8]>) -> SaslClientStep {
        let Some(ch) = challenge else {
            return SaslClientStep::Failure;
        };
        let text = String::from_utf8_lossy(ch);
        if let Some(rspauth) = text.strip_prefix("rspauth=") {
            let Some(session) = &self.session else {
                return SaslClientStep::Failure;
            };
            // Same formula as `verify_client_response`'s response-value,
            // but with A2 = ":" + digest-uri (no "AUTHENTICATE:" prefix) —
            // RFC 2831 §2.1.3.
            let rsp_ha2 = md5_hex(format!(":{}", session.digest_uri).as_bytes());
            let expected = md5_hex(
                format!(
                    "{}:{}:00000001:{}:auth:{rsp_ha2}",
                    session.session_ha1, session.nonce, session.cnonce
                )
                .as_bytes(),
            );
            if !ct_eq_hex(rspauth.trim(), &expected) {
                return SaslClientStep::Failure;
            }
            self.complete = true;
            return SaslClientStep::Complete(Vec::new());
        }
        let params = parse_params(&text);
        let realm = params
            .get("realm")
            .cloned()
            .unwrap_or_else(|| "hopf".into());
        let nonce = match params.get("nonce") {
            Some(n) => n.clone(),
            None => return SaslClientStep::Failure,
        };
        let cnonce = generate_nonce_hex(8);
        let nc = "00000001";
        let qop = "auth";
        let digest_uri = format!("{}/{}", self.service, self.host);
        let ha1 = compute_ha1(&self.username, &realm, &self.password);
        let session_ha1 = md5_hex(format!("{ha1}:{nonce}:{cnonce}").as_bytes());
        let ha2 = md5_hex(format!("AUTHENTICATE:{digest_uri}").as_bytes());
        let response = md5_hex(
            format!("{session_ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes(),
        );
        let msg = format!(
            "username=\"{}\",realm=\"{realm}\",nonce=\"{nonce}\",cnonce=\"{cnonce}\",nc={nc},qop={qop},digest-uri=\"{digest_uri}\",response={response},charset=utf-8",
            self.username
        );
        self.session = Some(ClientSession {
            session_ha1,
            nonce,
            cnonce,
            digest_uri,
        });
        SaslClientStep::Complete(msg.into_bytes())
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_params_quotes_and_escapes() {
        let m = parse_params(r#"username="a\"b",realm=r,nonce="n""#);
        assert_eq!(m.get("username").map(String::as_str), Some(r#"a"b"#));
        assert_eq!(m.get("realm").map(String::as_str), Some("r"));
        assert_eq!(m.get("nonce").map(String::as_str), Some("n"));
        let ha1 = compute_ha1("u", "realm", "p");
        assert_eq!(ha1.len(), 32);
        let ch = generate_challenge("realm", "abc");
        assert!(ch.contains("realm=\"realm\""));
        assert!(ch.contains("nonce=\"abc\""));
    }

    /// Two callers authenticating the same user against the same server for
    /// two different protocols (e.g. IMAP vs POP) must produce different
    /// `digest-uri`s (RFC 2831 §2.1.2: `serv-type/host`) — a server that
    /// validates it (real DIGEST-MD5 servers do) would otherwise accept a
    /// response computed for the wrong protocol.
    #[test]
    fn digest_uri_reflects_caller_supplied_service() {
        let challenge = generate_challenge("realm", "abc");
        let mut imap_client = DigestMd5Client::new("u", "p", "host.example", "imap");
        let SaslClientStep::Complete(imap_msg) = imap_client.evaluate(Some(challenge.as_bytes()))
        else {
            panic!("expected Complete");
        };
        let imap_text = String::from_utf8(imap_msg).unwrap();
        assert!(imap_text.contains("digest-uri=\"imap/host.example\""));

        let mut pop_client = DigestMd5Client::new("u", "p", "host.example", "pop");
        let SaslClientStep::Complete(pop_msg) = pop_client.evaluate(Some(challenge.as_bytes()))
        else {
            panic!("expected Complete");
        };
        let pop_text = String::from_utf8(pop_msg).unwrap();
        assert!(pop_text.contains("digest-uri=\"pop/host.example\""));
    }

    /// RFC 2831 §2.1.3's mutual-authentication guarantee depends on the
    /// client checking the server's `rspauth` in its final message. An
    /// active on-path attacker impersonating the server can send any
    /// `rspauth=` value; the client must reject the exchange rather than
    /// accept it unconditionally.
    #[test]
    fn rejects_forged_server_rspauth() {
        let mut client = DigestMd5Client::new("u", &generate_nonce_hex(8), "host.example", "imap");
        let server_nonce = generate_nonce_hex(16);
        let challenge = generate_challenge("realm", &server_nonce);
        let SaslClientStep::Complete(_) = client.evaluate(Some(challenge.as_bytes())) else {
            panic!("expected Complete for the first step");
        };
        let forged = b"rspauth=00000000000000000000000000000000";
        assert!(matches!(
            client.evaluate(Some(forged)),
            SaslClientStep::Failure
        ));
    }

    /// The correctly-computed `rspauth` (the same value a real DIGEST-MD5
    /// server derives via [`verify_client_response`]) must still be
    /// accepted — the fix must check the value, not just reject everything.
    #[test]
    fn accepts_genuine_server_rspauth() {
        let password = generate_nonce_hex(8);
        let mut client = DigestMd5Client::new("u", &password, "host.example", "imap");
        let server_nonce = generate_nonce_hex(16);
        let challenge = generate_challenge("realm", &server_nonce);
        let SaslClientStep::Complete(response) = client.evaluate(Some(challenge.as_bytes()))
        else {
            panic!("expected Complete for the first step");
        };
        let response_text = String::from_utf8(response).unwrap();
        let params = parse_params(&response_text);
        let ha1 = compute_ha1("u", "realm", &password);
        let rspauth = verify_client_response(&ha1, &server_nonce, &params)
            .expect("a genuine client response must verify");
        let final_msg = format!("rspauth={rspauth}");
        assert!(matches!(
            client.evaluate(Some(final_msg.as_bytes())),
            SaslClientStep::Complete(_)
        ));
    }
}
