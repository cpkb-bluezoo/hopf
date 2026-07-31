// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! OAuth 2.0 Token Introspection (RFC 7662) — a real
//! [`CredentialStore::validate_bearer`] backend, replacing a local static
//! token map with an actual introspection-endpoint round trip.
//!
//! hopf-auth has no network I/O of its own — hopf-http (which does)
//! already depends on hopf-auth, so hopf-auth depending back on hopf-http
//! would be a cycle. The actual HTTP POST to the introspection endpoint is
//! supplied by the caller via [`IntrospectionTransport`], using whatever
//! HTTP client fits their runtime (e.g. hopf-http's client, driven off the
//! reactor thread the same way other blocking work in this workspace is —
//! see `hopf_core::storage::StorageExecutor`).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::mechanism::SaslMechanism;
use crate::store::{CertificateIdentity, CredentialStore, ScramCredentials, TokenValidation};

/// One RFC 7662 §2.1 introspection request.
#[derive(Debug, Clone)]
pub struct IntrospectionRequest {
    /// The token to introspect.
    pub token: String,
    /// RFC 7662 §2.1 `token_type_hint` — optional, but including it lets a
    /// compliant AS skip guessing the token type.
    pub token_type_hint: Option<String>,
}

impl IntrospectionRequest {
    /// New request with `token_type_hint=access_token` (the common case).
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            token_type_hint: Some("access_token".to_string()),
        }
    }

    /// Request body as `application/x-www-form-urlencoded` per RFC 7662 §2.1.
    pub fn to_form_body(&self) -> String {
        let mut body = format!("token={}", form_urlencode(&self.token));
        if let Some(hint) = &self.token_type_hint {
            body.push_str("&token_type_hint=");
            body.push_str(&form_urlencode(hint));
        }
        body
    }
}

fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// RFC 7662 §2.2 introspection response — only the fields this crate
/// consumes (`active`, `username`, `scope`, `exp`). Other fields a real
/// authorization server includes (`aud`, `iss`, `client_id`, `token_type`,
/// `nbf`, `sub`, `iat`, `jti`, ...) are structurally skipped during
/// parsing (never rejected as "unexpected"), per RFC 7662 §2.2's own note
/// that additional fields MAY be present.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active, per the authorization server.
    pub active: bool,
    /// Subject / username, when present.
    pub username: Option<String>,
    /// Scopes, split from RFC 7662's single space-separated `scope` string.
    pub scope: Vec<String>,
    /// Expiration, Unix seconds, when present.
    pub exp: Option<u64>,
}

impl IntrospectionResponse {
    /// Parse a raw introspection JSON response body.
    pub fn parse(json: &str) -> Option<Self> {
        let obj = json::parse_object(json)?;
        let active = matches!(obj.get("active"), Some(json::Value::Bool(true)));
        let username = match obj.get("username") {
            Some(json::Value::Str(s)) => Some(s.clone()),
            _ => None,
        };
        let scope = match obj.get("scope") {
            Some(json::Value::Str(s)) => {
                s.split_whitespace().map(|w| w.to_string()).collect()
            }
            _ => Vec::new(),
        };
        let exp = match obj.get("exp") {
            Some(json::Value::Num(n)) => n.parse::<u64>().ok(),
            _ => None,
        };
        Some(Self {
            active,
            username,
            scope,
            exp,
        })
    }
}

/// Supplies the actual HTTP POST to the introspection endpoint.
/// hopf-auth only builds the request body and parses the response; see
/// the module docs for why it can't make the call itself.
pub trait IntrospectionTransport: Send + Sync {
    /// POST `form_body` (already `application/x-www-form-urlencoded`) to
    /// the introspection endpoint and return the raw JSON response body,
    /// or `None` on any transport-level failure (network error, non-2xx
    /// status, timeout, ...).
    fn introspect(&self, form_body: &str) -> Option<String>;
}

/// A [`CredentialStore`] whose [`CredentialStore::validate_bearer`] calls
/// out to a real RFC 7662 introspection endpoint (via a caller-supplied
/// [`IntrospectionTransport`]) instead of consulting a local static token
/// map. Every other [`CredentialStore`] method delegates to `inner`
/// unchanged — this only replaces bearer-token validation.
pub struct IntrospectionCredentialStore {
    inner: Arc<dyn CredentialStore>,
    transport: Arc<dyn IntrospectionTransport>,
}

impl IntrospectionCredentialStore {
    /// Wrap `inner` (used for every mechanism except bearer-token
    /// validation) with introspection-backed `validate_bearer`.
    pub fn new(inner: Arc<dyn CredentialStore>, transport: Arc<dyn IntrospectionTransport>) -> Self {
        Self { inner, transport }
    }
}

impl CredentialStore for IntrospectionCredentialStore {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        self.inner.supported_mechanisms()
    }
    fn password_match(&self, username: &str, password: &str) -> bool {
        self.inner.password_match(username, password)
    }
    fn plaintext_password(&self, username: &str) -> Option<String> {
        self.inner.plaintext_password(username)
    }
    fn digest_ha1(&self, username: &str, realm: &str) -> Option<String> {
        self.inner.digest_ha1(username, realm)
    }
    fn cram_md5_digest(&self, username: &str, challenge: &str) -> Option<String> {
        self.inner.cram_md5_digest(username, challenge)
    }
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        self.inner.scram_credentials(username)
    }

    fn validate_bearer(&self, token: &str) -> Option<TokenValidation> {
        let req = IntrospectionRequest::new(token);
        let body = self.transport.introspect(&req.to_form_body())?;
        let resp = IntrospectionResponse::parse(&body)?;
        if !resp.active {
            return None;
        }
        // RFC 7662 doesn't require this — an AS returning `active: true`
        // has already made that determination — but a local expiry check
        // is cheap defense in depth against a stale cached/replayed
        // response outliving its `exp`.
        if let Some(exp) = resp.exp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if exp <= now {
                return None;
            }
        }
        Some(TokenValidation {
            username: resp.username.unwrap_or_default(),
            scopes: resp.scope,
        })
    }

    fn authenticate_certificate(&self, cert_key: &str) -> Option<CertificateIdentity> {
        self.inner.authenticate_certificate(cert_key)
    }
    fn authorize_as(&self, authcid: &str, authzid: &str) -> bool {
        self.inner.authorize_as(authcid, authzid)
    }
}

/// Minimal JSON reader — just enough to extract flat scalar fields from an
/// RFC 7662 introspection response, correctly skipping (not descending
/// into) any nested object/array fields it doesn't need. Not a general
/// JSON parser: kept deliberately small so hopf-auth doesn't need a JSON
/// crate dependency for one response shape.
mod json {
    use std::collections::HashMap;

    #[derive(Debug, Clone, PartialEq)]
    pub(super) enum Value {
        Str(String),
        Bool(bool),
        Num(String),
        Null,
        /// An array or object value — structurally skipped, not parsed
        /// (this module only ever needs top-level scalar fields).
        Other,
    }

    pub(super) fn parse_object(s: &str) -> Option<HashMap<String, Value>> {
        let mut out = HashMap::new();
        let mut i = skip_ws(s, 0);
        if s.as_bytes().get(i) != Some(&b'{') {
            return None;
        }
        i += 1;
        i = skip_ws(s, i);
        if s.as_bytes().get(i) == Some(&b'}') {
            return Some(out);
        }
        loop {
            i = skip_ws(s, i);
            let (key, next) = parse_string(s, i)?;
            i = skip_ws(s, next);
            if s.as_bytes().get(i) != Some(&b':') {
                return None;
            }
            i += 1;
            i = skip_ws(s, i);
            let (value, next) = parse_value(s, i)?;
            out.insert(key, value);
            i = skip_ws(s, next);
            match s.as_bytes().get(i) {
                Some(b',') => {
                    i += 1;
                }
                Some(b'}') => {
                    break;
                }
                _ => return None,
            }
        }
        Some(out)
    }

    fn parse_value(s: &str, i: usize) -> Option<(Value, usize)> {
        match *s.as_bytes().get(i)? {
            b'"' => {
                let (v, next) = parse_string(s, i)?;
                Some((Value::Str(v), next))
            }
            b't' if s[i..].starts_with("true") => Some((Value::Bool(true), i + 4)),
            b'f' if s[i..].starts_with("false") => Some((Value::Bool(false), i + 5)),
            b'n' if s[i..].starts_with("null") => Some((Value::Null, i + 4)),
            b'{' => skip_balanced(s, i, b'{', b'}').map(|end| (Value::Other, end)),
            b'[' => skip_balanced(s, i, b'[', b']').map(|end| (Value::Other, end)),
            b'-' | b'0'..=b'9' => {
                let b = s.as_bytes();
                let start = i;
                let mut j = i;
                if b[j] == b'-' {
                    j += 1;
                }
                while j < b.len() && (b[j].is_ascii_digit() || matches!(b[j], b'.' | b'e' | b'E' | b'+' | b'-'))
                {
                    j += 1;
                }
                Some((Value::Num(s[start..j].to_string()), j))
            }
            _ => None,
        }
    }

    /// `i` points at the opening `open` byte; returns the index just past
    /// the matching `close` byte, correctly ignoring braces/brackets that
    /// appear inside nested strings.
    fn skip_balanced(s: &str, i: usize, open: u8, close: u8) -> Option<usize> {
        let b = s.as_bytes();
        let mut depth = 0i32;
        let mut j = i;
        let mut in_string = false;
        while j < b.len() {
            let c = b[j];
            if in_string {
                if c == b'\\' {
                    j += 2;
                    continue;
                }
                if c == b'"' {
                    in_string = false;
                }
                j += 1;
                continue;
            }
            match c {
                b'"' => in_string = true,
                c if c == open => depth += 1,
                c if c == close => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(j + 1);
                    }
                }
                _ => {}
            }
            j += 1;
        }
        None
    }

    fn parse_string(s: &str, i: usize) -> Option<(String, usize)> {
        let b = s.as_bytes();
        if b.get(i) != Some(&b'"') {
            return None;
        }
        let mut out = String::new();
        let mut j = i + 1;
        loop {
            let c = *b.get(j)?;
            match c {
                b'"' => return Some((out, j + 1)),
                b'\\' => {
                    j += 1;
                    let esc = *b.get(j)?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'u' => {
                            let hex = s.get(j + 1..j + 5)?;
                            let cp = u32::from_str_radix(hex, 16).ok()?;
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                            j += 4;
                        }
                        _ => return None,
                    }
                    j += 1;
                }
                _ => {
                    // `j` is a valid char boundary here: we only ever land
                    // on an ASCII control byte (handled above) or the
                    // first byte of the next character.
                    let ch = s[j..].chars().next()?;
                    out.push(ch);
                    j += ch.len_utf8();
                }
            }
        }
    }

    fn skip_ws(s: &str, mut i: usize) -> usize {
        let b = s.as_bytes();
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        i
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PasswordStore;
    use std::sync::Mutex;

    #[test]
    fn form_body_encodes_token_and_hint() {
        let req = IntrospectionRequest::new("tok en+special");
        let body = req.to_form_body();
        assert_eq!(
            body,
            "token=tok+en%2Bspecial&token_type_hint=access_token"
        );
    }

    #[test]
    fn parses_active_response_with_username_and_scope() {
        let json = r#"{"active": true, "username": "alice", "scope": "read write", "exp": 9999999999}"#;
        let resp = IntrospectionResponse::parse(json).unwrap();
        assert!(resp.active);
        assert_eq!(resp.username.as_deref(), Some("alice"));
        assert_eq!(resp.scope, vec!["read".to_string(), "write".to_string()]);
        assert_eq!(resp.exp, Some(9999999999));
    }

    #[test]
    fn parses_inactive_response() {
        let json = r#"{"active": false}"#;
        let resp = IntrospectionResponse::parse(json).unwrap();
        assert!(!resp.active);
    }

    #[test]
    fn ignores_unknown_nested_fields() {
        let json = r#"{
            "active": true,
            "username": "bob",
            "aud": ["a", "b", {"nested": true}],
            "client_id": "abc",
            "extra_obj": {"a": {"b": [1,2,3]}, "c": "d,e\"f"},
            "scope": "openid"
        }"#;
        let resp = IntrospectionResponse::parse(json).unwrap();
        assert!(resp.active);
        assert_eq!(resp.username.as_deref(), Some("bob"));
        assert_eq!(resp.scope, vec!["openid".to_string()]);
    }

    #[test]
    fn handles_escaped_characters_in_strings() {
        let json = r#"{"active": true, "username": "a\"b\\c\td"}"#;
        let resp = IntrospectionResponse::parse(json).unwrap();
        assert_eq!(resp.username.as_deref(), Some("a\"b\\c\td"));
    }

    #[test]
    fn malformed_json_returns_none() {
        assert!(IntrospectionResponse::parse("not json").is_none());
        assert!(IntrospectionResponse::parse("{\"active\": true").is_none());
        assert!(IntrospectionResponse::parse("").is_none());
    }

    #[test]
    fn missing_scope_and_exp_default_sensibly() {
        let resp = IntrospectionResponse::parse(r#"{"active": true}"#).unwrap();
        assert!(resp.scope.is_empty());
        assert_eq!(resp.exp, None);
        assert_eq!(resp.username, None);
    }

    struct FakeTransport {
        response: Mutex<Option<String>>,
        last_request: Mutex<Option<String>>,
    }

    impl IntrospectionTransport for FakeTransport {
        fn introspect(&self, form_body: &str) -> Option<String> {
            *self.last_request.lock().unwrap() = Some(form_body.to_string());
            self.response.lock().unwrap().clone()
        }
    }

    #[test]
    fn validate_bearer_accepts_a_real_active_response() {
        let transport = Arc::new(FakeTransport {
            response: Mutex::new(Some(
                r#"{"active": true, "username": "alice", "scope": "read write"}"#.to_string(),
            )),
            last_request: Mutex::new(None),
        });
        let inner: Arc<dyn CredentialStore> = Arc::new(PasswordStore::new());
        let store = IntrospectionCredentialStore::new(inner, Arc::clone(&transport) as Arc<dyn IntrospectionTransport>);

        let result = store.validate_bearer("tok-123").unwrap();
        assert_eq!(result.username, "alice");
        assert_eq!(result.scopes, vec!["read".to_string(), "write".to_string()]);

        let sent = transport.last_request.lock().unwrap().clone().unwrap();
        assert!(sent.contains("token=tok-123"));
    }

    #[test]
    fn validate_bearer_rejects_inactive_token() {
        let transport = Arc::new(FakeTransport {
            response: Mutex::new(Some(r#"{"active": false}"#.to_string())),
            last_request: Mutex::new(None),
        });
        let inner: Arc<dyn CredentialStore> = Arc::new(PasswordStore::new());
        let store = IntrospectionCredentialStore::new(inner, transport);
        assert!(store.validate_bearer("revoked-token").is_none());
    }

    #[test]
    fn validate_bearer_rejects_on_transport_failure() {
        let transport = Arc::new(FakeTransport {
            response: Mutex::new(None),
            last_request: Mutex::new(None),
        });
        let inner: Arc<dyn CredentialStore> = Arc::new(PasswordStore::new());
        let store = IntrospectionCredentialStore::new(inner, transport);
        assert!(store.validate_bearer("any-token").is_none());
    }

    #[test]
    fn validate_bearer_rejects_an_already_expired_token_even_if_marked_active() {
        let transport = Arc::new(FakeTransport {
            response: Mutex::new(Some(
                r#"{"active": true, "username": "alice", "exp": 1}"#.to_string(),
            )),
            last_request: Mutex::new(None),
        });
        let inner: Arc<dyn CredentialStore> = Arc::new(PasswordStore::new());
        let store = IntrospectionCredentialStore::new(inner, transport);
        assert!(store.validate_bearer("stale-token").is_none());
    }

    #[test]
    fn other_credential_store_methods_delegate_to_inner() {
        let transport = Arc::new(FakeTransport {
            response: Mutex::new(None),
            last_request: Mutex::new(None),
        });
        let inner: Arc<dyn CredentialStore> =
            Arc::new(PasswordStore::new().with_user("alice", "s3cret"));
        let store = IntrospectionCredentialStore::new(inner, transport);
        assert!(store.password_match("alice", "s3cret"));
        assert!(!store.password_match("alice", "wrong"));
    }
}
