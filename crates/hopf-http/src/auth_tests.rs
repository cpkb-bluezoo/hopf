// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-process tests of the Basic, Digest and Bearer wrappers: a recording
//! writer stands in for the transport and a recording handler for the
//! application behind them.

use super::*;

use hopf_auth::{PasswordStore, PasswordTrustPolicy};
use hopf_core::ConnHandle;

use crate::stream::ServerResponseHandle;

/// What the wrapped handler saw.
#[derive(Default)]
struct Seen {
    headers: Vec<Headers>,
    body: Vec<u8>,
    started: u32,
    ended: u32,
    completed: u32,
}

type SharedSeen = Arc<Mutex<Seen>>;

struct Inner(SharedSeen);

impl ServerHandler for Inner {
    fn headers(&mut self, _: &mut dyn ServerWriter, headers: &Headers) {
        self.0.lock().unwrap().headers.push(headers.clone());
    }
    fn start_request_body(&mut self, _: &mut dyn ServerWriter) {
        self.0.lock().unwrap().started += 1;
    }
    fn request_body_content(&mut self, _: &mut dyn ServerWriter, data: &[u8]) {
        self.0.lock().unwrap().body.extend_from_slice(data);
    }
    fn end_request_body(&mut self, _: &mut dyn ServerWriter) {
        self.0.lock().unwrap().ended += 1;
    }
    fn request_complete(&mut self, _: &mut dyn ServerWriter) {
        self.0.lock().unwrap().completed += 1;
    }
}

struct InnerFactory(SharedSeen);

impl ServerHandlerFactory for InnerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(Inner(Arc::clone(&self.0)))
    }
}

/// Records the response the wrapper sends.
#[derive(Default)]
struct Out {
    sent: Vec<Headers>,
    completed: u32,
}

impl ServerWriter for Out {
    fn headers(&mut self, headers: Headers) {
        self.sent.push(headers);
    }
    fn start_response_body(&mut self) {}
    fn response_body_content(&mut self, _: &[u8]) {}
    fn end_response_body(&mut self) {}
    fn complete(&mut self) {
        self.completed += 1;
    }
    fn conn_handle(&self) -> ConnHandle {
        ConnHandle::from_execute(Arc::new(|task| task()))
    }
    fn response_handle(&self) -> ServerResponseHandle {
        ServerResponseHandle::detached(self.conn_handle())
    }
    fn pause_request_body(&mut self) {}
    fn resume_request_body(&mut self) {}
}

impl Out {
    fn status(&self) -> Option<u16> {
        self.sent.first().map(|h| h.status_code())
    }

    fn challenge(&self) -> String {
        self.sent[0].get("www-authenticate").expect("a challenge").to_string()
    }
}

fn request(method: &str, path: &str, authorization: Option<&str>) -> Headers {
    let mut h = Headers::new();
    h.add_pseudo(":method", method);
    h.add_pseudo(":path", path);
    h.add("host", "localhost");
    if let Some(a) = authorization {
        h.add("authorization", a);
    }
    h
}

fn basic_header(user: &str, pass: &str) -> String {
    format!("Basic {}", hopf_auth::crypto::encode_base64(format!("{user}:{pass}").as_bytes()))
}

fn basic_factory() -> (Box<dyn ServerHandler>, SharedSeen) {
    let seen = SharedSeen::default();
    let policy = PasswordTrustPolicy::new().with_user("alice", "s3cret").shared();
    let factory = BasicAuthFactory::new(Arc::new(InnerFactory(Arc::clone(&seen))), policy, BasicAuthConfig::new("files"));
    (factory.create_handler(), seen)
}

// -- parsing -----------------------------------------------------------------

#[test]
fn basic_credentials_are_split_at_the_first_colon() {
    let id = parse_basic_authorization(Some(&basic_header("bob", "pa:ss:word"))).unwrap();
    assert_eq!(id, IdentityMaterial::UsernamePassword { username: "bob".into(), password: "pa:ss:word".into() });
    let id = parse_basic_authorization(Some(&basic_header("bob", ""))).unwrap();
    assert_eq!(id, IdentityMaterial::UsernamePassword { username: "bob".into(), password: "".into() });
}

#[test]
fn the_basic_scheme_name_is_not_case_sensitive() {
    // RFC 9110 section 11.1: authentication scheme names are case-insensitive.
    for scheme in ["Basic", "basic", "BASIC", "bAsIc"] {
        let value = format!("{scheme} YWxpY2U6czNjcmV0");
        assert!(parse_basic_authorization(Some(&value)).is_some(), "{scheme}");
    }
}

#[test]
fn surrounding_and_extra_whitespace_is_tolerated() {
    assert!(parse_basic_authorization(Some("  Basic   YWxpY2U6czNjcmV0  ")).is_some());
}

#[test]
fn malformed_basic_credentials_are_rejected() {
    for bad in [
        None,
        Some(""),
        Some("Basic"),
        Some("Basic "),
        Some("Basic !!!not-base64!!!"),
        Some("Basic YWxpY2U"),      // "alice", no colon
        Some("Bearer YWxpY2U6czNjcmV0"),
        Some("YWxpY2U6czNjcmV0"),
    ] {
        assert!(parse_basic_authorization(bad).is_none(), "{bad:?}");
    }
    let not_utf8 = format!("Basic {}", hopf_auth::crypto::encode_base64(&[0xff, b':', 0xfe]));
    assert!(parse_basic_authorization(Some(&not_utf8)).is_none());
}

// -- Basic -------------------------------------------------------------------

#[test]
fn basic_without_credentials_gets_a_challenge_and_the_application_sees_nothing() {
    let (mut h, seen) = basic_factory();
    let mut out = Out::default();
    h.headers(&mut out, &request("GET", "/", None));
    assert_eq!(out.status(), Some(401));
    assert_eq!(out.challenge(), "Basic realm=\"files\"");
    assert_eq!(out.sent[0].get("content-length"), Some("0"));
    assert_eq!(out.completed, 1);
    h.request_complete(&mut out);
    assert_eq!(out.sent.len(), 1, "challenged once");
    assert!(seen.lock().unwrap().headers.is_empty());
    assert_eq!(seen.lock().unwrap().completed, 0);
}

#[test]
fn basic_with_the_wrong_password_or_user_is_challenged() {
    for (u, p) in [("alice", "nope"), ("mallory", "s3cret"), ("", "")] {
        let (mut h, seen) = basic_factory();
        let mut out = Out::default();
        h.headers(&mut out, &request("GET", "/", Some(&basic_header(u, p))));
        assert_eq!(out.status(), Some(401), "{u}:{p}");
        assert!(seen.lock().unwrap().headers.is_empty());
    }
}

#[test]
fn basic_with_the_right_password_reaches_the_application_with_the_user_named() {
    let (mut h, seen) = basic_factory();
    let mut out = Out::default();
    h.headers(&mut out, &request("GET", "/x", Some(&basic_header("alice", "s3cret"))));
    assert!(out.sent.is_empty(), "no response from the wrapper");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.headers.len(), 1);
    assert_eq!(seen.headers[0].get(AUTHENTICATED_USER), Some("alice"));
    assert_eq!(seen.headers[0].path(), Some("/x"));
}

#[test]
fn a_client_supplied_user_header_never_survives_basic_auth() {
    let (mut h, seen) = basic_factory();
    let mut out = Out::default();
    let mut req = request("GET", "/", Some(&basic_header("alice", "s3cret")));
    req.add(AUTHENTICATED_USER, "root");
    req.add("X-Hopf-Authenticated-User", "admin");
    h.headers(&mut out, &req);
    let seen = seen.lock().unwrap();
    let values: Vec<_> =
        seen.headers[0].iter().filter(|f| f.name.eq_ignore_ascii_case(AUTHENTICATED_USER)).map(|f| f.value.clone()).collect();
    assert_eq!(values, ["alice"], "exactly one, and it is the authenticated user");
}

#[test]
fn the_body_is_passed_on_only_when_authorized() {
    let (mut ok, seen) = basic_factory();
    let mut out = Out::default();
    ok.headers(&mut out, &request("PUT", "/", Some(&basic_header("alice", "s3cret"))));
    ok.start_request_body(&mut out);
    ok.request_body_content(&mut out, b"abc");
    ok.request_body_content(&mut out, b"def");
    ok.end_request_body(&mut out);
    ok.request_complete(&mut out);
    {
        let s = seen.lock().unwrap();
        assert_eq!((s.started, s.ended, s.completed), (1, 1, 1));
        assert_eq!(s.body, b"abcdef");
    }

    let (mut bad, seen) = basic_factory();
    let mut out = Out::default();
    bad.headers(&mut out, &request("PUT", "/", None));
    bad.start_request_body(&mut out);
    bad.request_body_content(&mut out, b"abc");
    bad.end_request_body(&mut out);
    bad.request_complete(&mut out);
    let s = seen.lock().unwrap();
    assert_eq!((s.started, s.ended, s.completed), (0, 0, 0));
    assert!(s.body.is_empty());
}

#[test]
fn a_request_that_completes_without_headers_is_challenged() {
    let (mut h, _) = basic_factory();
    let mut out = Out::default();
    h.request_complete(&mut out);
    assert_eq!(out.status(), Some(401));
}

// -- Digest ------------------------------------------------------------------

fn digest_factory(ttl: Option<Duration>) -> (DigestAuthFactory, SharedSeen) {
    let seen = SharedSeen::default();
    let store: Arc<dyn CredentialStore> =
        Arc::new(PasswordStore::new().with_digest_realm("files").with_user("alice", "s3cret"));
    let mut config = DigestAuthConfig::new("files");
    if let Some(t) = ttl {
        config = config.with_nonce_ttl(t);
    }
    (DigestAuthFactory::new(Arc::new(InnerFactory(Arc::clone(&seen))), store, config), seen)
}

/// Ask for a challenge and return its nonce.
fn issue_nonce(f: &DigestAuthFactory) -> String {
    let mut h = f.create_handler();
    let mut out = Out::default();
    h.headers(&mut out, &request("GET", "/", None));
    assert_eq!(out.status(), Some(401));
    let c = out.challenge();
    assert!(c.starts_with("Digest "), "{c}");
    assert!(c.contains("realm=\"files\"") && c.contains("qop=\"auth\""), "{c}");
    c.split("nonce=\"").nth(1).unwrap().split('"').next().unwrap().to_string()
}

fn digest_status(f: &DigestAuthFactory, method: &str, path: &str, creds: &str) -> Option<u16> {
    let mut h = f.create_handler();
    let mut out = Out::default();
    h.headers(&mut out, &request(method, path, Some(&format!("Digest {creds}"))));
    out.status()
}

#[test]
fn digest_challenges_carry_fresh_nonces() {
    let (f, _) = digest_factory(None);
    let (a, b) = (issue_nonce(&f), issue_nonce(&f));
    assert_ne!(a, b);
    assert_eq!(a.len(), 32);
}

#[test]
fn digest_accepts_a_correct_response_once_and_names_the_user() {
    let (f, seen) = digest_factory(None);
    let nonce = issue_nonce(&f);
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &nonce, "GET", "/doc");
    assert_eq!(digest_status(&f, "GET", "/doc", &creds), None);
    assert_eq!(seen.lock().unwrap().headers[0].get(AUTHENTICATED_USER), Some("alice"));
    assert_eq!(digest_status(&f, "GET", "/doc", &creds), Some(401), "a replay");
}

#[test]
fn digest_rejects_a_wrong_password_an_unknown_user_and_a_wrong_method() {
    let (f, seen) = digest_factory(None);
    for (user, pass, method) in [("alice", "wrong", "GET"), ("mallory", "s3cret", "GET"), ("alice", "s3cret", "POST")] {
        let nonce = issue_nonce(&f);
        let creds = build_digest_authorization(DigestAlgorithm::Sha256, user, pass, "files", &nonce, "GET", "/");
        assert_eq!(digest_status(&f, method, "/", &creds), Some(401), "{user}/{pass}/{method}");
    }
    assert!(seen.lock().unwrap().headers.is_empty());
}

#[test]
fn a_failed_attempt_uses_up_the_nonce() {
    let (f, _) = digest_factory(None);
    let nonce = issue_nonce(&f);
    let bad = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "wrong", "files", &nonce, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &bad), Some(401));
    let good = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &nonce, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &good), Some(401), "the client must ask again");
}

#[test]
fn digest_rejects_credentials_for_another_uri_than_the_request() {
    // RFC 7616 section 3.4: the uri in the credentials must be the request target.
    let (f, seen) = digest_factory(None);
    let nonce = issue_nonce(&f);
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &nonce, "GET", "/public");
    assert_eq!(digest_status(&f, "GET", "/private", &creds), Some(401));
    assert!(seen.lock().unwrap().headers.is_empty());
}

#[test]
fn digest_scheme_name_is_not_case_sensitive() {
    let (f, _) = digest_factory(None);
    let nonce = issue_nonce(&f);
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &nonce, "GET", "/");
    let mut h = f.create_handler();
    let mut out = Out::default();
    h.headers(&mut out, &request("GET", "/", Some(&format!("DIGEST {creds}"))));
    assert_eq!(out.status(), None);
}

#[test]
fn digest_with_missing_pieces_is_challenged() {
    let (f, _) = digest_factory(None);
    let nonce = issue_nonce(&f);
    for creds in [
        "".to_string(),
        "username=\"alice\"".to_string(),
        format!("nonce=\"{nonce}\""),
        format!("username=\"alice\", nonce=\"{nonce}\""),
    ] {
        assert_eq!(digest_status(&f, "GET", "/", &creds), Some(401), "{creds}");
    }
    let mut h = f.create_handler();
    let mut out = Out::default();
    h.headers(&mut out, &request("GET", "/", Some("Basic YWxpY2U6czNjcmV0")));
    assert_eq!(out.status(), Some(401), "another scheme");
}

#[test]
fn digest_nonces_expire() {
    let (f, _) = digest_factory(Some(Duration::from_millis(20)));
    let nonce = issue_nonce(&f);
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &nonce, "GET", "/");
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(digest_status(&f, "GET", "/", &creds), Some(401));
}

#[test]
fn the_number_of_outstanding_nonces_is_bounded() {
    // Every unauthenticated request mints a nonce; a flood must not grow the
    // table (and the per-request pruning scan) without limit.
    let (f, _) = digest_factory(None);
    for _ in 0..(MAX_OUTSTANDING_NONCES + 500) {
        issue_nonce(&f);
    }
    assert!(f.nonces.lock().unwrap().len() <= MAX_OUTSTANDING_NONCES);
}

#[test]
fn the_oldest_nonce_is_the_one_dropped_when_the_table_is_full() {
    let (f, _) = digest_factory(None);
    let first = issue_nonce(&f);
    for _ in 0..MAX_OUTSTANDING_NONCES {
        issue_nonce(&f);
    }
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &first, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &creds), Some(401), "evicted");
    let recent = issue_nonce(&f);
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &recent, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &creds), None, "a recent nonce still works");
}

#[test]
fn a_client_supplied_user_header_never_survives_digest_auth() {
    let (f, seen) = digest_factory(None);
    let nonce = issue_nonce(&f);
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &nonce, "GET", "/");
    let mut req = request("GET", "/", Some(&format!("Digest {creds}")));
    req.add(AUTHENTICATED_USER, "root");
    let mut h = f.create_handler();
    h.headers(&mut Out::default(), &req);
    let seen = seen.lock().unwrap();
    let n = seen.headers[0].iter().filter(|f| f.name.eq_ignore_ascii_case(AUTHENTICATED_USER)).count();
    assert_eq!((n, seen.headers[0].get(AUTHENTICATED_USER)), (1, Some("alice")));
}

// -- Bearer ------------------------------------------------------------------

fn bearer_factory(realm: Option<&str>) -> (Box<dyn ServerHandler>, SharedSeen) {
    let seen = SharedSeen::default();
    let policy: Arc<dyn TrustPolicy> = Arc::new(PasswordStore::new().with_token("tok-1", "alice"));
    let mut f = BearerAuthFactory::new(Arc::new(InnerFactory(Arc::clone(&seen))), policy);
    if let Some(r) = realm {
        f = f.with_realm(r);
    }
    (f.create_handler(), seen)
}

#[test]
fn a_known_bearer_token_reaches_the_application() {
    for scheme in ["Bearer", "bearer", "BEARER"] {
        let (mut h, seen) = bearer_factory(None);
        let mut out = Out::default();
        h.headers(&mut out, &request("GET", "/", Some(&format!("{scheme} tok-1"))));
        assert!(out.sent.is_empty(), "{scheme}");
        assert_eq!(seen.lock().unwrap().headers.len(), 1, "{scheme}");
    }
}

#[test]
fn bearer_rejects_unknown_tokens_other_schemes_and_nothing() {
    for value in [Some("Bearer nope"), Some("Bearer"), Some("Bearer "), Some("Basic dG9rLTE6eA=="), Some("tok-1"), None] {
        let (mut h, seen) = bearer_factory(None);
        let mut out = Out::default();
        h.headers(&mut out, &request("GET", "/", value));
        assert_eq!(out.status(), Some(401), "{value:?}");
        assert!(seen.lock().unwrap().headers.is_empty());
    }
}

#[test]
fn the_bearer_challenge_names_the_realm_when_there_is_one() {
    let (mut h, _) = bearer_factory(Some("api"));
    let mut out = Out::default();
    h.headers(&mut out, &request("GET", "/", None));
    assert_eq!(out.challenge(), "Bearer realm=\"api\"");
    let (mut h, _) = bearer_factory(None);
    let mut out = Out::default();
    h.headers(&mut out, &request("GET", "/", None));
    assert_eq!(out.challenge(), "Bearer");
}

#[test]
fn a_client_supplied_user_header_never_survives_bearer_auth() {
    // WebDAV trusts this header for its ACL checks: a valid token must not
    // let the client choose who it is.
    let (mut h, seen) = bearer_factory(None);
    let mut req = request("GET", "/", Some("Bearer tok-1"));
    req.add(AUTHENTICATED_USER, "root");
    h.headers(&mut Out::default(), &req);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.headers[0].get(AUTHENTICATED_USER), None, "{:?}", seen.headers[0]);
}

#[test]
fn bearer_forwards_the_body_only_when_authorized() {
    let (mut h, seen) = bearer_factory(None);
    let mut out = Out::default();
    h.headers(&mut out, &request("PUT", "/", Some("Bearer tok-1")));
    h.start_request_body(&mut out);
    h.request_body_content(&mut out, b"xyz");
    h.end_request_body(&mut out);
    h.request_complete(&mut out);
    let s = seen.lock().unwrap();
    assert_eq!((s.started, s.ended, s.completed, s.body.as_slice()), (1, 1, 1, &b"xyz"[..]));
    drop(s);

    let (mut h, seen) = bearer_factory(None);
    let mut out = Out::default();
    h.headers(&mut out, &request("PUT", "/", None));
    h.request_body_content(&mut out, b"xyz");
    h.request_complete(&mut out);
    assert!(seen.lock().unwrap().body.is_empty());
    assert_eq!(out.sent.len(), 1, "challenged once");
}

// -- Digest algorithms --------------------------------------------------------

fn md5_factory(allow_md5: bool) -> DigestAuthFactory {
    let seen = SharedSeen::default();
    let store: Arc<dyn CredentialStore> =
        Arc::new(PasswordStore::new().with_digest_realm("files").with_md5_digest().with_user("alice", "s3cret"));
    DigestAuthFactory::new(
        Arc::new(InnerFactory(seen)),
        store,
        DigestAuthConfig::new("files").with_md5(allow_md5),
    )
}

/// Every Digest challenge a fresh request is given: `(algorithm, nonce)`.
fn challenges(f: &DigestAuthFactory) -> Vec<(String, String)> {
    let mut h = f.create_handler();
    let mut out = Out::default();
    h.headers(&mut out, &request("GET", "/", None));
    assert_eq!(out.status(), Some(401));
    out.sent[0]
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("www-authenticate"))
        .map(|field| {
            let c = hopf_auth::http_digest::parse_challenge(&field.value).expect("a digest challenge");
            (c.algorithm.name().to_string(), c.nonce)
        })
        .collect()
}

#[test]
fn digest_challenges_for_sha256_alone_by_default() {
    let f = md5_factory(false);
    let c = challenges(&f);
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(c[0].0, "SHA-256");
}

#[test]
fn digest_with_md5_allowed_offers_sha256_first_then_md5() {
    let f = md5_factory(true);
    let c = challenges(&f);
    assert_eq!(c.iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>(), ["SHA-256", "MD5"]);
    assert_ne!(c[0].1, c[1].1, "each challenge has its own nonce");
}

#[test]
fn digest_md5_credentials_are_refused_unless_md5_is_allowed() {
    // The store holds an MD5 HA1 and the credentials are correct: still no.
    let f = md5_factory(false);
    let nonce = issue_nonce(&f);
    let creds = build_digest_authorization(DigestAlgorithm::Md5, "alice", "s3cret", "files", &nonce, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &creds), Some(401));
}

#[test]
fn digest_md5_credentials_work_when_md5_is_allowed() {
    let f = md5_factory(true);
    let c = challenges(&f);
    let md5_nonce = &c.iter().find(|(a, _)| a == "MD5").unwrap().1;
    let creds = build_digest_authorization(DigestAlgorithm::Md5, "alice", "s3cret", "files", md5_nonce, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &creds), None);
    let sha_nonce = &c.iter().find(|(a, _)| a == "SHA-256").unwrap().1;
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", sha_nonce, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &creds), None, "and SHA-256 still does");
}

#[test]
fn a_sha256_nonce_cannot_be_traded_down_to_md5() {
    let f = md5_factory(true);
    let c = challenges(&f);
    let sha_nonce = &c.iter().find(|(a, _)| a == "SHA-256").unwrap().1;
    let creds = build_digest_authorization(DigestAlgorithm::Md5, "alice", "s3cret", "files", sha_nonce, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &creds), Some(401));
}

#[test]
fn credentials_without_an_algorithm_count_as_md5() {
    // RFC 7616 section 3.3: an absent algorithm is MD5, so by default refused.
    let f = md5_factory(false);
    let nonce = issue_nonce(&f);
    let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &nonce, "GET", "/")
        .replace("algorithm=SHA-256, ", "");
    assert!(!creds.contains("algorithm"));
    assert_eq!(digest_status(&f, "GET", "/", &creds), Some(401));
}

#[test]
fn unknown_and_session_algorithms_are_refused() {
    let f = md5_factory(true);
    for alg in ["SHA-512-256", "SHA-256-sess", "MD5-sess", "bogus"] {
        let nonce = issue_nonce(&f);
        let creds = build_digest_authorization(DigestAlgorithm::Sha256, "alice", "s3cret", "files", &nonce, "GET", "/")
            .replace("algorithm=SHA-256", &format!("algorithm={alg}"));
        assert_eq!(digest_status(&f, "GET", "/", &creds), Some(401), "{alg}");
    }
}

#[test]
fn a_store_without_the_algorithms_ha1_fails_the_login() {
    // SHA-256 only in the store; MD5 allowed by the server: MD5 logins fail.
    let seen = SharedSeen::default();
    let store: Arc<dyn CredentialStore> =
        Arc::new(PasswordStore::new().with_digest_realm("files").with_user("alice", "s3cret"));
    let f = DigestAuthFactory::new(Arc::new(InnerFactory(seen)), store, DigestAuthConfig::new("files").with_md5(true));
    let c = challenges(&f);
    let md5_nonce = &c.iter().find(|(a, _)| a == "MD5").unwrap().1;
    let creds = build_digest_authorization(DigestAlgorithm::Md5, "alice", "s3cret", "files", md5_nonce, "GET", "/");
    assert_eq!(digest_status(&f, "GET", "/", &creds), Some(401));
}
