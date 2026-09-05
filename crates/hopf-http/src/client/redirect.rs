// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP redirect (3xx) following for [`HttpClient::fetch`] (issue #349).
//!
//! Off by default: [`HttpClient::follow_redirects`] must be called
//! explicitly, or a 3xx response reaches the caller's
//! [`HttpResponseHandler`] unchanged, exactly like any other response —
//! `fetch` doesn't even construct the machinery in this module unless a
//! [`RedirectPolicy`] is configured.
//!
//! This is deliberately not built on [`hopf_core::retry`]'s
//! `RetryPolicy`/`Retryable`: a redirect is a *different* request issued
//! immediately on a *successful* 3xx response, not a delayed replay of the
//! same request after a failure — the two share nothing mechanically
//! beyond both needing some bound on how many times to keep going.

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::Runtime;

use crate::headers::Headers;

use super::api::{HttpClientSessionHandle, HttpConnectionHandler, HttpResponseHandler};
use super::facade::HttpClient;

/// Bounds how many redirects [`HttpClient::fetch`] follows before giving
/// up with a "too many redirects" [`HttpResponseHandler::failed`]. Not set
/// by default — see [`HttpClient::follow_redirects`].
#[derive(Debug, Clone)]
pub struct RedirectPolicy {
    max_redirects: u32,
}

impl RedirectPolicy {
    /// `max_redirects` is the standard mitigation for a redirect loop —
    /// real HTTP clients don't track visited URLs, they just cap the hop
    /// count and fail past it, so a genuine A→B→A loop is caught once it
    /// exceeds this, the same as an accidental long chain.
    pub fn new(max_redirects: u32) -> Self {
        Self {
            max_redirects: max_redirects.max(1),
        }
    }

    /// The configured hop cap.
    pub fn max_redirects(&self) -> u32 {
        self.max_redirects
    }
}

impl Default for RedirectPolicy {
    /// 20 hops — matches common HTTP client library defaults.
    fn default() -> Self {
        Self::new(20)
    }
}

/// Where a request goes: scheme + authority + path (with any query string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedirectTarget {
    pub(crate) secure: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
}

impl RedirectTarget {
    fn same_origin(&self, other: &Self) -> bool {
        self.secure == other.secure
            && self.host.eq_ignore_ascii_case(&other.host)
            && self.port == other.port
    }
}

/// Resolve a `Location` header value against the request that received it.
///
/// Supports an absolute `http`/`https` URL, a protocol-relative
/// `//host[:port]/path`, or an absolute path (`/foo`). Does not support
/// RFC 3986 relative-reference resolution against the current path (a
/// bare `sibling`, a `../parent`, or a query-only `?x=y` reference) — a
/// server issuing one of those is treated as unresolvable, since none of
/// hopf-http's client code otherwise needs a general URI resolver.
pub(crate) fn resolve_location(current: &RedirectTarget, location: &str) -> Option<RedirectTarget> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    if let Some(rest) = location.strip_prefix("http://") {
        return parse_authority_and_path(false, rest);
    }
    if let Some(rest) = location.strip_prefix("https://") {
        return parse_authority_and_path(true, rest);
    }
    if let Some(rest) = location.strip_prefix("//") {
        return parse_authority_and_path(current.secure, rest);
    }
    if location.starts_with('/') {
        return Some(RedirectTarget {
            secure: current.secure,
            host: current.host.clone(),
            port: current.port,
            path: location.to_string(),
        });
    }
    None
}

fn parse_authority_and_path(secure: bool, rest: &str) -> Option<RedirectTarget> {
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (h.to_string(), p.parse::<u16>().ok()?),
        _ => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    Some(RedirectTarget {
        secure,
        host,
        port,
        path,
    })
}

/// RFC 9110 §15.4 request-rewrite rules for following a redirect: the
/// method/body the *next* request uses, given the status that redirected
/// it and the *current* method/body.
///
/// - 303: always downgrade to GET, drop the body, regardless of method.
/// - 301/302: downgrade POST to GET (dropping the body) for historical
///   compatibility; every other method (including GET/HEAD/PUT/DELETE) is
///   preserved.
/// - 307/308: always preserve the original method and body exactly.
pub(crate) fn next_method_and_body(
    status: u16,
    method: &str,
    body: Option<Vec<u8>>,
) -> (String, Option<Vec<u8>>) {
    match status {
        303 => ("GET".to_string(), None),
        301 | 302 if method.eq_ignore_ascii_case("POST") => ("GET".to_string(), None),
        _ => (method.to_string(), body),
    }
}

/// Strip credentials that must not follow a cross-origin redirect.
fn strip_cross_origin_headers(headers: &mut Headers) {
    headers.remove("authorization");
    headers.remove("cookie");
    headers.remove("proxy-authorization");
}

/// The 3xx statuses this module treats as followable redirects. Any other
/// status (including other 3xx like 304 Not Modified) is delivered to the
/// caller as an ordinary response.
fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Shared state for one [`HttpClient::fetch`] call, threaded across every
/// hop's own connection/handler pair.
pub(crate) struct FetchState {
    rt: Arc<Runtime>,
    dial_template: HttpClient,
    policy: RedirectPolicy,
    hops_used: u32,
    /// The caller's original handler — taken exactly once, to deliver the
    /// single terminal callback ([`HttpResponseHandler::close`] for the
    /// final response, or [`HttpResponseHandler::failed`] for a
    /// redirect-following error). `None` after that fires.
    handler: Option<Box<dyn HttpResponseHandler>>,
}

impl FetchState {
    pub(crate) fn new(
        rt: Arc<Runtime>,
        dial_template: HttpClient,
        policy: RedirectPolicy,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Self {
        Self {
            rt,
            dial_template,
            policy,
            hops_used: 0,
            handler: Some(handler),
        }
    }

    fn with_handler(state: &Arc<Mutex<Self>>, f: impl FnOnce(&mut dyn HttpResponseHandler)) {
        let mut guard = state.lock().unwrap();
        if let Some(h) = guard.handler.as_deref_mut() {
            f(h);
        }
    }

    fn take_handler_and(state: &Arc<Mutex<Self>>, f: impl FnOnce(Box<dyn HttpResponseHandler>)) {
        let taken = state.lock().unwrap().handler.take();
        if let Some(h) = taken {
            f(h);
        }
    }

    fn deliver_failed(state: &Arc<Mutex<Self>>, err: io::Error) {
        Self::take_handler_and(state, |mut h| h.failed(err));
    }

    /// Dial the next hop. On a synchronous dial-setup failure (bad host,
    /// TLS required but unavailable, ...) delivers the terminal failure
    /// itself rather than returning an error nobody would see.
    pub(crate) fn dial_hop(
        state: Arc<Mutex<Self>>,
        target: RedirectTarget,
        method: String,
        headers: Headers,
        body: Option<Vec<u8>>,
    ) {
        let client = {
            let guard = state.lock().unwrap();
            if target.secure && guard.dial_template.tls_connector().is_none() {
                drop(guard);
                Self::deliver_failed(
                    &state,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "redirect to https://{}{} requires a TLS connector, none configured",
                            target.host, target.path
                        ),
                    ),
                );
                return;
            }
            guard.dial_template.for_redirect_target(&target)
        };
        let rt = { Arc::clone(&state.lock().unwrap().rt) };
        let handler = Box::new(HopConnectionHandler {
            state,
            target,
            method,
            headers,
            body,
        });
        if let Err(e) = client.connect(&rt, handler) {
            // `connect` already reported this to the handler's `on_error`
            // via its own `inspect_err` — nothing further to do here.
            let _ = e;
        }
    }
}

/// [`HttpConnectionHandler`] for one hop's dial — issues exactly one
/// request once connected, then hands the response to [`HopResponseIntercept`].
struct HopConnectionHandler {
    state: Arc<Mutex<FetchState>>,
    target: RedirectTarget,
    method: String,
    headers: Headers,
    body: Option<Vec<u8>>,
}

impl HttpConnectionHandler for HopConnectionHandler {
    fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
        let mut req = session.method(&self.method, &self.target.path);
        for h in self.headers.iter() {
            let _ = req.header(&h.name, &h.value);
        }
        let intercept = Box::new(HopResponseIntercept {
            state: Arc::clone(&self.state),
            target: self.target.clone(),
            method: self.method.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
            is_redirect_candidate: false,
            status: 0,
            location: None,
        });
        match self.body.take() {
            None => {
                let _ = req.send(intercept);
            }
            Some(body) => {
                if req.start_request_body(intercept).is_ok() {
                    let _ = req.request_body_content(&body);
                    let _ = req.end_request_body();
                }
            }
        }
    }

    fn on_error(&mut self, err: &io::Error) {
        FetchState::deliver_failed(
            &self.state,
            io::Error::new(err.kind(), err.to_string()),
        );
    }
}

/// [`HttpResponseHandler`] wrapping one hop's response: forwards it to the
/// caller's original handler unchanged if it isn't a followable redirect;
/// otherwise buffers just the `Location` header, discards the (unneeded)
/// redirect response body, and dials the next hop from [`Self::close`].
struct HopResponseIntercept {
    state: Arc<Mutex<FetchState>>,
    target: RedirectTarget,
    method: String,
    headers: Headers,
    body: Option<Vec<u8>>,
    is_redirect_candidate: bool,
    status: u16,
    location: Option<String>,
}

impl HttpResponseHandler for HopResponseIntercept {
    fn ok(&mut self, status: u16) {
        // Only ever called for 2xx (see `HttpResponseHandler::ok`'s own
        // doc) — never a redirect candidate.
        self.status = status;
        self.is_redirect_candidate = false;
        FetchState::with_handler(&self.state, |h| h.ok(status));
    }

    fn error(&mut self, status: u16) {
        // Called for every non-2xx status, 3xx included — this is where a
        // redirect status actually arrives, not `ok`.
        self.status = status;
        self.is_redirect_candidate = is_redirect_status(status);
        if !self.is_redirect_candidate {
            FetchState::with_handler(&self.state, |h| h.error(status));
        }
    }

    fn header(&mut self, name: &str, value: &str) {
        if self.is_redirect_candidate {
            if name.eq_ignore_ascii_case("location") {
                self.location = Some(value.to_string());
            }
            return;
        }
        FetchState::with_handler(&self.state, |h| h.header(name, value));
    }

    fn start_response_body(&mut self) {
        if self.is_redirect_candidate {
            return;
        }
        FetchState::with_handler(&self.state, |h| h.start_response_body());
    }

    fn response_body_content(&mut self, data: &[u8]) {
        if self.is_redirect_candidate {
            return;
        }
        FetchState::with_handler(&self.state, |h| h.response_body_content(data));
    }

    fn end_response_body(&mut self) {
        if self.is_redirect_candidate {
            return;
        }
        FetchState::with_handler(&self.state, |h| h.end_response_body());
    }

    fn response_trailers(&mut self, headers: &Headers) {
        if self.is_redirect_candidate {
            return;
        }
        FetchState::with_handler(&self.state, |h| h.response_trailers(headers));
    }

    fn close(&mut self) {
        if !self.is_redirect_candidate {
            FetchState::take_handler_and(&self.state, |mut h| h.close());
            return;
        }
        let Some(location) = self.location.take() else {
            FetchState::deliver_failed(
                &self.state,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} redirect with no Location header", self.status),
                ),
            );
            return;
        };
        let Some(next_target) = resolve_location(&self.target, &location) else {
            FetchState::deliver_failed(
                &self.state,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("could not resolve redirect Location: {location}"),
                ),
            );
            return;
        };
        let (allowed, max) = {
            let mut st = self.state.lock().unwrap();
            st.hops_used += 1;
            (st.hops_used <= st.policy.max_redirects(), st.policy.max_redirects())
        };
        if !allowed {
            FetchState::deliver_failed(
                &self.state,
                io::Error::other(format!("too many redirects (max {max})")),
            );
            return;
        }
        let (next_method, next_body) =
            next_method_and_body(self.status, &self.method, self.body.take());
        let mut next_headers = self.headers.clone();
        if !next_target.same_origin(&self.target) {
            strip_cross_origin_headers(&mut next_headers);
        }
        FetchState::dial_hop(
            Arc::clone(&self.state),
            next_target,
            next_method,
            next_headers,
            next_body,
        );
    }

    fn failed(&mut self, err: io::Error) {
        FetchState::deliver_failed(&self.state, err);
    }
}

/// [`HttpConnectionHandler`] for [`HttpClient::fetch`] when no
/// [`RedirectPolicy`] is configured — issues one request and hands the
/// caller's handler straight to it, with no interception at all.
pub(crate) struct PlainFetchConnectionHandler {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: Headers,
    pub(crate) body: Option<Vec<u8>>,
    /// `Mutex`-wrapped only so this struct satisfies
    /// [`HttpConnectionHandler`]'s `Sync` bound — `Box<dyn
    /// HttpResponseHandler>` itself is `Send` but not `Sync`. Only ever
    /// touched from `&mut self` methods below, never concurrently.
    pub(crate) handler: Mutex<Option<Box<dyn HttpResponseHandler>>>,
}

impl HttpConnectionHandler for PlainFetchConnectionHandler {
    fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
        let Some(handler) = self.handler.get_mut().unwrap().take() else {
            return;
        };
        let mut req = session.method(&self.method, &self.path);
        for h in self.headers.iter() {
            let _ = req.header(&h.name, &h.value);
        }
        match self.body.take() {
            None => {
                let _ = req.send(handler);
            }
            Some(body) => {
                if req.start_request_body(handler).is_ok() {
                    let _ = req.request_body_content(&body);
                    let _ = req.end_request_body();
                }
            }
        }
    }

    fn on_error(&mut self, err: &io::Error) {
        if let Some(mut h) = self.handler.get_mut().unwrap().take() {
            h.failed(io::Error::new(err.kind(), err.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(secure: bool, host: &str, port: u16, path: &str) -> RedirectTarget {
        RedirectTarget {
            secure,
            host: host.to_string(),
            port,
            path: path.to_string(),
        }
    }

    #[test]
    fn absolute_path_stays_on_the_same_origin() {
        let current = target(true, "example.com", 443, "/old");
        let resolved = resolve_location(&current, "/new/place").unwrap();
        assert_eq!(resolved, target(true, "example.com", 443, "/new/place"));
    }

    #[test]
    fn absolute_https_url_switches_origin_entirely() {
        let current = target(false, "example.com", 80, "/old");
        let resolved = resolve_location(&current, "https://other.example:8443/new").unwrap();
        assert_eq!(resolved, target(true, "other.example", 8443, "/new"));
    }

    #[test]
    fn absolute_http_url_without_explicit_port_defaults_to_80() {
        let current = target(true, "example.com", 443, "/old");
        let resolved = resolve_location(&current, "http://plain.example/new").unwrap();
        assert_eq!(resolved, target(false, "plain.example", 80, "/new"));
    }

    #[test]
    fn absolute_https_url_without_explicit_port_defaults_to_443() {
        let current = target(false, "example.com", 80, "/old");
        let resolved = resolve_location(&current, "https://secure.example/new").unwrap();
        assert_eq!(resolved, target(true, "secure.example", 443, "/new"));
    }

    #[test]
    fn absolute_url_without_path_resolves_to_root() {
        let current = target(true, "example.com", 443, "/old");
        let resolved = resolve_location(&current, "https://other.example").unwrap();
        assert_eq!(resolved, target(true, "other.example", 443, "/"));
    }

    #[test]
    fn protocol_relative_reference_keeps_the_current_scheme() {
        let current = target(true, "example.com", 443, "/old");
        let resolved = resolve_location(&current, "//other.example/new").unwrap();
        assert_eq!(resolved, target(true, "other.example", 443, "/new"));
    }

    #[test]
    fn relative_reference_is_not_resolved() {
        let current = target(true, "example.com", 443, "/a/b");
        assert!(resolve_location(&current, "sibling").is_none());
        assert!(resolve_location(&current, "../parent").is_none());
        assert!(resolve_location(&current, "?query=only").is_none());
        assert!(resolve_location(&current, "").is_none());
    }

    #[test]
    fn method_and_body_rules_match_rfc_9110_15_4() {
        let body = || Some(b"payload".to_vec());

        // 303: always downgrade to GET, drop body.
        assert_eq!(
            next_method_and_body(303, "POST", body()),
            ("GET".to_string(), None)
        );
        assert_eq!(
            next_method_and_body(303, "PUT", body()),
            ("GET".to_string(), None)
        );

        // 301/302: only POST downgrades; everything else preserved.
        assert_eq!(
            next_method_and_body(301, "POST", body()),
            ("GET".to_string(), None)
        );
        assert_eq!(
            next_method_and_body(302, "POST", body()),
            ("GET".to_string(), None)
        );
        assert_eq!(
            next_method_and_body(301, "GET", None),
            ("GET".to_string(), None)
        );
        assert_eq!(
            next_method_and_body(302, "PUT", body()),
            ("PUT".to_string(), body())
        );

        // 307/308: always preserved exactly, including the body.
        assert_eq!(
            next_method_and_body(307, "POST", body()),
            ("POST".to_string(), body())
        );
        assert_eq!(
            next_method_and_body(308, "DELETE", None),
            ("DELETE".to_string(), None)
        );
    }

    #[test]
    fn same_origin_check_is_case_insensitive_on_host() {
        let a = target(true, "Example.com", 443, "/a");
        let b = target(true, "example.COM", 443, "/b");
        assert!(a.same_origin(&b));
        let c = target(true, "example.com", 8443, "/b");
        assert!(!a.same_origin(&c));
        let d = target(false, "example.com", 443, "/b");
        assert!(!a.same_origin(&d));
    }
}
