// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SPF — Sender Policy Framework (RFC 7208).
//!
//! [`check_host`] implements the `check_host()` algorithm of RFC 7208 §4
//! against the [`crate::auth::DnsLookup`] seam, fully asynchronously (DNS
//! answers arrive via callback, so evaluation is written continuation-passing
//! style rather than as a blocking recursive function).
//!
//! Known, deliberate limitation: the `%{p}` ("validated domain name") macro
//! always expands to `"unknown"` rather than performing the PTR-then-forward-
//! confirm lookup RFC 7208 §7.3 describes — the RFC itself says publishers
//! "SHOULD NOT" use it and resolvers merely "SHOULD" support it, precisely
//! because it is unreliable and expensive. The `ptr` *mechanism* (§5.5, which
//! records themselves use far more often) is fully implemented.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::dns_lookup::{DnsLookup, Lookup};
use super::macros::{self, MacroContext};

/// RFC 7208 §2.6 result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    /// Client is authorized to use the domain.
    Pass,
    /// Client is explicitly not authorized.
    Fail,
    /// Weak statement that the client is probably not authorized.
    SoftFail,
    /// Explicitly no assertion made.
    Neutral,
    /// Domain has no SPF policy.
    None,
    /// Transient error (DNS timeout/SERVFAIL); retry later.
    TempError,
    /// Permanent error (malformed record or syntax).
    PermError,
}

impl SpfResult {
    /// `Authentication-Results`-style lowercase token.
    pub fn as_str(&self) -> &'static str {
        match self {
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::Neutral => "neutral",
            SpfResult::None => "none",
            SpfResult::TempError => "temperror",
            SpfResult::PermError => "permerror",
        }
    }
}

/// Outcome of an SPF check: result plus an optional human-readable
/// explanation (from the matching record's `exp=` modifier, RFC 7208 §6.2 —
/// only ever populated for [`SpfResult::Fail`]).
#[derive(Debug, Clone)]
pub struct SpfOutcome {
    /// The result.
    pub result: SpfResult,
    /// Explanation text, if the record published one and the result is `Fail`.
    pub explanation: Option<String>,
}

/// Callback receiving the final [`SpfOutcome`].
pub type SpfCallback = Box<dyn FnOnce(SpfOutcome) + Send>;

const MAX_LOOKUPS: usize = 10;
const MAX_VOID_LOOKUPS: usize = 2;
const MAX_REDIRECT_DEPTH: usize = 10;
const MAX_MX_HOSTS: usize = 10;
const MAX_PTR_HOSTS: usize = 10;

/// Run RFC 7208 `check_host()`.
///
/// * `ip` — SMTP client address.
/// * `domain` — domain whose SPF record starts evaluation (the `MAIL FROM`
///   domain, or the `HELO`/`EHLO` domain when the reverse-path is null).
/// * `sender` — the full `MAIL FROM` address used for `%{s}`/`%{l}`/`%{o}`
///   (synthesize `postmaster@<helo>` for a null reverse-path per RFC 7208 §4.3).
/// * `helo_domain` — `%{h}`.
/// * `receiver` — this server's hostname, for `%{r}` in `exp=` text only.
pub fn check_host(
    dns: Arc<dyn DnsLookup>,
    ip: IpAddr,
    domain: &str,
    sender: &str,
    helo_domain: &str,
    receiver: &str,
    cb: SpfCallback,
) {
    let (local_part, sender_domain) = split_sender(sender);
    let frame = Box::new(Frame {
        dns,
        ip,
        sender: sender.to_string(),
        local_part,
        sender_domain,
        helo_domain: helo_domain.to_string(),
        receiver: receiver.to_string(),
        lookups: 0,
        void_lookups: 0,
    });
    evaluate_record(
        frame,
        domain.to_string(),
        0,
        Box::new(move |_frame, result, exp_domain| {
            finish(result, exp_domain, cb);
        }),
    );
}

fn finish(
    result: SpfResult,
    exp_domain: Option<(Arc<dyn DnsLookup>, String, MacroContext)>,
    cb: SpfCallback,
) {
    if result != SpfResult::Fail {
        cb(SpfOutcome {
            result,
            explanation: None,
        });
        return;
    }
    match exp_domain {
        None => cb(SpfOutcome {
            result,
            explanation: None,
        }),
        Some((dns, domain, ctx)) => {
            dns.query_txt(
                &domain,
                Box::new(move |lookup| {
                    let explanation = match lookup {
                        Lookup::Answers(txts) => txts
                            .into_iter()
                            .next()
                            .and_then(|t| macros::expand(&t, &ctx).ok()),
                        _ => None,
                    };
                    cb(SpfOutcome {
                        result,
                        explanation,
                    });
                }),
            );
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn split_sender(sender: &str) -> (String, String) {
    match sender.rsplit_once('@') {
        Some((l, d)) => (l.to_string(), d.to_string()),
        None => (sender.to_string(), String::new()),
    }
}

struct Frame {
    dns: Arc<dyn DnsLookup>,
    ip: IpAddr,
    sender: String,
    local_part: String,
    sender_domain: String,
    helo_domain: String,
    receiver: String,
    lookups: usize,
    void_lookups: usize,
}

impl Frame {
    fn ctx(&self, current_domain: &str) -> MacroContext {
        MacroContext {
            sender: self.sender.clone(),
            local_part: self.local_part.clone(),
            sender_domain: self.sender_domain.clone(),
            domain: current_domain.to_string(),
            ip: Some(self.ip),
            validated_domain: None,
            helo_domain: self.helo_domain.clone(),
            receiver: self.receiver.clone(),
            timestamp: now_unix(),
        }
    }

    /// Charge one of the 10 lookups budgeted by RFC 7208 §4.6.4. Returns
    /// `false` (and the caller should PermError) if the budget is exhausted.
    fn charge_lookup(&mut self) -> bool {
        self.lookups += 1;
        self.lookups <= MAX_LOOKUPS
    }

    fn charge_void(&mut self) -> bool {
        self.void_lookups += 1;
        self.void_lookups <= MAX_VOID_LOOKUPS
    }
}

type ExpDomain = Option<(Arc<dyn DnsLookup>, String, MacroContext)>;
type RecordCb = Box<dyn FnOnce(Box<Frame>, SpfResult, ExpDomain) + Send>;

fn is_spf_record(txt: &str) -> bool {
    let t = txt.trim_start();
    t.len() >= 6
        && t[..6].eq_ignore_ascii_case("v=spf1")
        && (t.len() == 6 || t.as_bytes()[6] == b' ' || t.as_bytes()[6] == b'\t')
}

fn evaluate_record(frame: Box<Frame>, domain: String, depth: usize, cb: RecordCb) {
    if depth > MAX_REDIRECT_DEPTH {
        cb(frame, SpfResult::PermError, None);
        return;
    }
    let dns = Arc::clone(&frame.dns);
    let mut frame = frame;
    let query_domain = domain.clone();
    dns.query_txt(
        &query_domain,
        Box::new(move |lookup| match lookup {
            Lookup::TempError => cb(frame, SpfResult::TempError, None),
            Lookup::NxDomain | Lookup::NoData => {
                frame.charge_void();
                cb(frame, SpfResult::None, None);
            }
            Lookup::Answers(txts) => {
                let matching: Vec<&String> = txts.iter().filter(|t| is_spf_record(t)).collect();
                if matching.is_empty() {
                    cb(frame, SpfResult::None, None);
                    return;
                }
                if matching.len() > 1 {
                    cb(frame, SpfResult::PermError, None);
                    return;
                }
                match parse_record(matching[0]) {
                    Err(()) => cb(frame, SpfResult::PermError, None),
                    Ok(record) => evaluate_terms(frame, domain, Arc::new(record), 0, depth, cb),
                }
            }
        }),
    );
}

fn evaluate_terms(
    frame: Box<Frame>,
    domain: String,
    record: Arc<ParsedRecord>,
    idx: usize,
    depth: usize,
    cb: RecordCb,
) {
    if idx >= record.terms.len() {
        match record.redirect.clone() {
            None => cb(frame, SpfResult::Neutral, None),
            Some(spec) => {
                let mut frame = frame;
                let ctx = frame.ctx(&domain);
                let target = match macros::expand(&spec, &ctx) {
                    Ok(d) => d,
                    Err(()) => {
                        cb(frame, SpfResult::PermError, None);
                        return;
                    }
                };
                if !frame.charge_lookup() {
                    cb(frame, SpfResult::PermError, None);
                    return;
                }
                evaluate_record(
                    frame,
                    target,
                    depth + 1,
                    Box::new(move |frame, result, exp| {
                        // A redirect target lacking any SPF record is a PermError
                        // of the *redirecting* record (RFC 7208 §6.1).
                        let result = if result == SpfResult::None {
                            SpfResult::PermError
                        } else {
                            result
                        };
                        cb(frame, result, exp);
                    }),
                );
            }
        }
        return;
    }

    let (qualifier, mechanism) = record.terms[idx].clone();
    match mechanism {
        Mechanism::All => {
            let result = qualifier.to_result();
            finish_match(frame, domain, &record, result, cb);
        }
        Mechanism::Ip4 { addr, cidr } => {
            let matched = matches!(frame.ip, IpAddr::V4(client) if ip4_in_cidr(client, addr, cidr));
            if matched {
                finish_match(frame, domain, &record, qualifier.to_result(), cb);
            } else {
                evaluate_terms(frame, domain, record, idx + 1, depth, cb);
            }
        }
        Mechanism::Ip6 { addr, cidr } => {
            let matched = matches!(frame.ip, IpAddr::V6(client) if ip6_in_cidr(client, addr, cidr));
            if matched {
                finish_match(frame, domain, &record, qualifier.to_result(), cb);
            } else {
                evaluate_terms(frame, domain, record, idx + 1, depth, cb);
            }
        }
        Mechanism::A {
            domain: dspec,
            cidr4,
            cidr6,
        } => {
            let mut frame = frame;
            let ctx = frame.ctx(&domain);
            let target = match dspec {
                Some(spec) => match macros::expand(&spec, &ctx) {
                    Ok(d) => d,
                    Err(()) => {
                        cb(frame, SpfResult::PermError, None);
                        return;
                    }
                },
                None => domain.clone(),
            };
            if !frame.charge_lookup() {
                cb(frame, SpfResult::PermError, None);
                return;
            }
            check_a_or_aaaa(
                frame,
                &target,
                cidr4.unwrap_or(32),
                cidr6.unwrap_or(128),
                Box::new(move |frame, matched, temp_error| {
                    if temp_error {
                        cb(frame, SpfResult::TempError, None);
                    } else if matched {
                        finish_match(frame, domain, &record, qualifier.to_result(), cb);
                    } else {
                        evaluate_terms(frame, domain, record, idx + 1, depth, cb);
                    }
                }),
            );
        }
        Mechanism::Mx {
            domain: dspec,
            cidr4,
            cidr6,
        } => {
            let mut frame = frame;
            let ctx = frame.ctx(&domain);
            let target = match dspec {
                Some(spec) => match macros::expand(&spec, &ctx) {
                    Ok(d) => d,
                    Err(()) => {
                        cb(frame, SpfResult::PermError, None);
                        return;
                    }
                },
                None => domain.clone(),
            };
            if !frame.charge_lookup() {
                cb(frame, SpfResult::PermError, None);
                return;
            }
            let dns = Arc::clone(&frame.dns);
            dns.query_mx(
                &target,
                Box::new(move |lookup| match lookup {
                    Lookup::TempError => cb(frame, SpfResult::TempError, None),
                    Lookup::NxDomain | Lookup::NoData => {
                        frame.charge_void();
                        evaluate_terms(frame, domain, record, idx + 1, depth, cb);
                    }
                    Lookup::Answers(mut mx) => {
                        mx.sort_by_key(|(pref, _)| *pref);
                        mx.truncate(MAX_MX_HOSTS);
                        let hosts: Vec<String> = mx.into_iter().map(|(_, h)| h).collect();
                        check_hosts_any(
                            frame,
                            hosts,
                            cidr4.unwrap_or(32),
                            cidr6.unwrap_or(128),
                            Box::new(move |frame, matched| {
                                if matched {
                                    finish_match(frame, domain, &record, qualifier.to_result(), cb);
                                } else {
                                    evaluate_terms(frame, domain, record, idx + 1, depth, cb);
                                }
                            }),
                        );
                    }
                }),
            );
        }
        Mechanism::Ptr { domain: dspec } => {
            let mut frame = frame;
            let ctx = frame.ctx(&domain);
            let target = match dspec {
                Some(spec) => match macros::expand(&spec, &ctx) {
                    Ok(d) => d,
                    Err(()) => {
                        cb(frame, SpfResult::PermError, None);
                        return;
                    }
                },
                None => domain.clone(),
            };
            if !frame.charge_lookup() {
                cb(frame, SpfResult::PermError, None);
                return;
            }
            check_ptr(
                frame,
                target,
                Box::new(move |frame, matched| {
                    if matched {
                        finish_match(frame, domain, &record, qualifier.to_result(), cb);
                    } else {
                        evaluate_terms(frame, domain, record, idx + 1, depth, cb);
                    }
                }),
            );
        }
        Mechanism::Exists(dspec) => {
            let mut frame = frame;
            let ctx = frame.ctx(&domain);
            let target = match macros::expand(&dspec, &ctx) {
                Ok(d) => d,
                Err(()) => {
                    cb(frame, SpfResult::PermError, None);
                    return;
                }
            };
            if !frame.charge_lookup() {
                cb(frame, SpfResult::PermError, None);
                return;
            }
            let dns = Arc::clone(&frame.dns);
            dns.query_a(
                &target,
                Box::new(move |lookup| match lookup {
                    Lookup::TempError => cb(frame, SpfResult::TempError, None),
                    Lookup::Answers(_) => {
                        finish_match(frame, domain, &record, qualifier.to_result(), cb)
                    }
                    Lookup::NxDomain | Lookup::NoData => {
                        frame.charge_void();
                        evaluate_terms(frame, domain, record, idx + 1, depth, cb);
                    }
                }),
            );
        }
        Mechanism::Include(dspec) => {
            let mut frame = frame;
            let ctx = frame.ctx(&domain);
            let target = match macros::expand(&dspec, &ctx) {
                Ok(d) => d,
                Err(()) => {
                    cb(frame, SpfResult::PermError, None);
                    return;
                }
            };
            if !frame.charge_lookup() {
                cb(frame, SpfResult::PermError, None);
                return;
            }
            evaluate_record(
                frame,
                target,
                depth + 1,
                Box::new(move |frame, sub_result, _exp| match sub_result {
                    SpfResult::Pass => {
                        finish_match(frame, domain, &record, qualifier.to_result(), cb)
                    }
                    SpfResult::TempError => cb(frame, SpfResult::TempError, None),
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => {
                        evaluate_terms(frame, domain, record, idx + 1, depth, cb)
                    }
                    SpfResult::None | SpfResult::PermError => cb(frame, SpfResult::PermError, None),
                }),
            );
        }
    }
}

/// A term matched: resolve `exp=` (only meaningful for `Fail`) and finish.
fn finish_match(
    frame: Box<Frame>,
    domain: String,
    record: &ParsedRecord,
    result: SpfResult,
    cb: RecordCb,
) {
    if result != SpfResult::Fail {
        cb(frame, result, None);
        return;
    }
    match &record.exp {
        None => cb(frame, result, None),
        Some(spec) => {
            let ctx = frame.ctx(&domain);
            match macros::expand(spec, &ctx) {
                Ok(exp_target) => {
                    let dns = Arc::clone(&frame.dns);
                    cb(frame, result, Some((dns, exp_target, ctx)));
                }
                Err(()) => cb(frame, result, None),
            }
        }
    }
}

type AddrCheckCb = Box<dyn FnOnce(Box<Frame>, bool, bool) + Send>; // (frame, matched, temp_error)

fn check_a_or_aaaa(frame: Box<Frame>, name: &str, cidr4: u8, cidr6: u8, cb: AddrCheckCb) {
    let dns = Arc::clone(&frame.dns);
    let mut frame = frame;
    match frame.ip {
        IpAddr::V4(client) => {
            dns.query_a(
                name,
                Box::new(move |lookup| match lookup {
                    Lookup::TempError => cb(frame, false, true),
                    Lookup::Answers(addrs) => {
                        let matched = addrs.iter().any(|a| ip4_in_cidr(client, *a, cidr4));
                        cb(frame, matched, false);
                    }
                    Lookup::NxDomain | Lookup::NoData => {
                        frame.charge_void();
                        cb(frame, false, false);
                    }
                }),
            );
        }
        IpAddr::V6(client) => {
            dns.query_aaaa(
                name,
                Box::new(move |lookup| match lookup {
                    Lookup::TempError => cb(frame, false, true),
                    Lookup::Answers(addrs) => {
                        let matched = addrs.iter().any(|a| ip6_in_cidr(client, *a, cidr6));
                        cb(frame, matched, false);
                    }
                    Lookup::NxDomain | Lookup::NoData => {
                        frame.charge_void();
                        cb(frame, false, false);
                    }
                }),
            );
        }
    }
}

type HostsAnyCb = Box<dyn FnOnce(Box<Frame>, bool) + Send>;

/// Check each of `hosts` in turn (short-circuiting on first match) for an
/// A/AAAA record matching the client IP within the given CIDR — used by the
/// `mx` mechanism's per-exchange lookups, which do not separately count
/// against the 10-lookup budget (RFC 7208 §4.6.4) but are capped in number.
fn check_hosts_any(frame: Box<Frame>, hosts: Vec<String>, cidr4: u8, cidr6: u8, cb: HostsAnyCb) {
    fn step(frame: Box<Frame>, hosts: Vec<String>, i: usize, cidr4: u8, cidr6: u8, cb: HostsAnyCb) {
        if i >= hosts.len() {
            cb(frame, false);
            return;
        }
        let host = hosts[i].clone();
        check_a_or_aaaa(
            frame,
            &host,
            cidr4,
            cidr6,
            Box::new(move |frame, matched, _temp_error| {
                // Per-exchange failures are treated as no-match, not a hard
                // error, so one bad MX host doesn't fail the whole mechanism.
                if matched {
                    cb(frame, true);
                } else {
                    step(frame, hosts, i + 1, cidr4, cidr6, cb);
                }
            }),
        );
    }
    step(frame, hosts, 0, cidr4, cidr6, cb);
}

/// `ptr` mechanism (RFC 7208 §5.5): PTR-lookup the client IP, forward-confirm
/// each candidate name (A/AAAA) resolves back to the client IP, and check
/// whether any confirmed name equals or is a subdomain of `domain`.
fn check_ptr(frame: Box<Frame>, domain: String, cb: HostsAnyCb) {
    let dns = Arc::clone(&frame.dns);
    let mut frame = frame;
    let ip = frame.ip;
    let ptr_name = match ip {
        IpAddr::V4(a) => reverse_v4_name(a),
        IpAddr::V6(a) => reverse_v6_name(a),
    };
    dns.query_ptr(
        &ptr_name,
        Box::new(move |lookup| match lookup {
            Lookup::TempError => cb(frame, false),
            Lookup::NxDomain | Lookup::NoData => {
                frame.charge_void();
                cb(frame, false);
            }
            Lookup::Answers(mut names) => {
                names.truncate(MAX_PTR_HOSTS);
                confirm_ptr_names(frame, names, 0, ip, domain, cb);
            }
        }),
    );
}

fn confirm_ptr_names(
    frame: Box<Frame>,
    names: Vec<String>,
    i: usize,
    ip: IpAddr,
    domain: String,
    cb: HostsAnyCb,
) {
    if i >= names.len() {
        cb(frame, false);
        return;
    }
    let name = names[i].trim_end_matches('.').to_string();
    let dns = Arc::clone(&frame.dns);
    let name_for_check = name.clone();
    match ip {
        IpAddr::V4(client) => dns.query_a(
            &name,
            Box::new(move |lookup| {
                let confirmed = matches!(lookup, Lookup::Answers(addrs) if addrs.contains(&client));
                after_confirm(frame, names, i, ip, domain, name_for_check, confirmed, cb);
            }),
        ),
        IpAddr::V6(client) => dns.query_aaaa(
            &name,
            Box::new(move |lookup| {
                let confirmed = matches!(lookup, Lookup::Answers(addrs) if addrs.contains(&client));
                after_confirm(frame, names, i, ip, domain, name_for_check, confirmed, cb);
            }),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn after_confirm(
    frame: Box<Frame>,
    names: Vec<String>,
    i: usize,
    ip: IpAddr,
    domain: String,
    name: String,
    confirmed: bool,
    cb: HostsAnyCb,
) {
    if confirmed && domain_matches_or_subdomain(&name, &domain) {
        cb(frame, true);
    } else {
        confirm_ptr_names(frame, names, i + 1, ip, domain, cb);
    }
}

fn domain_matches_or_subdomain(name: &str, domain: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    name == domain || name.ends_with(&format!(".{domain}"))
}

fn reverse_v4_name(addr: Ipv4Addr) -> String {
    let o = addr.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

fn reverse_v6_name(addr: Ipv6Addr) -> String {
    let mut labels = Vec::with_capacity(32);
    for byte in addr.octets().iter().rev() {
        labels.push(format!("{:x}", byte & 0xf));
        labels.push(format!("{:x}", byte >> 4));
    }
    format!("{}.ip6.arpa", labels.join("."))
}

fn ip4_in_cidr(ip: Ipv4Addr, net: Ipv4Addr, cidr: u8) -> bool {
    if cidr == 0 {
        return true;
    }
    let mask: u32 = if cidr >= 32 {
        u32::MAX
    } else {
        !0u32 << (32 - cidr)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn ip6_in_cidr(ip: Ipv6Addr, net: Ipv6Addr, cidr: u8) -> bool {
    if cidr == 0 {
        return true;
    }
    let mask: u128 = if cidr >= 128 {
        u128::MAX
    } else {
        !0u128 << (128 - cidr)
    };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

// --- Record parsing (RFC 7208 §12 ABNF) -----------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

impl Qualifier {
    fn to_result(self) -> SpfResult {
        match self {
            Qualifier::Pass => SpfResult::Pass,
            Qualifier::Fail => SpfResult::Fail,
            Qualifier::SoftFail => SpfResult::SoftFail,
            Qualifier::Neutral => SpfResult::Neutral,
        }
    }
}

#[derive(Debug, Clone)]
enum Mechanism {
    All,
    Include(String),
    A {
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    Mx {
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    Ptr {
        domain: Option<String>,
    },
    Ip4 {
        addr: Ipv4Addr,
        cidr: u8,
    },
    Ip6 {
        addr: Ipv6Addr,
        cidr: u8,
    },
    Exists(String),
}

struct ParsedRecord {
    terms: Vec<(Qualifier, Mechanism)>,
    redirect: Option<String>,
    exp: Option<String>,
}

fn parse_record(text: &str) -> Result<ParsedRecord, ()> {
    let mut tokens = text.split_ascii_whitespace();
    let version = tokens.next().ok_or(())?;
    if !version.eq_ignore_ascii_case("v=spf1") {
        return Err(());
    }
    let mut terms = Vec::new();
    let mut redirect = None;
    let mut exp = None;
    for token in tokens {
        let (qualifier, rest) = match token.chars().next() {
            Some('+') => (Qualifier::Pass, &token[1..]),
            Some('-') => (Qualifier::Fail, &token[1..]),
            Some('~') => (Qualifier::SoftFail, &token[1..]),
            Some('?') => (Qualifier::Neutral, &token[1..]),
            Some(_) => (Qualifier::Pass, token),
            None => continue,
        };
        if rest.eq_ignore_ascii_case("all") {
            terms.push((qualifier, Mechanism::All));
        } else if let Some(spec) = strip_ci_prefix(rest, "include:") {
            if spec.is_empty() {
                return Err(());
            }
            terms.push((qualifier, Mechanism::Include(spec.to_string())));
        } else if let Some(spec) = strip_ci_prefix(rest, "exists:") {
            if spec.is_empty() {
                return Err(());
            }
            terms.push((qualifier, Mechanism::Exists(spec.to_string())));
        } else if let Some(spec) = strip_ci_prefix(rest, "ip4:") {
            let (addr, cidr) = parse_ip4_network(spec)?;
            terms.push((qualifier, Mechanism::Ip4 { addr, cidr }));
        } else if let Some(spec) = strip_ci_prefix(rest, "ip6:") {
            let (addr, cidr) = parse_ip6_network(spec)?;
            terms.push((qualifier, Mechanism::Ip6 { addr, cidr }));
        } else if rest.eq_ignore_ascii_case("a")
            || rest.len() > 1
                && rest[..1].eq_ignore_ascii_case("a")
                && matches!(rest.as_bytes()[1], b':' | b'/')
        {
            let (domain, cidr4, cidr6) = parse_domain_and_cidr(&rest[1..])?;
            terms.push((
                qualifier,
                Mechanism::A {
                    domain,
                    cidr4,
                    cidr6,
                },
            ));
        } else if rest.eq_ignore_ascii_case("mx")
            || rest.len() > 2
                && rest[..2].eq_ignore_ascii_case("mx")
                && matches!(rest.as_bytes()[2], b':' | b'/')
        {
            let (domain, cidr4, cidr6) = parse_domain_and_cidr(&rest[2..])?;
            terms.push((
                qualifier,
                Mechanism::Mx {
                    domain,
                    cidr4,
                    cidr6,
                },
            ));
        } else if rest.eq_ignore_ascii_case("ptr") {
            terms.push((qualifier, Mechanism::Ptr { domain: None }));
        } else if let Some(spec) = strip_ci_prefix(rest, "ptr:") {
            if spec.is_empty() {
                return Err(());
            }
            terms.push((
                qualifier,
                Mechanism::Ptr {
                    domain: Some(spec.to_string()),
                },
            ));
        } else if let Some(spec) = strip_ci_prefix(rest, "redirect=") {
            if spec.is_empty() {
                return Err(());
            }
            redirect = Some(spec.to_string());
        } else if let Some(spec) = strip_ci_prefix(rest, "exp=") {
            if spec.is_empty() {
                return Err(());
            }
            exp = Some(spec.to_string());
        } else if is_unknown_modifier(rest) {
            // Unrecognized `name=value` modifier — ignore per RFC 7208 §6.
        } else {
            return Err(());
        }
    }
    Ok(ParsedRecord {
        terms,
        redirect,
        exp,
    })
}

fn strip_ci_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn is_unknown_modifier(s: &str) -> bool {
    match s.find('=') {
        None => false,
        Some(pos) => {
            let name = &s[..pos];
            !name.is_empty()
                && name.chars().next().unwrap().is_ascii_alphabetic()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        }
    }
}

fn parse_ip4_network(s: &str) -> Result<(Ipv4Addr, u8), ()> {
    let (addr_s, cidr_s) = match s.find('/') {
        Some(pos) => (&s[..pos], Some(&s[pos + 1..])),
        None => (s, None),
    };
    let addr: Ipv4Addr = addr_s.parse().map_err(|_| ())?;
    let cidr = match cidr_s {
        Some(c) => {
            let n: u8 = c.parse().map_err(|_| ())?;
            if n > 32 {
                return Err(());
            }
            n
        }
        None => 32,
    };
    Ok((addr, cidr))
}

fn parse_ip6_network(s: &str) -> Result<(Ipv6Addr, u8), ()> {
    let (addr_s, cidr_s) = match s.find('/') {
        Some(pos) => (&s[..pos], Some(&s[pos + 1..])),
        None => (s, None),
    };
    let addr: Ipv6Addr = addr_s.parse().map_err(|_| ())?;
    let cidr = match cidr_s {
        Some(c) => {
            let n: u8 = c.parse().map_err(|_| ())?;
            if n > 128 {
                return Err(());
            }
            n
        }
        None => 128,
    };
    Ok((addr, cidr))
}

fn parse_domain_and_cidr(s: &str) -> Result<(Option<String>, Option<u8>, Option<u8>), ()> {
    if s.is_empty() {
        return Ok((None, None, None));
    }
    let (domain, cidr_part) = if let Some(rest) = s.strip_prefix(':') {
        match rest.find('/') {
            Some(pos) => (Some(rest[..pos].to_string()), Some(rest[pos..].to_string())),
            None => (Some(rest.to_string()), None),
        }
    } else if s.starts_with('/') {
        (None, Some(s.to_string()))
    } else {
        return Err(());
    };
    let (cidr4, cidr6) = match cidr_part {
        None => (None, None),
        Some(cp) => parse_dual_cidr(&cp)?,
    };
    if let Some(d) = &domain {
        if d.is_empty() {
            return Err(());
        }
    }
    Ok((domain, cidr4, cidr6))
}

fn parse_dual_cidr(s: &str) -> Result<(Option<u8>, Option<u8>), ()> {
    let s = s.strip_prefix('/').ok_or(())?;
    if let Some(rest) = s.strip_prefix('/') {
        let v6: u8 = rest.parse().map_err(|_| ())?;
        if v6 > 128 {
            return Err(());
        }
        Ok((None, Some(v6)))
    } else if let Some(pos) = s.find('/') {
        let v4: u8 = s[..pos].parse().map_err(|_| ())?;
        let v6: u8 = s[pos + 1..].parse().map_err(|_| ())?;
        if v4 > 32 || v6 > 128 {
            return Err(());
        }
        Ok((Some(v4), Some(v6)))
    } else {
        let v4: u8 = s.parse().map_err(|_| ())?;
        if v4 > 32 {
            return Err(());
        }
        Ok((Some(v4), None))
    }
}

#[cfg(test)]
mod tests;
