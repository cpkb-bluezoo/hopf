use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use super::*;

#[derive(Default)]
struct FakeDns {
    txt: HashMap<String, Vec<String>>,
    a: HashMap<String, Vec<Ipv4Addr>>,
    aaaa: HashMap<String, Vec<Ipv6Addr>>,
    mx: HashMap<String, Vec<(u16, String)>>,
    ptr: HashMap<String, Vec<String>>,
    /// Names every query for which fails temporarily.
    temp: HashSet<String>,
}

fn lookup_of<T: Clone>(v: Option<&Vec<T>>) -> Lookup<T> {
    match v {
        None => Lookup::NxDomain,
        Some(items) if items.is_empty() => Lookup::NoData,
        Some(items) => Lookup::Answers(items.clone()),
    }
}

impl FakeDns {
    fn with_aaaa(mut self, name: &str, addr: Ipv6Addr) -> Self {
        self.aaaa
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(addr);
        self
    }
    fn with_temp_error(mut self, name: &str) -> Self {
        self.temp.insert(name.to_ascii_lowercase());
        self
    }
    fn is_temp(&self, name: &str) -> bool {
        self.temp.contains(&name.to_ascii_lowercase())
    }
    fn with_txt(mut self, name: &str, record: &str) -> Self {
        self.txt
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(record.to_string());
        self
    }
    fn with_a(mut self, name: &str, addr: Ipv4Addr) -> Self {
        self.a
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(addr);
        self
    }
    fn with_mx(mut self, name: &str, pref: u16, exchange: &str) -> Self {
        self.mx
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push((pref, exchange.to_string()));
        self
    }
    fn with_ptr(mut self, name: &str, target: &str) -> Self {
        self.ptr
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(target.to_string());
        self
    }
}

impl DnsLookup for FakeDns {
    fn query_txt(&self, name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
        if self.is_temp(name) {
            return cb(Lookup::TempError);
        }
        cb(lookup_of(self.txt.get(&name.to_ascii_lowercase())));
    }
    fn query_a(&self, name: &str, cb: Box<dyn FnOnce(Lookup<Ipv4Addr>) + Send>) {
        if self.is_temp(name) {
            return cb(Lookup::TempError);
        }
        cb(lookup_of(self.a.get(&name.to_ascii_lowercase())));
    }
    fn query_aaaa(&self, name: &str, cb: Box<dyn FnOnce(Lookup<Ipv6Addr>) + Send>) {
        if self.is_temp(name) {
            return cb(Lookup::TempError);
        }
        cb(lookup_of(self.aaaa.get(&name.to_ascii_lowercase())));
    }
    fn query_mx(&self, name: &str, cb: Box<dyn FnOnce(Lookup<(u16, String)>) + Send>) {
        if self.is_temp(name) {
            return cb(Lookup::TempError);
        }
        cb(lookup_of(self.mx.get(&name.to_ascii_lowercase())));
    }
    fn query_ptr(&self, name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
        if self.is_temp(name) {
            return cb(Lookup::TempError);
        }
        cb(lookup_of(self.ptr.get(&name.to_ascii_lowercase())));
    }
}

fn run(dns: FakeDns, ip: &str, domain: &str, sender: &str, helo: &str) -> SpfOutcome {
    let out = Arc::new(Mutex::new(None));
    let out2 = Arc::clone(&out);
    check_host(
        Arc::new(dns),
        ip.parse().unwrap(),
        domain,
        sender,
        helo,
        "receiver.example.net",
        Box::new(move |outcome| {
            *out2.lock().unwrap() = Some(outcome);
        }),
    );
    let result = out
        .lock()
        .unwrap()
        .take()
        .expect("callback ran synchronously");
    result
}

#[test]
fn ip4_pass() {
    let dns = FakeDns::default().with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all");
    let out = run(
        dns,
        "192.0.2.5",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Pass);
}

#[test]
fn default_all_fail_with_explanation() {
    let dns = FakeDns::default()
        .with_txt(
            "example.com",
            "v=spf1 ip4:192.0.2.0/24 -all exp=explain.example.com",
        )
        .with_txt(
            "explain.example.com",
            "Rejected: %{i} is not one of example.com's designated mail servers",
        );
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Fail);
    assert_eq!(
        out.explanation.as_deref(),
        Some("Rejected: 10.0.0.1 is not one of example.com's designated mail servers")
    );
}

#[test]
fn softfail_and_neutral_qualifiers() {
    let dns = FakeDns::default().with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 ~all");
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::SoftFail);

    let dns = FakeDns::default().with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 ?all");
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Neutral);
}

#[test]
fn no_record_is_none() {
    let dns = FakeDns::default();
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::None);
}

#[test]
fn a_mechanism() {
    let dns = FakeDns::default()
        .with_txt("example.com", "v=spf1 a -all")
        .with_a("example.com", "192.0.2.7".parse().unwrap());
    let out = run(
        dns,
        "192.0.2.7",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Pass);
}

#[test]
fn mx_mechanism() {
    let dns = FakeDns::default()
        .with_txt("example.com", "v=spf1 mx -all")
        .with_mx("example.com", 10, "mail.example.com")
        .with_a("mail.example.com", "192.0.2.9".parse().unwrap());
    let out = run(
        dns,
        "192.0.2.9",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Pass);
}

#[test]
fn include_mechanism_pass_and_fallthrough() {
    let dns = FakeDns::default()
        .with_txt("example.com", "v=spf1 include:_spf.provider.com -all")
        .with_txt("_spf.provider.com", "v=spf1 ip4:198.51.100.0/24 -all");
    let out = run(
        dns,
        "198.51.100.5",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Pass);

    let dns = FakeDns::default()
        .with_txt("example.com", "v=spf1 include:_spf.provider.com -all")
        .with_txt("_spf.provider.com", "v=spf1 ip4:198.51.100.0/24 -all");
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Fail);
}

#[test]
fn include_of_missing_domain_is_permerror() {
    let dns = FakeDns::default().with_txt("example.com", "v=spf1 include:missing.example -all");
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::PermError);
}

#[test]
fn redirect_modifier() {
    let dns = FakeDns::default()
        .with_txt("example.com", "v=spf1 redirect=_spf.example.net")
        .with_txt("_spf.example.net", "v=spf1 ip4:203.0.113.0/24 -all");
    let out = run(
        dns,
        "203.0.113.9",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Pass);
}

#[test]
fn exists_mechanism_with_macro() {
    let dns = FakeDns::default()
        .with_txt("example.com", "v=spf1 exists:%{ir}.spf.example.com -all")
        .with_a("1.0.0.10.spf.example.com", "127.0.0.1".parse().unwrap());
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Pass);
}

#[test]
fn ptr_mechanism() {
    let dns = FakeDns::default()
        .with_txt("example.com", "v=spf1 ptr -all")
        .with_ptr("1.0.0.10.in-addr.arpa", "mail.example.com")
        .with_a("mail.example.com", "10.0.0.1".parse().unwrap());
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Pass);
}

#[test]
fn malformed_record_is_permerror() {
    let dns = FakeDns::default().with_txt("example.com", "v=spf1 bogusmechanism -all");
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::PermError);
}

#[test]
fn null_sender_uses_helo() {
    // Null MAIL FROM: caller passes `postmaster@<helo>` as `sender`.
    let dns = FakeDns::default().with_txt("mail.example.com", "v=spf1 ip4:192.0.2.0/24 -all");
    let out = run(
        dns,
        "192.0.2.5",
        "mail.example.com",
        "postmaster@mail.example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::Pass);
}

#[test]
fn lookup_limit_exceeded_is_permerror() {
    // 11 includes, each consuming one of the 10-lookup budget.
    let mut dns = FakeDns::default();
    let mut record = "v=spf1".to_string();
    for i in 0..11 {
        record.push_str(&format!(" include:l{i}.example.com"));
        dns = dns.with_txt(&format!("l{i}.example.com"), "v=spf1 -all");
    }
    dns = dns.with_txt("example.com", &record);
    let out = run(
        dns,
        "10.0.0.1",
        "example.com",
        "user@example.com",
        "mail.example.com",
    );
    assert_eq!(out.result, SpfResult::PermError);
}

// ── helpers ──────────────────────────────────────────────────────────────

fn spf(dns: FakeDns, ip: &str) -> SpfResult {
    run(dns, ip, "example.com", "user@example.com", "mail.example.com").result
}

fn record(text: &str) -> FakeDns {
    FakeDns::default().with_txt("example.com", text)
}

fn a(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

// ── the record itself ────────────────────────────────────────────────────

#[test]
fn a_domain_without_a_record_has_none_whether_nxdomain_or_nodata() {
    assert_eq!(spf(FakeDns::default(), "192.0.2.1"), SpfResult::None);
    let mut dns = FakeDns::default();
    dns.txt.insert("example.com".into(), Vec::new());
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::None);
}

#[test]
fn txt_records_that_are_not_spf_are_ignored() {
    let dns = record("google-site-verification=abc").with_txt("example.com", "v=spf1 +all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Pass);
    let dns = record("v=spf10 +all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::None, "v=spf10 is not v=spf1");
}

#[test]
fn the_version_tag_is_not_case_sensitive() {
    assert_eq!(spf(record("V=SPF1 +ALL"), "192.0.2.1"), SpfResult::Pass);
}

#[test]
fn two_spf_records_are_a_permerror() {
    let dns = record("v=spf1 +all").with_txt("example.com", "v=spf1 -all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn a_dns_failure_for_the_record_is_a_temperror() {
    assert_eq!(spf(FakeDns::default().with_temp_error("example.com"), "192.0.2.1"), SpfResult::TempError);
}

#[test]
fn a_record_with_no_terms_is_neutral() {
    assert_eq!(spf(record("v=spf1"), "192.0.2.1"), SpfResult::Neutral);
}

#[test]
fn nothing_matching_is_neutral_and_terms_after_all_are_ignored() {
    assert_eq!(spf(record("v=spf1 ip4:10.0.0.0/8"), "192.0.2.1"), SpfResult::Neutral);
    assert_eq!(spf(record("v=spf1 -all ip4:192.0.2.1"), "192.0.2.1"), SpfResult::Fail);
}

#[test]
fn every_qualifier_gives_its_result() {
    for (q, expect) in [
        ("", SpfResult::Pass),
        ("+", SpfResult::Pass),
        ("-", SpfResult::Fail),
        ("~", SpfResult::SoftFail),
        ("?", SpfResult::Neutral),
    ] {
        assert_eq!(spf(record(&format!("v=spf1 {q}all")), "192.0.2.1"), expect, "qualifier {q:?}");
    }
}

#[test]
fn results_have_their_authentication_results_names() {
    for (r, name) in [
        (SpfResult::Pass, "pass"),
        (SpfResult::Fail, "fail"),
        (SpfResult::SoftFail, "softfail"),
        (SpfResult::Neutral, "neutral"),
        (SpfResult::None, "none"),
        (SpfResult::TempError, "temperror"),
        (SpfResult::PermError, "permerror"),
    ] {
        assert_eq!(r.as_str(), name);
    }
}

// ── syntax errors ────────────────────────────────────────────────────────

#[test]
fn syntax_errors_are_permerrors() {
    for bad in [
        "v=spf1 foo",
        "v=spf1 ip4",
        "v=spf1 ip4:",
        "v=spf1 ip4:300.0.0.1",
        "v=spf1 ip4:192.0.2.1/33",
        "v=spf1 ip6:::1/129",
        "v=spf1 ip6:nonsense",
        "v=spf1 a/33",
        "v=spf1 a//129",
        "v=spf1 a:",
        "v=spf1 mx:",
        "v=spf1 ptr:",
        "v=spf1 include:",
        "v=spf1 exists:",
        "v=spf1 redirect=",
        "v=spf1 exp=",
        "v=spf1 all:example.com",
        "v=spf1 a:example.com/abc",
    ] {
        assert_eq!(spf(record(bad), "192.0.2.1"), SpfResult::PermError, "{bad}");
    }
}

#[test]
fn unknown_modifiers_are_ignored_and_unknown_mechanisms_are_not() {
    assert_eq!(spf(record("v=spf1 foo=bar +all"), "192.0.2.1"), SpfResult::Pass);
    assert_eq!(spf(record("v=spf1 foo.bar-baz_1=x +all"), "192.0.2.1"), SpfResult::Pass);
    assert_eq!(spf(record("v=spf1 foo:bar +all"), "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn mechanism_names_are_not_case_sensitive() {
    assert_eq!(spf(record("v=spf1 IP4:192.0.2.1 -ALL"), "192.0.2.1"), SpfResult::Pass);
    assert_eq!(spf(record("v=spf1 INCLUDE:other.example -all").with_txt("other.example", "v=spf1 +all"), "192.0.2.1"), SpfResult::Pass);
}

#[test]
fn a_redirect_or_exp_given_twice_is_a_permerror() {
    // RFC 7208 section 6: each modifier at most once.
    let dns = record("v=spf1 redirect=a.example redirect=b.example")
        .with_txt("a.example", "v=spf1 +all")
        .with_txt("b.example", "v=spf1 -all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::PermError);
    assert_eq!(spf(record("v=spf1 -all exp=a.example exp=b.example"), "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn a_modifier_cannot_have_a_qualifier() {
    let dns = record("v=spf1 ?redirect=other.example").with_txt("other.example", "v=spf1 +all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::PermError);
    assert_eq!(spf(record("v=spf1 -all -exp=x.example"), "192.0.2.1"), SpfResult::PermError);
}

// ── ip4 / ip6 ────────────────────────────────────────────────────────────

#[test]
fn ip4_networks_match_on_their_prefix() {
    let r = record("v=spf1 ip4:192.0.2.0/25 -all");
    assert_eq!(spf(r, "192.0.2.127"), SpfResult::Pass);
    assert_eq!(spf(record("v=spf1 ip4:192.0.2.0/25 -all"), "192.0.2.128"), SpfResult::Fail);
    assert_eq!(spf(record("v=spf1 ip4:192.0.2.9 -all"), "192.0.2.9"), SpfResult::Pass, "no prefix means /32");
    assert_eq!(spf(record("v=spf1 ip4:192.0.2.9 -all"), "192.0.2.10"), SpfResult::Fail);
    assert_eq!(spf(record("v=spf1 ip4:0.0.0.0/0 -all"), "203.0.113.5"), SpfResult::Pass, "/0 is everyone");
}

#[test]
fn ip6_networks_match_on_their_prefix() {
    assert_eq!(spf(record("v=spf1 ip6:2001:db8::/32 -all"), "2001:db8:ffff::1"), SpfResult::Pass);
    assert_eq!(spf(record("v=spf1 ip6:2001:db8::/32 -all"), "2001:db9::1"), SpfResult::Fail);
    assert_eq!(spf(record("v=spf1 ip6:2001:db8::1 -all"), "2001:db8::1"), SpfResult::Pass);
    assert_eq!(spf(record("v=spf1 ip6:::/0 -all"), "2001:db8::1"), SpfResult::Pass);
}

#[test]
fn an_address_of_the_other_family_never_matches() {
    assert_eq!(spf(record("v=spf1 ip4:192.0.2.1 -all"), "2001:db8::1"), SpfResult::Fail);
    assert_eq!(spf(record("v=spf1 ip6:2001:db8::1 -all"), "192.0.2.1"), SpfResult::Fail);
}

#[test]
fn an_ipv4_client_that_arrives_as_an_ipv4_mapped_ipv6_address_is_treated_as_ipv4() {
    // RFC 7208 section 5: a dual-stack listener reports IPv4 peers this way.
    assert_eq!(spf(record("v=spf1 ip4:192.0.2.1 -all"), "::ffff:192.0.2.1"), SpfResult::Pass);
    let dns = record("v=spf1 a -all").with_a("example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "::ffff:192.0.2.1"), SpfResult::Pass);
}

// ── a ───────────────────────────────────────────────────────────────────

#[test]
fn a_matches_the_domains_own_address_or_the_named_ones() {
    let dns = record("v=spf1 a -all").with_a("example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Pass);
    let dns = record("v=spf1 a:mail.other.example -all").with_a("mail.other.example", a("192.0.2.2"));
    assert_eq!(spf(dns, "192.0.2.2"), SpfResult::Pass);
}

#[test]
fn a_with_a_prefix_matches_the_whole_network() {
    let dns = record("v=spf1 a/24 -all").with_a("example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.200"), SpfResult::Pass);
    let dns = record("v=spf1 a:mail.example.com/24 -all").with_a("mail.example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.3.1"), SpfResult::Fail);
}

#[test]
fn the_dual_cidr_form_gives_both_prefixes() {
    // `a/24//64`: IPv4 /24 and IPv6 /64.
    let dns = record("v=spf1 a/24//64 -all").with_a("example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.77"), SpfResult::Pass);
    let dns = record("v=spf1 a/24//64 -all").with_aaaa("example.com", "2001:db8:1:2::1".parse().unwrap());
    assert_eq!(spf(dns, "2001:db8:1:2:ffff::9"), SpfResult::Pass);
    let dns = record("v=spf1 mx:mail.example.com/24//64 -all")
        .with_mx("mail.example.com", 10, "mx1.example.com")
        .with_a("mx1.example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.50"), SpfResult::Pass);
}

#[test]
fn only_an_ipv6_prefix_may_be_given_alone_with_two_slashes() {
    let dns = record("v=spf1 a//64 -all").with_aaaa("example.com", "2001:db8:1:2::1".parse().unwrap());
    assert_eq!(spf(dns, "2001:db8:1:2::ffff"), SpfResult::Pass);
}

#[test]
fn a_single_slash_pair_that_is_not_the_dual_form_is_a_permerror() {
    assert_eq!(spf(record("v=spf1 a/24/64 -all"), "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn an_ipv6_client_is_checked_against_aaaa() {
    let dns = record("v=spf1 a -all").with_aaaa("example.com", "2001:db8::25".parse().unwrap());
    assert_eq!(spf(dns, "2001:db8::25"), SpfResult::Pass);
    let dns = record("v=spf1 a -all").with_a("example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "2001:db8::25"), SpfResult::Fail, "an A record cannot vouch for an IPv6 client");
}

#[test]
fn a_dns_failure_in_a_is_a_temperror() {
    let dns = record("v=spf1 a:flaky.example -all").with_temp_error("flaky.example");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::TempError);
}

// ── mx ──────────────────────────────────────────────────────────────────

#[test]
fn mx_matches_the_address_of_any_exchange() {
    let dns = record("v=spf1 mx -all")
        .with_mx("example.com", 20, "backup.example.com")
        .with_mx("example.com", 10, "mail.example.com")
        .with_a("mail.example.com", a("192.0.2.1"))
        .with_a("backup.example.com", a("192.0.2.2"));
    assert_eq!(spf(dns, "192.0.2.2"), SpfResult::Pass);
}

#[test]
fn mx_without_a_match_or_without_exchanges_does_not_match() {
    let dns = record("v=spf1 mx -all")
        .with_mx("example.com", 10, "mail.example.com")
        .with_a("mail.example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.99"), SpfResult::Fail);
    assert_eq!(spf(record("v=spf1 mx -all"), "192.0.2.1"), SpfResult::Fail);
}

#[test]
fn a_dns_failure_for_the_mx_query_is_a_temperror() {
    assert_eq!(spf(record("v=spf1 mx:flaky.example -all").with_temp_error("flaky.example"), "192.0.2.1"), SpfResult::TempError);
}

#[test]
fn an_exchange_that_will_not_resolve_is_skipped() {
    let dns = record("v=spf1 mx -all")
        .with_mx("example.com", 10, "broken.example.com")
        .with_mx("example.com", 20, "good.example.com")
        .with_temp_error("broken.example.com")
        .with_a("good.example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Pass);
}

#[test]
fn an_mx_with_more_than_ten_exchanges_is_a_permerror() {
    // RFC 7208 section 4.6.4: no more than 10 address lookups for one mx.
    let mut dns = record("v=spf1 mx -all");
    for i in 0..11 {
        dns = dns.with_mx("example.com", 10, &format!("mx{i}.example.com")).with_a(&format!("mx{i}.example.com"), a("10.0.0.1"));
    }
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::PermError);
}

// ── ptr ─────────────────────────────────────────────────────────────────

#[test]
fn ptr_needs_the_name_to_resolve_back_to_the_client() {
    let dns = record("v=spf1 ptr -all")
        .with_ptr("1.2.0.192.in-addr.arpa", "mail.example.com")
        .with_a("mail.example.com", a("192.0.2.99"));
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Fail, "the forward lookup does not give the client's address");
}

#[test]
fn ptr_accepts_a_subdomain_but_not_a_lookalike() {
    let dns = record("v=spf1 ptr -all")
        .with_ptr("1.2.0.192.in-addr.arpa", "deep.mail.example.com")
        .with_a("deep.mail.example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Pass);
    let dns = record("v=spf1 ptr -all")
        .with_ptr("1.2.0.192.in-addr.arpa", "mail.notexample.com")
        .with_a("mail.notexample.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Fail);
}

#[test]
fn ptr_may_name_another_domain_and_may_see_an_ipv6_client() {
    let dns = record("v=spf1 ptr:other.example -all")
        .with_ptr("1.2.0.192.in-addr.arpa", "mail.other.example")
        .with_a("mail.other.example", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Pass);
    let ip6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let nibbles = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
    let dns = record("v=spf1 ptr -all").with_ptr(nibbles, "v6.example.com").with_aaaa("v6.example.com", ip6);
    assert_eq!(spf(dns, "2001:db8::1"), SpfResult::Pass);
}

#[test]
fn ptr_with_no_reverse_name_or_a_failing_lookup_does_not_match() {
    assert_eq!(spf(record("v=spf1 ptr -all"), "192.0.2.1"), SpfResult::Fail);
    let dns = record("v=spf1 ptr -all").with_temp_error("1.2.0.192.in-addr.arpa");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Fail);
}

#[test]
fn only_the_first_ten_reverse_names_are_checked() {
    let mut dns = record("v=spf1 ptr -all");
    for i in 0..10 {
        dns = dns.with_ptr("1.2.0.192.in-addr.arpa", &format!("junk{i}.elsewhere.example"));
    }
    dns = dns.with_ptr("1.2.0.192.in-addr.arpa", "mail.example.com").with_a("mail.example.com", a("192.0.2.1"));
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Fail, "the eleventh name is beyond the limit");
}

// ── exists ──────────────────────────────────────────────────────────────

#[test]
fn exists_matches_when_the_expanded_name_has_an_address() {
    let dns = record("v=spf1 exists:%{i}._spf.example.com -all").with_a("192.0.2.1._spf.example.com", a("127.0.0.2"));
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Pass);
    let dns = record("v=spf1 exists:%{i}._spf.example.com -all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Fail);
}

#[test]
fn exists_with_a_failing_lookup_is_a_temperror() {
    let dns = record("v=spf1 exists:flaky.example -all").with_temp_error("flaky.example");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::TempError);
}

#[test]
fn exists_looks_up_a_even_for_an_ipv6_client() {
    let dns = record("v=spf1 exists:check.example -all").with_a("check.example", a("127.0.0.2"));
    assert_eq!(spf(dns, "2001:db8::1"), SpfResult::Pass);
}

#[test]
fn a_bad_macro_in_a_domain_spec_is_a_permerror() {
    for bad in ["a:%{q}.example", "mx:%{", "exists:%x.example", "include:%{d", "ptr:%"] {
        assert_eq!(spf(record(&format!("v=spf1 {bad} -all")), "192.0.2.1"), SpfResult::PermError, "{bad}");
    }
}

// ── include and redirect ────────────────────────────────────────────────

#[test]
fn include_matches_only_when_the_included_policy_passes() {
    let base = || FakeDns::default().with_txt("example.com", "v=spf1 include:other.example ~all");
    assert_eq!(spf(base().with_txt("other.example", "v=spf1 ip4:192.0.2.1 -all"), "192.0.2.1"), SpfResult::Pass);
    assert_eq!(
        spf(base().with_txt("other.example", "v=spf1 ip4:10.0.0.1 -all"), "192.0.2.1"),
        SpfResult::SoftFail,
        "a fail inside an include is no match, so evaluation goes on"
    );
    assert_eq!(spf(base().with_txt("other.example", "v=spf1 ?all"), "192.0.2.1"), SpfResult::SoftFail);
}

#[test]
fn an_include_of_a_domain_without_policy_or_with_a_broken_one_is_a_permerror() {
    let dns = record("v=spf1 include:nothing.example -all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::PermError);
    let dns = record("v=spf1 include:bad.example -all").with_txt("bad.example", "v=spf1 bogus");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn an_include_with_a_dns_failure_is_a_temperror() {
    let dns = record("v=spf1 include:flaky.example -all").with_temp_error("flaky.example");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::TempError);
}

#[test]
fn the_include_qualifier_applies_to_a_match() {
    let dns = record("v=spf1 -include:blocklist.example +all").with_txt("blocklist.example", "v=spf1 ip4:192.0.2.1 ?all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Fail);
}

#[test]
fn includes_that_loop_run_out_of_lookups() {
    let dns = record("v=spf1 include:a.example -all")
        .with_txt("a.example", "v=spf1 include:b.example -all")
        .with_txt("b.example", "v=spf1 include:a.example -all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn redirect_is_used_only_when_no_term_matched() {
    let dns = record("v=spf1 ip4:10.0.0.0/8 redirect=policy.example").with_txt("policy.example", "v=spf1 ip4:192.0.2.0/24 -all");
    assert_eq!(spf(dns, "192.0.2.5"), SpfResult::Pass);
    let dns = record("v=spf1 ip4:10.0.0.0/8 redirect=policy.example").with_txt("policy.example", "v=spf1 -all");
    assert_eq!(spf(dns, "10.1.1.1"), SpfResult::Pass, "a matching term wins over redirect");
}

#[test]
fn redirect_wherever_it_is_written_comes_last() {
    let dns = record("v=spf1 redirect=policy.example ip4:192.0.2.1").with_txt("policy.example", "v=spf1 -all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Pass);
}

#[test]
fn redirect_ignores_the_target_when_all_is_present() {
    let dns = record("v=spf1 -all redirect=policy.example").with_txt("policy.example", "v=spf1 +all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Fail);
}

#[test]
fn redirect_to_a_domain_with_no_policy_is_a_permerror() {
    assert_eq!(spf(record("v=spf1 redirect=nothing.example"), "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn redirect_expands_macros_in_its_target() {
    let dns = record("v=spf1 redirect=_spf.%{d}").with_txt("_spf.example.com", "v=spf1 +all");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::Pass);
}

#[test]
fn redirects_that_never_end_are_a_permerror() {
    let dns = record("v=spf1 redirect=a.example")
        .with_txt("a.example", "v=spf1 redirect=b.example")
        .with_txt("b.example", "v=spf1 redirect=a.example");
    assert_eq!(spf(dns, "192.0.2.1"), SpfResult::PermError);
}

// ── limits ──────────────────────────────────────────────────────────────

#[test]
fn ten_lookups_are_allowed_and_the_eleventh_is_not() {
    let mut ten = String::from("v=spf1");
    let mut dns = FakeDns::default();
    for i in 0..10 {
        ten.push_str(&format!(" a:h{i}.example"));
        dns = dns.with_a(&format!("h{i}.example"), a("10.0.0.1"));
    }
    ten.push_str(" -all");
    assert_eq!(spf(dns.with_txt("example.com", &ten), "192.0.2.1"), SpfResult::Fail);

    let mut eleven = String::from("v=spf1");
    let mut dns = FakeDns::default();
    for i in 0..11 {
        eleven.push_str(&format!(" a:h{i}.example"));
        dns = dns.with_a(&format!("h{i}.example"), a("10.0.0.1"));
    }
    eleven.push_str(" -all");
    assert_eq!(spf(dns.with_txt("example.com", &eleven), "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn more_than_two_void_lookups_are_a_permerror() {
    // RFC 7208 section 4.6.4: lookups that find nothing are limited to two.
    let rec = "v=spf1 a:v1.example a:v2.example a:v3.example -all";
    assert_eq!(spf(record(rec), "192.0.2.1"), SpfResult::PermError);
    let rec = "v=spf1 a:v1.example a:v2.example -all";
    assert_eq!(spf(record(rec), "192.0.2.1"), SpfResult::Fail, "two are allowed");
}

#[test]
fn void_lookups_are_counted_for_every_kind_of_lookup() {
    let rec = "v=spf1 mx:v1.example exists:v2.example ptr:x.example -all";
    // mx and exists are void; the ptr lookup of the client is void too.
    assert_eq!(spf(record(rec), "192.0.2.1"), SpfResult::PermError);
}

#[test]
fn the_record_lookup_of_the_checked_domain_is_not_a_void_lookup() {
    // example.com's own record is found; a missing policy at the start is `none`, not a void-limit error.
    assert_eq!(spf(FakeDns::default(), "192.0.2.1"), SpfResult::None);
}

// ── explanations ────────────────────────────────────────────────────────

#[test]
fn an_explanation_is_made_only_for_a_fail() {
    let dns = || {
        FakeDns::default()
            .with_txt("explain.example.com", "%{i} is not allowed to send for %{d}")
    };
    let soft = dns().with_txt("example.com", "v=spf1 ~all exp=explain.example.com");
    assert_eq!(run(soft, "192.0.2.1", "example.com", "u@example.com", "h.example").explanation, None);
    let hard = dns().with_txt("example.com", "v=spf1 -all exp=explain.example.com");
    let out = run(hard, "192.0.2.1", "example.com", "u@example.com", "h.example");
    assert_eq!(out.result, SpfResult::Fail);
    assert_eq!(out.explanation.as_deref(), Some("192.0.2.1 is not allowed to send for example.com"));
}

#[test]
fn a_missing_or_unreadable_explanation_leaves_the_fail_as_it_is() {
    for exp in ["exp=nothing.example", "exp=%{q}.example", "exp=flaky.example"] {
        let dns = record(&format!("v=spf1 -all {exp}")).with_temp_error("flaky.example");
        let out = run(dns, "192.0.2.1", "example.com", "u@example.com", "h.example");
        assert_eq!(out.result, SpfResult::Fail, "{exp}");
        assert_eq!(out.explanation, None, "{exp}");
    }
}

#[test]
fn the_explanation_may_use_the_receiver_and_the_sender_macros() {
    let dns = record("v=spf1 -all exp=why.example.com").with_txt("why.example.com", "%{r} says no to %{s} (%{l} at %{o}) via %{h}");
    let out = run(dns, "192.0.2.1", "example.com", "bob@example.com", "helo.example");
    assert_eq!(
        out.explanation.as_deref(),
        Some("receiver.example.net says no to bob@example.com (bob at example.com) via helo.example")
    );
}

#[test]
fn a_redirected_fail_takes_its_explanation_from_the_policy_that_failed() {
    let dns = record("v=spf1 redirect=policy.example")
        .with_txt("policy.example", "v=spf1 -all exp=why.example")
        .with_txt("why.example", "denied by policy");
    let out = run(dns, "192.0.2.1", "example.com", "u@example.com", "h.example");
    assert_eq!(out.result, SpfResult::Fail);
    assert_eq!(out.explanation.as_deref(), Some("denied by policy"));
}

// ── macros ──────────────────────────────────────────────────────────────

fn macro_ctx() -> MacroContext {
    MacroContext {
        sender: "strong-bad@email.example.com".into(),
        local_part: "strong-bad".into(),
        sender_domain: "email.example.com".into(),
        domain: "email.example.com".into(),
        ip: Some("192.0.2.3".parse().unwrap()),
        validated_domain: None,
        helo_domain: "helo.example".into(),
        receiver: "receiver.example.net".into(),
        timestamp: 1_110_000_000,
    }
}

#[test]
fn the_remaining_macro_letters_expand() {
    let c = macro_ctx();
    assert_eq!(macros::expand("%{h}", &c).unwrap(), "helo.example");
    assert_eq!(macros::expand("%{v}", &c).unwrap(), "in-addr");
    assert_eq!(macros::expand("%{p}", &c).unwrap(), "unknown");
    assert_eq!(macros::expand("%{c}", &c).unwrap(), "192.0.2.3");
    assert_eq!(macros::expand("%{r}", &c).unwrap(), "receiver.example.net");
    assert_eq!(macros::expand("%{t}", &c).unwrap(), "1110000000");
    assert_eq!(macros::expand("%-%_%%", &c).unwrap(), "%20 %");
}

#[test]
fn ipv6_macros_use_nibbles_and_ip6() {
    let mut c = macro_ctx();
    c.ip = Some("2001:db8::1".parse().unwrap());
    assert_eq!(macros::expand("%{v}", &c).unwrap(), "ip6");
    assert_eq!(macros::expand("%{ir}", &c).unwrap().split('.').next(), Some("1"));
    assert_eq!(macros::expand("%{c}", &c).unwrap(), "2001:db8::1");
}

#[test]
fn an_upper_case_letter_url_escapes_the_value() {
    let mut c = macro_ctx();
    c.local_part = "a b+c@d".into();
    assert_eq!(macros::expand("%{L}", &c).unwrap(), "a%20b%2Bc%40d");
    assert_eq!(macros::expand("%{l}", &c).unwrap(), "a b+c@d");
}

#[test]
fn delimiters_split_and_the_digit_keeps_the_rightmost_parts() {
    let mut c = macro_ctx();
    c.local_part = "a+b-c".into();
    assert_eq!(macros::expand("%{l+-}", &c).unwrap(), "a.b.c");
    assert_eq!(macros::expand("%{l2+-}", &c).unwrap(), "b.c");
    assert_eq!(macros::expand("%{l9+-}", &c).unwrap(), "a.b.c");
}

#[test]
fn a_zero_keep_count_is_not_valid() {
    // RFC 7208 section 7.1: the number must be positive.
    assert!(macros::expand("%{d0}", &macro_ctx()).is_err());
}

#[test]
fn malformed_macros_are_errors() {
    let c = macro_ctx();
    for bad in ["%{d", "%{d1", "%{dx}", "%{d#}", "%q", "%", "%{}", "%{d99999999999999999999}"] {
        assert!(macros::expand(bad, &c).is_err(), "{bad}");
    }
}

#[test]
fn a_macro_that_needs_the_client_address_fails_without_one() {
    let mut c = macro_ctx();
    c.ip = None;
    assert!(macros::expand("%{i}", &c).is_err());
    assert!(macros::expand("%{v}", &c).is_err());
    assert_eq!(macros::expand("%{c}", &c).unwrap(), "unknown");
}
