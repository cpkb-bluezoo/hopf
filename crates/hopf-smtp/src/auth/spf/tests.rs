use std::collections::HashMap;
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
}

fn lookup_of<T: Clone>(v: Option<&Vec<T>>) -> Lookup<T> {
    match v {
        None => Lookup::NxDomain,
        Some(items) if items.is_empty() => Lookup::NoData,
        Some(items) => Lookup::Answers(items.clone()),
    }
}

impl FakeDns {
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
        cb(lookup_of(self.txt.get(&name.to_ascii_lowercase())));
    }
    fn query_a(&self, name: &str, cb: Box<dyn FnOnce(Lookup<Ipv4Addr>) + Send>) {
        cb(lookup_of(self.a.get(&name.to_ascii_lowercase())));
    }
    fn query_aaaa(&self, name: &str, cb: Box<dyn FnOnce(Lookup<Ipv6Addr>) + Send>) {
        cb(lookup_of(self.aaaa.get(&name.to_ascii_lowercase())));
    }
    fn query_mx(&self, name: &str, cb: Box<dyn FnOnce(Lookup<(u16, String)>) + Send>) {
        cb(lookup_of(self.mx.get(&name.to_ascii_lowercase())));
    }
    fn query_ptr(&self, name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
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
