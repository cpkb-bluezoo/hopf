use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use super::*;

#[derive(Default)]
struct FakeDns {
    txt: HashMap<String, Vec<String>>,
}

impl FakeDns {
    fn with_txt(mut self, name: &str, record: &str) -> Self {
        self.txt
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(record.to_string());
        self
    }
}

impl DnsLookup for FakeDns {
    fn query_txt(&self, name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
        match self.txt.get(&name.to_ascii_lowercase()) {
            None => cb(Lookup::NxDomain),
            Some(v) => cb(Lookup::Answers(v.clone())),
        }
    }
    fn query_a(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<Ipv4Addr>) + Send>) {
        cb(Lookup::NxDomain);
    }
    fn query_aaaa(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<Ipv6Addr>) + Send>) {
        cb(Lookup::NxDomain);
    }
    fn query_mx(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<(u16, String)>) + Send>) {
        cb(Lookup::NxDomain);
    }
    fn query_ptr(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
        cb(Lookup::NxDomain);
    }
}

fn dkim_pass(domain: &str) -> DkimSignatureResult {
    DkimSignatureResult {
        result: DkimResult::Pass,
        signing_domain: Some(domain.to_string()),
        selector: Some("sel1".to_string()),
    }
}

fn psl() -> &'static PublicSuffixList {
    PublicSuffixList::bundled()
}

fn run(
    dns: FakeDns,
    from_domain: &str,
    spf_result: SpfResult,
    spf_domain: Option<&str>,
    dkim_results: Vec<DkimSignatureResult>,
) -> DmarcOutcome {
    let out = Arc::new(Mutex::new(None));
    let out2 = Arc::clone(&out);
    evaluate(
        Arc::new(dns),
        psl(),
        from_domain,
        spf_result,
        spf_domain.map(|s| s.to_string()),
        Arc::new(dkim_results),
        Box::new(move |o| *out2.lock().unwrap() = Some(o)),
    );
    let r = out.lock().unwrap().take().unwrap();
    r
}

#[test]
fn spf_aligned_pass() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = run(
        dns,
        "example.com",
        SpfResult::Pass,
        Some("example.com"),
        vec![],
    );
    assert_eq!(out.result, DmarcResult::Pass);
    assert_eq!(out.verdict, AuthVerdict::Pass);
}

#[test]
fn dkim_aligned_pass() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = run(
        dns,
        "example.com",
        SpfResult::Fail,
        None,
        vec![dkim_pass("example.com")],
    );
    assert_eq!(out.result, DmarcResult::Pass);
    assert_eq!(out.verdict, AuthVerdict::Pass);
}

#[test]
fn relaxed_alignment_matches_organizational_domain() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = run(
        dns,
        "example.com",
        SpfResult::Pass,
        Some("mail.example.com"),
        vec![],
    );
    assert_eq!(out.result, DmarcResult::Pass);
}

#[test]
fn strict_alignment_rejects_subdomain_match() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject; aspf=s");
    let out = run(
        dns,
        "example.com",
        SpfResult::Pass,
        Some("mail.example.com"),
        vec![],
    );
    assert_eq!(out.result, DmarcResult::Fail);
    assert_eq!(out.verdict, AuthVerdict::Reject);
}

#[test]
fn neither_aligned_p_reject() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = run(dns, "example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.result, DmarcResult::Fail);
    assert_eq!(out.verdict, AuthVerdict::Reject);
}

#[test]
fn neither_aligned_p_quarantine() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=quarantine");
    let out = run(dns, "example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.verdict, AuthVerdict::Quarantine);
}

#[test]
fn neither_aligned_p_none_is_monitor_only() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=none");
    let out = run(dns, "example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.verdict, AuthVerdict::None);
}

#[test]
fn subdomain_falls_back_to_org_domain_sp() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=none; sp=reject");
    let out = run(dns, "mail.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.policy, DmarcPolicy::Reject);
    assert_eq!(out.verdict, AuthVerdict::Reject);
}

#[test]
fn subdomain_own_record_takes_priority_over_org() {
    let dns = FakeDns::default()
        .with_txt("_dmarc.mail.example.com", "v=DMARC1; p=quarantine")
        .with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = run(dns, "mail.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.policy, DmarcPolicy::Quarantine);
}

#[test]
fn no_record_anywhere_is_none() {
    let dns = FakeDns::default();
    let out = run(dns, "example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.result, DmarcResult::None);
    assert_eq!(out.verdict, AuthVerdict::None);
}

#[test]
fn pct_zero_always_downgrades() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject; pct=0");
    let out = run(dns, "example.com", SpfResult::Fail, None, vec![]);
    // reject downgrades to quarantine when not sampled in.
    assert_eq!(out.verdict, AuthVerdict::Quarantine);
}

#[test]
fn malformed_record_is_permerror() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=bogus");
    let out = run(dns, "example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.result, DmarcResult::PermError);
}

#[test]
fn multiple_records_is_permerror() {
    let dns = FakeDns::default()
        .with_txt("_dmarc.example.com", "v=DMARC1; p=reject")
        .with_txt("_dmarc.example.com", "v=DMARC1; p=none");
    let out = run(dns, "example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.result, DmarcResult::PermError);
}
