use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use super::*;

#[derive(Default)]
struct FakeDns {
    txt: HashMap<String, Vec<String>>,
    /// Domains that exist for A lookups (anything else → NXDOMAIN).
    a_exists: std::collections::HashSet<String>,
    /// Names whose every query fails temporarily.
    temp: std::collections::HashSet<String>,
}

impl FakeDns {
    fn with_temp_error(mut self, name: &str) -> Self {
        self.temp.insert(name.to_ascii_lowercase());
        self
    }

    fn with_txt(mut self, name: &str, record: &str) -> Self {
        self.txt
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(record.to_string());
        self
    }

    fn with_a(mut self, name: &str) -> Self {
        self.a_exists.insert(name.to_ascii_lowercase());
        self
    }
}

impl DnsLookup for FakeDns {
    fn query_txt(&self, name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
        if self.temp.contains(&name.to_ascii_lowercase()) {
            return cb(Lookup::TempError);
        }
        match self.txt.get(&name.to_ascii_lowercase()) {
            None => cb(Lookup::NxDomain),
            Some(v) => cb(Lookup::Answers(v.clone())),
        }
    }
    fn query_a(&self, name: &str, cb: Box<dyn FnOnce(Lookup<Ipv4Addr>) + Send>) {
        if self.temp.contains(&name.to_ascii_lowercase()) {
            return cb(Lookup::TempError);
        }
        if self.a_exists.contains(&name.to_ascii_lowercase()) {
            cb(Lookup::Answers(vec![Ipv4Addr::new(127, 0, 0, 1)]));
        } else {
            cb(Lookup::NxDomain);
        }
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
    run_with_duplicate_from(dns, from_domain, false, spf_result, spf_domain, dkim_results)
}

#[allow(clippy::too_many_arguments)]
fn run_with_duplicate_from(
    dns: FakeDns,
    from_domain: &str,
    has_duplicate_from: bool,
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
        has_duplicate_from,
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
fn duplicate_from_forces_fail_even_when_otherwise_aligned() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = run_with_duplicate_from(
        dns,
        "example.com",
        true,
        SpfResult::Pass,
        Some("example.com"),
        vec![dkim_pass("example.com")],
    );
    assert_eq!(out.result, DmarcResult::Fail);
    assert_eq!(out.verdict, AuthVerdict::Reject);
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
    let dns = FakeDns::default()
        .with_txt("_dmarc.example.com", "v=DMARC1; p=none; sp=reject")
        .with_a("mail.example.com");
    let out = run(dns, "mail.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.policy, DmarcPolicy::Reject);
    assert_eq!(out.verdict, AuthVerdict::Reject);
}

#[test]
fn np_applied_when_from_domain_nxdomain() {
    let dns = FakeDns::default().with_txt(
        "_dmarc.example.com",
        "v=DMARC1; p=none; sp=quarantine; np=reject",
    );
    // No A record for nonexistent.example.com → NXDOMAIN → np=reject.
    let out = run(
        dns,
        "nonexistent.example.com",
        SpfResult::Fail,
        None,
        vec![],
    );
    assert_eq!(out.policy, DmarcPolicy::Reject);
    assert_eq!(out.verdict, AuthVerdict::Reject);
}

#[test]
fn np_ignored_when_from_domain_exists() {
    let dns = FakeDns::default()
        .with_txt(
            "_dmarc.example.com",
            "v=DMARC1; p=none; sp=quarantine; np=reject",
        )
        .with_a("mail.example.com");
    let out = run(dns, "mail.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.policy, DmarcPolicy::Quarantine);
    assert_eq!(out.verdict, AuthVerdict::Quarantine);
}

#[test]
fn psd_tag_parsed() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=none; psd=y");
    let out = run(dns, "example.com", SpfResult::Pass, Some("example.com"), vec![]);
    assert!(out.record.as_ref().unwrap().psd);
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


// ── helpers ──────────────────────────────────────────────────────────────

fn with_record(record: &str) -> FakeDns {
    FakeDns::default().with_txt("_dmarc.example.com", record)
}

/// DMARC for example.com with SPF passing for `spf_domain` (and no DKIM).
fn spf_only(dns: FakeDns, spf_domain: &str) -> DmarcOutcome {
    run(dns, "example.com", SpfResult::Pass, Some(spf_domain), vec![])
}

fn failing(dns: FakeDns) -> DmarcOutcome {
    run(dns, "example.com", SpfResult::Fail, Some("example.com"), vec![])
}

fn record_of(text: &str) -> DmarcRecord {
    parse_record(text).unwrap_or_else(|()| panic!("{text} should parse"))
}

// ── the record ───────────────────────────────────────────────────────────

#[test]
fn a_minimal_record_has_the_defaults() {
    let r = record_of("v=DMARC1; p=none");
    assert_eq!(r.p, DmarcPolicy::None);
    assert_eq!((r.sp, r.np), (None, None));
    assert!(!r.psd);
    assert_eq!((r.adkim, r.aspf), (Alignment::Relaxed, Alignment::Relaxed));
    assert_eq!(r.pct, 100);
    assert!(r.rua.is_empty() && r.ruf.is_empty());
    assert_eq!(r.fo, ["0"]);
    assert_eq!(r.rf, ["afrf"]);
}

#[test]
fn every_tag_is_read() {
    let r = record_of(
        "v=DMARC1; p=reject; sp=quarantine; np=none; psd=y; adkim=s; aspf=s; pct=40; \
         rua=mailto:a@x.example,mailto:b@x.example!10m; ruf=mailto:f@x.example; fo=0:1:d:s; rf=afrf:iodef",
    );
    assert_eq!(r.p, DmarcPolicy::Reject);
    assert_eq!(r.sp, Some(DmarcPolicy::Quarantine));
    assert_eq!(r.np, Some(DmarcPolicy::None));
    assert!(r.psd);
    assert_eq!((r.adkim, r.aspf), (Alignment::Strict, Alignment::Strict));
    assert_eq!(r.pct, 40);
    assert_eq!(r.rua, ["mailto:a@x.example", "mailto:b@x.example!10m"]);
    assert_eq!(r.ruf, ["mailto:f@x.example"]);
    assert_eq!(r.fo, ["0", "1", "d", "s"]);
    assert_eq!(r.rf, ["afrf", "iodef"]);
}

#[test]
fn spaces_around_tags_and_values_and_a_trailing_semicolon_are_fine() {
    let r = record_of("  v=DMARC1 ;  p = reject ;pct= 50 ;");
    assert_eq!((r.p, r.pct), (DmarcPolicy::Reject, 50));
}

#[test]
fn unknown_tags_are_ignored() {
    let r = record_of("v=DMARC1; p=none; future=whatever; x-thing=1");
    assert_eq!(r.p, DmarcPolicy::None);
}

#[test]
fn policy_and_mode_values_are_not_case_sensitive() {
    // RFC 7489 section 6.4's ABNF literals are case-insensitive.
    let r = record_of("v=DMARC1; p=REJECT; sp=Quarantine; np=NONE; adkim=S; aspf=R; psd=Y");
    assert_eq!(r.p, DmarcPolicy::Reject);
    assert_eq!(r.sp, Some(DmarcPolicy::Quarantine));
    assert_eq!(r.np, Some(DmarcPolicy::None));
    assert_eq!((r.adkim, r.aspf), (Alignment::Strict, Alignment::Relaxed));
    assert!(r.psd);
}

#[test]
fn an_uppercase_reject_policy_is_enforced() {
    let out = failing(with_record("v=DMARC1; p=REJECT"));
    assert_eq!(out.result, DmarcResult::Fail);
    assert_eq!(out.verdict, AuthVerdict::Reject);
}

#[test]
fn records_with_bad_values_are_refused() {
    for bad in [
        "v=DMARC1",
        "v=DMARC1; p=maybe",
        "v=DMARC1; p=none; sp=maybe",
        "v=DMARC1; p=none; np=maybe",
        "v=DMARC1; p=none; adkim=x",
        "v=DMARC1; p=none; aspf=strict",
        "v=DMARC1; p=none; psd=maybe",
        "v=DMARC1; p=none; pct=101",
        "v=DMARC1; p=none; pct=abc",
        "v=DMARC1; p=none; pct=-1",
        "p=none",
        "v=DMARC2; p=none",
    ] {
        assert!(parse_record(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_percentage_may_be_zero_or_a_hundred() {
    assert_eq!(record_of("v=DMARC1; p=none; pct=0").pct, 0);
    assert_eq!(record_of("v=DMARC1; p=none; pct=100").pct, 100);
}

#[test]
fn empty_report_addresses_are_not_addresses() {
    let r = record_of("v=DMARC1; p=none; rua=; ruf=mailto:a@x.example,,");
    assert!(r.rua.is_empty(), "{:?}", r.rua);
    assert_eq!(r.ruf, ["mailto:a@x.example"]);
}

#[test]
fn only_a_v_tag_that_starts_the_record_makes_it_a_dmarc_record() {
    assert!(is_dmarc_record("v=DMARC1; p=none"));
    assert!(is_dmarc_record("  V=dmarc1; p=none"));
    assert!(!is_dmarc_record("p=none; v=DMARC1"));
    assert!(!is_dmarc_record("v=spf1 -all"));
    assert!(!is_dmarc_record(""));
}

#[test]
fn results_and_policies_have_their_names() {
    for (r, name) in [
        (DmarcResult::Pass, "pass"),
        (DmarcResult::Fail, "fail"),
        (DmarcResult::None, "none"),
        (DmarcResult::TempError, "temperror"),
        (DmarcResult::PermError, "permerror"),
    ] {
        assert_eq!(r.as_str(), name);
    }
}

// ── finding the record ───────────────────────────────────────────────────

#[test]
fn a_temporary_dns_failure_at_the_domain_or_at_the_organizational_domain_is_a_temperror() {
    let out = failing(FakeDns::default().with_temp_error("_dmarc.example.com"));
    assert_eq!(out.result, DmarcResult::TempError);
    assert_eq!(out.verdict, AuthVerdict::None);
    let out = run(
        FakeDns::default().with_temp_error("_dmarc.example.com"),
        "mail.example.com",
        SpfResult::Fail,
        None,
        vec![],
    );
    assert_eq!(out.result, DmarcResult::TempError, "the organizational domain's lookup failing is just as unknown");
}

#[test]
fn txt_records_at_the_name_that_are_not_dmarc_leave_the_set_empty_and_the_organizational_domain_is_asked() {
    // RFC 7489 section 6.6.3: records that are not DMARC are discarded, and
    // an empty set means "ask the organizational domain".
    let dns = FakeDns::default()
        .with_txt("_dmarc.mail.example.com", "v=spf1 -all") // e.g. a wildcard TXT
        .with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = run(dns, "mail.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.result, DmarcResult::Fail);
    assert_eq!(out.verdict, AuthVerdict::Reject, "the organizational domain's policy applies");
}

#[test]
fn txt_records_that_are_not_dmarc_anywhere_mean_no_policy() {
    let dns = FakeDns::default()
        .with_txt("_dmarc.example.com", "google-site-verification=x");
    assert_eq!(failing(dns).result, DmarcResult::None);
}

#[test]
fn a_non_dmarc_record_beside_the_dmarc_one_is_ignored() {
    let dns = with_record("something else").with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    assert_eq!(failing(dns).verdict, AuthVerdict::Reject);
}

#[test]
fn two_dmarc_records_at_the_name_are_a_permerror_with_no_enforcement() {
    let dns = with_record("v=DMARC1; p=none").with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = failing(dns);
    assert_eq!(out.result, DmarcResult::PermError);
    assert_eq!(out.verdict, AuthVerdict::None);
    assert!(out.record.is_none());
}

#[test]
fn a_malformed_record_at_the_organizational_domain_means_no_policy() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=bogus");
    let out = run(dns, "mail.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.result, DmarcResult::None);
}

#[test]
fn a_domain_that_is_its_own_organizational_domain_is_looked_up_once() {
    // No fallback exists for example.com itself.
    assert_eq!(failing(FakeDns::default()).result, DmarcResult::None);
}

#[test]
fn a_public_suffix_has_no_organizational_domain_to_fall_back_to() {
    let out = run(FakeDns::default(), "com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.result, DmarcResult::None);
}

#[test]
fn the_from_domain_is_read_without_regard_to_case_or_a_trailing_dot() {
    let out = run(with_record("v=DMARC1; p=reject"), "EXAMPLE.com.", SpfResult::Pass, Some("example.com"), vec![]);
    assert_eq!(out.result, DmarcResult::Pass);
    assert_eq!(out.from_domain, "example.com");
}

// ── alignment ────────────────────────────────────────────────────────────

#[test]
fn spf_aligns_only_when_it_passed_and_the_domain_matches() {
    let rec = "v=DMARC1; p=reject";
    assert_eq!(spf_only(with_record(rec), "example.com").result, DmarcResult::Pass);
    assert_eq!(spf_only(with_record(rec), "bounce.example.com").result, DmarcResult::Pass, "relaxed: same organizational domain");
    assert_eq!(spf_only(with_record(rec), "other.example").result, DmarcResult::Fail);
    for not_pass in [SpfResult::Fail, SpfResult::SoftFail, SpfResult::Neutral, SpfResult::None, SpfResult::TempError, SpfResult::PermError] {
        let out = run(with_record(rec), "example.com", not_pass, Some("example.com"), vec![]);
        assert_eq!(out.result, DmarcResult::Fail, "{not_pass:?}");
    }
    let out = run(with_record(rec), "example.com", SpfResult::Pass, None, vec![]);
    assert_eq!(out.result, DmarcResult::Fail, "no authenticated domain to align");
}

#[test]
fn strict_spf_alignment_wants_the_same_domain() {
    let rec = "v=DMARC1; p=reject; aspf=s";
    assert_eq!(spf_only(with_record(rec), "example.com").result, DmarcResult::Pass);
    assert_eq!(spf_only(with_record(rec), "bounce.example.com").result, DmarcResult::Fail);
}

#[test]
fn dkim_aligns_only_when_it_passed_and_the_domain_matches() {
    let rec = "v=DMARC1; p=reject";
    let d = |r: DkimResult, dom: &str| DkimSignatureResult { result: r, signing_domain: Some(dom.into()), selector: None };
    let out = run(with_record(rec), "example.com", SpfResult::Fail, None, vec![d(DkimResult::Fail, "example.com")]);
    assert_eq!(out.result, DmarcResult::Fail, "a failed signature does not count");
    let out = run(with_record(rec), "example.com", SpfResult::Fail, None, vec![d(DkimResult::Pass, "other.example")]);
    assert_eq!(out.result, DmarcResult::Fail, "an aligned domain is required");
    let no_domain = DkimSignatureResult { result: DkimResult::Pass, signing_domain: None, selector: None };
    let out = run(with_record(rec), "example.com", SpfResult::Fail, None, vec![no_domain]);
    assert_eq!(out.result, DmarcResult::Fail);
}

#[test]
fn any_one_aligned_passing_signature_is_enough() {
    let d = |r: DkimResult, dom: &str| DkimSignatureResult { result: r, signing_domain: Some(dom.into()), selector: None };
    let out = run(
        with_record("v=DMARC1; p=reject"),
        "example.com",
        SpfResult::Fail,
        None,
        vec![d(DkimResult::Pass, "esp.example"), d(DkimResult::Fail, "example.com"), d(DkimResult::Pass, "mail.example.com")],
    );
    assert_eq!(out.result, DmarcResult::Pass);
}

#[test]
fn strict_dkim_alignment_wants_the_same_domain() {
    let rec = "v=DMARC1; p=reject; adkim=s";
    let sig = |dom: &str| vec![dkim_pass(dom)];
    assert_eq!(run(with_record(rec), "example.com", SpfResult::Fail, None, sig("example.com")).result, DmarcResult::Pass);
    assert_eq!(run(with_record(rec), "example.com", SpfResult::Fail, None, sig("mail.example.com")).result, DmarcResult::Fail);
}

#[test]
fn alignment_modes_for_spf_and_dkim_are_independent() {
    let rec = "v=DMARC1; p=reject; aspf=s; adkim=r";
    let out = run(with_record(rec), "example.com", SpfResult::Pass, Some("bounce.example.com"), vec![dkim_pass("mail.example.com")]);
    assert_eq!(out.result, DmarcResult::Pass, "DKIM is relaxed, so it aligns even though strict SPF does not");
}

#[test]
fn domain_alignment_helper_handles_each_mode() {
    let p = psl();
    assert!(domain_aligns("example.com", "EXAMPLE.com.", p, Alignment::Strict));
    assert!(!domain_aligns("a.example.com", "example.com", p, Alignment::Strict));
    assert!(domain_aligns("a.example.com", "b.example.com", p, Alignment::Relaxed));
    assert!(!domain_aligns("example.com", "example.org", p, Alignment::Relaxed));
    // A public suffix is not an organizational domain: two names under it are different organizations.
    assert!(!domain_aligns("one.co.uk", "two.co.uk", p, Alignment::Relaxed));
}

// ── what is done about a failure ─────────────────────────────────────────

#[test]
fn a_pass_is_a_pass_whatever_the_policy() {
    for p in ["none", "quarantine", "reject"] {
        let out = spf_only(with_record(&format!("v=DMARC1; p={p}")), "example.com");
        assert_eq!((out.result, out.verdict), (DmarcResult::Pass, AuthVerdict::Pass), "{p}");
    }
}

#[test]
fn a_failure_gets_the_domains_policy() {
    for (p, verdict) in [
        ("none", AuthVerdict::None),
        ("quarantine", AuthVerdict::Quarantine),
        ("reject", AuthVerdict::Reject),
    ] {
        let out = failing(with_record(&format!("v=DMARC1; p={p}")));
        assert_eq!(out.verdict, verdict, "{p}");
        assert_eq!(out.policy, match p { "none" => DmarcPolicy::None, "quarantine" => DmarcPolicy::Quarantine, _ => DmarcPolicy::Reject });
        assert!(out.record.is_some());
    }
}

#[test]
fn a_percentage_of_zero_takes_the_policy_one_step_down() {
    for (p, verdict) in [
        ("reject", AuthVerdict::Quarantine),
        ("quarantine", AuthVerdict::None),
        ("none", AuthVerdict::None),
    ] {
        let out = failing(with_record(&format!("v=DMARC1; p={p}; pct=0")));
        assert_eq!(out.verdict, verdict, "{p}");
        assert_eq!(out.policy, match p { "none" => DmarcPolicy::None, "quarantine" => DmarcPolicy::Quarantine, _ => DmarcPolicy::Reject }, "the policy reported is the published one");
    }
}

#[test]
fn a_percentage_in_between_applies_to_about_that_share_of_failures() {
    let mut rejected = 0u32;
    for _ in 0..2000 {
        if failing(with_record("v=DMARC1; p=reject; pct=25")).verdict == AuthVerdict::Reject {
            rejected += 1;
        }
    }
    // Every other failure gets quarantine; 25% of 2000 is 500.
    assert!((380..=620).contains(&rejected), "{rejected} of 2000 were rejected");
}

#[test]
fn a_hundred_percent_never_downgrades() {
    for _ in 0..200 {
        assert_eq!(failing(with_record("v=DMARC1; p=reject; pct=100")).verdict, AuthVerdict::Reject);
    }
}

#[test]
fn a_subdomain_using_the_organizational_record_gets_sp_and_otherwise_p() {
    let both = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject; sp=none");
    let out = run(both, "mail.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!((out.policy, out.verdict), (DmarcPolicy::None, AuthVerdict::None));
    let only_p = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject");
    let out = run(only_p, "mail.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.verdict, AuthVerdict::Reject);
}

#[test]
fn np_is_used_for_a_subdomain_that_does_not_exist_and_sp_for_one_that_does() {
    let rec = "v=DMARC1; p=none; sp=quarantine; np=reject";
    let dns = || FakeDns::default().with_txt("_dmarc.example.com", rec);
    let out = run(dns(), "ghost.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.verdict, AuthVerdict::Reject, "no A record: it does not exist");
    let out = run(dns().with_a("real.example.com"), "real.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.verdict, AuthVerdict::Quarantine);
}

#[test]
fn np_falls_back_to_sp_then_p_when_not_given() {
    let dns = FakeDns::default().with_txt("_dmarc.example.com", "v=DMARC1; p=reject; sp=quarantine");
    // No np: the existence lookup is skipped and sp applies.
    let out = run(dns, "ghost.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.verdict, AuthVerdict::Quarantine);
}

#[test]
fn a_dns_failure_checking_whether_the_subdomain_exists_is_a_temperror() {
    let dns = FakeDns::default()
        .with_txt("_dmarc.example.com", "v=DMARC1; p=none; np=reject")
        .with_temp_error("ghost.example.com");
    let out = run(dns, "ghost.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.result, DmarcResult::TempError);
}

#[test]
fn np_is_not_consulted_when_the_domain_has_its_own_record() {
    let dns = FakeDns::default().with_txt("_dmarc.ghost.example.com", "v=DMARC1; p=quarantine; np=reject");
    let out = run(dns, "ghost.example.com", SpfResult::Fail, None, vec![]);
    assert_eq!(out.verdict, AuthVerdict::Quarantine);
}

#[test]
fn the_verdict_is_none_when_there_is_no_record() {
    let out = failing(FakeDns::default());
    assert_eq!((out.result, out.verdict, out.policy), (DmarcResult::None, AuthVerdict::None, DmarcPolicy::None));
    assert!(out.record.is_none());
}
