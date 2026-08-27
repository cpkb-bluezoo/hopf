// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DMARC — Domain-based Message Authentication, Reporting, and Conformance
//! (RFC 7489), plus `np=` / `psd=` from the in-progress DMARCbis revision.
//!
//! `np=` (non-existent subdomain policy) is applied when the organizational
//! domain's record is used and an A lookup for the exact `From:` domain
//! returns NXDOMAIN. `psd=` is parsed and exposed on [`DmarcRecord`].

pub mod aggregate;
pub mod forensic;

pub use aggregate::{
    AggregateRecord, DkimAuthResult, DmarcAggregateReport, PublishedPolicy, ReportMetadata,
    SpfAuthResult,
};
pub use forensic::{AuthFailureKind, DmarcForensicReport};

use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::dkim::{DkimResult, DkimSignatureResult};
use crate::auth::dns_lookup::{DnsLookup, Lookup};
use crate::auth::psl::PublicSuffixList;
use crate::auth::spf::SpfResult;

/// RFC 7489 §11.2 result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcResult {
    /// SPF or DKIM aligned and passed.
    Pass,
    /// Neither aligned.
    Fail,
    /// No DMARC record found for the domain or its organizational domain.
    None,
    /// Transient DNS error.
    TempError,
    /// Malformed record, or ambiguous (multiple) records at the DNS name.
    PermError,
}

impl DmarcResult {
    /// `Authentication-Results`-style lowercase token (RFC 7489 §11.2
    /// registers `dmarc` as an Authentication-Results method).
    pub fn as_str(&self) -> &'static str {
        match self {
            DmarcResult::Pass => "pass",
            DmarcResult::Fail => "fail",
            DmarcResult::None => "none",
            DmarcResult::TempError => "temperror",
            DmarcResult::PermError => "permerror",
        }
    }
}

/// `p=`/`sp=`/`np=` policy value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// No explicit policy action requested.
    None,
    /// Suggest quarantine (e.g. spam folder).
    Quarantine,
    /// Suggest rejection.
    Reject,
}

/// Actual enforcement decision after alignment, policy, and `pct=` sampling
/// (Gumdrop `AuthVerdict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthVerdict {
    /// Message authenticated; deliver normally.
    Pass,
    /// Reject the message.
    Reject,
    /// Quarantine the message.
    Quarantine,
    /// No enforcement (monitor-only policy, or no usable record).
    None,
}

/// `adkim=`/`aspf=` alignment mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    /// Exact domain match required.
    Strict,
    /// Organizational-domain match suffices (default).
    Relaxed,
}

/// Parsed `_dmarc` TXT record (RFC 7489 §6.4 / DMARCbis).
#[derive(Debug, Clone)]
pub struct DmarcRecord {
    /// `p=` — policy for the domain itself.
    pub p: DmarcPolicy,
    /// `sp=` — policy for subdomains (defaults to `p` when absent).
    pub sp: Option<DmarcPolicy>,
    /// `np=` — policy for non-existent subdomains (DMARCbis).
    pub np: Option<DmarcPolicy>,
    /// `psd=` — record is published for a Public Suffix Domain (DMARCbis).
    pub psd: bool,
    /// `adkim=` — DKIM alignment mode (default relaxed).
    pub adkim: Alignment,
    /// `aspf=` — SPF alignment mode (default relaxed).
    pub aspf: Alignment,
    /// `pct=` — percentage of failing messages the policy applies to (default 100).
    pub pct: u8,
    /// `rua=` — aggregate report URIs.
    pub rua: Vec<String>,
    /// `ruf=` — forensic report URIs.
    pub ruf: Vec<String>,
    /// `fo=` — failure reporting options (default `["0"]`).
    pub fo: Vec<String>,
    /// `rf=` — failure report format (default `["afrf"]`).
    pub rf: Vec<String>,
}

/// Outcome of a DMARC evaluation.
#[derive(Debug, Clone)]
pub struct DmarcOutcome {
    /// Alignment result.
    pub result: DmarcResult,
    /// Effective policy considered (before `pct=` sampling/downgrade).
    pub policy: DmarcPolicy,
    /// The `From:` header domain evaluated.
    pub from_domain: String,
    /// Enforcement decision.
    pub verdict: AuthVerdict,
    /// The record used, if any (for report generation).
    pub record: Option<DmarcRecord>,
}

/// Callback receiving the [`DmarcOutcome`].
pub type DmarcCallback = Box<dyn FnOnce(DmarcOutcome) + Send>;

/// Evaluate DMARC for a message (RFC 7489 §6.6.3, §6.7).
///
/// * `from_domain` — the RFC 5322 `From:` header's domain.
/// * `spf_result`/`spf_domain` — the SPF outcome and the domain SPF actually
///   authenticated (`MAIL FROM` or `HELO` domain).
/// * `dkim_results` — every verified `DKIM-Signature` (from
///   [`crate::auth::dkim::verify_all_with_body_hashes`]) — DMARC must
///   consider all of them, not just the first, when checking DKIM alignment.
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    dns: Arc<dyn DnsLookup>,
    psl: &'static PublicSuffixList,
    from_domain: &str,
    has_duplicate_from: bool,
    spf_result: SpfResult,
    spf_domain: Option<String>,
    dkim_results: Arc<Vec<DkimSignatureResult>>,
    cb: DmarcCallback,
) {
    let from_domain = from_domain.trim_end_matches('.').to_ascii_lowercase();
    let query_name = format!("_dmarc.{from_domain}");
    let from_domain_cb = from_domain.clone();
    let dns_inner = Arc::clone(&dns);
    dns.query_txt(
        &query_name,
        Box::new(move |lookup| match lookup {
            Lookup::TempError => cb(empty_outcome(DmarcResult::TempError, from_domain_cb)),
            Lookup::Answers(txts) => match select_record(&txts) {
                Ok(text) => match parse_record(&text) {
                    Ok(record) => finish_with_record(
                        Arc::clone(&dns_inner),
                        from_domain_cb,
                        false,
                        record,
                        psl,
                        has_duplicate_from,
                        spf_result,
                        spf_domain,
                        dkim_results,
                        cb,
                    ),
                    Err(()) => cb(empty_outcome(DmarcResult::PermError, from_domain_cb)),
                },
                Err(()) => cb(empty_outcome(DmarcResult::PermError, from_domain_cb)),
            },
            Lookup::NxDomain | Lookup::NoData => match psl.organizational_domain(&from_domain_cb) {
                Some(org) if org != from_domain_cb => {
                    let org_query = format!("_dmarc.{org}");
                    let dns2 = Arc::clone(&dns_inner);
                    dns_inner.query_txt(
                        &org_query,
                        Box::new(move |lookup2| match lookup2 {
                            Lookup::TempError => {
                                cb(empty_outcome(DmarcResult::TempError, from_domain_cb))
                            }
                            Lookup::Answers(txts) => match select_record(&txts) {
                                Ok(text) => match parse_record(&text) {
                                    Ok(record) => finish_with_record(
                                        dns2,
                                        from_domain_cb,
                                        true,
                                        record,
                                        psl,
                                        has_duplicate_from,
                                        spf_result,
                                        spf_domain,
                                        dkim_results,
                                        cb,
                                    ),
                                    Err(()) => cb(empty_outcome(DmarcResult::None, from_domain_cb)),
                                },
                                Err(()) => cb(empty_outcome(DmarcResult::None, from_domain_cb)),
                            },
                            Lookup::NxDomain | Lookup::NoData => {
                                cb(empty_outcome(DmarcResult::None, from_domain_cb))
                            }
                        }),
                    );
                }
                _ => cb(empty_outcome(DmarcResult::None, from_domain_cb)),
            },
        }),
    );
}

fn empty_outcome(result: DmarcResult, from_domain: String) -> DmarcOutcome {
    DmarcOutcome {
        result,
        policy: DmarcPolicy::None,
        from_domain,
        verdict: AuthVerdict::None,
        record: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_with_record(
    dns: Arc<dyn DnsLookup>,
    from_domain: String,
    used_org_fallback: bool,
    record: DmarcRecord,
    psl: &'static PublicSuffixList,
    has_duplicate_from: bool,
    spf_result: SpfResult,
    spf_domain: Option<String>,
    dkim_results: Arc<Vec<DkimSignatureResult>>,
    cb: DmarcCallback,
) {
    // RFC 5322 §3.6.2 permits at most one `From:` header; a message with
    // more than one is ambiguous about which one a recipient's mail client
    // will display, so alignment against `from_domain` (necessarily just
    // one of them) cannot be trusted to vouch for what the recipient
    // actually sees — treat the message the same as a failed alignment
    // (RFC 7489 §7.6) rather than risk a PASS for the wrong header.
    let spf_aligned = !has_duplicate_from
        && spf_result == SpfResult::Pass
        && spf_domain
            .as_deref()
            .map(|d| domain_aligns(d, &from_domain, psl, record.aspf))
            .unwrap_or(false);
    let dkim_aligned = !has_duplicate_from
        && dkim_results.iter().any(|r| {
            r.result == DkimResult::Pass
                && r.signing_domain
                    .as_deref()
                    .map(|d| domain_aligns(d, &from_domain, psl, record.adkim))
                    .unwrap_or(false)
        });
    let result = if spf_aligned || dkim_aligned {
        DmarcResult::Pass
    } else {
        DmarcResult::Fail
    };

    // DMARCbis `np=`: when using the organizational domain's record, check
    // whether the exact From: domain exists. NXDOMAIN → apply `np` (else `sp`).
    if used_org_fallback && record.np.is_some() {
        let from_check = from_domain.clone();
        dns.query_a(
            &from_check,
            Box::new(move |lookup| {
                match lookup {
                    Lookup::TempError => {
                        cb(empty_outcome(DmarcResult::TempError, from_domain));
                    }
                    Lookup::NxDomain => {
                        emit_outcome(from_domain, result, record, true, true, cb);
                    }
                    Lookup::Answers(_) | Lookup::NoData => {
                        emit_outcome(from_domain, result, record, true, false, cb);
                    }
                }
            }),
        );
        return;
    }

    emit_outcome(from_domain, result, record, used_org_fallback, false, cb);
}

fn emit_outcome(
    from_domain: String,
    result: DmarcResult,
    record: DmarcRecord,
    used_org_fallback: bool,
    from_domain_nxdomain: bool,
    cb: DmarcCallback,
) {
    let base_policy = if used_org_fallback {
        if from_domain_nxdomain {
            record.np.unwrap_or_else(|| record.sp.unwrap_or(record.p))
        } else {
            record.sp.unwrap_or(record.p)
        }
    } else {
        record.p
    };

    let verdict = if result == DmarcResult::Pass {
        AuthVerdict::Pass
    } else {
        let effective = if sample_in_pct(record.pct) {
            base_policy
        } else {
            downgrade(base_policy)
        };
        match effective {
            DmarcPolicy::None => AuthVerdict::None,
            DmarcPolicy::Quarantine => AuthVerdict::Quarantine,
            DmarcPolicy::Reject => AuthVerdict::Reject,
        }
    };

    cb(DmarcOutcome {
        result,
        policy: base_policy,
        from_domain,
        verdict,
        record: Some(record),
    });
}

fn downgrade(policy: DmarcPolicy) -> DmarcPolicy {
    match policy {
        DmarcPolicy::Reject => DmarcPolicy::Quarantine,
        DmarcPolicy::Quarantine => DmarcPolicy::None,
        DmarcPolicy::None => DmarcPolicy::None,
    }
}

fn sample_in_pct(pct: u8) -> bool {
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }
    let mut buf = [0u8; 1];
    if getrandom::getrandom(&mut buf).is_err() {
        return true;
    }
    (buf[0] as u16 * 100 / 256) < pct as u16
}

/// RFC 7489 §3.2 alignment check between an authenticated domain and the
/// `From:` domain.
pub fn domain_aligns(
    auth_domain: &str,
    from_domain: &str,
    psl: &PublicSuffixList,
    mode: Alignment,
) -> bool {
    let a = auth_domain.trim_end_matches('.').to_ascii_lowercase();
    let f = from_domain.trim_end_matches('.').to_ascii_lowercase();
    if a == f {
        return true;
    }
    match mode {
        Alignment::Strict => false,
        Alignment::Relaxed => {
            let oa = psl.organizational_domain(&a).unwrap_or(a);
            let of = psl.organizational_domain(&f).unwrap_or(f);
            oa == of
        }
    }
}

/// Exactly one `v=DMARC1` record must be present at the queried name (RFC
/// 7489 §6.6.3); zero or multiple is an error.
fn select_record(txts: &[String]) -> Result<String, ()> {
    let matching: Vec<&String> = txts.iter().filter(|t| is_dmarc_record(t)).collect();
    match matching.len() {
        1 => Ok(matching[0].clone()),
        _ => Err(()),
    }
}

fn is_dmarc_record(txt: &str) -> bool {
    let t = txt.trim_start();
    t.len() >= 8 && t[..8].eq_ignore_ascii_case("v=DMARC1")
}

fn parse_tag_list(value: &str) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, val)) = part.split_once('=') {
            tags.insert(name.trim().to_ascii_lowercase(), val.trim().to_string());
        }
    }
    tags
}

fn parse_policy(s: &str) -> Result<DmarcPolicy, ()> {
    match s {
        "none" => Ok(DmarcPolicy::None),
        "quarantine" => Ok(DmarcPolicy::Quarantine),
        "reject" => Ok(DmarcPolicy::Reject),
        _ => Err(()),
    }
}

fn parse_record(txt: &str) -> Result<DmarcRecord, ()> {
    let tags = parse_tag_list(txt);
    if !tags
        .get("v")
        .map(|v| v.eq_ignore_ascii_case("DMARC1"))
        .unwrap_or(false)
    {
        return Err(());
    }
    let p = parse_policy(tags.get("p").ok_or(())?)?;
    let sp = match tags.get("sp") {
        Some(s) => Some(parse_policy(s)?),
        None => None,
    };
    let np = match tags.get("np") {
        Some(s) => Some(parse_policy(s)?),
        None => None,
    };
    let psd = match tags.get("psd").map(|s| s.as_str()) {
        Some("y") | Some("yes") => true,
        Some("n") | Some("no") | None => false,
        Some(_) => return Err(()),
    };
    let adkim = match tags.get("adkim").map(|s| s.as_str()) {
        Some("s") => Alignment::Strict,
        Some("r") | None => Alignment::Relaxed,
        Some(_) => return Err(()),
    };
    let aspf = match tags.get("aspf").map(|s| s.as_str()) {
        Some("s") => Alignment::Strict,
        Some("r") | None => Alignment::Relaxed,
        Some(_) => return Err(()),
    };
    let pct = match tags.get("pct") {
        Some(s) => {
            let n: u8 = s.parse().map_err(|_| ())?;
            if n > 100 {
                return Err(());
            }
            n
        }
        None => 100,
    };
    let rua = tags
        .get("rua")
        .map(|s| s.split(',').map(|u| u.trim().to_string()).collect())
        .unwrap_or_default();
    let ruf = tags
        .get("ruf")
        .map(|s| s.split(',').map(|u| u.trim().to_string()).collect())
        .unwrap_or_default();
    let fo = tags
        .get("fo")
        .map(|s| s.split(':').map(|u| u.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["0".to_string()]);
    let rf = tags
        .get("rf")
        .map(|s| s.split(':').map(|u| u.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["afrf".to_string()]);
    Ok(DmarcRecord {
        p,
        sp,
        np,
        psd,
        adkim,
        aspf,
        pct,
        rua,
        ruf,
        fo,
        rf,
    })
}

#[cfg(test)]
mod tests;
