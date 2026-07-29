// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DMARC aggregate ("rua") report XML (RFC 7489 Appendix C).
//!
//! Building and sending these reports is app-driven — Gumdrop's stock
//! pipelines don't do it either — this module only renders the XML document
//! from data the app has already aggregated.

use std::fmt::Write as _;
use std::net::IpAddr;

use super::{Alignment, AuthVerdict, DmarcPolicy};
use crate::auth::dkim::DkimResult;
use crate::auth::spf::SpfResult;

/// `report_metadata` block.
#[derive(Debug, Clone)]
pub struct ReportMetadata {
    /// Name of the organization generating the report.
    pub org_name: String,
    /// Contact address for report questions.
    pub email: String,
    /// Additional contact info (e.g. a URL), optional.
    pub extra_contact_info: Option<String>,
    /// Unique report identifier.
    pub report_id: String,
    /// Reporting period start (UNIX seconds).
    pub begin: u64,
    /// Reporting period end (UNIX seconds).
    pub end: u64,
}

/// `policy_published` block — the DMARC record in effect for the period.
#[derive(Debug, Clone)]
pub struct PublishedPolicy {
    /// Domain the policy applies to.
    pub domain: String,
    /// `adkim=`.
    pub adkim: Alignment,
    /// `aspf=`.
    pub aspf: Alignment,
    /// `p=`.
    pub p: DmarcPolicy,
    /// `sp=`, if published.
    pub sp: Option<DmarcPolicy>,
    /// `pct=`.
    pub pct: u8,
}

/// One DKIM signature's contribution to `auth_results`.
#[derive(Debug, Clone)]
pub struct DkimAuthResult {
    /// `d=` of the signature.
    pub domain: String,
    /// `s=` of the signature.
    pub selector: Option<String>,
    /// Verification result.
    pub result: DkimResult,
}

/// SPF's contribution to `auth_results`.
#[derive(Debug, Clone)]
pub struct SpfAuthResult {
    /// Domain SPF was checked against.
    pub domain: String,
    /// Check result.
    pub result: SpfResult,
}

/// One `<record>` — traffic seen from `source_ip` claiming `header_from`.
#[derive(Debug, Clone)]
pub struct AggregateRecord {
    /// Sending IP address.
    pub source_ip: IpAddr,
    /// Number of messages matching this row (aggregation count).
    pub count: u64,
    /// Disposition actually applied.
    pub disposition: AuthVerdict,
    /// Whether DKIM was DMARC-aligned for this traffic.
    pub dkim_aligned: bool,
    /// Whether SPF was DMARC-aligned for this traffic.
    pub spf_aligned: bool,
    /// RFC 5322 `From:` domain.
    pub header_from: String,
    /// Per-signature DKIM results.
    pub dkim_auth_results: Vec<DkimAuthResult>,
    /// SPF result.
    pub spf_auth_results: Vec<SpfAuthResult>,
}

/// Builds an RFC 7489 Appendix C aggregate report XML document.
pub struct DmarcAggregateReport {
    metadata: ReportMetadata,
    policy: PublishedPolicy,
    records: Vec<AggregateRecord>,
}

impl DmarcAggregateReport {
    /// New report for `metadata`/`policy`, no records yet.
    pub fn new(metadata: ReportMetadata, policy: PublishedPolicy) -> Self {
        Self {
            metadata,
            policy,
            records: Vec::new(),
        }
    }

    /// Append one traffic record.
    pub fn add_record(&mut self, record: AggregateRecord) -> &mut Self {
        self.records.push(record);
        self
    }

    /// Render the `<feedback>` XML document.
    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<feedback>\n");

        out.push_str("  <report_metadata>\n");
        write_elem(&mut out, 4, "org_name", &self.metadata.org_name);
        write_elem(&mut out, 4, "email", &self.metadata.email);
        if let Some(extra) = &self.metadata.extra_contact_info {
            write_elem(&mut out, 4, "extra_contact_info", extra);
        }
        write_elem(&mut out, 4, "report_id", &self.metadata.report_id);
        out.push_str("    <date_range>\n");
        write_elem(&mut out, 6, "begin", &self.metadata.begin.to_string());
        write_elem(&mut out, 6, "end", &self.metadata.end.to_string());
        out.push_str("    </date_range>\n");
        out.push_str("  </report_metadata>\n");

        out.push_str("  <policy_published>\n");
        write_elem(&mut out, 4, "domain", &self.policy.domain);
        write_elem(&mut out, 4, "adkim", alignment_str(self.policy.adkim));
        write_elem(&mut out, 4, "aspf", alignment_str(self.policy.aspf));
        write_elem(&mut out, 4, "p", policy_str(self.policy.p));
        if let Some(sp) = self.policy.sp {
            write_elem(&mut out, 4, "sp", policy_str(sp));
        }
        write_elem(&mut out, 4, "pct", &self.policy.pct.to_string());
        out.push_str("  </policy_published>\n");

        for r in &self.records {
            out.push_str("  <record>\n    <row>\n");
            write_elem(&mut out, 6, "source_ip", &r.source_ip.to_string());
            write_elem(&mut out, 6, "count", &r.count.to_string());
            out.push_str("      <policy_evaluated>\n");
            write_elem(&mut out, 8, "disposition", disposition_str(r.disposition));
            write_elem(&mut out, 8, "dkim", pass_fail(r.dkim_aligned));
            write_elem(&mut out, 8, "spf", pass_fail(r.spf_aligned));
            out.push_str("      </policy_evaluated>\n");
            out.push_str("    </row>\n");
            out.push_str("    <identifiers>\n");
            write_elem(&mut out, 6, "header_from", &r.header_from);
            out.push_str("    </identifiers>\n");
            out.push_str("    <auth_results>\n");
            for d in &r.dkim_auth_results {
                out.push_str("      <dkim>\n");
                write_elem(&mut out, 8, "domain", &d.domain);
                if let Some(s) = &d.selector {
                    write_elem(&mut out, 8, "selector", s);
                }
                write_elem(&mut out, 8, "result", d.result.as_str());
                out.push_str("      </dkim>\n");
            }
            for s in &r.spf_auth_results {
                out.push_str("      <spf>\n");
                write_elem(&mut out, 8, "domain", &s.domain);
                write_elem(&mut out, 8, "result", s.result.as_str());
                out.push_str("      </spf>\n");
            }
            out.push_str("    </auth_results>\n");
            out.push_str("  </record>\n");
        }

        out.push_str("</feedback>\n");
        out
    }
}

fn write_elem(out: &mut String, indent: usize, name: &str, value: &str) {
    let _ = writeln!(
        out,
        "{:indent$}<{name}>{}</{name}>",
        "",
        xml_escape(value),
        indent = indent
    );
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

fn alignment_str(a: Alignment) -> &'static str {
    match a {
        Alignment::Relaxed => "r",
        Alignment::Strict => "s",
    }
}

fn policy_str(p: DmarcPolicy) -> &'static str {
    match p {
        DmarcPolicy::None => "none",
        DmarcPolicy::Quarantine => "quarantine",
        DmarcPolicy::Reject => "reject",
    }
}

fn disposition_str(v: AuthVerdict) -> &'static str {
    match v {
        AuthVerdict::Pass | AuthVerdict::None => "none",
        AuthVerdict::Quarantine => "quarantine",
        AuthVerdict::Reject => "reject",
    }
}

fn pass_fail(b: bool) -> &'static str {
    if b {
        "pass"
    } else {
        "fail"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_well_formed_document() {
        let metadata = ReportMetadata {
            org_name: "Example Reporter".to_string(),
            email: "noreply@example.org".to_string(),
            extra_contact_info: None,
            report_id: "1234".to_string(),
            begin: 1_753_600_000,
            end: 1_753_686_400,
        };
        let policy = PublishedPolicy {
            domain: "example.com".to_string(),
            adkim: Alignment::Relaxed,
            aspf: Alignment::Relaxed,
            p: DmarcPolicy::Reject,
            sp: Some(DmarcPolicy::Reject),
            pct: 100,
        };
        let mut report = DmarcAggregateReport::new(metadata, policy);
        report.add_record(AggregateRecord {
            source_ip: "203.0.113.9".parse().unwrap(),
            count: 3,
            disposition: AuthVerdict::Reject,
            dkim_aligned: false,
            spf_aligned: true,
            header_from: "example.com".to_string(),
            dkim_auth_results: vec![DkimAuthResult {
                domain: "example.com".to_string(),
                selector: Some("sel1".to_string()),
                result: DkimResult::Fail,
            }],
            spf_auth_results: vec![SpfAuthResult {
                domain: "example.com".to_string(),
                result: SpfResult::Pass,
            }],
        });
        let xml = report.to_xml();
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"));
        assert!(xml.contains("<org_name>Example Reporter</org_name>"));
        assert!(xml.contains("<source_ip>203.0.113.9</source_ip>"));
        assert!(xml.contains("<count>3</count>"));
        assert!(xml.contains("<disposition>reject</disposition>"));
        assert!(xml.contains("<dkim>fail</dkim>"));
        assert!(xml.contains("<spf>pass</spf>"));
        assert!(xml.contains("<result>fail</result>"));
        assert!(xml.contains("<result>pass</result>"));
        assert!(xml.trim_end().ends_with("</feedback>"));
    }

    #[test]
    fn escapes_untrusted_text_fields() {
        let metadata = ReportMetadata {
            org_name: "A & B <evil>".to_string(),
            email: "x@example.org".to_string(),
            extra_contact_info: None,
            report_id: "r1".to_string(),
            begin: 0,
            end: 1,
        };
        let policy = PublishedPolicy {
            domain: "example.com".to_string(),
            adkim: Alignment::Relaxed,
            aspf: Alignment::Relaxed,
            p: DmarcPolicy::None,
            sp: None,
            pct: 100,
        };
        let report = DmarcAggregateReport::new(metadata, policy);
        let xml = report.to_xml();
        assert!(xml.contains("A &amp; B &lt;evil&gt;"));
        assert!(!xml.contains("<evil>"));
    }
}
