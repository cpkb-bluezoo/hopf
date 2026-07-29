// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DMARC forensic ("ruf") failure reports — Abuse Reporting Format (RFC
//! 5965) with the `auth-failure` feedback type (RFC 6591).
//!
//! Building and sending these reports is app-driven, same as
//! [`super::aggregate`] — this module only renders the MIME document.

use std::fmt::Write as _;
use std::net::IpAddr;

/// What failed authentication, for the `Auth-Failure:` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureKind {
    /// DKIM signature failed or was absent/unaligned.
    Dkim,
    /// SPF failed or was unaligned.
    Spf,
}

impl AuthFailureKind {
    fn as_str(self) -> &'static str {
        match self {
            AuthFailureKind::Dkim => "dkim",
            AuthFailureKind::Spf => "spf",
        }
    }
}

/// Data needed to render one forensic report.
pub struct DmarcForensicReport {
    /// Human-readable text for the first MIME part.
    pub human_text: String,
    /// `User-Agent:` value (e.g. `"hopf-smtp/0.1"`).
    pub user_agent: String,
    /// `Original-Envelope-Id:` / report identifier, optional.
    pub original_envelope_id: Option<String>,
    /// `Original-Mail-From:`.
    pub original_mail_from: Option<String>,
    /// `Original-Rcpt-To:`.
    pub original_rcpt_to: Option<String>,
    /// `Arrival-Date:` (RFC 5322 date-time string).
    pub arrival_date: String,
    /// `Source-IP:`.
    pub source_ip: IpAddr,
    /// `Authentication-Results:` value.
    pub authentication_results: String,
    /// `Reported-Domain:` — the `From:` domain being reported on.
    pub reported_domain: String,
    /// Which mechanism(s) failed.
    pub auth_failure: Vec<AuthFailureKind>,
    /// `DKIM-Domain:`, if a DKIM signature was present.
    pub dkim_domain: Option<String>,
    /// `DKIM-Selector:`, if a DKIM signature was present.
    pub dkim_selector: Option<String>,
    /// Original message headers, verbatim (`Name: value\r\n` per line), for
    /// the trailing `text/rfc822-headers` part.
    pub original_headers: String,
}

impl DmarcForensicReport {
    /// Render as a complete `multipart/report; report-type=feedback-report`
    /// MIME document body (everything after the outer message's own headers
    /// — callers wrap this with their own `From`/`To`/`Subject`/`MIME-Version`
    /// and this `Content-Type`).
    pub fn to_mime(&self) -> String {
        let boundary = "----=_hopf-dmarc-forensic-report";
        let mut out = String::new();

        out.push_str(&format!(
            "This is a multipart message in MIME format.\r\n\r\n--{boundary}\r\n"
        ));
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
        out.push_str(&self.human_text);
        out.push_str("\r\n\r\n");

        out.push_str(&format!("--{boundary}\r\n"));
        out.push_str("Content-Type: message/feedback-report\r\n\r\n");
        out.push_str(&self.feedback_report_body());
        out.push_str("\r\n");

        out.push_str(&format!("--{boundary}\r\n"));
        out.push_str("Content-Type: text/rfc822-headers\r\n\r\n");
        out.push_str(&self.original_headers);
        out.push_str("\r\n");

        out.push_str(&format!("--{boundary}--\r\n"));
        out
    }

    fn feedback_report_body(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "Feedback-Type: auth-failure");
        let _ = writeln!(out, "User-Agent: {}", self.user_agent);
        let _ = writeln!(out, "Version: 1");
        if let Some(id) = &self.original_envelope_id {
            let _ = writeln!(out, "Original-Envelope-Id: {id}");
        }
        if let Some(from) = &self.original_mail_from {
            let _ = writeln!(out, "Original-Mail-From: {from}");
        }
        if let Some(rcpt) = &self.original_rcpt_to {
            let _ = writeln!(out, "Original-Rcpt-To: {rcpt}");
        }
        let _ = writeln!(out, "Arrival-Date: {}", self.arrival_date);
        let _ = writeln!(out, "Source-IP: {}", self.source_ip);
        let _ = writeln!(
            out,
            "Authentication-Results: {}",
            self.authentication_results
        );
        let _ = writeln!(out, "Reported-Domain: {}", self.reported_domain);
        for kind in &self.auth_failure {
            let _ = writeln!(out, "Auth-Failure: {}", kind.as_str());
        }
        if let Some(d) = &self.dkim_domain {
            let _ = writeln!(out, "DKIM-Domain: {d}");
        }
        if let Some(s) = &self.dkim_selector {
            let _ = writeln!(out, "DKIM-Selector: {s}");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DmarcForensicReport {
        DmarcForensicReport {
            human_text: "This is an authentication failure report.".to_string(),
            user_agent: "hopf-smtp/0.1".to_string(),
            original_envelope_id: None,
            original_mail_from: Some("sender@example.com".to_string()),
            original_rcpt_to: Some("recipient@example.org".to_string()),
            arrival_date: "Tue, 28 Jul 2026 10:00:00 +0000".to_string(),
            source_ip: "203.0.113.9".parse().unwrap(),
            authentication_results: "example.org; dmarc=fail header.from=example.com".to_string(),
            reported_domain: "example.com".to_string(),
            auth_failure: vec![AuthFailureKind::Spf, AuthFailureKind::Dkim],
            dkim_domain: Some("example.com".to_string()),
            dkim_selector: Some("sel1".to_string()),
            original_headers: "From: sender@example.com\r\nTo: recipient@example.org\r\n"
                .to_string(),
        }
    }

    #[test]
    fn renders_multipart_structure() {
        let mime = sample().to_mime();
        assert!(mime.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(mime.contains("Content-Type: message/feedback-report"));
        assert!(mime.contains("Content-Type: text/rfc822-headers"));
        assert!(mime.contains("Feedback-Type: auth-failure"));
        assert!(mime.contains("Auth-Failure: spf"));
        assert!(mime.contains("Auth-Failure: dkim"));
        assert!(mime.contains("Source-IP: 203.0.113.9"));
        assert!(mime.contains("DKIM-Domain: example.com"));
        assert!(mime.ends_with("--\r\n"));
    }

    #[test]
    fn includes_original_headers_verbatim() {
        let mime = sample().to_mime();
        assert!(mime.contains("From: sender@example.com\r\nTo: recipient@example.org\r\n"));
    }
}
