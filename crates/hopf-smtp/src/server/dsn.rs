// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 3461 Delivery Status Notifications for stock SMTP handlers.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use rmimeparser::EmailAddress;

use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams, DsnReturn};

/// Per-recipient delivery outcome used when building a DSN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsnAction {
    /// Message successfully delivered to the mailbox / next hop.
    Delivered,
    /// Permanent or temporary failure to deliver.
    Failed,
}

impl DsnAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Failed => "failed",
        }
    }

    fn status(self) -> &'static str {
        match self {
            Self::Delivered => "2.0.0",
            Self::Failed => "5.0.0",
        }
    }
}

/// One recipient line in a DSN.
#[derive(Debug, Clone)]
pub struct DsnRecipientReport {
    /// Final recipient (RFC822 address).
    pub final_recipient: String,
    /// ORCPT original recipient, if supplied (`type;address`).
    pub original_recipient: Option<String>,
    /// Outcome for this recipient.
    pub action: DsnAction,
    /// Human-readable diagnostic (optional).
    pub diagnostic: Option<String>,
}

/// Inputs for a complete RFC 3461 `multipart/report; report-type=delivery-status`.
#[derive(Debug, Clone)]
pub struct DeliveryStatusNotification {
    /// Reporting MTA hostname.
    pub reporting_mta: String,
    /// Envelope sender that should receive the DSN (null → do not send).
    pub reverse_path: Option<EmailAddress>,
    /// Message-level delivery requirements (RET / ENVID).
    pub delivery: DeliveryRequirements,
    /// Per-recipient outcomes.
    pub recipients: Vec<DsnRecipientReport>,
    /// Original message bytes (used when `RET=FULL`); headers-only when
    /// `RET=HDRS` or REQUIRETLS forces headers (RFC 8689 §4.5).
    pub original_message: Vec<u8>,
}

impl DeliveryStatusNotification {
    /// Whether any recipient report should produce a DSN for the reverse-path.
    pub fn should_notify(recipients: &[(DsnRecipientParams, DsnAction)]) -> bool {
        recipients.iter().any(|(params, action)| match action {
            DsnAction::Delivered => params.notify.wants_success(),
            DsnAction::Failed => params.notify.wants_failure(),
        })
    }

    /// Filter to the recipients that actually requested this notification.
    pub fn filter_reports(
        reports: Vec<(DsnRecipientParams, DsnRecipientReport)>,
    ) -> Vec<DsnRecipientReport> {
        reports
            .into_iter()
            .filter_map(|(params, report)| {
                let want = match report.action {
                    DsnAction::Delivered => params.notify.wants_success(),
                    DsnAction::Failed => params.notify.wants_failure(),
                };
                want.then_some(report)
            })
            .collect()
    }

    /// Render a complete RFC 5322 message (headers + body) suitable for
    /// delivery to the reverse-path.
    pub fn render(&self) -> Option<Vec<u8>> {
        let to = self.reverse_path.as_ref()?;
        if self.recipients.is_empty() {
            return None;
        }

        let boundary = "----=_hopf-dsn";
        let date = smtp_date_now();
        let message_id = format!(
            "<dsn.{}.{}@{}>",
            now_secs(),
            self.recipients.len(),
            self.reporting_mta
        );

        let mut out = String::new();
        let _ = writeln!(out, "From: Mail Delivery System <mailer-daemon@{}>", self.reporting_mta);
        let _ = writeln!(out, "To: {}", to.address());
        let _ = writeln!(out, "Date: {date}");
        let _ = writeln!(out, "Message-ID: {message_id}");
        let _ = writeln!(out, "Subject: Delivery Status Notification");
        let _ = writeln!(out, "MIME-Version: 1.0");
        let _ = writeln!(
            out,
            "Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\""
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "This is a MIME-formatted message.");
        let _ = writeln!(out);
        let _ = writeln!(out, "--{boundary}");
        let _ = writeln!(out, "Content-Type: text/plain; charset=utf-8");
        let _ = writeln!(out);
        out.push_str(&self.human_text());
        let _ = writeln!(out);
        let _ = writeln!(out, "--{boundary}");
        let _ = writeln!(out, "Content-Type: message/delivery-status");
        let _ = writeln!(out);
        out.push_str(&self.delivery_status_body());
        let _ = writeln!(out, "--{boundary}");

        let ret_full = matches!(self.delivery.dsn_ret, Some(DsnReturn::Full))
            && !self.delivery.require_tls;
        if ret_full {
            let _ = writeln!(out, "Content-Type: message/rfc822");
            let _ = writeln!(out);
            out.push_str(&String::from_utf8_lossy(&self.original_message));
            if !self.original_message.ends_with(b"\n") {
                let _ = writeln!(out);
            }
        } else {
            let _ = writeln!(out, "Content-Type: text/rfc822-headers");
            let _ = writeln!(out);
            out.push_str(&headers_only(&self.original_message));
            if !out.ends_with('\n') {
                let _ = writeln!(out);
            }
        }
        let _ = writeln!(out, "--{boundary}--");
        Some(out.into_bytes())
    }

    fn human_text(&self) -> String {
        let mut text = String::from(
            "This is the mail system at host {}. A message you sent has produced a delivery status notification.\r\n\r\n",
        );
        text = text.replace("{}", &self.reporting_mta);
        for r in &self.recipients {
            let _ = writeln!(
                text,
                "  <{}>: {}",
                r.final_recipient,
                r.action.as_str()
            );
            if let Some(d) = &r.diagnostic {
                let _ = writeln!(text, "    ({d})");
            }
        }
        text
    }

    fn delivery_status_body(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "Reporting-MTA: dns;{}", self.reporting_mta);
        if let Some(envid) = &self.delivery.dsn_envid {
            let _ = writeln!(out, "Original-Envelope-Id: {envid}");
        }
        let _ = writeln!(out, "Arrival-Date: {}", smtp_date_now());
        let _ = writeln!(out);
        for r in &self.recipients {
            if let Some(orcpt) = &r.original_recipient {
                let _ = writeln!(out, "Original-Recipient: {orcpt}");
            }
            let _ = writeln!(out, "Final-Recipient: rfc822;{}", r.final_recipient);
            let _ = writeln!(out, "Action: {}", r.action.as_str());
            let _ = writeln!(out, "Status: {}", r.action.status());
            if let Some(d) = &r.diagnostic {
                let _ = writeln!(out, "Diagnostic-Code: smtp;{d}");
            }
            let _ = writeln!(out);
        }
        out
    }
}

fn headers_only(message: &[u8]) -> String {
    let text = String::from_utf8_lossy(message);
    if let Some(idx) = text.find("\r\n\r\n") {
        text[..idx + 2].to_string()
    } else if let Some(idx) = text.find("\n\n") {
        text[..idx + 1].to_string()
    } else {
        text.into_owned()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn smtp_date_now() -> String {
    // RFC 5322-ish UTC date without pulling in a full time crate.
    let secs = now_secs();
    let days = secs / 86400;
    let time = secs % 86400;
    let hour = time / 3600;
    let min = (time % 3600) / 60;
    let sec = time % 60;
    // Civil date from days since Unix epoch (1970-01-01 = Thursday).
    let (y, m, d) = civil_from_days(days as i64);
    let wday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days % 7) as usize];
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(m - 1) as usize];
    format!("{wday}, {d:02} {month} {y} {hour:02}:{min:02}:{sec:02} +0000")
}

/// Algorithm from Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Format an ORCPT field (`type;address`) from DSN recipient params.
pub fn orcpt_field(params: &DsnRecipientParams) -> Option<String> {
    match (&params.orcpt_type, &params.orcpt_address) {
        (Some(ty), Some(addr)) => Some(format!("{ty};{addr}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::delivery::DsnNotify;

    #[test]
    fn default_notify_wants_failure_not_success() {
        let n = DsnNotify::default();
        assert!(n.wants_failure());
        assert!(!n.wants_success());
    }

    #[test]
    fn render_includes_envid_and_headers_only_by_default() {
        let dsn = DeliveryStatusNotification {
            reporting_mta: "mail.example".into(),
            reverse_path: Some(EmailAddress::new(None, "alice", "example.com", true)),
            delivery: DeliveryRequirements {
                dsn_envid: Some("abc123".into()),
                dsn_ret: Some(DsnReturn::Hdrs),
                ..Default::default()
            },
            recipients: vec![DsnRecipientReport {
                final_recipient: "bob@example.com".into(),
                original_recipient: Some("rfc822;bob@example.com".into()),
                action: DsnAction::Failed,
                diagnostic: Some("mailbox full".into()),
            }],
            original_message: b"From: a\r\nSubject: hi\r\n\r\nbody\r\n".to_vec(),
        };
        let bytes = dsn.render().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Original-Envelope-Id: abc123"));
        assert!(text.contains("Action: failed"));
        assert!(text.contains("text/rfc822-headers"));
        assert!(!text.contains("\r\nbody\r\n"));
    }

    #[test]
    fn requiretls_forces_headers_even_with_ret_full() {
        let dsn = DeliveryStatusNotification {
            reporting_mta: "mail.example".into(),
            reverse_path: Some(EmailAddress::new(None, "alice", "example.com", true)),
            delivery: DeliveryRequirements {
                require_tls: true,
                dsn_ret: Some(DsnReturn::Full),
                ..Default::default()
            },
            recipients: vec![DsnRecipientReport {
                final_recipient: "bob@example.com".into(),
                original_recipient: None,
                action: DsnAction::Failed,
                diagnostic: None,
            }],
            original_message: b"Subject: s\r\n\r\nsecret\r\n".to_vec(),
        };
        let rendered = dsn.render().unwrap();
        let text = String::from_utf8_lossy(&rendered);
        assert!(text.contains("text/rfc822-headers"));
        assert!(!text.contains("secret"));
    }
}
