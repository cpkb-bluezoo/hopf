// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Optional RFC 8601 `Authentication-Results` header synthesis for
//! [`super::AuthPipeline`] — issue #87.

use std::sync::Arc;

use crate::auth::dkim::DkimSignatureResult;
use crate::auth::dmarc::DmarcOutcome;
use crate::auth::spf::SpfOutcome;

use super::Relay;

/// Shared, cloneable handle to a synthesized `Authentication-Results`
/// header field — resolves once SPF, DKIM, and (when a `From:` domain was
/// present) DMARC have all been evaluated. Obtain via
/// [`super::AuthPipeline::authentication_results`], which returns `None`
/// unless [`super::AuthPipelineBuilder::authentication_results`] was used
/// to opt in.
///
/// The resolved [`String`] is the complete field — `"Authentication-Results: "`
/// through the last result, **without** a trailing CRLF — ready to prepend
/// (plus your own `\r\n`) to the stored/delivered message. Applying it is
/// the caller's responsibility: see the type-level docs on
/// [`super::AuthPipelineBuilder::authentication_results`] for why this
/// can't safely happen automatically, and for the interaction with a
/// `message_handler` tee such as a spool file.
#[derive(Clone)]
pub struct AuthResultsHandle(pub(super) Arc<Relay<String>>);

impl AuthResultsHandle {
    /// Non-blocking check: `Some(header_field)` if synthesis has completed.
    pub fn poll(&self) -> Option<String> {
        self.0.peek()
    }

    /// Run `cb` once the header field is available (immediately, if it
    /// already is).
    pub fn on_ready(&self, cb: impl FnOnce(String) + Send + 'static) {
        self.0.on_ready(Box::new(cb));
    }
}

/// Render the complete `Authentication-Results:` field (RFC 8601 §2.2,
/// §2.7), one `resinfo` per method, folded onto its own line. `dmarc` is
/// `None` when there was no usable `From:` domain to evaluate DMARC
/// against (the same fail-open case [`super::AuthVerdictHandle`] resolves
/// to [`crate::auth::dmarc::AuthVerdict::None`] for) — rendered as
/// `dmarc=none` for the same reason `dkim=none`/`spf=none` are used below
/// when nothing to report was found.
pub(super) fn render_authentication_results(
    authserv_id: &str,
    spf: &SpfOutcome,
    spf_domain: &str,
    dkim_results: &[DkimSignatureResult],
    dmarc: Option<&DmarcOutcome>,
) -> String {
    let mut out = format!("Authentication-Results: {authserv_id};");

    out.push_str(&format!(
        "\r\n\tspf={} smtp.mailfrom={}",
        spf.result.as_str(),
        spf_domain
    ));

    if dkim_results.is_empty() {
        out.push_str(";\r\n\tdkim=none");
    } else {
        for r in dkim_results {
            out.push(';');
            out.push_str(&format!("\r\n\tdkim={}", r.result.as_str()));
            if let Some(d) = &r.signing_domain {
                out.push_str(&format!(" header.d={d}"));
            }
        }
    }

    match dmarc {
        Some(outcome) => {
            out.push(';');
            out.push_str(&format!(
                "\r\n\tdmarc={} header.from={}",
                outcome.result.as_str(),
                outcome.from_domain
            ));
        }
        None => {
            out.push(';');
            out.push_str("\r\n\tdmarc=none");
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::dkim::DkimResult;
    use crate::auth::dmarc::{DmarcPolicy, DmarcResult};
    use crate::auth::spf::SpfResult;

    fn spf(result: SpfResult) -> SpfOutcome {
        SpfOutcome {
            result,
            explanation: None,
        }
    }

    #[test]
    fn renders_all_pass_with_no_signatures() {
        let rendered = render_authentication_results(
            "mail.example.com",
            &spf(SpfResult::Pass),
            "example.com",
            &[],
            None,
        );
        assert_eq!(
            rendered,
            "Authentication-Results: mail.example.com;\r\n\tspf=pass smtp.mailfrom=example.com;\r\n\tdkim=none;\r\n\tdmarc=none"
        );
    }

    #[test]
    fn renders_dkim_and_dmarc_results_with_domains() {
        let dkim = vec![DkimSignatureResult {
            result: DkimResult::Pass,
            signing_domain: Some("example.com".to_string()),
            selector: Some("selector1".to_string()),
        }];
        let dmarc = DmarcOutcome {
            result: DmarcResult::Pass,
            policy: DmarcPolicy::Reject,
            from_domain: "example.com".to_string(),
            verdict: crate::auth::dmarc::AuthVerdict::Pass,
            record: None,
        };
        let rendered = render_authentication_results(
            "mail.example.com",
            &spf(SpfResult::Pass),
            "example.com",
            &dkim,
            Some(&dmarc),
        );
        assert!(rendered.starts_with("Authentication-Results: mail.example.com;"));
        assert!(rendered.contains("spf=pass smtp.mailfrom=example.com;"));
        assert!(rendered.contains("dkim=pass header.d=example.com;"));
        assert!(rendered.ends_with("dmarc=pass header.from=example.com"));
        assert!(!rendered.ends_with(';'), "no trailing semicolon after the last resinfo");
    }

    #[test]
    fn renders_multiple_signatures_as_separate_resinfo() {
        let dkim = vec![
            DkimSignatureResult {
                result: DkimResult::Pass,
                signing_domain: Some("a.example".to_string()),
                selector: Some("s1".to_string()),
            },
            DkimSignatureResult {
                result: DkimResult::Fail,
                signing_domain: Some("b.example".to_string()),
                selector: Some("s2".to_string()),
            },
        ];
        let rendered = render_authentication_results(
            "mail.example.com",
            &spf(SpfResult::None),
            "example.com",
            &dkim,
            None,
        );
        assert!(rendered.contains("dkim=pass header.d=a.example;"));
        assert!(rendered.contains("dkim=fail header.d=b.example;"));
    }
}
