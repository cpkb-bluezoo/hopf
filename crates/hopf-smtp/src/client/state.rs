// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Gumdrop-shaped SMTP client state traits.
//!
//! Each trait represents a stage of the SMTP protocol state machine.
//! Implementations on [`super::endpoint::SmtpClientEndpoint`] accept commands
//! and buffer them for dispatch; the actual bytes are flushed to the endpoint
//! after the driver callback returns.

use std::time::Duration;

use crate::{BodyType, DsnRecipientParams, DsnReturn};

/// Post-connect stage: send EHLO or HELO.
pub trait SmtpClientHello {
    /// Send `EHLO hostname`.
    fn ehlo(&mut self, hostname: &str);
    /// Send `HELO hostname`.
    fn helo(&mut self, hostname: &str);
    /// Send `QUIT` and close, without establishing a session — e.g. the
    /// server isn't acceptable (wrong host, policy violation), or (for the
    /// post-STARTTLS stage) TLS succeeded but the handler decides not to
    /// continue.
    fn quit(&mut self);
}

/// `MAIL FROM` extension parameters. Reuses the same wire vocabulary the
/// server side already parses (`server::delivery::parse_mail_from_arg`):
/// `SIZE=`, `BODY=`, `SMTPUTF8`, `RET=`, `ENVID=`, `REQUIRETLS`,
/// `MT-PRIORITY=`, `HOLDFOR=` (FUTURERELEASE), `BY=` (DELIVERBY). All
/// fields default to "not sent".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailFromParams {
    /// `SIZE=n` (RFC 1870) — declared message size in octets.
    pub size: Option<u64>,
    /// `BODY=` (RFC 6152 / RFC 3030).
    pub body: Option<BodyType>,
    /// `SMTPUTF8` (RFC 6531).
    pub smtputf8: bool,
    /// `RET=` (RFC 3461 DSN).
    pub dsn_ret: Option<DsnReturn>,
    /// `ENVID=` (RFC 3461 DSN).
    pub dsn_envid: Option<String>,
    /// `REQUIRETLS` (RFC 8689).
    pub require_tls: bool,
    /// `MT-PRIORITY=` (RFC 6710), −9…+9.
    pub priority: Option<i8>,
    /// `HOLDFOR=` (FUTURERELEASE, RFC 4865) — hold for this long before
    /// attempting delivery.
    pub hold_for: Option<Duration>,
    /// `BY=seconds[R|N]` (DELIVERBY, RFC 2852) — deadline interval and
    /// whether the server should return (`true`) or just notify (`false`)
    /// on failure to meet it.
    pub deliver_by: Option<(Duration, bool)>,
}

impl MailFromParams {
    /// Render as ` KEY=VALUE` tokens appended after `MAIL FROM:<addr>`.
    pub(super) fn render(&self) -> String {
        let mut out = String::new();
        if let Some(n) = self.size {
            out.push_str(&format!(" SIZE={n}"));
        }
        if let Some(body) = self.body {
            let tag = match body {
                BodyType::SevenBit => "7BIT",
                BodyType::EightBitMime => "8BITMIME",
                BodyType::BinaryMime => "BINARYMIME",
            };
            out.push_str(&format!(" BODY={tag}"));
        }
        if self.smtputf8 {
            out.push_str(" SMTPUTF8");
        }
        if let Some(ret) = self.dsn_ret {
            let tag = match ret {
                DsnReturn::Full => "FULL",
                DsnReturn::Hdrs => "HDRS",
            };
            out.push_str(&format!(" RET={tag}"));
        }
        if let Some(ref envid) = self.dsn_envid {
            out.push_str(&format!(" ENVID={envid}"));
        }
        if self.require_tls {
            out.push_str(" REQUIRETLS");
        }
        if let Some(p) = self.priority {
            out.push_str(&format!(" MT-PRIORITY={p}"));
        }
        if let Some(d) = self.hold_for {
            out.push_str(&format!(" HOLDFOR={}", d.as_secs()));
        }
        if let Some((d, return_on_fail)) = self.deliver_by {
            let flag = if return_on_fail { "R" } else { "N" };
            out.push_str(&format!(" BY={}{flag}", d.as_secs()));
        }
        out
    }
}

/// Capabilities advertised by the server in its EHLO response.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SmtpCapabilities {
    /// Server advertises STARTTLS (RFC 3207).
    pub starttls: bool,
    /// Maximum message size in bytes; 0 = unrestricted (RFC 1870).
    pub max_size: u64,
    /// Advertised AUTH mechanisms (uppercased, RFC 4954).
    pub auth_methods: Vec<String>,
    /// PIPELINING (RFC 2920).
    pub pipelining: bool,
    /// CHUNKING / BDAT (RFC 3030).
    pub chunking: bool,
    /// 8BITMIME (RFC 6152).
    pub eight_bit_mime: bool,
    /// SMTPUTF8 (RFC 6531).
    pub smtp_utf8: bool,
    /// DSN (RFC 3461).
    pub dsn: bool,
    /// ENHANCEDSTATUSCODES (RFC 2034).
    pub enhanced_status_codes: bool,
    /// REQUIRETLS (RFC 8689).
    pub require_tls: bool,
    /// BINARYMIME (RFC 3030).
    pub binary_mime: bool,
    /// MT-PRIORITY (RFC 6710) — server accepts the MAIL FROM parameter.
    pub mt_priority: bool,
    /// FUTURERELEASE (RFC 4865) — server accepts HOLDFOR/HOLDUNTIL.
    pub future_release: bool,
    /// DELIVERBY (RFC 2852) — server accepts the BY parameter.
    pub deliver_by: bool,
    /// LIMITS RCPTMAX (RFC 9422) — max recipients per message; 0 = unstated.
    pub limits_rcpt_max: u32,
    /// LIMITS MAILMAX (RFC 9422) — max messages per connection; 0 = unstated.
    pub limits_mail_max: u32,
}

/// Post-EHLO stage: envelope, STARTTLS, AUTH, QUIT.
pub trait SmtpClientSession: SmtpClientHello {
    /// Send `MAIL FROM:<sender>` (or `<>` for null sender), with optional
    /// extension parameters (SIZE, BODY, SMTPUTF8, DSN RET/ENVID,
    /// REQUIRETLS, MT-PRIORITY, FUTURERELEASE, DELIVERBY).
    fn mail_from(&mut self, sender: Option<&str>, params: &MailFromParams);

    /// Send `STARTTLS`.
    fn starttls(&mut self);

    /// Send `AUTH mechanism [initial-response]`.
    ///
    /// `initial` is the base64-encoded initial response if provided.
    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>);

    // `quit()` is inherited from the `SmtpClientHello` supertrait.

    /// Send `VRFY address` (RFC 5321 §3.5.1) to verify a mailbox exists.
    fn vrfy(&mut self, address: &str);

    /// Send `EXPN list` (RFC 5321 §3.5.2) to expand a mailing list.
    fn expn(&mut self, list: &str);

    /// Capabilities from the server's EHLO response.
    fn capabilities(&self) -> &SmtpCapabilities;
}

/// Post-STARTTLS stage: must re-EHLO.
pub trait SmtpClientPostTls: SmtpClientHello {}

/// AUTH SASL exchange (RFC 4954).
pub trait SmtpClientAuthExchange {
    /// Send a base64-encoded SASL response.
    fn respond(&mut self, response: &[u8]);
    /// Abort AUTH with `*`.
    fn abort(&mut self);
}

/// Post-MAIL-FROM stage: RCPT TO, RSET, DATA.
pub trait SmtpClientEnvelope: SmtpClientSession {
    /// Send `RCPT TO:<recipient>`, with optional DSN NOTIFY/ORCPT parameters.
    fn rcpt_to(&mut self, recipient: &str, params: &DsnRecipientParams);
    /// Send `RSET`.
    fn rset(&mut self);
    /// Send `DATA` (or enter BDAT mode if CHUNKING is available).
    fn start_data(&mut self);
    /// Whether at least one RCPT TO has been accepted.
    fn has_accepted_recipients(&self) -> bool;
}

/// DATA-ready stage: write content then end.
pub trait SmtpClientMessageData {
    /// Append dot-stuffed content to the DATA stream.
    fn write_content(&mut self, content: &[u8]);
    /// End the message (`CRLF.CRLF`).
    fn end_message(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_params_render_nothing() {
        assert_eq!(MailFromParams::default().render(), "");
    }

    #[test]
    fn all_params_render_in_order() {
        let params = MailFromParams {
            size: Some(1024),
            body: Some(BodyType::EightBitMime),
            smtputf8: true,
            dsn_ret: Some(DsnReturn::Full),
            dsn_envid: Some("xyz123".into()),
            require_tls: true,
            priority: Some(-3),
            hold_for: Some(Duration::from_secs(300)),
            deliver_by: Some((Duration::from_secs(3600), true)),
        };
        assert_eq!(
            params.render(),
            " SIZE=1024 BODY=8BITMIME SMTPUTF8 RET=FULL ENVID=xyz123 REQUIRETLS \
             MT-PRIORITY=-3 HOLDFOR=300 BY=3600R"
        );
    }

    #[test]
    fn deliver_by_notify_flag() {
        let params = MailFromParams {
            deliver_by: Some((Duration::from_secs(60), false)),
            ..Default::default()
        };
        assert_eq!(params.render(), " BY=60N");
    }
}
