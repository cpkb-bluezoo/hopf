// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MAIL FROM / RCPT TO parameters and delivery preferences.

use std::time::{Duration, SystemTime};

/// BODY parameter (RFC 6152 / RFC 3030).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BodyType {
    /// Traditional 7-bit.
    #[default]
    SevenBit,
    /// 8BITMIME.
    EightBitMime,
    /// BINARYMIME (requires BDAT).
    BinaryMime,
}

impl BodyType {
    /// Parse `7BIT` / `8BITMIME` / `BINARYMIME` (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "7BIT" => Some(Self::SevenBit),
            "8BITMIME" => Some(Self::EightBitMime),
            "BINARYMIME" => Some(Self::BinaryMime),
            _ => None,
        }
    }

    /// BINARYMIME must use BDAT, not DATA.
    pub fn requires_bdat(self) -> bool {
        matches!(self, Self::BinaryMime)
    }
}

/// DSN RET parameter (RFC 3461).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsnReturn {
    /// Include full original message.
    Full,
    /// Headers only.
    Hdrs,
}

impl DsnReturn {
    /// Parse `FULL` / `HDRS`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "FULL" => Some(Self::Full),
            "HDRS" => Some(Self::Hdrs),
            _ => None,
        }
    }
}

/// DELIVERBY deadline (RFC 2852).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverBy {
    /// Absolute deadline.
    pub deadline: SystemTime,
    /// `true` = return (R), `false` = notify (N).
    pub return_on_fail: bool,
}

/// Message-level delivery requirements from MAIL FROM parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryRequirements {
    /// REQUIRETLS (RFC 8689).
    pub require_tls: bool,
    /// MT-PRIORITY (−9…+9).
    pub priority: Option<i8>,
    /// FUTURERELEASE hold-until time.
    pub hold_until: Option<SystemTime>,
    /// DELIVERBY deadline.
    pub deliver_by: Option<DeliverBy>,
    /// DSN RET.
    pub dsn_ret: Option<DsnReturn>,
    /// DSN ENVID.
    pub dsn_envid: Option<String>,
}

impl DeliveryRequirements {
    /// REQUIRETLS was requested.
    pub fn is_require_tls(&self) -> bool {
        self.require_tls
    }

    /// MT-PRIORITY was specified.
    pub fn has_priority(&self) -> bool {
        self.priority.is_some()
    }

    /// FUTURERELEASE hold is active.
    pub fn is_future_release(&self) -> bool {
        self.hold_until.is_some()
    }

    /// DELIVERBY deadline was specified.
    pub fn has_deliver_by_deadline(&self) -> bool {
        self.deliver_by.is_some()
    }
}

/// DSN NOTIFY flags (RFC 3461).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DsnNotify {
    /// NEVER (exclusive).
    pub never: bool,
    /// SUCCESS.
    pub success: bool,
    /// FAILURE.
    pub failure: bool,
    /// DELAY.
    pub delay: bool,
}

/// Per-recipient DSN parameters from RCPT TO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DsnRecipientParams {
    /// NOTIFY flags.
    pub notify: DsnNotify,
    /// ORCPT type (e.g. `rfc822`).
    pub orcpt_type: Option<String>,
    /// ORCPT address.
    pub orcpt_address: Option<String>,
}

impl DsnRecipientParams {
    /// Render as ` KEY=VALUE` tokens appended after `RCPT TO:<addr>`,
    /// matching exactly what [`parse_rcpt_to_arg`] parses back.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let n = &self.notify;
        if n.never || n.success || n.failure || n.delay {
            let mut flags = Vec::new();
            if n.never {
                flags.push("NEVER");
            } else {
                if n.success {
                    flags.push("SUCCESS");
                }
                if n.failure {
                    flags.push("FAILURE");
                }
                if n.delay {
                    flags.push("DELAY");
                }
            }
            out.push_str(&format!(" NOTIFY={}", flags.join(",")));
        }
        if let (Some(ty), Some(addr)) = (&self.orcpt_type, &self.orcpt_address) {
            out.push_str(&format!(" ORCPT={ty};{addr}"));
        }
        out
    }
}

/// Parsed MAIL FROM argument (address + extension params).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailFromParse {
    /// Envelope sender; `None` for null reverse-path.
    pub sender_raw: Option<String>,
    /// Declared SIZE.
    pub size: Option<u64>,
    /// BODY type.
    pub body: BodyType,
    /// SMTPUTF8 requested.
    pub smtputf8: bool,
    /// Delivery options.
    pub delivery: DeliveryRequirements,
}

/// Error parsing MAIL FROM / RCPT parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamParseError {
    /// Human-readable reason.
    pub message: String,
}

impl ParamParseError {
    fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

/// Pragmatic MAIL FROM argument parser (`FROM:<addr> [params…]`).
pub fn parse_mail_from_arg(arg: &str) -> Result<MailFromParse, ParamParseError> {
    let arg = arg.trim();
    let rest = arg
        .strip_prefix("FROM:")
        .or_else(|| arg.strip_prefix("from:"))
        .or_else(|| arg.strip_prefix("From:"))
        .ok_or_else(|| ParamParseError::new("Syntax: MAIL FROM:<address>"))?
        .trim();

    let (address_part, params_part) = split_angle_or_token(rest)?;
    let sender_raw = if address_part.is_empty() {
        None
    } else {
        Some(address_part.to_string())
    };

    let mut out = MailFromParse {
        sender_raw,
        size: None,
        body: BodyType::SevenBit,
        smtputf8: false,
        delivery: DeliveryRequirements::default(),
    };

    if let Some(params) = params_part {
        for param in split_params(params) {
            let upper = param.to_ascii_uppercase();
            if let Some(v) = upper.strip_prefix("SIZE=") {
                let n: u64 = v
                    .parse()
                    .map_err(|_| ParamParseError::new("Invalid SIZE parameter"))?;
                out.size = Some(n);
            } else if let Some(v) = upper.strip_prefix("BODY=") {
                out.body = BodyType::parse(v)
                    .ok_or_else(|| ParamParseError::new("Invalid BODY parameter"))?;
            } else if upper == "SMTPUTF8" {
                out.smtputf8 = true;
            } else if upper == "REQUIRETLS" {
                out.delivery.require_tls = true;
            } else if let Some(v) = upper.strip_prefix("MT-PRIORITY=") {
                let p: i8 = v
                    .parse()
                    .map_err(|_| ParamParseError::new("Invalid MT-PRIORITY"))?;
                out.delivery.priority = Some(p);
            } else if let Some(v) = upper.strip_prefix("RET=") {
                out.delivery.dsn_ret = Some(
                    DsnReturn::parse(v)
                        .ok_or_else(|| ParamParseError::new("Invalid RET parameter"))?,
                );
            } else if let Some(v) = param.split_once('=').filter(|(k, _)| {
                k.eq_ignore_ascii_case("ENVID")
            }) {
                out.delivery.dsn_envid = Some(v.1.to_string());
            } else if let Some(v) = upper.strip_prefix("HOLDFOR=") {
                let secs: u64 = v
                    .parse()
                    .map_err(|_| ParamParseError::new("Invalid HOLDFOR"))?;
                out.delivery.hold_until =
                    Some(SystemTime::now() + Duration::from_secs(secs));
            } else if let Some(v) = upper.strip_prefix("HOLDUNTIL=") {
                // Pragmatic: treat as unix seconds if numeric.
                if let Ok(secs) = v.parse::<u64>() {
                    out.delivery.hold_until =
                        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
                }
            } else if let Some(v) = upper.strip_prefix("BY=") {
                // BY=seconds[R|N] — simplified absolute offset from now.
                let (num, ret) = if let Some(n) = v.strip_suffix('R') {
                    (n, true)
                } else if let Some(n) = v.strip_suffix('N') {
                    (n, false)
                } else {
                    (v, true)
                };
                let secs: u64 = num
                    .parse()
                    .map_err(|_| ParamParseError::new("Invalid BY parameter"))?;
                out.delivery.deliver_by = Some(DeliverBy {
                    deadline: SystemTime::now() + Duration::from_secs(secs),
                    return_on_fail: ret,
                });
            }
            // Unknown params ignored pragmatically.
        }
    }
    Ok(out)
}

/// Parse RCPT TO argument → (address, dsn params).
pub fn parse_rcpt_to_arg(arg: &str) -> Result<(String, DsnRecipientParams), ParamParseError> {
    let arg = arg.trim();
    let rest = arg
        .strip_prefix("TO:")
        .or_else(|| arg.strip_prefix("to:"))
        .or_else(|| arg.strip_prefix("To:"))
        .ok_or_else(|| ParamParseError::new("Syntax: RCPT TO:<address>"))?
        .trim();

    let (address_part, params_part) = split_angle_or_token(rest)?;
    if address_part.is_empty() {
        return Err(ParamParseError::new("Empty recipient address"));
    }

    let mut dsn = DsnRecipientParams::default();
    if let Some(params) = params_part {
        for param in split_params(params) {
            let upper = param.to_ascii_uppercase();
            if let Some(v) = upper.strip_prefix("NOTIFY=") {
                for part in v.split(',') {
                    match part.trim() {
                        "NEVER" => dsn.notify.never = true,
                        "SUCCESS" => dsn.notify.success = true,
                        "FAILURE" => dsn.notify.failure = true,
                        "DELAY" => dsn.notify.delay = true,
                        _ => {
                            return Err(ParamParseError::new("Invalid NOTIFY parameter"));
                        }
                    }
                }
                if dsn.notify.never
                    && (dsn.notify.success || dsn.notify.failure || dsn.notify.delay)
                {
                    return Err(ParamParseError::new(
                        "NOTIFY=NEVER cannot be combined with other values",
                    ));
                }
            } else if let Some((_, rest)) = param.split_once('=').filter(|(k, _)| {
                k.eq_ignore_ascii_case("ORCPT")
            }) {
                if let Some((ty, addr)) = rest.split_once(';') {
                    dsn.orcpt_type = Some(ty.to_string());
                    dsn.orcpt_address = Some(addr.to_string());
                } else {
                    return Err(ParamParseError::new(
                        "Invalid ORCPT syntax (expected type;address)",
                    ));
                }
            }
        }
    }
    Ok((address_part.to_string(), dsn))
}

fn split_angle_or_token(rest: &str) -> Result<(&str, Option<&str>), ParamParseError> {
    if rest.starts_with('<') {
        let close = rest
            .find('>')
            .ok_or_else(|| ParamParseError::new("Unclosed angle-addr"))?;
        let addr = &rest[1..close];
        let after = rest[close + 1..].trim();
        Ok((addr, if after.is_empty() { None } else { Some(after) }))
    } else {
        let mut parts = rest.splitn(2, char::is_whitespace);
        let addr = parts.next().unwrap_or("");
        let after = parts.next().map(str::trim).filter(|s| !s.is_empty());
        Ok((addr, after))
    }
}

fn split_params(params: &str) -> Vec<&str> {
    params.split_whitespace().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_sender() {
        let p = parse_mail_from_arg("FROM:<>").unwrap();
        assert!(p.sender_raw.is_none());
    }

    #[test]
    fn mail_params() {
        let p = parse_mail_from_arg(
            "FROM:<a@b.com> SIZE=100 BODY=8BITMIME SMTPUTF8 REQUIRETLS RET=HDRS ENVID=xyz",
        )
        .unwrap();
        assert_eq!(p.sender_raw.as_deref(), Some("a@b.com"));
        assert_eq!(p.size, Some(100));
        assert_eq!(p.body, BodyType::EightBitMime);
        assert!(p.smtputf8);
        assert!(p.delivery.require_tls);
        assert_eq!(p.delivery.dsn_ret, Some(DsnReturn::Hdrs));
        assert_eq!(p.delivery.dsn_envid.as_deref(), Some("xyz"));
    }

    #[test]
    fn rcpt_notify() {
        let (addr, dsn) =
            parse_rcpt_to_arg("TO:<u@d.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;o@d.com")
                .unwrap();
        assert_eq!(addr, "u@d.com");
        assert!(dsn.notify.success && dsn.notify.failure);
        assert_eq!(dsn.orcpt_type.as_deref(), Some("rfc822"));
    }

    #[test]
    fn dsn_recipient_params_render_empty() {
        assert_eq!(DsnRecipientParams::default().render(), "");
    }

    #[test]
    fn dsn_recipient_params_render_round_trips_through_parser() {
        let params = DsnRecipientParams {
            notify: DsnNotify { never: false, success: true, failure: true, delay: false },
            orcpt_type: Some("rfc822".into()),
            orcpt_address: Some("o@d.com".into()),
        };
        let rendered = params.render();
        assert_eq!(rendered, " NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;o@d.com");
        let (_, reparsed) = parse_rcpt_to_arg(&format!("TO:<u@d.com>{rendered}")).unwrap();
        assert_eq!(reparsed, params);
    }

    #[test]
    fn dsn_recipient_params_render_notify_never() {
        let params = DsnRecipientParams {
            notify: DsnNotify { never: true, ..Default::default() },
            ..Default::default()
        };
        assert_eq!(params.render(), " NOTIFY=NEVER");
    }
}
