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

impl DsnNotify {
    /// Whether any NOTIFY token was explicitly supplied (vs. the RFC default).
    pub fn is_explicit(&self) -> bool {
        self.never || self.success || self.failure || self.delay
    }

    /// RFC 3461 §4.1: unspecified NOTIFY ≡ `FAILURE,DELAY`.
    fn effective_failure(self) -> bool {
        if self.never {
            return false;
        }
        if !self.is_explicit() {
            return true;
        }
        self.failure
    }

    fn effective_success(self) -> bool {
        !self.never && self.success
    }

    /// Sender wants a success DSN for this recipient.
    pub fn wants_success(self) -> bool {
        self.effective_success()
    }

    /// Sender wants a failure DSN for this recipient.
    pub fn wants_failure(self) -> bool {
        self.effective_failure()
    }

    /// Sender wants a delay DSN for this recipient: the message is taking
    /// long to deliver but is still being tried. RFC 3461 section 4.1: an
    /// unspecified NOTIFY is `FAILURE,DELAY`.
    pub fn wants_delay(self) -> bool {
        !self.never && (!self.is_explicit() || self.delay)
    }
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

/// The tokens of the argument of `MAIL FROM:` or `RCPT TO:` (RFC 5321
/// §4.1.1.2, §4.1.1.3): the path, with the angle brackets taken off, and the
/// ESMTP parameters, each a `name[=value]` word.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathArgs {
    /// The path; empty for the null reverse-path `<>`.
    pub address: String,
    /// The parameters, in order, as written.
    pub params: Vec<String>,
}

/// White space as `char::is_whitespace` has it, for ASCII.
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathStage {
    /// Skipping white space before the first token.
    Start,
    /// Matching the `FROM:` / `TO:` keyword.
    Keyword,
    /// After the keyword, skipping white space.
    AfterKeyword,
    /// Inside `<...>`.
    Angle,
    /// An address with no angle brackets.
    Bare,
    /// Between parameters.
    BetweenParams,
    /// Inside a parameter.
    Param,
    /// A syntax error: the rest is skipped.
    Dead,
}

/// Reads the argument of `MAIL` or `RCPT` as the bytes arrive: the keyword,
/// the path, and each parameter are recognised as they complete, and the
/// argument itself is never held.
#[derive(Debug, Clone)]
pub struct PathTokenizer {
    keyword: &'static [u8],
    syntax: &'static str,
    require_keyword: bool,
    stage: PathStage,
    head: Vec<u8>,
    address: Vec<u8>,
    params: Vec<Vec<u8>>,
    cur: Vec<u8>,
}

impl PathTokenizer {
    /// For `MAIL FROM:`. With `require_keyword` an argument that does not
    /// begin with `FROM:` (in any case) is a syntax error; without it, the
    /// path alone is accepted, as clients commonly send it.
    pub fn mail(require_keyword: bool) -> Self {
        Self::new(b"FROM:", "Syntax: MAIL FROM:<address>", require_keyword)
    }

    /// For `RCPT TO:`; see [`Self::mail`].
    pub fn rcpt(require_keyword: bool) -> Self {
        Self::new(b"TO:", "Syntax: RCPT TO:<address>", require_keyword)
    }

    fn new(keyword: &'static [u8], syntax: &'static str, require_keyword: bool) -> Self {
        Self {
            keyword,
            syntax,
            require_keyword,
            stage: PathStage::Start,
            head: Vec::new(),
            address: Vec::new(),
            params: Vec::new(),
            cur: Vec::new(),
        }
    }

    /// The next byte of the argument.
    pub fn feed(&mut self, b: u8) {
        match self.stage {
            PathStage::Dead => {}
            PathStage::Start => {
                if is_ws(b) {
                } else if b == b'<' {
                    // A path with no keyword before it.
                    self.stage = if self.require_keyword { PathStage::Dead } else { PathStage::Angle };
                } else {
                    self.stage = PathStage::Keyword;
                    self.keyword_byte(b);
                }
            }
            PathStage::Keyword => self.keyword_byte(b),
            PathStage::AfterKeyword => {
                if is_ws(b) {
                } else if b == b'<' {
                    self.stage = PathStage::Angle;
                } else {
                    self.stage = PathStage::Bare;
                    self.address.push(b);
                }
            }
            PathStage::Angle => {
                if b == b'>' {
                    self.stage = PathStage::BetweenParams;
                } else {
                    self.address.push(b);
                }
            }
            PathStage::Bare => {
                if is_ws(b) {
                    self.stage = PathStage::BetweenParams;
                } else {
                    self.address.push(b);
                }
            }
            PathStage::BetweenParams => {
                if !is_ws(b) {
                    self.stage = PathStage::Param;
                    self.cur.push(b);
                }
            }
            PathStage::Param => {
                if is_ws(b) {
                    self.params.push(std::mem::take(&mut self.cur));
                    self.stage = PathStage::BetweenParams;
                } else {
                    self.cur.push(b);
                }
            }
        }
    }

    fn keyword_byte(&mut self, b: u8) {
        let i = self.head.len();
        if i < self.keyword.len() && b.to_ascii_uppercase() == self.keyword[i] {
            self.head.push(b);
            if self.head.len() == self.keyword.len() {
                self.head.clear();
                self.stage = PathStage::AfterKeyword;
            }
            return;
        }
        if self.require_keyword {
            self.stage = PathStage::Dead;
            return;
        }
        // Not the keyword: what has been read is the start of a bare
        // address.
        let mut bytes = std::mem::take(&mut self.head);
        bytes.push(b);
        self.stage = PathStage::Bare;
        for x in bytes {
            self.feed(x);
        }
    }

    /// The end of the argument.
    pub fn finish(mut self) -> Result<PathArgs, ParamParseError> {
        match self.stage {
            PathStage::Dead => return Err(ParamParseError::new(self.syntax)),
            PathStage::Start | PathStage::Keyword if self.require_keyword => {
                return Err(ParamParseError::new(self.syntax));
            }
            PathStage::Keyword => {
                // Only part of a keyword: it was the address.
                let bytes = std::mem::take(&mut self.head);
                self.address = bytes;
            }
            PathStage::Angle => return Err(ParamParseError::new("Unclosed angle-addr")),
            PathStage::Param => self.params.push(std::mem::take(&mut self.cur)),
            _ => {}
        }
        Ok(PathArgs {
            address: String::from_utf8_lossy(&self.address).into_owned(),
            params: self
                .params
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect(),
        })
    }
}

/// Reads a whole argument string with [`PathTokenizer`].
fn tokenize_path(mut tokenizer: PathTokenizer, arg: &str) -> Result<PathArgs, ParamParseError> {
    for b in arg.bytes() {
        tokenizer.feed(b);
    }
    tokenizer.finish()
}

/// Pragmatic MAIL FROM argument parser (`FROM:<addr> [params…]`).
pub fn parse_mail_from_arg(arg: &str) -> Result<MailFromParse, ParamParseError> {
    interpret_mail_from(&tokenize_path(PathTokenizer::mail(true), arg)?)
}

/// What the tokens of a `MAIL FROM:` argument mean.
pub fn interpret_mail_from(args: &PathArgs) -> Result<MailFromParse, ParamParseError> {
    let sender_raw = if args.address.is_empty() {
        None
    } else {
        Some(args.address.clone())
    };

    let mut out = MailFromParse {
        sender_raw,
        size: None,
        body: BodyType::SevenBit,
        smtputf8: false,
        delivery: DeliveryRequirements::default(),
    };

    {
        for param in args.params.iter().map(String::as_str) {
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
                if !(-9..=9).contains(&p) {
                    return Err(ParamParseError::new(
                        "MT-PRIORITY must be between -9 and 9",
                    ));
                }
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
                // RFC 2852 section 4: `BY=<seconds>;<R|N>[T]`, the time
                // possibly negative (a deadline already past). The older
                // form with no semicolon, `BY=<seconds>[R|N]`, is read too.
                let (num, mode) = match v.split_once(';') {
                    Some((n, m)) => (n, m),
                    None => match v.strip_suffix(['R', 'N']) {
                        Some(n) => (n, &v[n.len()..]),
                        None => (v, "R"),
                    },
                };
                let ret = match mode {
                    "R" | "RT" => true,
                    "N" | "NT" => false,
                    _ => return Err(ParamParseError::new("Invalid BY parameter")),
                };
                let secs: i64 = num
                    .parse()
                    .map_err(|_| ParamParseError::new("Invalid BY parameter"))?;
                let now = SystemTime::now();
                let deadline = if secs >= 0 {
                    now + Duration::from_secs(secs as u64)
                } else {
                    now.checked_sub(Duration::from_secs(secs.unsigned_abs())).unwrap_or(SystemTime::UNIX_EPOCH)
                };
                out.delivery.deliver_by = Some(DeliverBy {
                    deadline,
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
    interpret_rcpt_to(&tokenize_path(PathTokenizer::rcpt(true), arg)?)
}

/// What the tokens of a `RCPT TO:` argument mean.
pub fn interpret_rcpt_to(args: &PathArgs) -> Result<(String, DsnRecipientParams), ParamParseError> {
    if args.address.is_empty() {
        return Err(ParamParseError::new("Empty recipient address"));
    }

    let mut dsn = DsnRecipientParams::default();
    {
        for param in args.params.iter().map(String::as_str) {
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
    Ok((args.address.clone(), dsn))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delay_notice_is_wanted_by_default_and_when_asked_for_but_never_with_never() {
        // RFC 3461 section 4.1: an unspecified NOTIFY is FAILURE,DELAY.
        assert!(DsnNotify::default().wants_delay());
        assert!(DsnNotify { delay: true, ..Default::default() }.wants_delay());
        assert!(!DsnNotify { failure: true, ..Default::default() }.wants_delay());
        assert!(!DsnNotify { success: true, failure: true, ..Default::default() }.wants_delay());
        assert!(!DsnNotify { never: true, ..Default::default() }.wants_delay());
    }

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

    /// The tokens as the code that waited for the whole argument and then
    /// searched it made them: the oracle the incremental tokenizer is held to.
    fn old_tokens(arg: &str, prefixes: [&str; 3], syntax: &str) -> Result<(String, Vec<String>), String> {
        let arg = arg.trim();
        let rest = prefixes
            .iter()
            .find_map(|p| arg.strip_prefix(p))
            .ok_or_else(|| syntax.to_string())?
            .trim();
        let (addr, after) = if rest.starts_with('<') {
            let close = rest.find('>').ok_or_else(|| "Unclosed angle-addr".to_string())?;
            let after = rest[close + 1..].trim();
            (&rest[1..close], if after.is_empty() { None } else { Some(after) })
        } else {
            let mut parts = rest.splitn(2, char::is_whitespace);
            let addr = parts.next().unwrap_or("");
            (addr, parts.next().map(str::trim).filter(|s| !s.is_empty()))
        };
        let params = after.map(|p| p.split_whitespace().map(String::from).collect()).unwrap_or_default();
        Ok((addr.to_string(), params))
    }

    #[test]
    fn path_tokens_match_the_whole_argument_parser() {
        let bodies = [
            "<a@b.com>", "<>", "<a@b.com> SIZE=100", "<a@b.com>   SIZE=100  BODY=8BITMIME ",
            "<a@b.com>SIZE=1", "< a@b.com >", "<a b@c>", "<unclosed", "<a@b> <c@d>", "a@b.com",
            "a@b.com SIZE=5", "", " ", "<a@b>\tNOTIFY=NEVER", "<a@b> ORCPT=rfc822;x@y", "<<a>>",
            "<a@b> x y z", "<a>\rb", "<@route:a@b>",
        ];
        for (keyword, prefixes, syntax, make) in [
            ("FROM:", ["FROM:", "from:", "From:"], "Syntax: MAIL FROM:<address>", PathTokenizer::mail as fn(bool) -> PathTokenizer),
            ("TO:", ["TO:", "to:", "To:"], "Syntax: RCPT TO:<address>", PathTokenizer::rcpt),
        ] {
            for lead in ["", " ", "  "] {
                for sep in ["", " ", "  ", "\t"] {
                    for body in bodies {
                        for case in [keyword.to_string(), keyword.to_lowercase(), {
                            let mut c = keyword.to_lowercase();
                            c.replace_range(0..1, &keyword[0..1]);
                            c
                        }] {
                            let arg = format!("{lead}{case}{sep}{body}");
                            let want = old_tokens(&arg, prefixes, syntax);
                            let got = tokenize_path(make(true), &arg)
                                .map(|a| (a.address, a.params))
                                .map_err(|e| e.message);
                            assert_eq!(got, want, "arg {arg:?}");
                        }
                    }
                }
            }
            // No keyword at all is a syntax error when it is required.
            for body in bodies {
                let want = old_tokens(body, prefixes, syntax);
                let got = tokenize_path(make(true), body).map(|a| (a.address, a.params)).map_err(|e| e.message);
                assert_eq!(got, want, "arg {body:?}");
            }
        }
    }

    #[test]
    fn without_a_required_keyword_the_path_alone_is_accepted() {
        let got = tokenize_path(PathTokenizer::mail(false), "<a@b.com> SIZE=10").unwrap();
        assert_eq!(got, PathArgs { address: "a@b.com".into(), params: vec!["SIZE=10".into()] });
        let got = tokenize_path(PathTokenizer::rcpt(false), "to:<u@d>").unwrap();
        assert_eq!(got.address, "u@d");
        // Any case of the keyword, and white space after it.
        let got = tokenize_path(PathTokenizer::mail(false), "FrOm:  <a@b>").unwrap();
        assert_eq!(got.address, "a@b");
        // A bare address that begins like the keyword.
        let got = tokenize_path(PathTokenizer::rcpt(false), "tom@example.com").unwrap();
        assert_eq!(got.address, "tom@example.com");
        let got = tokenize_path(PathTokenizer::rcpt(false), "t").unwrap();
        assert_eq!(got.address, "t");
    }
}
