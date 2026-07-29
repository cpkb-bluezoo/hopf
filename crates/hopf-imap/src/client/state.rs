// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP client staged state traits and shared types.
//!
//! Each trait exposes operations valid for that session stage. Implementations
//! on [`super::endpoint::ImapClientEndpoint`] queue wire bytes; they are flushed
//! to the [`hopf_core::Endpoint`] after the driver callback returns.

use crate::enable::EnabledExtensions;

/// Server capabilities from an untagged `CAPABILITY` response.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapCapabilities {
    /// Raw capability tokens (uppercased).
    pub tokens: Vec<String>,
    /// `STARTTLS` advertised.
    pub starttls: bool,
    /// `AUTH=PLAIN` (or `AUTH=*` containing PLAIN).
    pub auth_plain: bool,
    /// `LITERAL-` (RFC 7888).
    pub literal_minus: bool,
    /// `IDLE`.
    pub idle: bool,
    /// `LOGIN` disabled (`LOGINDISABLED`).
    pub login_disabled: bool,
    /// `MOVE`.
    pub move_: bool,
    /// `UIDPLUS`.
    pub uidplus: bool,
    /// `NAMESPACE`.
    pub namespace: bool,
    /// `ENABLE`.
    pub enable: bool,
    /// `CONDSTORE`.
    pub condstore: bool,
    /// `QRESYNC`.
    pub qresync: bool,
    /// `UNSELECT`.
    pub unselect: bool,
    /// `ID`.
    pub id: bool,
    /// `QUOTA`.
    pub quota: bool,
}

impl ImapCapabilities {
    /// Parse space-separated capability tokens.
    pub fn parse(text: &str) -> Self {
        let mut caps = Self::default();
        for tok in text.split_whitespace() {
            let u = tok.to_ascii_uppercase();
            match u.as_str() {
                "STARTTLS" => caps.starttls = true,
                "LITERAL-" => caps.literal_minus = true,
                "IDLE" => caps.idle = true,
                "LOGINDISABLED" => caps.login_disabled = true,
                "MOVE" => caps.move_ = true,
                "UIDPLUS" => caps.uidplus = true,
                "NAMESPACE" => caps.namespace = true,
                "ENABLE" => caps.enable = true,
                "CONDSTORE" => caps.condstore = true,
                "QRESYNC" => caps.qresync = true,
                "UNSELECT" => caps.unselect = true,
                "ID" => caps.id = true,
                "QUOTA" => caps.quota = true,
                _ => {
                    if let Some(mech) = u.strip_prefix("AUTH=") {
                        if mech == "PLAIN" {
                            caps.auth_plain = true;
                        }
                    }
                }
            }
            caps.tokens.push(u);
        }
        caps
    }

    /// Whether `name` (case-insensitive) is advertised.
    pub fn has(&self, name: &str) -> bool {
        let u = name.to_ascii_uppercase();
        self.tokens.iter().any(|t| t == &u)
    }
}

/// Mailbox summary collected during SELECT / EXAMINE.
#[derive(Debug, Default, Clone)]
pub struct ImapMailboxInfo {
    /// Mailbox name that was selected.
    pub name: String,
    /// `EXISTS` count.
    pub exists: u32,
    /// `RECENT` count.
    pub recent: u32,
    /// `UNSEEN` from response code, if any.
    pub unseen: Option<u32>,
    /// `UIDVALIDITY`.
    pub uid_validity: Option<u32>,
    /// `UIDNEXT`.
    pub uid_next: Option<u32>,
    /// `FLAGS` list text.
    pub flags: Vec<String>,
    /// `PERMANENTFLAGS` list text.
    pub permanent_flags: Vec<String>,
    /// `true` if `[READ-WRITE]`, `false` if `[READ-ONLY]`.
    pub read_write: Option<bool>,
    /// `HIGHESTMODSEQ` when CONDSTORE is active.
    pub highest_modseq: Option<u64>,
}

/// Basic parsed FETCH attribute bag (core subset).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapFetchData {
    /// Message sequence number.
    pub seq: u32,
    /// `FLAGS` atoms.
    pub flags: Vec<String>,
    /// `UID` if present.
    pub uid: Option<u32>,
    /// `RFC822.SIZE` if present.
    pub size: Option<u64>,
    /// `MODSEQ` if present.
    pub modseq: Option<u64>,
    /// Accumulated literal / body octets for simple RFC822 / BODY[] fetches.
    pub body: Vec<u8>,
}

/// Parsed untagged `STATUS` data.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapStatusData {
    /// Mailbox name.
    pub mailbox: String,
    /// `MESSAGES`.
    pub messages: Option<u32>,
    /// `RECENT`.
    pub recent: Option<u32>,
    /// `UIDNEXT`.
    pub uid_next: Option<u32>,
    /// `UIDVALIDITY`.
    pub uid_validity: Option<u32>,
    /// `UNSEEN`.
    pub unseen: Option<u32>,
    /// `DELETED`.
    pub deleted: Option<u32>,
    /// `SIZE`.
    pub size: Option<u64>,
    /// `HIGHESTMODSEQ`.
    pub highest_modseq: Option<u64>,
}

impl ImapStatusData {
    /// Parse `STATUS mailbox (item value …)` (without leading `* `).
    pub fn parse(raw: &str) -> Option<Self> {
        let rest = raw
            .strip_prefix("STATUS ")
            .or_else(|| raw.strip_prefix("status "))?;
        let rest = rest.trim_start();
        let (mailbox, items) = split_mailbox_and_list(rest)?;
        let mut data = Self {
            mailbox,
            ..Self::default()
        };
        let mut toks = items.split_whitespace();
        while let Some(item) = toks.next() {
            let val = toks.next()?;
            match item.to_ascii_uppercase().as_str() {
                "MESSAGES" => data.messages = val.parse().ok(),
                "RECENT" => data.recent = val.parse().ok(),
                "UIDNEXT" => data.uid_next = val.parse().ok(),
                "UIDVALIDITY" => data.uid_validity = val.parse().ok(),
                "UNSEEN" => data.unseen = val.parse().ok(),
                "DELETED" => data.deleted = val.parse().ok(),
                "SIZE" => data.size = val.parse().ok(),
                "HIGHESTMODSEQ" => data.highest_modseq = val.parse().ok(),
                _ => {}
            }
        }
        Some(data)
    }
}

/// One `LIST` / `LSUB` entry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapListEntry {
    /// Attribute atoms (`\\Noselect`, …).
    pub attributes: Vec<String>,
    /// Hierarchy delimiter (`None` if `NIL`).
    pub delimiter: Option<String>,
    /// Mailbox name.
    pub name: String,
}

impl ImapListEntry {
    /// Parse `LIST (attrs) delim name` or `LSUB …` (without leading `* `).
    pub fn parse(raw: &str) -> Option<Self> {
        let rest = if let Some(r) = raw.strip_prefix("LIST ") {
            r
        } else if let Some(r) = raw.strip_prefix("LSUB ") {
            r
        } else if let Some(r) = raw.strip_prefix("list ") {
            r
        } else {
            raw.strip_prefix("lsub ")?
        };
        let rest = rest.trim_start();
        if !rest.starts_with('(') {
            return None;
        }
        let end = find_closing_paren(rest)?;
        let attrs = parse_atom_list(&rest[..=end]);
        let after = rest[end + 1..].trim_start();
        let (delim_tok, name_rest) = split_astring(after)?;
        let delimiter = if delim_tok.eq_ignore_ascii_case("NIL") {
            None
        } else {
            Some(unquote(delim_tok))
        };
        let name = unquote(name_rest.trim());
        Some(Self {
            attributes: attrs,
            delimiter,
            name,
        })
    }
}

/// One NAMESPACE triple (`prefix`, delimiter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapNamespace {
    /// Namespace prefix.
    pub prefix: String,
    /// Hierarchy delimiter (`None` if `NIL`).
    pub delimiter: Option<String>,
}

/// Parsed `NAMESPACE` response.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapNamespaceData {
    /// Personal namespaces.
    pub personal: Vec<ImapNamespace>,
    /// Other users' namespaces.
    pub other: Vec<ImapNamespace>,
    /// Shared namespaces.
    pub shared: Vec<ImapNamespace>,
}

impl ImapNamespaceData {
    /// Parse `personal other shared` — the `NAMESPACE` keyword itself is
    /// already consumed by the lexer's bounded capture ([`ImapEvent::Namespace`](super::reply::ImapEvent::Namespace)).
    pub fn parse(raw: &str) -> Option<Self> {
        let rest = raw.trim_start();
        let mut data = Self::default();
        let mut cursor = rest;
        data.personal = parse_namespace_list(&mut cursor)?;
        data.other = parse_namespace_list(&mut cursor)?;
        data.shared = parse_namespace_list(&mut cursor)?;
        Some(data)
    }
}

/// One QUOTA resource line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapQuotaResource {
    /// Resource name (`STORAGE`, `MESSAGE`, …).
    pub name: String,
    /// Current usage.
    pub usage: i64,
    /// Limit (`-1` = unlimited when servers emit it).
    pub limit: i64,
}

/// Parsed untagged `QUOTA` response.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapQuotaData {
    /// Quota root name.
    pub root: String,
    /// Resources.
    pub resources: Vec<ImapQuotaResource>,
}

impl ImapQuotaData {
    /// Parse `root (name usage limit …)` — the `QUOTA` keyword itself is
    /// already consumed by the lexer's bounded capture ([`ImapEvent::Quota`](super::reply::ImapEvent::Quota)).
    pub fn parse(raw: &str) -> Option<Self> {
        let rest = raw.trim_start();
        let (root, items) = split_mailbox_and_list(rest)?;
        let mut resources = Vec::new();
        let mut toks = items.split_whitespace();
        while let Some(name) = toks.next() {
            let usage = toks.next()?.parse().ok()?;
            let limit = toks.next()?.parse().ok()?;
            resources.push(ImapQuotaResource {
                name: name.to_string(),
                usage,
                limit,
            });
        }
        Some(Self { root, resources })
    }
}

/// Parsed `QUOTAROOT` line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapQuotaRootData {
    /// Mailbox name.
    pub mailbox: String,
    /// Associated quota roots.
    pub roots: Vec<String>,
}

impl ImapQuotaRootData {
    /// Parse `mailbox root…` — the `QUOTAROOT` keyword itself is already
    /// consumed by the lexer's bounded capture ([`ImapEvent::QuotaRoot`](super::reply::ImapEvent::QuotaRoot)).
    pub fn parse(raw: &str) -> Option<Self> {
        let rest = raw.trim_start();
        let mut parts = rest.split_whitespace();
        let mailbox = unquote(parts.next()?);
        let roots: Vec<_> = parts.map(unquote).collect();
        Some(Self { mailbox, roots })
    }
}

/// Parsed `[COPYUID uidvalidity from to]` / move response code payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapCopyUid {
    /// Destination UIDVALIDITY.
    pub uid_validity: u32,
    /// Source UID set (as wire text).
    pub source_uids: String,
    /// Destination UID set (as wire text).
    pub dest_uids: String,
}

impl ImapCopyUid {
    /// Parse the interior of a `COPYUID` response code (no brackets).
    pub fn parse(code: &str) -> Option<Self> {
        let rest = code
            .strip_prefix("COPYUID ")
            .or_else(|| code.strip_prefix("copyuid "))?
            .trim_start();
        let mut parts = rest.splitn(3, ' ');
        let uid_validity = parts.next()?.parse().ok()?;
        let source_uids = parts.next()?.to_string();
        let dest_uids = parts.next()?.to_string();
        Some(Self {
            uid_validity,
            source_uids,
            dest_uids,
        })
    }
}

/// Parsed `[APPENDUID uidvalidity uid]` response code payload (RFC 4315
/// UIDPLUS), surfaced on a successful APPEND.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImapAppendUid {
    /// Destination mailbox's UIDVALIDITY.
    pub uid_validity: u32,
    /// The newly appended message's UID.
    pub uid: u32,
}

impl ImapAppendUid {
    /// Parse the interior of an `APPENDUID` response code (no brackets).
    pub fn parse(code: &str) -> Option<Self> {
        let rest = code
            .strip_prefix("APPENDUID ")
            .or_else(|| code.strip_prefix("appenduid "))?
            .trim_start();
        let mut parts = rest.splitn(2, ' ');
        let uid_validity = parts.next()?.parse().ok()?;
        let uid = parts.next()?.trim().parse().ok()?;
        Some(Self { uid_validity, uid })
    }
}

/// Client-side ENABLE tracking (CONDSTORE / QRESYNC).
pub type ImapEnabledFeatures = EnabledExtensions;

/// NOT AUTHENTICATED state operations.
pub trait ImapClientNotAuthenticated {
    /// Send `CAPABILITY`.
    fn capability(&mut self);
    /// Send `LOGIN user pass`.
    fn login(&mut self, username: &str, password: &str);
    /// Send `AUTHENTICATE mechanism [initial-response]`.
    ///
    /// `initial` is raw SASL bytes (not yet base64); when `Some`, sent as
    /// SASL-IR. When `None`, wait for `+` then [`ImapClientAuthExchange::respond`].
    fn authenticate(&mut self, mechanism: &str, initial: Option<&[u8]>);
    /// Send `STARTTLS`.
    fn starttls(&mut self);
    /// Send `ID` (RFC 2971). `nil` sends `ID NIL`.
    fn id(&mut self, fields: Option<&[(&str, &str)]>);
    /// Send `LOGOUT`.
    fn logout(&mut self);
    /// Capabilities from the most recent CAPABILITY response.
    fn capabilities(&self) -> &ImapCapabilities;
}

/// Post-STARTTLS (TLS established): re-CAPABILITY then auth.
pub trait ImapClientPostStarttls: ImapClientNotAuthenticated {}

/// Mid-AUTHENTICATE SASL exchange.
pub trait ImapClientAuthExchange {
    /// Send a base64-encoded SASL response line.
    fn respond(&mut self, response: &[u8]);
    /// Abort AUTH with `*`.
    fn abort(&mut self);
}

/// AUTHENTICATED state operations.
pub trait ImapClientAuthenticated {
    /// Send `CAPABILITY`.
    fn capability(&mut self);
    /// Send `SELECT mailbox`.
    fn select(&mut self, mailbox: &str);
    /// Send `EXAMINE mailbox`.
    fn examine(&mut self, mailbox: &str);
    /// Send `LIST reference pattern`.
    fn list(&mut self, reference: &str, pattern: &str);
    /// Send `LSUB reference pattern`.
    fn lsub(&mut self, reference: &str, pattern: &str);
    /// Send `STATUS mailbox (items…)`.
    fn status(&mut self, mailbox: &str, items: &str);
    /// Begin `APPEND` (literal framing; wait for `+` unless LITERAL- applies).
    /// `date` is an already-formatted RFC 9051 §6.3.12 `date-time` string
    /// (e.g. `"01-Jan-2024 00:00:00 +0000"`) setting the appended
    /// message's INTERNALDATE; `None` lets the server assign "now".
    fn append(
        &mut self,
        mailbox: &str,
        flags: Option<&str>,
        date: Option<&str>,
        size: u64,
        use_literal_minus: bool,
    );
    /// Send `NAMESPACE` when advertised.
    fn namespace(&mut self);
    /// Send `ENABLE` with space-separated features (e.g. `CONDSTORE QRESYNC`).
    fn enable(&mut self, features: &str);
    /// Send `ID` (RFC 2971).
    fn id(&mut self, fields: Option<&[(&str, &str)]>);
    /// Send `GETQUOTA` when advertised.
    fn get_quota(&mut self, root: &str);
    /// Send `GETQUOTAROOT` when advertised.
    fn get_quota_root(&mut self, mailbox: &str);
    /// Send `SETQUOTA` when advertised (`resources` = `"STORAGE 1024 MESSAGE 100"`).
    fn set_quota(&mut self, root: &str, resources: &str);
    /// Enter IDLE (RFC 2177) when advertised.
    fn idle(&mut self);
    /// Send `NOOP`.
    fn noop(&mut self);
    /// Send `CREATE mailbox` (RFC 9051 §6.3.3).
    fn create(&mut self, mailbox: &str);
    /// Send `DELETE mailbox` (RFC 9051 §6.3.4).
    fn delete(&mut self, mailbox: &str);
    /// Send `RENAME from to` (RFC 9051 §6.3.5).
    fn rename(&mut self, from: &str, to: &str);
    /// Send `SUBSCRIBE mailbox` (RFC 9051 §6.3.6).
    fn subscribe(&mut self, mailbox: &str);
    /// Send `UNSUBSCRIBE mailbox` (RFC 9051 §6.3.7).
    fn unsubscribe(&mut self, mailbox: &str);
    /// Send `LOGOUT`.
    fn logout(&mut self);
    /// Capabilities from the most recent CAPABILITY response.
    fn capabilities(&self) -> &ImapCapabilities;
    /// Features enabled via `ENABLE`.
    fn enabled_features(&self) -> &ImapEnabledFeatures;
}

/// Mid-APPEND after continuation (or LITERAL- immediate data).
pub trait ImapClientAppend {
    /// Send the message octets (and terminating CRLF is caller's responsibility
    /// only if required by the server; typically just the raw message bytes).
    fn send_literal(&mut self, data: &[u8]);
}

/// SELECTED state operations.
pub trait ImapClientSelected: ImapClientAuthenticated {
    /// Send `FETCH sequence items`.
    fn fetch(&mut self, sequence_set: &str, items: &str);
    /// Send `UID FETCH sequence items`.
    fn uid_fetch(&mut self, sequence_set: &str, items: &str);
    /// Send `SEARCH criteria`.
    fn search(&mut self, criteria: &str);
    /// Send `UID SEARCH criteria`.
    fn uid_search(&mut self, criteria: &str);
    /// Send `STORE sequence action flags` (`action` = `+FLAGS`, `-FLAGS`, `FLAGS`).
    fn store(&mut self, sequence_set: &str, action: &str, flags: &str);
    /// Send `UID STORE`.
    fn uid_store(&mut self, sequence_set: &str, action: &str, flags: &str);
    /// Send `COPY sequence mailbox`.
    fn copy(&mut self, sequence_set: &str, mailbox: &str);
    /// Send `UID COPY`.
    fn uid_copy(&mut self, sequence_set: &str, mailbox: &str);
    /// Send `MOVE sequence mailbox` when advertised.
    fn move_(&mut self, sequence_set: &str, mailbox: &str);
    /// Send `UID MOVE` when advertised.
    fn uid_move(&mut self, sequence_set: &str, mailbox: &str);
    /// Send `EXPUNGE`.
    fn expunge(&mut self);
    /// Send `UID EXPUNGE set` when UIDPLUS is advertised.
    fn uid_expunge(&mut self, uid_set: &str);
    /// Send `CLOSE`.
    fn close(&mut self);
    /// Send `UNSELECT` when advertised.
    fn unselect(&mut self);
}

/// IDLE state: wait for mailbox events, then [`ImapClientIdle::done`].
pub trait ImapClientIdle {
    /// Send `DONE` to leave IDLE and await the tagged completion.
    fn done(&mut self);
}

// ── parsing helpers ───────────────────────────────────────────────────────────

fn find_closing_paren(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut in_quote = false;
    for (i, &b) in bytes.iter().enumerate() {
        if in_quote {
            if b == b'\\' {
                continue;
            }
            if b == b'"' {
                in_quote = false;
            }
            continue;
        }
        match b {
            b'"' => in_quote = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_atom_list(s: &str) -> Vec<String> {
    let s = s.trim();
    let inner = s
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(s);
    inner.split_whitespace().map(|a| a.to_string()).collect()
}

fn split_mailbox_and_list(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    if let Some(open) = s.find('(') {
        let mailbox = unquote(s[..open].trim());
        let close = find_closing_paren(&s[open..])? + open;
        let items = s[open + 1..close].to_string();
        Some((mailbox, items))
    } else {
        None
    }
}

fn split_astring(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.starts_with('"') {
        let bytes = s.as_bytes();
        let mut i = 1;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                let tok = &s[..=i];
                return Some((tok, s[i + 1..].trim_start()));
            }
            i += 1;
        }
        None
    } else {
        let mut parts = s.splitn(2, char::is_whitespace);
        let tok = parts.next()?;
        let rest = parts.next().unwrap_or("");
        Some((tok, rest))
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s.to_string()
    }
}

fn parse_namespace_list(cursor: &mut &str) -> Option<Vec<ImapNamespace>> {
    *cursor = cursor.trim_start();
    if cursor.is_empty() {
        return Some(Vec::new());
    }
    if cursor.len() >= 3 && cursor[..3].eq_ignore_ascii_case("NIL") {
        *cursor = cursor[3..].trim_start();
        return Some(Vec::new());
    }
    if !cursor.starts_with('(') {
        return None;
    }
    let end = find_closing_paren(cursor)?;
    let inner = &cursor[1..end];
    *cursor = cursor[end + 1..].trim_start();
    let mut out = Vec::new();
    let mut rest = inner.trim();
    while !rest.is_empty() {
        rest = rest.trim_start();
        if !rest.starts_with('(') {
            break;
        }
        let e = find_closing_paren(rest)?;
        let pair = &rest[1..e];
        rest = rest[e + 1..].trim_start();
        let (prefix_tok, delim_rest) = split_astring(pair)?;
        let delim_tok = delim_rest.trim();
        let delimiter = if delim_tok.eq_ignore_ascii_case("NIL") {
            None
        } else {
            Some(unquote(delim_tok))
        };
        out.push(ImapNamespace {
            prefix: unquote(prefix_tok),
            delimiter,
        });
    }
    Some(out)
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parse_status_data() {
        let d = ImapStatusData::parse("STATUS INBOX (MESSAGES 17 UIDNEXT 18)").unwrap();
        assert_eq!(d.mailbox, "INBOX");
        assert_eq!(d.messages, Some(17));
        assert_eq!(d.uid_next, Some(18));
    }

    #[test]
    fn parse_list_entry() {
        let e = ImapListEntry::parse(r#"LIST (\HasNoChildren) "/" INBOX"#).unwrap();
        assert_eq!(e.attributes, vec!["\\HasNoChildren"]);
        assert_eq!(e.delimiter.as_deref(), Some("/"));
        assert_eq!(e.name, "INBOX");
    }

    #[test]
    fn parse_copyuid() {
        let c = ImapCopyUid::parse("COPYUID 38505 304,319 3956,3957").unwrap();
        assert_eq!(c.uid_validity, 38505);
        assert_eq!(c.source_uids, "304,319");
        assert_eq!(c.dest_uids, "3956,3957");
    }

    #[test]
    fn parse_appenduid() {
        let a = ImapAppendUid::parse("APPENDUID 38505 3956").unwrap();
        assert_eq!(a.uid_validity, 38505);
        assert_eq!(a.uid, 3956);
    }

    #[test]
    fn parse_namespace() {
        let n = ImapNamespaceData::parse(r#"(("" "/")) NIL NIL"#).unwrap();
        assert_eq!(n.personal.len(), 1);
        assert_eq!(n.personal[0].prefix, "");
        assert_eq!(n.personal[0].delimiter.as_deref(), Some("/"));
        assert!(n.other.is_empty());
    }

    #[test]
    fn parse_quota() {
        let q = ImapQuotaData::parse("\"\" (STORAGE 10 512)").unwrap();
        assert_eq!(q.root, "");
        assert_eq!(q.resources[0].name, "STORAGE");
        assert_eq!(q.resources[0].usage, 10);
        assert_eq!(q.resources[0].limit, 512);
    }
}
