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
    /// `COMPRESS=DEFLATE` (RFC 4978).
    pub compress_deflate: bool,
    /// `UTF8=ACCEPT` (RFC 6855).
    pub utf8_accept: bool,
    /// `LIST-EXTENDED` (RFC 5258): selection and return options on LIST.
    pub list_extended: bool,
    /// `LIST-STATUS` (RFC 5819): `RETURN (STATUS (…))` on LIST.
    pub list_status: bool,
    /// `SPECIAL-USE` (RFC 6154): `\\Sent`, `\\Trash`, … attributes.
    pub special_use: bool,
    /// `CHILDREN` (RFC 3348): `\\HasChildren` / `\\HasNoChildren`.
    pub children: bool,
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
                "COMPRESS=DEFLATE" => caps.compress_deflate = true,
                "UTF8=ACCEPT" => caps.utf8_accept = true,
                "LIST-EXTENDED" => caps.list_extended = true,
                "LIST-STATUS" => caps.list_status = true,
                "SPECIAL-USE" => caps.special_use = true,
                "CHILDREN" => caps.children = true,
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
    /// RFC 8474 `MAILBOXID` response code.
    pub mailbox_id: Option<String>,
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
    /// RFC 8474 `EMAILID`, if requested and returned.
    pub email_id: Option<String>,
    /// RFC 8474 `THREADID`, if requested and returned as a real value
    /// (rather than `NIL`).
    pub thread_id: Option<String>,
    /// Accumulated literal / body octets for simple RFC822 / BODY[] fetches.
    pub body: Vec<u8>,
    /// `ENVELOPE` as sent, with any literal strings re-encoded as quoted
    /// strings; parse with [`ImapEnvelope::parse`](super::structure::ImapEnvelope::parse).
    pub envelope: Option<String>,
    /// `BODYSTRUCTURE` (or the non-extensible `BODY`) as sent, literals
    /// re-encoded as quoted strings; parse with
    /// [`ImapBodyStructure::parse`](super::structure::ImapBodyStructure::parse).
    pub bodystructure: Option<String>,
    /// `INTERNALDATE`, without its quotes (e.g. `17-Jul-1996 02:44:25 -0700`).
    pub internaldate: Option<String>,
}

/// Options for an extended `LIST` (RFC 5258), with the `RETURN` items
/// other extensions add: `CHILDREN` (RFC 3348), `SPECIAL-USE` (RFC 6154)
/// and `STATUS` (RFC 5819, LIST-STATUS).
///
/// Check the server's [`ImapCapabilities`] first: `list_extended` for any
/// selection option or `RETURN`, `list_status` for `return_status`,
/// `special_use` for `special_use` / `return_special_use`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapListOptions {
    /// Selection option `SUBSCRIBED`: list only subscribed mailboxes (and
    /// return `\\Subscribed`).
    pub subscribed: bool,
    /// Selection option `REMOTE`.
    pub remote: bool,
    /// Selection option `RECURSIVEMATCH` (needs another selection option).
    pub recursive_match: bool,
    /// Selection option `SPECIAL-USE`: list only mailboxes with a
    /// special-use attribute.
    pub special_use: bool,
    /// `RETURN (SUBSCRIBED)`.
    pub return_subscribed: bool,
    /// `RETURN (CHILDREN)`.
    pub return_children: bool,
    /// `RETURN (SPECIAL-USE)`.
    pub return_special_use: bool,
    /// `RETURN (STATUS (items…))`: the status items wanted for every
    /// listed mailbox (`MESSAGES`, `UNSEEN`, `UIDNEXT`, `UIDVALIDITY`,
    /// `RECENT`, `SIZE`, `HIGHESTMODSEQ`, …). Empty: no STATUS.
    pub return_status: Vec<String>,
}

impl ImapListOptions {
    /// The selection-option list, `(SUBSCRIBED …)`, or `None` when empty.
    pub fn selection(&self) -> Option<String> {
        let mut out = Vec::new();
        if self.subscribed {
            out.push("SUBSCRIBED");
        }
        if self.remote {
            out.push("REMOTE");
        }
        if self.recursive_match {
            out.push("RECURSIVEMATCH");
        }
        if self.special_use {
            out.push("SPECIAL-USE");
        }
        (!out.is_empty()).then(|| format!("({})", out.join(" ")))
    }

    /// The `RETURN (…)` clause, or `None` when nothing is requested.
    pub fn return_clause(&self) -> Option<String> {
        let mut out: Vec<String> = Vec::new();
        if self.return_subscribed {
            out.push("SUBSCRIBED".into());
        }
        if self.return_children {
            out.push("CHILDREN".into());
        }
        if self.return_special_use {
            out.push("SPECIAL-USE".into());
        }
        if !self.return_status.is_empty() {
            let items: Vec<String> = self.return_status.iter().map(|s| s.trim().to_ascii_uppercase()).collect();
            out.push(format!("STATUS ({})", items.join(" ")));
        }
        (!out.is_empty()).then(|| format!("RETURN ({})", out.join(" ")))
    }
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
    /// RFC 8474 `MAILBOXID`.
    pub mailbox_id: Option<String>,
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
                "MAILBOXID" => {
                    data.mailbox_id = val
                        .strip_prefix('(')
                        .and_then(|s| s.strip_suffix(')'))
                        .map(|s| s.to_string());
                }
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

/// One RFC 5464 METADATA entry/value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapMetadataEntry {
    /// Annotation entry path (e.g. `/private/comment`).
    pub entry: String,
    /// Its value; `None` for a literal `NIL` (not expected in a
    /// GETMETADATA response per RFC 5464 §3, but tolerated).
    pub value: Option<String>,
}

/// Parsed untagged `METADATA` response.
///
/// Values sent as a wire literal (`{n}\r\n…`) rather than a quoted string
/// or bare atom aren't supported — the same limitation `ImapNamespaceData`
/// / `ImapQuotaData` already have, inherited from the lexer's single-line
/// bounded-capture for these responses (see [`super::reply::ImapEvent::Metadata`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImapMetadataData {
    /// Mailbox the entries apply to (`""` = server annotations).
    pub mailbox: String,
    /// `(entry, value)` pairs, in response order.
    pub entries: Vec<ImapMetadataEntry>,
}

impl ImapMetadataData {
    /// Parse `mailbox (entry value entry value …)` — the `METADATA`
    /// keyword itself is already consumed by the lexer's bounded capture.
    pub fn parse(raw: &str) -> Option<Self> {
        let rest = raw.trim_start();
        let (mailbox, items) = split_mailbox_and_list(rest)?;
        let mut entries = Vec::new();
        let mut cursor = items.as_str();
        loop {
            cursor = cursor.trim_start();
            if cursor.is_empty() {
                break;
            }
            let (entry_tok, after) = split_astring(cursor)?;
            let entry = unquote(entry_tok);
            let after = after.trim_start();
            let (value, after) = if after.get(..3).map(|s| s.eq_ignore_ascii_case("NIL")) == Some(true)
            {
                (None, after[3..].trim_start())
            } else {
                let (value_tok, after) = split_astring(after)?;
                (Some(unquote(value_tok)), after)
            };
            entries.push(ImapMetadataEntry { entry, value });
            cursor = after;
        }
        Some(Self { mailbox, entries })
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

/// One node of a parsed `THREAD` response tree (RFC 5256 §2): a message's
/// result number (sequence number or UID, per the issuing command), plus
/// its replies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapThreadNode {
    /// Sequence number or UID (per `THREAD`/`UID THREAD`) of this message.
    pub result_number: u32,
    /// Direct replies to this message, in wire order.
    pub children: Vec<ImapThreadNode>,
}

/// Parse a `THREAD` response body into its forest of threads — the
/// `THREAD` keyword itself is already consumed by the lexer's bounded
/// capture ([`ImapEvent::ThreadData`](super::reply::ImapEvent::ThreadData)).
/// An empty (all-whitespace) body parses as no threads, matching RFC 5256
/// §2's "no untagged THREAD at all when there's nothing to thread" — a
/// caller that never sees the event should treat that the same way.
pub fn parse_thread_response(raw: &str) -> Option<Vec<ImapThreadNode>> {
    let mut out = Vec::new();
    let mut cursor = raw.trim();
    while cursor.starts_with('(') {
        let close = find_closing_paren(cursor)?;
        let inner = &cursor[1..close];
        let (node, leftover) = parse_thread_chain(inner)?;
        if !leftover.trim().is_empty() {
            return None;
        }
        out.push(node);
        cursor = cursor[close + 1..].trim_start();
    }
    if cursor.is_empty() {
        Some(out)
    } else {
        None
    }
}

/// Parse one `thread-chain`/`thread-nested` body (the contents of one
/// top-level pair of parentheses, with the parentheses already stripped),
/// returning the resulting subtree and whatever text follows it (always
/// empty at the top level; recursion needs the remainder to detect
/// trailing sibling groups).
fn parse_thread_chain(s: &str) -> Option<(ImapThreadNode, &str)> {
    let s = s.trim_start();
    let end = s.find([' ', '(', ')']).unwrap_or(s.len());
    let result_number: u32 = s[..end].parse().ok()?;
    let rest = s[end..].trim_start();
    if rest.is_empty() {
        return Some((ImapThreadNode { result_number, children: Vec::new() }, rest));
    }
    if rest.starts_with('(') {
        // One or more parenthesized sibling groups: each is a separate reply.
        let mut children = Vec::new();
        let mut cursor = rest;
        while cursor.starts_with('(') {
            let close = find_closing_paren(cursor)?;
            let inner = &cursor[1..close];
            let (child, leftover) = parse_thread_chain(inner)?;
            if !leftover.trim().is_empty() {
                return None;
            }
            children.push(child);
            cursor = &cursor[close + 1..];
        }
        return Some((ImapThreadNode { result_number, children }, cursor));
    }
    // A bare number continues the chain as this node's single reply.
    let (child, leftover) = parse_thread_chain(rest)?;
    Some((ImapThreadNode { result_number, children: vec![child] }, leftover))
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
    /// Send an RFC 5258 extended `LIST` with selection and return options
    /// (see [`ImapListOptions`]). With no options set this is a plain
    /// `LIST`. `RETURN (STATUS …)` replies arrive as `on_status_data`
    /// calls interleaved with the `on_list_entry` calls.
    fn list_extended(&mut self, reference: &str, pattern: &str, options: &ImapListOptions);
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
    /// Send `COMPRESS DEFLATE` (RFC 4978) when advertised. Once the tagged
    /// `OK` arrives, every subsequent byte in both directions on this
    /// connection is transparently DEFLATE-compressed.
    fn compress_deflate(&mut self);
    /// Send `ID` (RFC 2971).
    fn id(&mut self, fields: Option<&[(&str, &str)]>);
    /// Send `GETQUOTA` when advertised.
    fn get_quota(&mut self, root: &str);
    /// Send `GETQUOTAROOT` when advertised.
    fn get_quota_root(&mut self, mailbox: &str);
    /// Send `SETQUOTA` when advertised (`resources` = `"STORAGE 1024 MESSAGE 100"`).
    fn set_quota(&mut self, root: &str, resources: &str);
    /// Send `GETMETADATA mailbox (entries…)` when advertised. `mailbox`
    /// is `""` for server annotations; `options` is an already-formatted
    /// `(DEPTH … MAXSIZE …)` prefix, or empty for none.
    fn get_metadata(&mut self, mailbox: &str, entries: &str, options: &str);
    /// Send `SETMETADATA mailbox (entry value…)` when advertised.
    /// `entries` is an already-formatted `entry value entry value…` body
    /// (a value of `NIL` deletes that entry).
    fn set_metadata(&mut self, mailbox: &str, entries: &str);
    /// Send `NOTIFY SET (SELECTED <events>)` when advertised — see
    /// `crate::server::notify` for which selectors/event-groups a hopf
    /// server actually supports (`events` is e.g.
    /// `"MessageNew MessageExpunge FlagChange"`).
    fn notify_set_selected(&mut self, events: &str);
    /// Send `NOTIFY NONE` when advertised.
    fn notify_none(&mut self);
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
    /// Send `SORT (sort-criteria) charset search-criteria` (RFC 5256 §3).
    fn sort(&mut self, sort_criteria: &str, charset: &str, search_criteria: &str);
    /// Send `UID SORT`.
    fn uid_sort(&mut self, sort_criteria: &str, charset: &str, search_criteria: &str);
    /// Send `THREAD algorithm charset search-criteria` (RFC 5256 §2).
    fn thread(&mut self, algorithm: &str, charset: &str, search_criteria: &str);
    /// Send `UID THREAD`.
    fn uid_thread(&mut self, algorithm: &str, charset: &str, search_criteria: &str);
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

/// What a driver may do when it is woken from outside the reactor — the
/// staged state object for the session's current state, or [`Busy`] when
/// no command is legal right now.
///
/// Handed to [`ImapClientDriver::on_wake`](super::handlers::ImapClientDriver::on_wake).
/// This is how an interactive client (one whose commands originate on a UI
/// or worker thread, not inside a reply callback) drives a live session:
/// queue the work somewhere the driver can see, call
/// [`hopf_core::ConnHandle::poke`] on the handle stashed from an earlier
/// callback, and drain the queue in `on_wake` with the state in hand.
///
/// [`Busy`]: ImapClientWakeState::Busy
pub enum ImapClientWakeState<'a> {
    /// Greeting seen, not yet authenticated (also after a failed login).
    NotAuthenticated(&'a mut dyn ImapClientNotAuthenticated),
    /// Authenticated, no mailbox selected.
    Authenticated(&'a mut dyn ImapClientAuthenticated),
    /// A mailbox is selected.
    Selected(&'a mut dyn ImapClientSelected),
    /// IDLE is active: the only legal command is
    /// [`ImapClientIdle::done`]; issue anything else from
    /// [`on_idle_complete`](super::handlers::ImapClientDriver::on_idle_complete).
    Idle(&'a mut dyn ImapClientIdle),
    /// Nothing can be issued yet: connecting, mid-STARTTLS, IDLE sent but
    /// not yet acknowledged, or logging out. Keep the work queued; the
    /// next wake or callback will find a usable state.
    Busy,
}

impl ImapClientWakeState<'_> {
    /// Short name of the variant, for logs and tests.
    pub fn name(&self) -> &'static str {
        match self {
            Self::NotAuthenticated(_) => "not_authenticated",
            Self::Authenticated(_) => "authenticated",
            Self::Selected(_) => "selected",
            Self::Idle(_) => "idle",
            Self::Busy => "busy",
        }
    }
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
    fn parse_thread_response_chain_and_nested() {
        // A leaf, a single-child chain, and a multi-child (nested) root.
        let threads = parse_thread_response("(2)(3 6)(6 (4 23)(44 7))").unwrap();
        assert_eq!(threads.len(), 3);
        assert_eq!(threads[0], ImapThreadNode { result_number: 2, children: vec![] });
        assert_eq!(
            threads[1],
            ImapThreadNode {
                result_number: 3,
                children: vec![ImapThreadNode { result_number: 6, children: vec![] }],
            }
        );
        let multi = &threads[2];
        assert_eq!(multi.result_number, 6);
        assert_eq!(multi.children.len(), 2);
        assert_eq!(multi.children[0].result_number, 4);
        assert_eq!(multi.children[0].children[0].result_number, 23);
        assert_eq!(multi.children[1].result_number, 44);
        assert_eq!(multi.children[1].children[0].result_number, 7);
    }

    #[test]
    fn parse_thread_response_empty_body_is_no_threads() {
        assert_eq!(parse_thread_response("").unwrap(), Vec::new());
        assert_eq!(parse_thread_response("   ").unwrap(), Vec::new());
    }

    #[test]
    fn parse_thread_response_rejects_malformed_input() {
        assert!(parse_thread_response("not a thread").is_none());
        assert!(parse_thread_response("(1").is_none());
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
