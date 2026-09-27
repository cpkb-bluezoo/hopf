// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 5256 SORT.

use hopf_mailbox::MessageContext;

/// One SORT key (RFC 5256 §3), optionally reversed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    /// Internal ("arrival") date/time.
    Arrival,
    /// IMAP addr-mailbox of the first Cc address.
    Cc,
    /// Sent (`Date:` header) date/time.
    Date,
    /// IMAP addr-mailbox of the first From address.
    From,
    /// Message size in octets.
    Size,
    /// Base subject text (RFC 5256 §2.1).
    Subject,
    /// IMAP addr-mailbox of the first To address.
    To,
}

/// A [`SortKey`] plus its direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SortCriterion {
    /// Which field to compare.
    pub key: SortKey,
    /// `REVERSE`: reverses this key only (RFC 5256 §3), not the implicit
    /// sequence-number tie-break.
    pub reverse: bool,
}

/// Parse `SORT`/`UID SORT`'s full argument grammar: `(sort-criteria)
/// charset search-criteria` (RFC 5256 §3). `charset` is accepted but not
/// otherwise used — hopf-imap's header/body matching is UTF-8 throughout
/// regardless of what the client declares — except that anything other
/// than `UTF-8`/`US-ASCII` is rejected, matching common client
/// expectations for `NO [BADCHARSET ...]`. Returns the parsed keys and the
/// still-unparsed search-criteria remainder (the caller runs that through
/// [`crate::server::search_parse::parse_search`]).
pub fn parse_sort_command(args: &str) -> Result<(Vec<SortCriterion>, String), String> {
    let args = args.trim_start();
    if !args.starts_with('(') {
        return Err("SORT requires a parenthesized key list".into());
    }
    let close = args
        .find(')')
        .ok_or_else(|| "unclosed SORT key list".to_string())?;
    let (paren, rest) = args.split_at(close + 1);
    let criteria = parse_sort_criteria(paren)?;
    let (charset, rest) = crate::server::codec::parse_astring(rest.trim_start())?;
    validate_charset(&charset)?;
    Ok((criteria, rest.trim_start().to_string()))
}

/// RFC 5256 §5's `[BADCHARSET]` case: only UTF-8 and US-ASCII are ever
/// meaningfully different from what hopf-imap already does with header
/// bytes, so those are the only two accepted.
pub(crate) fn validate_charset(charset: &str) -> Result<(), String> {
    if charset.eq_ignore_ascii_case("UTF-8") || charset.eq_ignore_ascii_case("US-ASCII") {
        Ok(())
    } else {
        Err(format!("[BADCHARSET (UTF-8 US-ASCII)] unsupported charset {charset}"))
    }
}

/// Parse the parenthesized sort-criteria list, e.g. `(REVERSE DATE SUBJECT)`.
pub fn parse_sort_criteria(s: &str) -> Result<Vec<SortCriterion>, String> {
    let s = s.trim();
    let inner = s
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| "SORT requires a parenthesized key list".to_string())?;
    let mut criteria = Vec::new();
    let mut pending_reverse = false;
    for tok in inner.split_whitespace() {
        let key = match tok.to_ascii_uppercase().as_str() {
            "REVERSE" => {
                pending_reverse = true;
                continue;
            }
            "ARRIVAL" => SortKey::Arrival,
            "CC" => SortKey::Cc,
            "DATE" => SortKey::Date,
            "FROM" => SortKey::From,
            "SIZE" => SortKey::Size,
            "SUBJECT" => SortKey::Subject,
            "TO" => SortKey::To,
            other => return Err(format!("unknown SORT key {other}")),
        };
        criteria.push(SortCriterion {
            key,
            reverse: pending_reverse,
        });
        pending_reverse = false;
    }
    if criteria.is_empty() {
        return Err("empty SORT key list".into());
    }
    Ok(criteria)
}

/// One message's extracted sort keys, and its (sequence or UID) result
/// number — everything [`sort_messages`] needs, gathered ahead of time so
/// the actual sort is pure in-memory comparison (no further mailbox I/O).
#[derive(Clone, Debug)]
pub struct SortableMessage {
    /// The number this message is reported as in the response (a UID or a
    /// sequence number, depending on `SORT` vs `UID SORT`).
    pub result_number: u64,
    /// Tie-break: always the sequence number, regardless of `by_uid`
    /// (RFC 5256 §3: "the implicit sort criterion is sequence number").
    pub sequence_number: u32,
    /// Internal ("arrival") date, Unix millis.
    pub arrival: i64,
    /// Sent (`Date:` header) date, Unix millis.
    pub sent: i64,
    /// Size in octets.
    pub size: u64,
    /// First `From` address.
    pub from: String,
    /// First `To` address.
    pub to: String,
    /// First `Cc` address.
    pub cc: String,
    /// [`base_subject`] of the `Subject` header.
    pub base_subject: String,
}

impl SortableMessage {
    /// Gather every field [`sort_messages`] might need for `ctx` — called
    /// once per matched message, on the storage pool.
    pub fn gather(ctx: &dyn MessageContext, result_number: u64) -> std::io::Result<Self> {
        Ok(Self {
            result_number,
            sequence_number: ctx.message_number(),
            arrival: ctx.internal_date_millis().unwrap_or(0),
            sent: ctx.sent_date_millis().unwrap_or(0),
            size: ctx.size(),
            from: first_address(&ctx.header("From")?),
            to: first_address(&ctx.header("To")?),
            cc: first_address(&ctx.header("Cc")?),
            base_subject: base_subject(&ctx.header("Subject")?),
        })
    }
}

/// The first whitespace-separated token of an indexed address field (the
/// index stores `From`/`To`/`Cc` as space-joined addr-mailboxes in header
/// order — see `hopf_mailbox::index::IndexBuilder`).
fn first_address(joined: &str) -> String {
    joined.split_whitespace().next().unwrap_or("").to_string()
}

/// Sorts `messages` in place per `criteria`, left-to-right, each key
/// breaking ties left by the previous one, with sequence number as the
/// final (always ascending, per RFC 5256 §3) tie-break.
pub fn sort_messages(messages: &mut [SortableMessage], criteria: &[SortCriterion]) {
    messages.sort_by(|a, b| {
        for c in criteria {
            let ord = compare_key(a, b, c.key);
            let ord = if c.reverse { ord.reverse() } else { ord };
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        a.sequence_number.cmp(&b.sequence_number)
    });
}

fn compare_key(a: &SortableMessage, b: &SortableMessage, key: SortKey) -> std::cmp::Ordering {
    match key {
        SortKey::Arrival => a.arrival.cmp(&b.arrival),
        SortKey::Date => a.sent.cmp(&b.sent),
        SortKey::Size => a.size.cmp(&b.size),
        SortKey::From => a.from.cmp(&b.from),
        SortKey::To => a.to.cmp(&b.to),
        SortKey::Cc => a.cc.cmp(&b.cc),
        SortKey::Subject => a.base_subject.cmp(&b.base_subject),
    }
}

/// RFC 5256 §2.1 base subject algorithm — used both by the `SUBJECT` sort
/// key and by THREAD (both algorithms group by it). `subject` is the raw
/// header value, already unfolded to one line by the header extractor.
pub fn base_subject(subject: &str) -> String {
    // (1) tabs/continuations -> space, multiple spaces -> one. The header
    // extractor already joins folded continuation lines with a single
    // space (see `hopf_mailbox::search`), so this just normalizes runs of
    // whitespace left over from that.
    let mut s = collapse_whitespace(subject.trim());
    loop {
        let before = s.clone();
        s = strip_trailer(&s);
        s = strip_leader(&s);
        s = strip_blob_if_nonempty_remainder(&s);
        if s == before {
            break;
        }
    }
    // (6) [fwd:...] wrapper: unwrap and restart from (2).
    if let Some(inner) = strip_fwd_wrapper(&s) {
        return base_subject(&inner);
    }
    s.to_ascii_lowercase()
}

/// RFC 5256 §2.2's "is a reply or forward" test (used by THREAD REFERENCES
/// steps 5B/5C): true iff `subject` starts with something [`strip_leader`]
/// would remove — a `Re:`/`Fwd:`/`Fw:` (optionally with a `[...]` blob
/// first), after whitespace normalization.
pub fn is_reply_or_forward(subject: &str) -> bool {
    let collapsed = collapse_whitespace(subject.trim());
    strip_leader(&collapsed) != collapsed
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for c in s.chars() {
        let is_ws = c == ' ' || c == '\t' || c == '\r' || c == '\n';
        if is_ws {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(c);
            last_was_space = false;
        }
    }
    out.trim().to_string()
}

/// `subj-trailer = "(fwd)" / WSP` — repeatedly strip trailing `(fwd)` or
/// whitespace.
fn strip_trailer(s: &str) -> String {
    let mut s = s.to_string();
    loop {
        let trimmed = s.trim_end();
        if trimmed.len() != s.len() {
            s = trimmed.to_string();
            continue;
        }
        if let Some(rest) = s.strip_suffix("(fwd)") {
            s = rest.to_string();
            continue;
        }
        break;
    }
    s
}

/// `subj-leader = subj-blob *(subj-refwd) / *(subj-refwd)` — strips a
/// leading `Re:`/`Fwd:`/`Fw:` (optionally with a `[...]` blob before the
/// colon), any amount of surrounding whitespace.
fn strip_leader(s: &str) -> String {
    let mut s = s;
    loop {
        let t = s.trim_start();
        if let Some(rest) = strip_one_refwd(t) {
            s = rest;
            continue;
        }
        if t.len() != s.len() {
            s = t;
            continue;
        }
        break;
    }
    s.to_string()
}

/// Matches one `subj-refwd = ("re" / ("fw" ["d"])) *WSP [subj-blob] ":"` at
/// the start of `s`, case-insensitively; returns what follows the colon.
fn strip_one_refwd(s: &str) -> Option<&str> {
    let lower_prefix_len = if s.len() >= 2 && s[..2].eq_ignore_ascii_case("re") {
        2
    } else if s.len() >= 3 && s[..3].eq_ignore_ascii_case("fwd") {
        3
    } else if s.len() >= 2 && s[..2].eq_ignore_ascii_case("fw") {
        2
    } else {
        return None;
    };
    let mut rest = s[lower_prefix_len..].trim_start();
    // Optional `[...]` blob before the colon (e.g. "Re[2]:").
    if let Some(after_bracket) = strip_blob_prefix(rest) {
        rest = after_bracket.trim_start();
    }
    rest.strip_prefix(':').map(|r| r.trim_start())
}

/// `subj-blob = "[" *BLOBCHAR "]" *WSP` where BLOBCHAR excludes `[`/`]` —
/// returns what follows the closing `]` (and any trailing whitespace) if
/// `s` starts with a well-formed blob, else `None`.
fn strip_blob_prefix(s: &str) -> Option<&str> {
    let rest = s.strip_prefix('[')?;
    let end = rest.find(['[', ']'])?;
    if rest.as_bytes()[end] != b']' {
        return None; // an inner '[' before the closing ']' — not a blob
    }
    Some(rest[end + 1..].trim_start())
}

/// (4): if a leading blob's removal would still leave a non-empty
/// subj-base, remove it; otherwise leave `s` untouched.
fn strip_blob_if_nonempty_remainder(s: &str) -> String {
    if let Some(after) = strip_blob_prefix(s) {
        if !after.is_empty() {
            return after.to_string();
        }
    }
    s.to_string()
}

/// (6): `subj-fwd-hdr = "[fwd:"`, `subj-fwd-trl = "]"` — case-insensitive.
fn strip_fwd_wrapper(s: &str) -> Option<String> {
    if s.len() < 6 {
        return None;
    }
    if !s[..5].eq_ignore_ascii_case("[fwd:") || !s.ends_with(']') {
        return None;
    }
    Some(s[5..s.len() - 1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_subject_strips_re_and_fwd() {
        assert_eq!(base_subject("Re: hello"), "hello");
        assert_eq!(base_subject("Fwd: hello"), "hello");
        assert_eq!(base_subject("FW: hello"), "hello");
        assert_eq!(base_subject("Re: Re: hello"), "hello");
        assert_eq!(base_subject("hello"), "hello");
    }

    #[test]
    fn base_subject_strips_trailing_fwd_marker() {
        assert_eq!(base_subject("hello (fwd)"), "hello");
        assert_eq!(base_subject("hello (fwd) (fwd)"), "hello");
    }

    #[test]
    fn base_subject_strips_mailing_list_blob() {
        assert_eq!(base_subject("[bug-hopf] hello"), "hello");
        assert_eq!(base_subject("Re: [bug-hopf] hello"), "hello");
    }

    #[test]
    fn base_subject_unwraps_fwd_bracket_form() {
        assert_eq!(base_subject("[fwd: hello]"), "hello");
    }

    #[test]
    fn base_subject_is_case_insensitive_and_folds_whitespace() {
        assert_eq!(base_subject("  RE:   hello   world  "), "hello world");
    }

    #[test]
    fn base_subject_does_not_strip_a_bare_blob_leaving_empty_base() {
        // Removing the blob would leave nothing, so §2.1 step (4) says
        // don't: this is the whole (non-list-tag) subject.
        assert_eq!(base_subject("[bug-hopf]"), "[bug-hopf]".to_ascii_lowercase());
    }

    #[test]
    fn parse_sort_criteria_basic() {
        let c = parse_sort_criteria("(REVERSE DATE SUBJECT)").unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].key, SortKey::Date);
        assert!(c[0].reverse);
        assert_eq!(c[1].key, SortKey::Subject);
        assert!(!c[1].reverse);
    }

    #[test]
    fn parse_sort_criteria_rejects_unknown_key() {
        assert!(parse_sort_criteria("(BOGUS)").is_err());
    }

    fn msg(seq: u32, size: u64, subject: &str) -> SortableMessage {
        SortableMessage {
            result_number: seq as u64,
            sequence_number: seq,
            arrival: 0,
            sent: 0,
            size,
            from: String::new(),
            to: String::new(),
            cc: String::new(),
            base_subject: base_subject(subject),
        }
    }

    #[test]
    fn sort_by_size_then_sequence_tiebreak() {
        let mut msgs = vec![msg(3, 10, "c"), msg(1, 20, "a"), msg(2, 10, "b")];
        sort_messages(
            &mut msgs,
            &[SortCriterion {
                key: SortKey::Size,
                reverse: false,
            }],
        );
        let order: Vec<u32> = msgs.iter().map(|m| m.sequence_number).collect();
        // size 10 (seq 2, seq 3, tie broken by sequence) then size 20 (seq 1)
        assert_eq!(order, vec![2, 3, 1]);
    }

    #[test]
    fn sort_reverse_only_reverses_that_one_criterion() {
        let mut msgs = vec![msg(1, 10, "z"), msg(2, 10, "a")];
        sort_messages(
            &mut msgs,
            &[
                SortCriterion {
                    key: SortKey::Size,
                    reverse: true,
                },
                SortCriterion {
                    key: SortKey::Subject,
                    reverse: false,
                },
            ],
        );
        // Sizes are equal, so SIZE's REVERSE has no effect here; SUBJECT
        // (not reversed) breaks the tie ascending: "a" before "z".
        let order: Vec<u32> = msgs.iter().map(|m| m.sequence_number).collect();
        assert_eq!(order, vec![2, 1]);
    }
}
