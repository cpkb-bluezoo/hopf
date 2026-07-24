// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP SEARCH criteria and message context.

use std::collections::BTreeSet;
use std::io;

use crate::flag::Flag;
use crate::message_set::MessageSet;

/// Access to message metadata / content for search evaluation.
pub trait MessageContext {
    /// 1-based sequence number.
    fn message_number(&self) -> u32;
    /// IMAP UID.
    fn uid(&self) -> u64;
    /// Size in octets.
    fn size(&self) -> u64;
    /// System flags.
    fn flags(&self) -> BTreeSet<Flag>;
    /// User keywords.
    fn keywords(&self) -> BTreeSet<String>;
    /// Internal date as Unix millis, or `None`.
    fn internal_date_millis(&self) -> Option<i64>;
    /// Sent (`Date`) as Unix millis, or `None`.
    fn sent_date_millis(&self) -> Option<i64>;
    /// Header field value(s) joined, lowercased for substring match.
    fn header(&self, name: &str) -> io::Result<String>;
    /// Body text (may be empty if not indexed / not loaded).
    fn body(&self) -> io::Result<String>;
    /// CONDSTORE modseq, if known.
    fn modseq(&self) -> Option<u64> {
        None
    }
}

/// IMAP SEARCH predicate tree (RFC 9051 §6.4.4).
#[derive(Clone, Debug)]
pub enum SearchCriteria {
    /// ALL
    All,
    /// Message has system flag.
    HasFlag(Flag),
    /// Message lacks system flag.
    NotFlag(Flag),
    /// NEW = Recent ∧ Unseen
    New,
    /// OLD = ¬Recent
    Old,
    /// KEYWORD
    Keyword(String),
    /// UNKEYWORD
    Unkeyword(String),
    /// LARGER
    Larger(u64),
    /// SMALLER
    Smaller(u64),
    /// BEFORE (internal date, local calendar day)
    Before(i32, u32, u32),
    /// ON
    On(i32, u32, u32),
    /// SINCE
    Since(i32, u32, u32),
    /// SENTBEFORE
    SentBefore(i32, u32, u32),
    /// SENTON
    SentOn(i32, u32, u32),
    /// SENTSINCE
    SentSince(i32, u32, u32),
    /// HEADER name substring
    Header {
        /// Header field name.
        name: String,
        /// Case-insensitive substring.
        pattern: String,
    },
    /// BODY substring
    Body(String),
    /// TEXT (headers or body) substring
    Text(String),
    /// UID set
    Uid(MessageSet),
    /// Sequence set
    Sequence(MessageSet),
    /// MODSEQ (CONDSTORE)
    ModSeq(u64),
    /// AND of criteria
    And(Vec<SearchCriteria>),
    /// OR of two criteria
    Or(Box<SearchCriteria>, Box<SearchCriteria>),
    /// NOT
    Not(Box<SearchCriteria>),
}

impl SearchCriteria {
    /// ALL
    pub fn all() -> Self {
        Self::All
    }

    /// AND
    pub fn and(parts: Vec<SearchCriteria>) -> Self {
        Self::And(parts)
    }

    /// OR
    pub fn or(a: SearchCriteria, b: SearchCriteria) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }

    /// NOT
    pub fn negate(c: SearchCriteria) -> Self {
        Self::Not(Box::new(c))
    }

    /// UNSEEN
    pub fn unseen() -> Self {
        Self::NotFlag(Flag::Seen)
    }

    /// SEEN
    pub fn seen() -> Self {
        Self::HasFlag(Flag::Seen)
    }

    /// FLAGGED
    pub fn flagged() -> Self {
        Self::HasFlag(Flag::Flagged)
    }

    /// DELETED
    pub fn deleted() -> Self {
        Self::HasFlag(Flag::Deleted)
    }

    /// DRAFT
    pub fn draft() -> Self {
        Self::HasFlag(Flag::Draft)
    }

    /// ANSWERED
    pub fn answered() -> Self {
        Self::HasFlag(Flag::Answered)
    }

    /// RECENT
    pub fn recent() -> Self {
        Self::HasFlag(Flag::Recent)
    }

    /// FROM
    pub fn from(pattern: impl Into<String>) -> Self {
        Self::Header {
            name: "From".into(),
            pattern: pattern.into(),
        }
    }

    /// SUBJECT
    pub fn subject(pattern: impl Into<String>) -> Self {
        Self::Header {
            name: "Subject".into(),
            pattern: pattern.into(),
        }
    }

    /// BODY
    pub fn body(pattern: impl Into<String>) -> Self {
        Self::Body(pattern.into())
    }

    /// TEXT
    pub fn text(pattern: impl Into<String>) -> Self {
        Self::Text(pattern.into())
    }

    /// Whether this tree needs body content (BODY or TEXT).
    pub fn needs_body(&self) -> bool {
        match self {
            Self::Body(_) | Self::Text(_) => true,
            Self::And(v) => v.iter().any(|c| c.needs_body()),
            Self::Or(a, b) => a.needs_body() || b.needs_body(),
            Self::Not(c) => c.needs_body(),
            _ => false,
        }
    }

    /// Evaluate against a message context.
    pub fn matches(&self, ctx: &dyn MessageContext) -> io::Result<bool> {
        Ok(match self {
            Self::All => true,
            Self::HasFlag(f) => ctx.flags().contains(f),
            Self::NotFlag(f) => !ctx.flags().contains(f),
            Self::New => {
                let f = ctx.flags();
                f.contains(&Flag::Recent) && !f.contains(&Flag::Seen)
            }
            Self::Old => !ctx.flags().contains(&Flag::Recent),
            Self::Keyword(k) => {
                let kl = k.to_ascii_lowercase();
                ctx.keywords()
                    .iter()
                    .any(|x| x.eq_ignore_ascii_case(&kl) || x.to_ascii_lowercase() == kl)
            }
            Self::Unkeyword(k) => {
                let kl = k.to_ascii_lowercase();
                !ctx.keywords()
                    .iter()
                    .any(|x| x.eq_ignore_ascii_case(&kl))
            }
            Self::Larger(n) => ctx.size() > *n,
            Self::Smaller(n) => ctx.size() < *n,
            Self::Before(y, m, d) => date_before(ctx.internal_date_millis(), *y, *m, *d),
            Self::On(y, m, d) => date_on(ctx.internal_date_millis(), *y, *m, *d),
            Self::Since(y, m, d) => date_since(ctx.internal_date_millis(), *y, *m, *d),
            Self::SentBefore(y, m, d) => date_before(ctx.sent_date_millis(), *y, *m, *d),
            Self::SentOn(y, m, d) => date_on(ctx.sent_date_millis(), *y, *m, *d),
            Self::SentSince(y, m, d) => date_since(ctx.sent_date_millis(), *y, *m, *d),
            Self::Header { name, pattern } => {
                let v = ctx.header(name)?;
                v.to_ascii_lowercase()
                    .contains(&pattern.to_ascii_lowercase())
            }
            Self::Body(pat) => {
                let body = ctx.body()?;
                body.to_ascii_lowercase()
                    .contains(&pat.to_ascii_lowercase())
            }
            Self::Text(pat) => {
                let p = pat.to_ascii_lowercase();
                let headers = ["from", "to", "cc", "bcc", "subject", "message-id"];
                let mut hit = false;
                for h in headers {
                    if ctx.header(h)?.to_ascii_lowercase().contains(&p) {
                        hit = true;
                        break;
                    }
                }
                if !hit {
                    hit = ctx.body()?.to_ascii_lowercase().contains(&p);
                }
                hit
            }
            Self::Uid(set) => {
                // Callers should resolve `*` against mailbox uid_next-1 when needed.
                set.contains(ctx.uid(), ctx.uid())
            }
            Self::Sequence(set) => {
                set.contains(ctx.message_number() as u64, ctx.message_number() as u64)
            }
            Self::ModSeq(n) => ctx.modseq().map(|m| m >= *n).unwrap_or(false),
            Self::And(parts) => {
                let mut ok = true;
                for p in parts {
                    if !p.matches(ctx)? {
                        ok = false;
                        break;
                    }
                }
                ok
            }
            Self::Or(a, b) => a.matches(ctx)? || b.matches(ctx)?,
            Self::Not(c) => !c.matches(ctx)?,
        })
    }
}

fn ymd_from_millis(ms: i64) -> (i32, u32, u32) {
    // Civil date in UTC — good enough for SEARCH day predicates.
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    // 1970-01-01 = day 0
    civil_from_days(days)
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    // Howard Hinnant algorithms
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn date_on(ms: Option<i64>, y: i32, m: u32, d: u32) -> bool {
    match ms {
        Some(ms) => ymd_from_millis(ms) == (y, m, d),
        None => false,
    }
}

fn date_before(ms: Option<i64>, y: i32, m: u32, d: u32) -> bool {
    match ms {
        Some(ms) => {
            let (yy, mm, dd) = ymd_from_millis(ms);
            (yy, mm, dd) < (y, m, d)
        }
        None => false,
    }
}

fn date_since(ms: Option<i64>, y: i32, m: u32, d: u32) -> bool {
    match ms {
        Some(ms) => {
            let (yy, mm, dd) = ymd_from_millis(ms);
            (yy, mm, dd) >= (y, m, d)
        }
        None => false,
    }
}
