// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::time::{SystemTime, UNIX_EPOCH};

use crate::headers::Headers;
use crate::utils::parse_http_date;

use super::entity_tag::{parse_entity_tag_list, EntityTag, EntityTagList};

/// The validators of a resource's current representation.
#[derive(Debug, Clone, Default)]
pub struct Validators {
    /// Current entity-tag, if the server can produce one.
    pub etag: Option<EntityTag>,
    /// Current modification time, if known.
    pub last_modified: Option<SystemTime>,
}

impl Validators {
    /// Validators with neither tag nor date (preconditions then only act on
    /// existence, e.g. `If-None-Match: *`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the entity-tag.
    pub fn etag(mut self, etag: EntityTag) -> Self {
        self.etag = Some(etag);
        self
    }

    /// Set the modification time.
    pub fn last_modified(mut self, t: SystemTime) -> Self {
        self.last_modified = Some(t);
        self
    }
}

/// What a request's preconditions mean for the current resource state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precondition {
    /// Carry on and perform the request normally.
    Proceed,
    /// `GET`/`HEAD` only: send `304 Not Modified` instead of the body.
    NotModified,
    /// Do not perform the request: send `412 Precondition Failed`.
    PreconditionFailed,
}

/// Whole seconds since the epoch. HTTP-dates have one-second resolution,
/// so a modification time must be truncated before it is compared with one:
/// a file modified at 12:00:00.5 was sent as `12:00:00`, and a client echoing
/// that back has the current version.
fn secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64) - i64::from(e.duration().subsec_nanos() > 0),
    }
}

/// All values of `name`, comma-joined (a list field may arrive as several
/// lines).
fn combined(req: &Headers, name: &str) -> Option<String> {
    let mut it = req.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    let first = it.next()?;
    let mut out = first.value.clone();
    for h in it {
        out.push_str(", ");
        out.push_str(&h.value);
    }
    Some(out)
}

/// A date field's value, unless it must be ignored: it appears more than
/// once (RFC 9110 §13.1.3: "more than one member") or is not an HTTP-date.
fn date_field(req: &Headers, name: &str) -> Option<i64> {
    let mut it = req.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    let first = it.next()?;
    if it.next().is_some() {
        return None;
    }
    parse_http_date(&first.value).map(secs)
}

/// Evaluate a request's preconditions against a resource (RFC 9110 §13.2.2).
///
/// `current` is the resource's present validators, or `None` if it does not
/// exist. Steps, in the RFC's order:
///
/// 1. `If-Match`: false (no strong match, or `*` on a missing resource) is
///    [`Precondition::PreconditionFailed`].
/// 2. Otherwise `If-Unmodified-Since`: modified after the date is
///    `PreconditionFailed`.
/// 3. `If-None-Match`: a weak match (or `*` on an existing resource) is
///    `NotModified` for `GET`/`HEAD` and `PreconditionFailed` for anything
///    else.
/// 4. Otherwise, for `GET`/`HEAD`, `If-Modified-Since`: not modified after
///    the date is `NotModified`.
///
/// A field that is malformed (or, for dates, repeated) is ignored, as the
/// RFC requires. `If-Range` is not evaluated here.
///
/// Call this before changing anything; a handler that has already acted
/// cannot honour a failed precondition.
pub fn evaluate_preconditions(
    method: &str,
    request: &Headers,
    current: Option<&Validators>,
) -> Precondition {
    let safe = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
    let modified = current.and_then(|v| v.last_modified).map(secs);

    // 1. If-Match.
    let if_match = combined(request, "if-match");
    if let Some(list) = if_match.as_deref().and_then(parse_entity_tag_list) {
        let ok = match (&list, current) {
            (_, None) => false,
            (EntityTagList::Any, Some(_)) => true,
            (EntityTagList::Tags(tags), Some(v)) => v
                .etag
                .as_ref()
                .is_some_and(|cur| tags.iter().any(|t| t.strong_eq(cur))),
        };
        if !ok {
            return Precondition::PreconditionFailed;
        }
    } else if let Some(date) = date_field(request, "if-unmodified-since") {
        // 2. If-Unmodified-Since, only when If-Match is absent.
        if modified.is_some_and(|m| m > date) {
            return Precondition::PreconditionFailed;
        }
    }

    // 3. If-None-Match.
    let if_none_match = combined(request, "if-none-match");
    if let Some(list) = if_none_match.as_deref().and_then(parse_entity_tag_list) {
        let matched = match (&list, current) {
            (_, None) => false,
            (EntityTagList::Any, Some(_)) => true,
            (EntityTagList::Tags(tags), Some(v)) => v
                .etag
                .as_ref()
                .is_some_and(|cur| tags.iter().any(|t| t.weak_eq(cur))),
        };
        if matched {
            return if safe {
                Precondition::NotModified
            } else {
                Precondition::PreconditionFailed
            };
        }
    } else if safe && !request.contains("if-none-match") {
        // 4. If-Modified-Since, only when If-None-Match is absent.
        if let Some(date) = date_field(request, "if-modified-since") {
            if modified.is_some_and(|m| m <= date) {
                return Precondition::NotModified;
            }
        }
    }

    Precondition::Proceed
}
