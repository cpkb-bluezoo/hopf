// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP NOTIFY (RFC 5465) — deliberately partial support.
//!
//! This implementation covers:
//! - `NOTIFY NONE` (turn notifications off).
//! - `NOTIFY SET (SELECTED MessageNew MessageExpunge FlagChange)` — any
//!   subset/order of those three event groups, for the *currently
//!   selected* mailbox only — delivered as unsolicited `EXISTS` /
//!   `EXPUNGE` / `FETCH (FLAGS ...)` responses at any point while the
//!   connection isn't itself blocked inside an `IDLE` command, reusing the
//!   same poll-and-diff machinery `IDLE` already has (see
//!   [`crate::server::idle`]) against the same baseline snapshot, so an
//!   event is reported exactly once regardless of which of the two
//!   mechanisms happens to observe it first.
//!
//! Deliberately deferred — rejected with a clear parse error (surfaced as
//! a tagged `BAD`), not silently ignored:
//! - The `personal`, `inboxes`, `subtree` and `mailboxes` mailbox
//!   selectors: real support needs polling every mailbox in the store, not
//!   just the selected one, which this server's connection-scoped storage
//!   access doesn't yet have a cheap way to do.
//! - The `AnnotationChange`, `MailboxName`, `SubscriptionChange` and
//!   `MailboxMetadataChange` / `ServerMetadataChange` event groups.
//! - `MessageNew`'s optional trailing status-item sublist (e.g.
//!   `MessageNew (UIDNEXT)`) and `SET STATUS`'s immediate catch-up
//!   `STATUS` response for newly-registered selectors — the `STATUS`
//!   keyword itself is accepted (so a client that always sends it isn't
//!   rejected) but has no additional effect.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// One NOTIFY event group this implementation understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NotifyEvent {
    /// `MessageNew`
    MessageNew,
    /// `MessageExpunge`
    MessageExpunge,
    /// `FlagChange`
    FlagChange,
}

/// This connection's requested NOTIFY registration, as parsed from one
/// `NOTIFY` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotifyState {
    /// `NOTIFY NONE`.
    None,
    /// `NOTIFY SET (SELECTED <events>)`.
    Selected(BTreeSet<NotifyEvent>),
}

/// Parse `NOTIFY` command args (everything after the verb).
pub fn parse_notify(args: &str) -> Result<NotifyState, String> {
    let args = args.trim();
    if args.eq_ignore_ascii_case("NONE") {
        return Ok(NotifyState::None);
    }
    let (first, rest) = split_first_word(args).ok_or_else(|| "expected NONE or SET".to_string())?;
    if !first.eq_ignore_ascii_case("SET") {
        return Err(format!("expected NONE or SET, got: {first}"));
    }
    let mut rest = rest.trim_start();
    if let Some((word, after)) = split_first_word(rest) {
        if word.eq_ignore_ascii_case("STATUS") {
            rest = after.trim_start();
        }
    }
    if !rest.starts_with('(') || !rest.ends_with(')') {
        return Err("expected a single parenthesized mailbox-selector group".into());
    }
    let inner = &rest[1..rest.len() - 1];
    if inner.contains('(') || inner.contains(')') {
        return Err(
            "nested selector groups and per-event status-item lists are not supported".into(),
        );
    }
    let mut tokens = inner.split_whitespace();
    let selector = tokens
        .next()
        .ok_or_else(|| "expected a mailbox-selector".to_string())?;
    if !selector.eq_ignore_ascii_case("SELECTED") {
        return Err(format!(
            "unsupported NOTIFY mailbox-selector: {selector} (only SELECTED is implemented)"
        ));
    }
    let mut events = BTreeSet::new();
    for tok in tokens {
        match tok.to_ascii_uppercase().as_str() {
            "MESSAGENEW" => {
                events.insert(NotifyEvent::MessageNew);
            }
            "MESSAGEEXPUNGE" => {
                events.insert(NotifyEvent::MessageExpunge);
            }
            "FLAGCHANGE" => {
                events.insert(NotifyEvent::FlagChange);
            }
            "NONE" => {}
            other => {
                return Err(format!(
                    "unsupported NOTIFY event-group: {other} (only MessageNew, MessageExpunge, FlagChange are implemented)"
                ));
            }
        }
    }
    Ok(NotifyState::Selected(events))
}

fn split_first_word(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    if end == 0 {
        None
    } else {
        Some((&s[..end], &s[end..]))
    }
}

/// Keep only the diff lines from [`crate::server::idle::idle_diff_lines`]
/// that `events` asked for, classifying each by its trailing keyword —
/// `EXISTS` is `MessageNew`, `EXPUNGE` is `MessageExpunge`, `FETCH (FLAGS`
/// is `FlagChange`.
pub fn filter_notify_lines(lines: Vec<String>, events: &BTreeSet<NotifyEvent>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|line| {
            if line.ends_with("EXISTS") {
                events.contains(&NotifyEvent::MessageNew)
            } else if line.ends_with("EXPUNGE") {
                events.contains(&NotifyEvent::MessageExpunge)
            } else if line.contains("FETCH (FLAGS") {
                events.contains(&NotifyEvent::FlagChange)
            } else {
                false
            }
        })
        .collect()
}

/// Shared, thread-safe NOTIFY registration — the timer callback (running
/// outside any single command dispatch) reads this to decide whether to
/// keep polling and what to filter for; `cmd_notify` writes it.
#[derive(Clone, Default)]
pub struct NotifyShared {
    events: Arc<Mutex<Option<BTreeSet<NotifyEvent>>>>,
    /// Whether a poll timer chain is currently scheduled for this
    /// connection — guards against arming a second, concurrent chain if
    /// the client sends `NOTIFY SET` more than once in a row.
    armed: Arc<AtomicBool>,
}

impl NotifyShared {
    /// Replace the current registration (`None` = `NOTIFY NONE`).
    pub fn set(&self, events: Option<BTreeSet<NotifyEvent>>) {
        *self.events.lock().unwrap() = events;
    }

    /// Currently-registered event set, if NOTIFY is active.
    pub fn wanted(&self) -> Option<BTreeSet<NotifyEvent>> {
        self.events.lock().unwrap().clone()
    }

    /// Whether a poll chain is already scheduled.
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Relaxed)
    }

    /// Mark a poll chain as scheduled (or, on `false`, note that the
    /// previous chain has stopped and a future `NOTIFY SET` needs to arm
    /// a fresh one).
    pub fn set_armed(&self, armed: bool) {
        self.armed.store(armed, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_none() {
        assert_eq!(parse_notify("NONE").unwrap(), NotifyState::None);
        assert_eq!(parse_notify("none").unwrap(), NotifyState::None);
    }

    #[test]
    fn parses_set_selected_with_all_events() {
        let s = parse_notify("SET (SELECTED MessageNew MessageExpunge FlagChange)").unwrap();
        match s {
            NotifyState::Selected(events) => {
                assert_eq!(events.len(), 3);
                assert!(events.contains(&NotifyEvent::MessageNew));
                assert!(events.contains(&NotifyEvent::MessageExpunge));
                assert!(events.contains(&NotifyEvent::FlagChange));
            }
            NotifyState::None => panic!("expected Selected"),
        }
    }

    #[test]
    fn parses_set_status_prefix_and_subset_of_events() {
        let s = parse_notify("SET STATUS (SELECTED FlagChange)").unwrap();
        match s {
            NotifyState::Selected(events) => {
                assert_eq!(events, BTreeSet::from([NotifyEvent::FlagChange]));
            }
            NotifyState::None => panic!("expected Selected"),
        }
    }

    #[test]
    fn rejects_unsupported_selector() {
        let err = parse_notify("SET (PERSONAL MessageNew)").unwrap_err();
        assert!(err.contains("PERSONAL"), "{err}");
    }

    #[test]
    fn rejects_unsupported_event_group() {
        let err = parse_notify("SET (SELECTED MailboxName)").unwrap_err();
        assert!(err.contains("MailboxName") || err.contains("MAILBOXNAME"), "{err}");
    }

    #[test]
    fn rejects_multiple_selector_groups() {
        assert!(parse_notify("SET (SELECTED MessageNew) (PERSONAL MessageNew)").is_err());
    }

    #[test]
    fn filter_lines_by_event_kind() {
        let lines = vec![
            "1 EXPUNGE".to_string(),
            "2 EXISTS".to_string(),
            "2 FETCH (FLAGS (\\Seen))".to_string(),
        ];
        let only_flags = filter_notify_lines(lines.clone(), &BTreeSet::from([NotifyEvent::FlagChange]));
        assert_eq!(only_flags, vec!["2 FETCH (FLAGS (\\Seen))".to_string()]);

        let new_and_expunge = filter_notify_lines(
            lines,
            &BTreeSet::from([NotifyEvent::MessageNew, NotifyEvent::MessageExpunge]),
        );
        assert_eq!(
            new_and_expunge,
            vec!["1 EXPUNGE".to_string(), "2 EXISTS".to_string()]
        );
    }
}
