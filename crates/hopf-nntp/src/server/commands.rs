// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The commands that read the news (RFC 3977 sections 6 to 8), run on a
//! storage thread against the connection's [`ReaderHandler`].
//!
//! Each writes its answer to an [`Output`] as it goes, so that nothing it
//! sends is ever held whole, and each stops as soon as the output says it has
//! nowhere to go. A command either fails before it has sent anything, with a
//! status line, or it has begun a multi-line answer that cannot be taken
//! back, and a failure after that ends the connection.

use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::server::codec::{ListKind, NewGroupsSince, NntpCommand, Target, MAX_ARTICLE_NUMBER};
use crate::server::egress::{ArticlePart, NntpDotStuffer};
use crate::server::handler::{HandlerError, Located, NewsgroupInfo, OverviewRecord, PostSink, ReaderHandler};
use crate::server::metrics::NntpServerMetrics;
use crate::server::pipe::Output;
use crate::server::reply::{self, END};
use crate::server::wildmat::Wildmat;

/// How many article numbers are asked of the handler at a time.
const PAGE: usize = 256;

/// What the connection has selected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionState {
    /// The selected newsgroup.
    pub group: Option<String>,
    /// The current article number.
    pub current: Option<u32>,
}

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobEnd {
    /// The connection carries on.
    Continue,
    /// The answer could not be finished, or could not be delivered: the
    /// connection must be closed.
    Fatal,
    /// `340` was sent: the client's article follows.
    PostData,
}

/// Does `command` run against the handler (and so on the storage pool)?
pub(crate) fn needs_handler(command: &NntpCommand) -> bool {
    matches!(
        command,
        NntpCommand::Group(_)
            | NntpCommand::ListGroup(..)
            | NntpCommand::Last
            | NntpCommand::Next
            | NntpCommand::Article(_)
            | NntpCommand::Head(_)
            | NntpCommand::Body(_)
            | NntpCommand::Stat(_)
            | NntpCommand::List(_)
            | NntpCommand::NewGroups(_)
            | NntpCommand::Over(_)
            | NntpCommand::Hdr(..)
            | NntpCommand::Post
    )
}

fn say(out: &mut Output, code: u16, text: &str) -> bool {
    out.write(&reply::status(code, text))
}

fn fault(out: &mut Output, error: &HandlerError, what: &str) -> JobEnd {
    hopf_core::subsystem_log(
        hopf_core::LogLevel::Error,
        "hopf-nntp",
        "nntp.handler.failed",
        format!("{what} failed: {error}"),
    );
    if say(out, 403, "Internal fault or problem preventing action being taken") {
        JobEnd::Continue
    } else {
        JobEnd::Fatal
    }
}

fn ended(alive: bool) -> JobEnd {
    if alive {
        JobEnd::Continue
    } else {
        JobEnd::Fatal
    }
}

/// Runs `command`.
pub(crate) fn run(
    command: &NntpCommand,
    handler: &mut dyn ReaderHandler,
    session: &mut SessionState,
    out: &mut Output,
    metrics: &NntpServerMetrics,
) -> JobEnd {
    match command {
        NntpCommand::Group(name) => group(handler, session, out, name),
        NntpCommand::ListGroup(name, range) => list_group(handler, session, out, name.as_deref(), range.as_ref()),
        NntpCommand::Last => step(handler, session, out, false),
        NntpCommand::Next => step(handler, session, out, true),
        NntpCommand::Article(t) => article(handler, session, out, metrics, t, ArticlePart::Full),
        NntpCommand::Head(t) => article(handler, session, out, metrics, t, ArticlePart::Head),
        NntpCommand::Body(t) => article(handler, session, out, metrics, t, ArticlePart::Body),
        NntpCommand::Stat(t) => stat(handler, session, out, t),
        NntpCommand::List(kind) => list(handler, out, kind),
        NntpCommand::NewGroups(since) => new_groups(handler, out, since),
        NntpCommand::Over(t) => over(handler, session, out, t),
        NntpCommand::Hdr(field, t) => hdr(handler, session, out, field, t),
        // Not commands for the handler; the connection answers these itself.
        _ => ended(say(out, 500, "Unknown command")),
    }
}

// ---- POST ----

/// Where a post in progress is kept between the pieces of it.
pub(crate) struct PostSlot {
    pub sink: Mutex<Option<Box<dyn PostSink>>>,
    /// Why the article is being refused, for the `441`, once it has been.
    pub error: Mutex<Option<String>>,
}

impl PostSlot {
    pub(crate) fn new() -> Self {
        Self { sink: Mutex::new(None), error: Mutex::new(None) }
    }

    /// Lets go of a post that was abandoned.
    pub(crate) fn abandon(&self) {
        let sink = self.sink.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(sink) = sink {
            sink.abort();
        }
    }

    fn refuse(&self, error: &HandlerError) {
        let text = match error {
            HandlerError::Refused(text) => text.clone(),
            other => {
                hopf_core::subsystem_log(
                    hopf_core::LogLevel::Error,
                    "hopf-nntp",
                    "nntp.post.failed",
                    format!("a post failed: {other}"),
                );
                "Posting failed".to_string()
            }
        };
        *self.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(text);
    }
}

/// `POST`: asks the handler for somewhere to put the article.
pub(crate) fn post_begin(handler: &mut dyn ReaderHandler, post: &PostSlot, out: &mut Output) -> JobEnd {
    *post.error.lock().unwrap_or_else(|e| e.into_inner()) = None;
    match handler.begin_post() {
        Ok(sink) => {
            *post.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
            if say(out, 340, "Input article; end with <CR-LF>.<CR-LF>") {
                JobEnd::PostData
            } else {
                post.abandon();
                JobEnd::Fatal
            }
        }
        Err(HandlerError::Refused(text)) => ended(say(out, 440, &text)),
        Err(e) => fault(out, &e, "POST"),
    }
}

/// Gives the sink the next piece of the article.
pub(crate) fn post_write(post: &PostSlot, piece: &[u8]) -> JobEnd {
    let mut slot = post.sink.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(sink) = slot.as_mut() {
        if let Err(e) = sink.write(piece) {
            *slot = None;
            post.refuse(&e);
        }
    }
    JobEnd::Continue
}

/// The article was too large: the sink is let go of and the post refused.
pub(crate) fn post_too_large(post: &PostSlot) -> JobEnd {
    post.abandon();
    *post.error.lock().unwrap_or_else(|e| e.into_inner()) = Some("Article too large".to_string());
    JobEnd::Continue
}

/// The article has arrived: accepts it, or says why not.
pub(crate) fn post_commit(post: &PostSlot, out: &mut Output, metrics: &NntpServerMetrics) -> JobEnd {
    let refusal = post.error.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(text) = refusal {
        return ended(say(out, 441, &text));
    }
    let sink = post.sink.lock().unwrap_or_else(|e| e.into_inner()).take();
    let Some(sink) = sink else {
        return ended(say(out, 441, "Posting failed"));
    };
    match sink.commit() {
        Ok(()) => {
            metrics.articles_posted.fetch_add(1, Ordering::Relaxed);
            ended(say(out, 240, "Article received OK"))
        }
        Err(e) => {
            post.refuse(&e);
            let text = post.error.lock().unwrap_or_else(|e| e.into_inner()).take().unwrap_or_default();
            ended(say(out, 441, &text))
        }
    }
}

// ---- GROUP, LISTGROUP, LAST, NEXT ----

fn select(
    handler: &mut dyn ReaderHandler,
    session: &mut SessionState,
    out: &mut Output,
    name: &str,
) -> Result<crate::server::handler::GroupStatus, JobEnd> {
    match handler.select_group(name) {
        Ok(status) => {
            session.group = Some(name.to_string());
            session.current = (status.count > 0 && status.low > 0).then_some(status.low);
            Ok(status)
        }
        Err(HandlerError::NoSuchGroup) => Err(ended(say(out, 411, "No such newsgroup"))),
        Err(e) => Err(fault(out, &e, "GROUP")),
    }
}

fn group(handler: &mut dyn ReaderHandler, session: &mut SessionState, out: &mut Output, name: &str) -> JobEnd {
    match select(handler, session, out, name) {
        Ok(s) => ended(say(out, 211, &format!("{} {} {} {}", s.count, s.low, s.high, name))),
        Err(end) => end,
    }
}

fn list_group(
    handler: &mut dyn ReaderHandler,
    session: &mut SessionState,
    out: &mut Output,
    name: Option<&str>,
    range: Option<&Target>,
) -> JobEnd {
    let name = match name {
        Some(n) => n.to_string(),
        None => match &session.group {
            Some(g) => g.clone(),
            None => return ended(say(out, 412, "No newsgroup selected")),
        },
    };
    // LISTGROUP selects its group, as GROUP does, and sets the current
    // article the same way.
    let status = match select(handler, session, out, &name) {
        Ok(s) => s,
        Err(end) => return end,
    };
    let (from, to) = match range {
        None => (0, MAX_ARTICLE_NUMBER),
        Some(Target::Number(n)) => (*n, *n),
        Some(Target::Range(lo, None)) => (*lo, MAX_ARTICLE_NUMBER),
        Some(Target::Range(lo, Some(hi))) => (*lo, *hi),
        Some(_) => (0, MAX_ARTICLE_NUMBER),
    };
    if !say(out, 211, &format!("{} {} {} {} list follows", status.count, status.low, status.high, name)) {
        return JobEnd::Fatal;
    }
    let mut next = from.max(1);
    let mut line = Vec::new();
    while next <= to {
        let page = match handler.article_numbers(next, to, PAGE) {
            Ok(p) => p,
            Err(e) => return mid_stream(&e, "LISTGROUP"),
        };
        let Some(&last) = page.last() else { break };
        line.clear();
        for n in &page {
            line.extend_from_slice(n.to_string().as_bytes());
            line.extend_from_slice(b"\r\n");
        }
        if !out.write(&line) {
            return JobEnd::Fatal;
        }
        if last >= to || last == u32::MAX {
            break;
        }
        next = last + 1;
    }
    ended(out.write(END))
}

fn mid_stream(error: &HandlerError, what: &str) -> JobEnd {
    hopf_core::subsystem_log(
        hopf_core::LogLevel::Error,
        "hopf-nntp",
        "nntp.handler.failed",
        format!("{what} failed part-way: {error}"),
    );
    JobEnd::Fatal
}

fn step(handler: &mut dyn ReaderHandler, session: &mut SessionState, out: &mut Output, forward: bool) -> JobEnd {
    if session.group.is_none() {
        return ended(say(out, 412, "No newsgroup selected"));
    }
    let Some(current) = session.current else {
        return ended(say(out, 420, "Current article number is invalid"));
    };
    let found = if forward {
        handler.next_article(current)
    } else {
        handler.previous_article(current)
    };
    let number = match found {
        Ok(Some(n)) => n,
        Ok(None) => {
            return ended(if forward {
                say(out, 421, "No next article in this group")
            } else {
                say(out, 422, "No previous article in this group")
            })
        }
        Err(e) => return fault(out, &e, if forward { "NEXT" } else { "LAST" }),
    };
    match handler.locate_number(number) {
        Ok(Some(l)) => {
            session.current = Some(number);
            ended(say(out, 223, &format!("{} {} Article found", l.number, l.message_id)))
        }
        // The article went away between the two calls.
        Ok(None) => ended(say(out, 420, "Current article number is invalid")),
        Err(e) => fault(out, &e, "NEXT"),
    }
}

// ---- ARTICLE, HEAD, BODY, STAT ----

/// The article a command names, or the end of the command.
fn find(
    handler: &mut dyn ReaderHandler,
    session: &mut SessionState,
    out: &mut Output,
    target: &Target,
) -> Result<Located, JobEnd> {
    let (number, by_number) = match target {
        Target::MessageId(id) => {
            return match handler.locate_message_id(id) {
                Ok(Some(l)) => Ok(l),
                Ok(None) => Err(ended(say(out, 430, "No article with that message-id"))),
                Err(e) => Err(fault(out, &e, "article lookup")),
            };
        }
        Target::Current => {
            if session.group.is_none() {
                return Err(ended(say(out, 412, "No newsgroup selected")));
            }
            match session.current {
                Some(n) => (n, false),
                None => return Err(ended(say(out, 420, "Current article number is invalid"))),
            }
        }
        Target::Number(n) => {
            if session.group.is_none() {
                return Err(ended(say(out, 412, "No newsgroup selected")));
            }
            (*n, true)
        }
        // The lexer does not make these for an article command.
        Target::Range(..) => return Err(ended(say(out, 501, "Syntax error in command"))),
    };
    match handler.locate_number(number) {
        Ok(Some(l)) => {
            if by_number {
                session.current = Some(number);
            }
            Ok(l)
        }
        Ok(None) if by_number => Err(ended(say(out, 423, "No article with that number"))),
        Ok(None) => Err(ended(say(out, 420, "Current article number is invalid"))),
        Err(e) => Err(fault(out, &e, "article lookup")),
    }
}

fn article(
    handler: &mut dyn ReaderHandler,
    session: &mut SessionState,
    out: &mut Output,
    metrics: &NntpServerMetrics,
    target: &Target,
    part: ArticlePart,
) -> JobEnd {
    let located = match find(handler, session, out, target) {
        Ok(l) => l,
        Err(end) => return end,
    };
    let (code, what) = match part {
        ArticlePart::Full => (220, "Article follows"),
        ArticlePart::Head => (221, "Headers follow"),
        ArticlePart::Body => (222, "Body follows"),
    };
    if !say(out, code, &format!("{} {} {}", located.number, located.message_id, what)) {
        return JobEnd::Fatal;
    }
    let mut stuffer = NntpDotStuffer::new(part);
    let mut stuffed = Vec::new();
    let read = handler.read_article(&located, &mut |chunk| {
        stuffed.clear();
        let wanted = stuffer.feed(chunk, &mut stuffed);
        out.write(&stuffed) && wanted
    });
    if !out.alive() {
        return JobEnd::Fatal;
    }
    if let Err(e) = read {
        return mid_stream(&e, "article read");
    }
    stuffed.clear();
    stuffer.finish(&mut stuffed);
    metrics.articles_retrieved.fetch_add(1, Ordering::Relaxed);
    ended(out.write(&stuffed))
}

fn stat(handler: &mut dyn ReaderHandler, session: &mut SessionState, out: &mut Output, target: &Target) -> JobEnd {
    match find(handler, session, out, target) {
        Ok(l) => ended(say(out, 223, &format!("{} {} Article exists", l.number, l.message_id))),
        Err(end) => end,
    }
}

// ---- LIST, NEWGROUPS ----

fn group_line(g: &NewsgroupInfo, out: &mut Vec<u8>) {
    reply::data_line(&format!("{} {} {} {}", g.name, g.high, g.low, g.posting.letter()), out);
}

fn list(handler: &mut dyn ReaderHandler, out: &mut Output, kind: &ListKind) -> JobEnd {
    match kind {
        ListKind::OverviewFmt => {
            let mut body = Vec::new();
            for field in ["Subject:", "From:", "Date:", "Message-ID:", "References:", ":bytes", ":lines"] {
                reply::data_line(field, &mut body);
            }
            body.extend_from_slice(END);
            let ok = say(out, 215, "Order of fields in overview database") && out.write(&body);
            ended(ok)
        }
        ListKind::Active(w) | ListKind::Newsgroups(w) => {
            let wildmat = match w {
                None => Wildmat::all(),
                Some(text) => match Wildmat::parse(text) {
                    Some(w) => w,
                    None => return ended(say(out, 501, "Syntax error in wildmat")),
                },
            };
            let descriptions = matches!(kind, ListKind::Newsgroups(_));
            if !say(out, 215, "List of newsgroups follows") {
                return JobEnd::Fatal;
            }
            let mut line = Vec::new();
            let result = handler.groups(&wildmat, !descriptions, &mut |g| {
                line.clear();
                if descriptions {
                    reply::data_line(&format!("{}\t{}", g.name, g.description), &mut line);
                } else {
                    group_line(&g, &mut line);
                }
                out.write(&line)
            });
            if let Err(e) = result {
                return mid_stream(&e, "LIST");
            }
            if !out.alive() {
                return JobEnd::Fatal;
            }
            ended(out.write(END))
        }
    }
}

fn new_groups(handler: &mut dyn ReaderHandler, out: &mut Output, since: &NewGroupsSince) -> JobEnd {
    let when = to_system_time(since, SystemTime::now());
    if !say(out, 231, "List of new newsgroups follows") {
        return JobEnd::Fatal;
    }
    let mut line = Vec::new();
    let result = handler.new_groups(when, &mut |g| {
        line.clear();
        group_line(&g, &mut line);
        out.write(&line)
    });
    if let Err(e) = result {
        return mid_stream(&e, "NEWGROUPS");
    }
    if !out.alive() {
        return JobEnd::Fatal;
    }
    ended(out.write(END))
}

/// The moment `since` names, taking its time to be UTC whether or not `GMT`
/// was given (the server keeps no local time zone).
pub(crate) fn to_system_time(since: &NewGroupsSince, now: SystemTime) -> SystemTime {
    let now_year = civil_from_days(
        now.duration_since(UNIX_EPOCH).map(|d| (d.as_secs() / 86_400) as i64).unwrap_or(0),
    )
    .0;
    let year = full_year(since, now_year);
    let days = days_from_civil(year, i64::from(since.month), i64::from(since.day));
    let secs = days * 86_400
        + i64::from(since.hour) * 3600
        + i64::from(since.minute) * 60
        + i64::from(since.second);
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH
    }
}

/// The year `since` names, given the current year.
fn full_year(since: &NewGroupsSince, now_year: i64) -> i64 {
    if since.four_digit_year {
        return i64::from(since.year);
    }
    // Two digits: this century if they are no later than this year's, the
    // last otherwise (RFC 3977 section 7.3.1).
    let century = now_year / 100 * 100;
    if i64::from(since.year) <= now_year % 100 {
        century + i64::from(since.year)
    } else {
        century - 100 + i64::from(since.year)
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date (year, month, day) of a number of days since 1970-01-01.
pub(crate) fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---- OVER, HDR ----

/// The articles an overview command covers.
enum Span {
    One(Located),
    Numbers { to: u32, first: Vec<u32> },
}

/// Resolves the target of OVER or HDR, answering the command itself when
/// there is nothing to cover.
fn span(
    handler: &mut dyn ReaderHandler,
    session: &mut SessionState,
    out: &mut Output,
    target: &Target,
) -> Result<Span, JobEnd> {
    let (from, to) = match target {
        Target::MessageId(id) => {
            return match handler.locate_message_id(id) {
                Ok(Some(l)) => Ok(Span::One(l)),
                Ok(None) => Err(ended(say(out, 430, "No article with that message-id"))),
                Err(e) => Err(fault(out, &e, "article lookup")),
            };
        }
        Target::Current => {
            if session.group.is_none() {
                return Err(ended(say(out, 412, "No newsgroup selected")));
            }
            let Some(n) = session.current else {
                return Err(ended(say(out, 420, "Current article number is invalid")));
            };
            return match handler.locate_number(n) {
                Ok(Some(l)) => Ok(Span::One(l)),
                Ok(None) => Err(ended(say(out, 420, "Current article number is invalid"))),
                Err(e) => Err(fault(out, &e, "article lookup")),
            };
        }
        Target::Number(n) => (*n, *n),
        Target::Range(lo, None) => (*lo, MAX_ARTICLE_NUMBER),
        Target::Range(lo, Some(hi)) => (*lo, *hi),
    };
    if session.group.is_none() {
        return Err(ended(say(out, 412, "No newsgroup selected")));
    }
    if to < from {
        return Err(ended(say(out, 423, "No articles in that range")));
    }
    match handler.article_numbers(from, to, PAGE) {
        Ok(first) if first.is_empty() => Err(ended(say(out, 423, "No articles in that range"))),
        Ok(first) => Ok(Span::Numbers { to, first }),
        Err(e) => Err(fault(out, &e, "article numbers")),
    }
}

/// Calls `each` for every article of `span`, stopping when it says to.
fn each_article(
    handler: &mut dyn ReaderHandler,
    span: Span,
    mut each: impl FnMut(&mut dyn ReaderHandler, &Located) -> Result<bool, HandlerError>,
) -> Result<(), HandlerError> {
    match span {
        Span::One(l) => {
            each(handler, &l)?;
        }
        Span::Numbers { to, first, .. } => {
            let mut page = first;
            loop {
                let Some(&last) = page.last() else { break };
                for &n in &page {
                    // An article that has gone since the numbers were listed
                    // is left out.
                    if let Some(l) = handler.locate_number(n)? {
                        if !each(handler, &l)? {
                            return Ok(());
                        }
                    }
                }
                if last >= to || last == u32::MAX {
                    break;
                }
                page = handler.article_numbers(last + 1, to, PAGE)?;
            }
        }
    }
    Ok(())
}

fn over(handler: &mut dyn ReaderHandler, session: &mut SessionState, out: &mut Output, target: &Target) -> JobEnd {
    let span = match span(handler, session, out, target) {
        Ok(s) => s,
        Err(end) => return end,
    };
    if !say(out, 224, "Overview information follows") {
        return JobEnd::Fatal;
    }
    let mut line = Vec::new();
    let result = each_article(handler, span, |h, article| {
        let record = h.overview(article)?;
        line.clear();
        reply::data_line(&overview_line(&record), &mut line);
        Ok(out.write(&line))
    });
    if let Err(e) = result {
        return mid_stream(&e, "OVER");
    }
    if !out.alive() {
        return JobEnd::Fatal;
    }
    ended(out.write(END))
}

/// The fields of one `OVER` line, tab separated. Tabs and line ends in a
/// value have become spaces already; this makes sure of it.
fn overview_line(r: &OverviewRecord) -> String {
    fn clean(s: &str) -> String {
        s.chars().map(|c| if matches!(c, '\t' | '\r' | '\n') { ' ' } else { c }).collect()
    }
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        r.number,
        clean(&r.subject),
        clean(&r.from),
        clean(&r.date),
        clean(&r.message_id),
        clean(&r.references),
        r.bytes,
        r.lines
    )
}

fn hdr(
    handler: &mut dyn ReaderHandler,
    session: &mut SessionState,
    out: &mut Output,
    field: &str,
    target: &Target,
) -> JobEnd {
    #[derive(PartialEq)]
    enum Which {
        Header,
        Bytes,
        Lines,
    }
    let lower = field.to_ascii_lowercase();
    let which = match lower.as_str() {
        ":bytes" => Which::Bytes,
        ":lines" => Which::Lines,
        s if s.starts_with(':') => return ended(say(out, 503, "Feature not supported")),
        // A header name has no colon (RFC 3977 section 8.5.2).
        s if s.contains(':') => return ended(say(out, 501, "Syntax error in command")),
        _ => Which::Header,
    };
    let span = match span(handler, session, out, target) {
        Ok(s) => s,
        Err(end) => return end,
    };
    if !say(out, 225, "Headers follow") {
        return JobEnd::Fatal;
    }
    let names: Vec<&str> = if which == Which::Header { vec![lower.as_str()] } else { Vec::new() };
    let mut line = Vec::new();
    let result = each_article(handler, span, |h, article| {
        let summary = h.summarise(article, &names)?;
        let value = match which {
            Which::Header => summary.fields.into_iter().next().flatten().unwrap_or_default(),
            Which::Bytes => summary.bytes.to_string(),
            Which::Lines => summary.lines.to_string(),
        };
        let value: String = value.chars().map(|c| if matches!(c, '\t' | '\r' | '\n') { ' ' } else { c }).collect();
        line.clear();
        reply::data_line(&format!("{} {}", article.number, value), &mut line);
        Ok(out.write(&line))
    });
    if let Err(e) = result {
        return mid_stream(&e, "HDR");
    }
    if !out.alive() {
        return JobEnd::Fatal;
    }
    ended(out.write(END))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn since(y: u32, four: bool, m: u32, d: u32) -> NewGroupsSince {
        NewGroupsSince { year: y, four_digit_year: four, month: m, day: d, hour: 0, minute: 0, second: 0, gmt: true }
    }

    #[test]
    fn civil_dates_round_trip_through_days() {
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2026, 11, 22), (1999, 12, 31), (2100, 3, 1)] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
    }

    #[test]
    fn a_four_digit_year_is_taken_as_given() {
        let t = to_system_time(&since(2026, true, 1, 2), SystemTime::now());
        assert_eq!(t.duration_since(UNIX_EPOCH).unwrap().as_secs(), (days_from_civil(2026, 1, 2) * 86_400) as u64);
    }

    #[test]
    fn two_digit_years_are_this_century_up_to_this_year_and_the_last_after() {
        let year = |yy: u32| full_year(&since(yy, false, 1, 1), 2026);
        assert_eq!(year(0), 2000);
        assert_eq!(year(26), 2026);
        assert_eq!(year(27), 1927);
        assert_eq!(year(70), 1970);
        assert_eq!(year(99), 1999);
    }

    #[test]
    fn overview_values_lose_their_tabs_and_line_ends() {
        let r = OverviewRecord {
            number: 3,
            subject: "a\tb".into(),
            from: "f".into(),
            date: "d".into(),
            message_id: "<m>".into(),
            references: String::new(),
            bytes: 10,
            lines: 2,
        };
        assert_eq!(overview_line(&r), "3\ta b\tf\td\t<m>\t\t10\t2");
    }
}
