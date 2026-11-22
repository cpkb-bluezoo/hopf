// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The stock handler: the mailboxes of a [`MailboxStore`] served as
//! newsgroups.
//!
//! A mailbox is a newsgroup, its name with the store's hierarchy delimiter
//! written as `.` (so the mailbox `comp/lang/rust` is `comp.lang.rust`).
//! A message's article number is its UID, so that numbers never change and
//! are never reused. Only messages with a UID that fits an article number
//! (up to 2,147,483,647) are served.
//!
//! One store is opened for each connection, for the user the factory names
//! (the news spool is shared, so it is the same user for everybody however
//! the client authenticates), and groups are opened read-only when selected.

use std::sync::Arc;
use std::time::SystemTime;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use hopf_mailbox::{
    Mailbox, MailboxAttribute, MailboxError, MailboxFactory, MailboxStore, MessageReadCallback,
    SearchCriteria,
};

use crate::server::codec::{is_message_id, MAX_ARTICLE_NUMBER};
use crate::server::commands::civil_from_days;
use crate::server::handler::{
    ClientConnected, ConnectedState, GroupStatus, HandlerError, HandlerResult, Located,
    NewsgroupInfo, NntpConnectionMetadata, NntpHandlerFactory, PostSink, PostingStatus, ReaderHandler,
};
use crate::server::scan::ArticleScanner;
use crate::server::wildmat::Wildmat;

/// The user whose mailboxes hold the newsgroups unless told otherwise.
pub const DEFAULT_STORE_USER: &str = "news";

/// The greeting unless told otherwise.
pub const DEFAULT_GREETING: &str = "NNTP server ready";

/// Makes the stock handler for each connection.
pub struct DefaultNntpHandlerFactory {
    greeting: String,
    factory: Arc<dyn MailboxFactory>,
    store_user: String,
    posting_allowed: bool,
    hostname: String,
}

impl DefaultNntpHandlerFactory {
    /// A factory that serves the mailboxes of stores made by `factory`.
    pub fn new(greeting: impl Into<String>, factory: Arc<dyn MailboxFactory>) -> Self {
        Self {
            greeting: greeting.into(),
            factory,
            store_user: DEFAULT_STORE_USER.to_string(),
            posting_allowed: true,
            hostname: "localhost".to_string(),
        }
    }

    /// The name the server gives itself in the `Message-ID` it adds to a
    /// posted article that has none (default `localhost`).
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    /// The user the store is opened for (default [`DEFAULT_STORE_USER`]).
    pub fn with_store_user(mut self, user: impl Into<String>) -> Self {
        self.store_user = user.into();
        self
    }

    /// Whether clients are told they may post (default true). The service's
    /// own setting must allow it as well.
    pub fn with_posting_allowed(mut self, allowed: bool) -> Self {
        self.posting_allowed = allowed;
        self
    }
}

impl NntpHandlerFactory for DefaultNntpHandlerFactory {
    fn create(&self) -> Box<dyn ClientConnected> {
        Box::new(DefaultClientConnected {
            greeting: self.greeting.clone(),
            factory: Arc::clone(&self.factory),
            store_user: self.store_user.clone(),
            posting_allowed: self.posting_allowed,
            hostname: self.hostname.clone(),
        })
    }
}

struct DefaultClientConnected {
    greeting: String,
    factory: Arc<dyn MailboxFactory>,
    store_user: String,
    posting_allowed: bool,
    hostname: String,
}

impl ClientConnected for DefaultClientConnected {
    fn connected(&mut self, state: &mut dyn ConnectedState, _meta: &NntpConnectionMetadata) {
        let posting = if self.posting_allowed { PostingStatus::Allowed } else { PostingStatus::NotAllowed };
        let handler = MailboxReaderHandler::new(Arc::clone(&self.factory), self.store_user.clone(), posting)
            .with_hostname(self.hostname.clone());
        state.accept_connection(&self.greeting, self.posting_allowed, Box::new(handler));
    }
}

/// One article of a selected group.
#[derive(Debug, Clone, Copy)]
struct Entry {
    number: u32,
    seq: u32,
}

/// A group opened for reading, with the numbers of its articles.
struct Open {
    group: String,
    mailbox: Box<dyn Mailbox>,
    /// In increasing order of number.
    index: Vec<Entry>,
    /// When the group was last looked at on disk.
    read_at: std::time::Instant,
}

/// Set in [`Located::token`] for an article of the group a message-id lookup
/// found it in, when that is not the selected one.
const FOREIGN: u64 = 1 << 63;

/// Serves the mailboxes of a store as newsgroups. See the module
/// documentation.
pub struct MailboxReaderHandler {
    factory: Arc<dyn MailboxFactory>,
    user: String,
    posting: PostingStatus,
    hostname: String,
    store: Option<Box<dyn MailboxStore>>,
    selected: Option<Open>,
    foreign: Option<Open>,
}

impl MailboxReaderHandler {
    /// A handler over stores made by `factory`, opened for `user`.
    pub fn new(factory: Arc<dyn MailboxFactory>, user: String, posting: PostingStatus) -> Self {
        Self {
            factory,
            user,
            posting,
            hostname: "localhost".to_string(),
            store: None,
            selected: None,
            foreign: None,
        }
    }

    /// The name used in the `Message-ID` of a posted article that has none.
    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = hostname;
        self
    }

    fn store(&mut self) -> HandlerResult<&mut Box<dyn MailboxStore>> {
        if self.store.is_none() {
            let mut store = self.factory.create_store();
            store.open(&self.user)?;
            self.store = Some(store);
        }
        Ok(self.store.as_mut().unwrap())
    }

    fn mailbox_name(&mut self, group: &str) -> HandlerResult<String> {
        let delimiter = self.store()?.hierarchy_delimiter();
        Ok(if delimiter == '.' { group.to_string() } else { group.replace('.', &delimiter.to_string()) })
    }

    fn group_name(delimiter: char, mailbox: &str) -> String {
        if delimiter == '.' {
            mailbox.to_string()
        } else {
            mailbox.replace(delimiter, ".")
        }
    }

    fn open(&mut self, group: &str) -> HandlerResult<Open> {
        let name = self.mailbox_name(group)?;
        let mailbox = match self.store()?.open_mailbox(&name, true) {
            Ok(mb) => mb,
            Err(MailboxError::NotFound(_)) => return Err(HandlerError::NoSuchGroup),
            Err(e) => return Err(e.into()),
        };
        let mut index: Vec<Entry> = mailbox
            .messages()?
            .into_iter()
            .filter_map(|d| {
                let number = d.uid.unwrap_or(u64::from(d.message_number));
                (number >= 1 && number <= u64::from(MAX_ARTICLE_NUMBER)).then_some(Entry {
                    number: number as u32,
                    seq: d.message_number,
                })
            })
            .collect();
        index.sort_by_key(|e| e.number);
        Ok(Open { group: group.to_string(), mailbox, index, read_at: std::time::Instant::now() })
    }

    /// Looks at the selected group on disk again, for articles that have
    /// arrived since it was selected (a post, a delivery). The numbers a
    /// client already has stay as they were: they are UIDs.
    fn refresh_selected(&mut self) -> HandlerResult<()> {
        let Some(open) = self.selected.as_mut() else { return Ok(()) };
        open.mailbox.refresh()?;
        let mut index: Vec<Entry> = open
            .mailbox
            .messages()?
            .into_iter()
            .filter_map(|d| {
                let number = d.uid.unwrap_or(u64::from(d.message_number));
                (number >= 1 && number <= u64::from(MAX_ARTICLE_NUMBER)).then_some(Entry {
                    number: number as u32,
                    seq: d.message_number,
                })
            })
            .collect();
        index.sort_by_key(|e| e.number);
        open.index = index;
        open.read_at = std::time::Instant::now();
        Ok(())
    }

    fn status(open: &Open) -> GroupStatus {
        GroupStatus {
            count: open.index.len() as u32,
            low: open.index.first().map_or(0, |e| e.number),
            high: open.index.last().map_or(0, |e| e.number),
        }
    }

    /// The message-id of message `seq`, read from its headers.
    fn message_id(mailbox: &mut dyn Mailbox, seq: u32) -> HandlerResult<String> {
        let mut scanner = ArticleScanner::new(&["message-id"]);
        let mut callback = Reader(&mut |chunk: &[u8]| {
            scanner.feed(chunk);
            !scanner.headers_done()
        });
        mailbox.read_message(seq, &mut callback)?;
        let id = scanner.finish().fields.into_iter().next().flatten().unwrap_or_default();
        let id = id.trim();
        Ok(if is_message_id(id) { id.to_string() } else { "<0>".to_string() })
    }

    fn open_for<'a>(&'a mut self, article: &Located) -> HandlerResult<&'a mut Open> {
        let slot = if article.token & FOREIGN != 0 { &mut self.foreign } else { &mut self.selected };
        slot.as_mut().ok_or_else(|| HandlerError::Failed("the article's group is no longer open".into()))
    }
}

/// Adapts a closure to the mailbox's read callback.
struct Reader<'a>(&'a mut dyn FnMut(&[u8]) -> bool);

impl MessageReadCallback for Reader<'_> {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        (self.0)(chunk)
    }
}

impl ReaderHandler for MailboxReaderHandler {
    fn select_group(&mut self, name: &str) -> HandlerResult<GroupStatus> {
        let open = self.open(name)?;
        let status = Self::status(&open);
        self.selected = Some(open);
        Ok(status)
    }

    fn article_numbers(&mut self, from: u32, to: u32, limit: usize) -> HandlerResult<Vec<u32>> {
        // A range that reaches past the last article known may reach articles
        // that have come in since; look again, but not on every page.
        let stale = self.selected.as_ref().is_some_and(|o| {
            o.index.last().map_or(0, |e| e.number) < to && o.read_at.elapsed() >= std::time::Duration::from_secs(1)
        });
        if stale {
            self.refresh_selected()?;
        }
        let Some(open) = &self.selected else { return Ok(Vec::new()) };
        let start = open.index.partition_point(|e| e.number < from);
        Ok(open.index[start..]
            .iter()
            .take_while(|e| e.number <= to)
            .take(limit)
            .map(|e| e.number)
            .collect())
    }

    fn locate_number(&mut self, number: u32) -> HandlerResult<Option<Located>> {
        if self.selected.as_ref().is_some_and(|o| o.index.binary_search_by_key(&number, |e| e.number).is_err()) {
            // Not there: it may have arrived since the group was selected.
            self.refresh_selected()?;
        }
        let Some(open) = self.selected.as_mut() else { return Ok(None) };
        let Ok(at) = open.index.binary_search_by_key(&number, |e| e.number) else { return Ok(None) };
        let seq = open.index[at].seq;
        let message_id = Self::message_id(open.mailbox.as_mut(), seq)?;
        Ok(Some(Located { number, message_id, token: u64::from(seq) }))
    }

    fn locate_message_id(&mut self, id: &str) -> HandlerResult<Option<Located>> {
        let criteria = SearchCriteria::Header { name: "message-id".into(), pattern: id.to_string() };
        // The selected group first.
        if let Some(open) = self.selected.as_mut() {
            for seq in open.mailbox.search(&criteria)? {
                if Self::message_id(open.mailbox.as_mut(), seq)? == id {
                    let number = open.index.iter().find(|e| e.seq == seq).map_or(0, |e| e.number);
                    return Ok(Some(Located { number, message_id: id.to_string(), token: u64::from(seq) }));
                }
            }
        }
        // Then every other.
        let selected = self.selected.as_ref().map(|o| o.group.clone());
        let delimiter = self.store()?.hierarchy_delimiter();
        let mut names = Vec::new();
        for info in self.store()?.list("", "*")? {
            if !info.attributes.contains(&MailboxAttribute::NoSelect) && !info.name.is_empty() {
                names.push(Self::group_name(delimiter, &info.name));
            }
        }
        for group in names {
            if Some(&group) == selected.as_ref() {
                continue;
            }
            let mut open = match self.open(&group) {
                Ok(o) => o,
                Err(HandlerError::NoSuchGroup) => continue,
                Err(e) => return Err(e),
            };
            for seq in open.mailbox.search(&criteria)? {
                if Self::message_id(open.mailbox.as_mut(), seq)? == id {
                    self.foreign = Some(open);
                    return Ok(Some(Located { number: 0, message_id: id.to_string(), token: FOREIGN | u64::from(seq) }));
                }
            }
        }
        Ok(None)
    }

    fn read_article(&mut self, article: &Located, sink: &mut dyn FnMut(&[u8]) -> bool) -> HandlerResult<()> {
        let seq = (article.token & !FOREIGN) as u32;
        let open = self.open_for(article)?;
        let mut callback = Reader(sink);
        open.mailbox.read_message(seq, &mut callback)?;
        Ok(())
    }

    fn groups(
        &mut self,
        wanted: &Wildmat,
        counts: bool,
        sink: &mut dyn FnMut(NewsgroupInfo) -> bool,
    ) -> HandlerResult<()> {
        let delimiter = self.store()?.hierarchy_delimiter();
        let infos = self.store()?.list("", "*")?;
        for info in infos {
            if info.attributes.contains(&MailboxAttribute::NoSelect) || info.name.is_empty() {
                continue;
            }
            let name = Self::group_name(delimiter, &info.name);
            if !wanted.matches(&name) {
                continue;
            }
            let (high, low) = if counts {
                match self.open(&name) {
                    Ok(open) => {
                        let s = Self::status(&open);
                        (s.high, s.low)
                    }
                    // A mailbox that went away since the listing.
                    Err(HandlerError::NoSuchGroup) => continue,
                    Err(e) => return Err(e),
                }
            } else {
                (0, 0)
            };
            let group = NewsgroupInfo { name, high, low, posting: self.posting, description: String::new() };
            if !sink(group) {
                break;
            }
        }
        Ok(())
    }

    fn new_groups(&mut self, _since: SystemTime, _sink: &mut dyn FnMut(NewsgroupInfo) -> bool) -> HandlerResult<()> {
        // A mailbox store does not record when a mailbox was made.
        Ok(())
    }

    fn begin_post(&mut self) -> HandlerResult<Box<dyn PostSink>> {
        if self.posting == PostingStatus::NotAllowed {
            return Err(HandlerError::Refused("Posting not permitted".into()));
        }
        let mut store = self.factory.create_store();
        store.open(&self.user)?;
        Ok(Box::new(MailboxPostSink {
            store,
            hostname: self.hostname.clone(),
            header: Vec::new(),
            targets: Vec::new(),
            streaming: false,
        }))
    }

    fn previous_article(&mut self, number: u32) -> HandlerResult<Option<u32>> {
        let Some(open) = &self.selected else { return Ok(None) };
        let at = open.index.partition_point(|e| e.number < number);
        Ok(at.checked_sub(1).map(|i| open.index[i].number))
    }

    fn close(&mut self) {
        self.selected = None;
        self.foreign = None;
        if let Some(mut store) = self.store.take() {
            let _ = store.close();
        }
    }
}

// ---- posting ----

/// The most of a posted article's headers the stock sink keeps, to find where
/// it goes.
pub const MAX_POST_HEADER: usize = 64 * 1024;

/// Counts the identifiers the server makes, so that two made in the same
/// instant differ.
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Files a posted article in each group it names that exists. It keeps the
/// header block (up to [`MAX_POST_HEADER`]) to read the `Newsgroups` header,
/// and passes the rest of the article on to the groups as it arrives.
struct MailboxPostSink {
    store: Box<dyn MailboxStore>,
    hostname: String,
    header: Vec<u8>,
    targets: Vec<Box<dyn Mailbox>>,
    /// The header block has been dealt with; what arrives goes to the groups.
    streaming: bool,
}

/// Where the header block of `bytes` ends: the offset of the empty line that
/// ends it and the offset just after that line.
fn header_end(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut line_start = 0;
    while let Some(nl) = bytes[line_start..].iter().position(|&b| b == b'\n') {
        let end = line_start + nl;
        let line = &bytes[line_start..end];
        if line.is_empty() || line == b"\r" {
            return Some((line_start, end + 1));
        }
        line_start = end + 1;
    }
    None
}

/// The value of header `name` in a header block, folds undone.
fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    let mut value: Option<String> = None;
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(v) = &mut value {
            if line.starts_with([' ', '\t']) {
                v.push(' ');
                v.push_str(line.trim());
                continue;
            }
            break;
        }
        if let Some((n, v)) = line.split_once(':') {
            if n.eq_ignore_ascii_case(name) {
                value = Some(v.trim().to_string());
            }
        }
    }
    value
}

/// `Sat, 21 Nov 2026 10:00:00 +0000` for a time in seconds since the epoch.
fn rfc5322_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    let rem = secs % 86_400;
    format!(
        "{}, {d} {} {y} {:02}:{:02}:{:02} +0000",
        DAYS[((days + 4) % 7) as usize],
        MONTHS[(m - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

impl MailboxPostSink {
    fn abort_targets(&mut self) {
        for mut t in self.targets.drain(..) {
            let _ = t.abort_append();
            let _ = t.close(false);
        }
    }

    /// The header block is complete at `header[..blank_end]`: read it, decide
    /// where the article goes, and begin writing it there.
    fn begin(&mut self, blank_start: usize, blank_end: usize) -> HandlerResult<()> {
        let buffered = std::mem::take(&mut self.header);
        let head = &buffered[..blank_start];
        let rest = &buffered[blank_end..];
        let refuse = |text: &str| HandlerError::Refused(text.to_string());

        let Some(groups) = header_value(head, "newsgroups").filter(|g| !g.is_empty()) else {
            return Err(refuse("No Newsgroups header"));
        };
        for required in ["from", "subject"] {
            if header_value(head, required).is_none() {
                return Err(refuse(&format!("No {} header", if required == "from" { "From" } else { "Subject" })));
            }
        }
        let now = std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let mut added = Vec::new();
        match header_value(head, "message-id") {
            Some(id) if is_message_id(&id) => {}
            Some(_) => return Err(refuse("Invalid Message-ID")),
            None => {
                let id = format!(
                    "<{:x}.{:x}.{:x}@{}>",
                    now.as_secs(),
                    now.subsec_nanos(),
                    NEXT_ID.fetch_add(1, Ordering::Relaxed),
                    self.hostname
                );
                added.extend_from_slice(format!("Message-ID: {id}\r\n").as_bytes());
            }
        }
        if header_value(head, "date").is_none() {
            added.extend_from_slice(format!("Date: {}\r\n", rfc5322_date(now.as_secs())).as_bytes());
        }

        let delimiter = self.store.hierarchy_delimiter();
        let mut seen = BTreeSet::new();
        for group in groups.split(',').map(str::trim).filter(|g| !g.is_empty()) {
            let name = if delimiter == '.' { group.to_string() } else { group.replace('.', &delimiter.to_string()) };
            if !seen.insert(name.clone()) {
                continue;
            }
            match self.store.open_mailbox(&name, false) {
                Ok(mut mb) => {
                    let started = mb.start_append(&BTreeSet::new(), None);
                    if let Err(e) = started {
                        let _ = mb.close(false);
                        self.abort_targets();
                        return Err(match e {
                            MailboxError::ReadOnly => refuse("Group is read-only"),
                            e => e.into(),
                        });
                    }
                    self.targets.push(mb);
                }
                Err(MailboxError::NotFound(_)) => {}
                Err(e) => {
                    self.abort_targets();
                    return Err(e.into());
                }
            }
        }
        if self.targets.is_empty() {
            return Err(refuse("No such newsgroup"));
        }

        let mut first = Vec::with_capacity(head.len() + added.len() + 2 + rest.len());
        first.extend_from_slice(head);
        first.extend_from_slice(&added);
        first.extend_from_slice(b"\r\n");
        first.extend_from_slice(rest);
        self.streaming = true;
        self.pass_on(&first)
    }

    fn pass_on(&mut self, piece: &[u8]) -> HandlerResult<()> {
        for t in &mut self.targets {
            if let Err(e) = t.append_content(piece) {
                self.abort_targets();
                return Err(e.into());
            }
        }
        Ok(())
    }
}

impl PostSink for MailboxPostSink {
    fn write(&mut self, piece: &[u8]) -> HandlerResult<()> {
        if self.streaming {
            return self.pass_on(piece);
        }
        // Only the header block is held, and only up to a bound.
        self.header.extend_from_slice(piece);
        if let Some((start, end)) = header_end(&self.header) {
            return self.begin(start, end);
        }
        if self.header.len() > MAX_POST_HEADER {
            self.header.clear();
            return Err(HandlerError::Refused("Header block too large".into()));
        }
        Ok(())
    }

    fn commit(mut self: Box<Self>) -> HandlerResult<()> {
        if !self.streaming {
            if self.header.is_empty() {
                return Err(HandlerError::Refused("Empty article".into()));
            }
            // Headers and no body: end the block as a client would have.
            if !self.header.ends_with(b"\n") {
                self.header.extend_from_slice(b"\r\n");
            }
            self.header.extend_from_slice(b"\r\n");
            let (start, end) = header_end(&self.header).expect("an empty line was just added");
            self.begin(start, end)?;
        }
        for mut t in std::mem::take(&mut self.targets) {
            if let Err(e) = t.end_append() {
                let _ = t.close(false);
                return Err(e.into());
            }
            let _ = t.close(false);
        }
        let _ = self.store.close();
        Ok(())
    }

    fn abort(mut self: Box<Self>) {
        self.abort_targets();
        let _ = self.store.close();
    }
}

impl Drop for MailboxPostSink {
    fn drop(&mut self) {
        // A sink dropped by a failed write or a refusal has nothing begun
        // that is not undone.
        self.abort_targets();
    }
}
