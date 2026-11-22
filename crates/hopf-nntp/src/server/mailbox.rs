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

use hopf_mailbox::{
    Mailbox, MailboxAttribute, MailboxError, MailboxFactory, MailboxStore, MessageReadCallback,
    SearchCriteria,
};

use crate::server::codec::{is_message_id, MAX_ARTICLE_NUMBER};
use crate::server::handler::{
    ClientConnected, ConnectedState, GroupStatus, HandlerError, HandlerResult, Located,
    NewsgroupInfo, NntpConnectionMetadata, NntpHandlerFactory, PostingStatus, ReaderHandler,
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
}

impl DefaultNntpHandlerFactory {
    /// A factory that serves the mailboxes of stores made by `factory`.
    pub fn new(greeting: impl Into<String>, factory: Arc<dyn MailboxFactory>) -> Self {
        Self {
            greeting: greeting.into(),
            factory,
            store_user: DEFAULT_STORE_USER.to_string(),
            posting_allowed: true,
        }
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
        })
    }
}

struct DefaultClientConnected {
    greeting: String,
    factory: Arc<dyn MailboxFactory>,
    store_user: String,
    posting_allowed: bool,
}

impl ClientConnected for DefaultClientConnected {
    fn connected(&mut self, state: &mut dyn ConnectedState, _meta: &NntpConnectionMetadata) {
        let posting = if self.posting_allowed { PostingStatus::Allowed } else { PostingStatus::NotAllowed };
        let handler = MailboxReaderHandler::new(Arc::clone(&self.factory), self.store_user.clone(), posting);
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
            store: None,
            selected: None,
            foreign: None,
        }
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
        Ok(Open { group: group.to_string(), mailbox, index })
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
