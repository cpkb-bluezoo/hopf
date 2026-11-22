// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The handler SPI of the NNTP server.
//!
//! A connection meets two handlers in turn. The [`ClientConnected`] handler
//! made by the [`NntpHandlerFactory`] sees the connection arrive and accepts
//! it (naming the greeting, and giving the [`ReaderHandler`] that will serve
//! it) or refuses it. The [`ReaderHandler`] is the news itself: the groups,
//! the articles in them, and where a post goes.
//!
//! Every method of a [`ReaderHandler`] may block, and runs on the runtime's
//! storage pool, never on a reactor thread. Articles and listings are given
//! to the server a piece at a time, through callbacks that say whether the
//! server wants more, so that a handler never holds an article or a listing
//! whole and a slow client slows the reading rather than filling memory.

use std::fmt;
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::server::scan::{ArticleScanner, ArticleSummary};
use crate::server::wildmat::Wildmat;

/// What a handler sees of a connection.
#[derive(Debug, Clone)]
pub struct NntpConnectionMetadata {
    /// The client's address.
    pub peer: SocketAddr,
    /// The address the client connected to.
    pub local: SocketAddr,
    /// Is the connection encrypted?
    pub tls: bool,
}

/// Makes the handler for each new connection.
pub trait NntpHandlerFactory: Send + Sync {
    /// A handler for a connection that has just been accepted.
    fn create(&self) -> Box<dyn ClientConnected>;
}

/// The first stage: a connection has arrived.
pub trait ClientConnected: Send {
    /// A client has connected. Accept it or refuse it through `state`.
    fn connected(&mut self, state: &mut dyn ConnectedState, meta: &NntpConnectionMetadata);

    /// The connection has ended.
    fn disconnected(&mut self) {}
}

/// What a [`ClientConnected`] handler can do about a new connection.
pub trait ConnectedState {
    /// Greets the client (`200`, or `201` when posting is not allowed) and
    /// serves it with `handler`.
    fn accept_connection(&mut self, greeting: &str, posting_allowed: bool, handler: Box<dyn ReaderHandler>);

    /// Refuses the client with `400` and closes the connection.
    fn reject_connection(&mut self, message: &str);
}

/// Why a handler could not do what it was asked.
#[derive(Debug)]
pub enum HandlerError {
    /// There is no such newsgroup.
    NoSuchGroup,
    /// The handler will not do it, for a reason the client may be told (for
    /// a post: the article is not acceptable). The text is sent to the
    /// client.
    Refused(String),
    /// The handler failed: the store could not be read, or an article went
    /// away while it was being read. The text is for the log, not the client.
    Failed(String),
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchGroup => f.write_str("no such newsgroup"),
            Self::Refused(m) => f.write_str(m),
            Self::Failed(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for HandlerError {}

impl From<hopf_mailbox::MailboxError> for HandlerError {
    fn from(e: hopf_mailbox::MailboxError) -> Self {
        Self::Failed(e.to_string())
    }
}

/// The result of a handler method.
pub type HandlerResult<T> = Result<T, HandlerError>;

/// The state of a newsgroup, as `GROUP` reports it (RFC 3977 section 6.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupStatus {
    /// The number of articles; an estimate if the handler cannot say.
    pub count: u32,
    /// The lowest article number, or 0 for an empty group.
    pub low: u32,
    /// The highest article number, or 0 for an empty group.
    pub high: u32,
}

/// Whether posting to a group is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostingStatus {
    /// `y`
    Allowed,
    /// `n`
    NotAllowed,
    /// `m`: articles are held for a moderator.
    Moderated,
}

impl PostingStatus {
    /// The letter `LIST ACTIVE` shows.
    pub fn letter(self) -> char {
        match self {
            Self::Allowed => 'y',
            Self::NotAllowed => 'n',
            Self::Moderated => 'm',
        }
    }
}

/// A newsgroup in a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsgroupInfo {
    /// The group's name.
    pub name: String,
    /// The highest article number, or 0.
    pub high: u32,
    /// The lowest article number, or 0.
    pub low: u32,
    /// Whether posting is allowed.
    pub posting: PostingStatus,
    /// A line of text about the group, for `LIST NEWSGROUPS`; may be empty.
    pub description: String,
}

/// An article found: its number in the selected group and its message-id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The article's number in the selected group, or 0 if it was found by
    /// message-id and is not in that group (or none is selected).
    pub number: u32,
    /// The message-id with its angle brackets, or `<0>` for an article that
    /// has none.
    pub message_id: String,
    /// A handle of the handler's own: where the article is, for
    /// [`ReaderHandler::read_article`] to find it again.
    pub token: u64,
}

/// One line of `OVER`: the fields of RFC 3977 section 8.3 in their order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverviewRecord {
    /// The article's number, or 0 when it was named by message-id.
    pub number: u32,
    /// `Subject`
    pub subject: String,
    /// `From`
    pub from: String,
    /// `Date`
    pub date: String,
    /// `Message-ID`
    pub message_id: String,
    /// `References`
    pub references: String,
    /// `:bytes`
    pub bytes: u64,
    /// `:lines`
    pub lines: u64,
}

/// The news: groups, articles, and where articles go. See the module
/// documentation.
pub trait ReaderHandler: Send {
    /// Selects `name`. The handler's other methods that speak of "the
    /// selected group" mean this one until it is called again.
    fn select_group(&mut self, name: &str) -> HandlerResult<GroupStatus>;

    /// The numbers of the articles of the selected group from `from` to `to`
    /// inclusive, in increasing order, at most `limit` of them.
    fn article_numbers(&mut self, from: u32, to: u32, limit: usize) -> HandlerResult<Vec<u32>>;

    /// The article of the selected group with `number`, if there is one.
    fn locate_number(&mut self, number: u32) -> HandlerResult<Option<Located>>;

    /// The article with message-id `id` (with its angle brackets), in the
    /// selected group or any other.
    fn locate_message_id(&mut self, id: &str) -> HandlerResult<Option<Located>>;

    /// Gives the octets of `article`, headers, an empty line and body, to
    /// `sink` in pieces of any size and in order, until it returns false or
    /// the article ends. Line ends may be CRLF or bare LF: the server makes
    /// them CRLF.
    fn read_article(&mut self, article: &Located, sink: &mut dyn FnMut(&[u8]) -> bool) -> HandlerResult<()>;

    /// The groups whose names `wanted` accepts, to `sink`, until it returns
    /// false. When `counts` is false the listing is for descriptions only,
    /// and `high` and `low` may be left 0, which spares a handler the cost
    /// of finding them.
    fn groups(
        &mut self,
        wanted: &Wildmat,
        counts: bool,
        sink: &mut dyn FnMut(NewsgroupInfo) -> bool,
    ) -> HandlerResult<()>;

    /// The groups created since `since`, to `sink`. A handler that does not
    /// know when groups were created lists none.
    fn new_groups(&mut self, since: SystemTime, sink: &mut dyn FnMut(NewsgroupInfo) -> bool) -> HandlerResult<()> {
        let _ = (since, sink);
        Ok(())
    }

    /// The article after `number` in the selected group, if any.
    fn next_article(&mut self, number: u32) -> HandlerResult<Option<u32>> {
        if number == u32::MAX {
            return Ok(None);
        }
        Ok(self.article_numbers(number + 1, i32::MAX as u32, 1)?.first().copied())
    }

    /// The article before `number` in the selected group, if any.
    fn previous_article(&mut self, number: u32) -> HandlerResult<Option<u32>> {
        let mut last = None;
        let mut from = 1;
        while from < number {
            let page = self.article_numbers(from, number - 1, 1024)?;
            let Some(&tail) = page.last() else { break };
            last = Some(tail);
            if tail >= number - 1 {
                break;
            }
            from = tail + 1;
        }
        Ok(last)
    }

    /// The values of the header fields `names` of `article`, with its size
    /// and the number of lines in its body, found by reading it. A handler
    /// that has these in an index should answer from there instead.
    fn summarise(&mut self, article: &Located, names: &[&str]) -> HandlerResult<ArticleSummary> {
        let mut scanner = ArticleScanner::new(names);
        self.read_article(article, &mut |chunk| {
            scanner.feed(chunk);
            true
        })?;
        Ok(scanner.finish())
    }

    /// The overview line of `article`.
    fn overview(&mut self, article: &Located) -> HandlerResult<OverviewRecord> {
        let s = self.summarise(article, &["subject", "from", "date", "message-id", "references"])?;
        let mut f = s.fields.into_iter().map(Option::unwrap_or_default);
        let (subject, from, date) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
        let message_id = match f.next().unwrap() {
            id if id.is_empty() => article.message_id.clone(),
            id => id,
        };
        let references = f.next().unwrap();
        Ok(OverviewRecord {
            number: article.number,
            subject,
            from,
            date,
            message_id,
            references,
            bytes: s.bytes,
            lines: s.lines,
        })
    }

    /// A client has asked to post. Returns the sink the article is written
    /// to, or refuses (with [`HandlerError::Refused`], whose text is sent to
    /// the client). The stock refusal is for a handler that takes no posts.
    fn begin_post(&mut self) -> HandlerResult<Box<dyn PostSink>> {
        Err(HandlerError::Refused("Posting not permitted".into()))
    }

    /// The connection has ended; let go of what it held.
    fn close(&mut self) {}
}

/// Where a posted article goes. The article arrives in pieces, dot-unstuffed
/// and with CRLF line ends as the client sent them, headers first; it is never
/// given whole. Every method may block, and runs on the storage pool.
///
/// One piece is written at a time, and the connection reads no more of the
/// client's article until the write has returned, so a store that falls
/// behind slows the client.
pub trait PostSink: Send {
    /// The next piece of the article. A [`HandlerError::Refused`] says why the
    /// article cannot be accepted; the rest of it is read and thrown away, and
    /// the client is told `441` with the text. The sink is dropped after any
    /// error, so it should have let go of what it held; [`abort`](Self::abort)
    /// is not called.
    fn write(&mut self, piece: &[u8]) -> HandlerResult<()>;

    /// The article is complete: accept it. An error refuses it (`441`).
    fn commit(self: Box<Self>) -> HandlerResult<()>;

    /// The post is abandoned (the client went away, or the article was too
    /// large): let go of whatever was kept.
    fn abort(self: Box<Self>);
}
