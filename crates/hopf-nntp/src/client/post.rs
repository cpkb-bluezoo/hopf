// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Posting an article in constant memory: the piece-by-piece writer a post is
//! driven through, the dot-stuffer behind it, and attachments read and
//! uuencoded off the reactor.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, TryRecvError};
use std::sync::Arc;

use hopf_core::{ConnHandle, Endpoint};
use rmimeparser::UuencodeEncoder;

/// What an [`NntpPoster`] wants done after it has been called.
#[derive(Debug)]
pub enum PostStep {
    /// More to write: call again once the connection has taken what was
    /// written.
    More,
    /// Nothing to write yet. Call [`PostWaker::wake`] (from any thread) when
    /// there is; until then the poster is not called.
    Wait,
    /// The article is complete: end it.
    Done,
    /// The article cannot be completed. A half-sent article cannot be
    /// abandoned on an NNTP connection, so the connection is closed and the
    /// error reported.
    Failed(io::Error),
}

/// Writes an article to a `POST` a piece at a time.
///
/// [`next`](Self::next) is called on the connection's reactor thread, first
/// when the server has answered `340` and then each time the connection has
/// taken what the last call wrote, so a poster that writes a chunk per call
/// never holds more than that chunk. It must not block: a poster whose data
/// comes from somewhere slow reads it on another thread and returns
/// [`PostStep::Wait`] until that thread calls [`PostWaker::wake`].
pub trait NntpPoster: Send {
    /// Writes the next piece of the article to `out`.
    fn next(&mut self, out: &mut NntpPostStream<'_>) -> PostStep;
}

/// Wakes a poster that returned [`PostStep::Wait`].
#[derive(Clone)]
pub struct PostWaker {
    waiting: Arc<AtomicBool>,
    conn: ConnHandle,
}

impl PostWaker {
    /// The poster has more to write; call it again.
    pub fn wake(&self) {
        self.waiting.store(false, Ordering::SeqCst);
        self.conn.poke();
    }
}

/// Where a poster writes the article to.
///
/// What is written is the article as the application has it: any line ends
/// (LF becomes CRLF), and no stuffing, which is done on the way out, as is
/// the line with the single dot that ends the article.
pub struct NntpPostStream<'a> {
    ep: &'a mut dyn Endpoint,
    stuffer: &'a mut PostStuffer,
    waiting: &'a Arc<AtomicBool>,
}

impl<'a> NntpPostStream<'a> {
    pub(crate) fn new(ep: &'a mut dyn Endpoint, stuffer: &'a mut PostStuffer, waiting: &'a Arc<AtomicBool>) -> Self {
        Self { ep, stuffer, waiting }
    }

    /// Writes `data`, which may end in the middle of a line.
    pub fn write(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut out = Vec::with_capacity(data.len() + data.len() / 32 + 8);
        self.stuffer.feed(data, &mut out);
        self.ep.send(&out);
    }

    /// A waker for the connection, for a poster that waits for data read on
    /// another thread.
    pub fn waker(&self) -> PostWaker {
        PostWaker { waiting: Arc::clone(self.waiting), conn: self.ep.handle() }
    }
}

/// Dot-stuffs an article as it is written, a piece at a time, holding two
/// flags and no line.
///
/// A bare LF becomes CRLF, a CR that is not followed by LF is kept, and a line
/// that begins with `.` gains a second. [`finish`](Self::finish) ends an
/// unterminated last line and adds the line with the single dot. Its output
/// for a whole article is [`crate::dot_stuff`]'s, however the article is split.
#[derive(Debug, Clone)]
pub(crate) struct PostStuffer {
    line_start: bool,
    pending_cr: bool,
}

impl PostStuffer {
    pub fn new() -> Self {
        Self { line_start: true, pending_cr: false }
    }

    fn byte(&mut self, b: u8, out: &mut Vec<u8>) {
        if self.pending_cr {
            self.pending_cr = false;
            if b == b'\n' {
                out.extend_from_slice(b"\r\n");
                self.line_start = true;
                return;
            }
            // A CR that does not end a line is part of it.
            out.push(b'\r');
            self.line_start = false;
        }
        match b {
            b'\r' => self.pending_cr = true,
            b'\n' => {
                out.extend_from_slice(b"\r\n");
                self.line_start = true;
            }
            _ => {
                if self.line_start && b == b'.' {
                    out.push(b'.');
                }
                out.push(b);
                self.line_start = false;
            }
        }
    }

    pub fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) {
        for &b in data {
            self.byte(b, out);
        }
    }

    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if self.pending_cr {
            self.pending_cr = false;
            out.push(b'\r');
            self.line_start = false;
        }
        if !self.line_start {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");
    }
}

/// How much of an article in memory a poster of one in a slice writes at a time.
const SLICE_PIECE: usize = 16 * 1024;

/// Posts an article that is already in memory. [`crate::NntpSession::post`] is
/// this, so that there is one way an article is sent.
pub(crate) struct SlicePoster {
    article: Vec<u8>,
    at: usize,
}

impl SlicePoster {
    pub fn new(article: Vec<u8>) -> Self {
        Self { article, at: 0 }
    }
}

impl NntpPoster for SlicePoster {
    fn next(&mut self, out: &mut NntpPostStream<'_>) -> PostStep {
        let end = (self.at + SLICE_PIECE).min(self.article.len());
        out.write(&self.article[self.at..end]);
        self.at = end;
        if self.at == self.article.len() {
            PostStep::Done
        } else {
            PostStep::More
        }
    }
}

// ---- attachments ----

/// Where an attachment's content is read from. It is read on a thread of its
/// own, so a source may block.
pub trait AttachmentSource: Send {
    /// As [`std::io::Read::read`].
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// A [`Read`] as a source.
struct ReadSource<R>(R);

impl<R: Read + Send> AttachmentSource for ReadSource<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

/// A file to post as a uuencoded block after the text of an article.
pub struct NntpAttachment {
    name: String,
    mode: u32,
    source: Box<dyn AttachmentSource>,
}

/// A file opened when it is first read, on the reading thread.
struct LazyFile {
    path: PathBuf,
    file: Option<File>,
}

impl Read for LazyFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.file.is_none() {
            self.file = Some(File::open(&self.path)?);
        }
        Read::read(self.file.as_mut().unwrap(), buf)
    }
}

impl NntpAttachment {
    /// A file, posted under its own name and, on Unix, its own permissions
    /// (otherwise `0o644`). It is opened and read off the reactor; a file that
    /// cannot be read fails the post.
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "attachment".into());
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o644)
        };
        #[cfg(not(unix))]
        let mode = 0o644;
        Self { name, mode, source: Box::new(ReadSource(LazyFile { path: path.to_path_buf(), file: None })) }
    }

    /// Content in memory, posted as `name`.
    pub fn from_bytes(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::from_reader(name, io::Cursor::new(bytes))
    }

    /// Content read from `reader`, on a thread of its own, posted as `name`.
    pub fn from_reader(name: impl Into<String>, reader: impl Read + Send + 'static) -> Self {
        Self::from_source(name, ReadSource(reader))
    }

    /// Content from a source of your own, posted as `name`.
    pub fn from_source(name: impl Into<String>, source: impl AttachmentSource + 'static) -> Self {
        Self { name: name.into(), mode: 0o644, source: Box::new(source) }
    }

    /// The permission bits written in the `begin` line (default `0o644`).
    pub fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }
}

/// What the thread that reads an attachment sends the poster.
enum Piece {
    Data(Vec<u8>),
    End,
    Failed(io::Error),
}

/// How many encoded pieces the reading thread may be ahead of the connection.
const AHEAD: usize = 2;

/// Source bytes read and encoded at a time: a multiple of the 45 bytes of a
/// uuencoded line.
const READ_BLOCK: usize = 45 * 256;

fn read_and_encode(mut attachment: NntpAttachment, send: impl Fn(Piece) -> bool) {
    let mut encoder = UuencodeEncoder::new(&attachment.name, attachment.mode);
    let mut block = vec![0u8; READ_BLOCK];
    loop {
        let n = match attachment.source.read(&mut block) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                send(Piece::Failed(e));
                return;
            }
        };
        let mut encoded = Vec::with_capacity(n * 4 / 3 + 128);
        let _ = encoder.write(&mut encoded, &block[..n]);
        if !send(Piece::Data(encoded)) {
            return;
        }
    }
    let mut tail = Vec::new();
    let _ = encoder.finish(&mut tail);
    if send(Piece::Data(tail)) {
        send(Piece::End);
    }
}

/// Posts text, then attachments as uuencoded blocks, each read and encoded on
/// a thread of its own and written a piece at a time.
pub(crate) struct AttachmentPoster {
    text: SlicePoster,
    text_done: bool,
    remaining: VecDeque<NntpAttachment>,
    current: Option<Receiver<Piece>>,
}

impl AttachmentPoster {
    pub fn new(mut text: Vec<u8>, attachments: Vec<NntpAttachment>) -> Self {
        // The blocks begin on a line of their own.
        if !text.is_empty() && !text.ends_with(b"\n") {
            text.extend_from_slice(b"\r\n");
        }
        Self { text: SlicePoster::new(text), text_done: false, remaining: attachments.into(), current: None }
    }
}

impl NntpPoster for AttachmentPoster {
    fn next(&mut self, out: &mut NntpPostStream<'_>) -> PostStep {
        if !self.text_done {
            match self.text.next(out) {
                PostStep::Done => self.text_done = true,
                step => return step,
            }
            return PostStep::More;
        }
        loop {
            if self.current.is_none() {
                let Some(attachment) = self.remaining.pop_front() else {
                    return PostStep::Done;
                };
                let (tx, rx) = sync_channel(AHEAD);
                let waker = out.waker();
                let spawned = std::thread::Builder::new().name("nntp-attachment".into()).spawn(move || {
                    read_and_encode(attachment, |piece| {
                        let sent = tx.send(piece).is_ok();
                        waker.wake();
                        sent
                    });
                });
                if let Err(e) = spawned {
                    return PostStep::Failed(e);
                }
                self.current = Some(rx);
            }
            match self.current.as_ref().unwrap().try_recv() {
                Ok(Piece::Data(bytes)) => {
                    out.write(&bytes);
                    return PostStep::More;
                }
                Ok(Piece::End) => self.current = None,
                Ok(Piece::Failed(e)) => return PostStep::Failed(e),
                Err(TryRecvError::Empty) => return PostStep::Wait,
                Err(TryRecvError::Disconnected) => {
                    return PostStep::Failed(io::Error::new(io::ErrorKind::UnexpectedEof, "the attachment reader stopped"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::reply::dot_stuff;

    fn stuffed(chunks: &[&[u8]]) -> Vec<u8> {
        let mut s = PostStuffer::new();
        let mut out = Vec::new();
        for c in chunks {
            s.feed(c, &mut out);
        }
        s.finish(&mut out);
        out
    }

    const SAMPLES: &[&[u8]] = &[
        b"",
        b"x",
        b"Subject: s\n\n.dot\nbody",
        b"a\r\nb\r\n.\r\n..\r\nlast\r\n",
        b"lone\rcr and\r\nmore\r",
        b"\n\n\n",
        b".",
        b"\r\n.\r\n",
        b"ends with cr\r",
    ];

    #[test]
    fn it_gives_what_dot_stuff_gives_however_the_article_is_split() {
        for sample in SAMPLES {
            let whole = dot_stuff(sample);
            assert_eq!(stuffed(&[sample]), whole, "{sample:?}");
            for size in 1..=sample.len().max(1) {
                let chunks: Vec<&[u8]> = sample.chunks(size).collect();
                assert_eq!(stuffed(&chunks), whole, "{sample:?} in chunks of {size}");
            }
        }
    }

    #[test]
    fn the_stuffer_holds_nothing_but_two_flags() {
        assert_eq!(std::mem::size_of::<PostStuffer>(), 2);
    }

    #[test]
    fn the_encoder_blocks_are_whole_lines_of_input() {
        assert_eq!(READ_BLOCK % 45, 0);
    }
}
