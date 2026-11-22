// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The server holds a constant amount of memory however large an article is.
//!
//! Run with `cargo test -p hopf-nntp --features integration --test memory_bound`.
//! It is its own binary with no test harness, because it measures the peak of
//! the live heap with a counting allocator and so must be alone in its
//! process. The articles are files in a Maildir, written in blocks so that none
//! is ever held whole, and read by a client that keeps one block.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::{AppendGuard, MailboxFactory, MaildirFactory};
use hopf_nntp::{
    AttachmentSource, NntpArticleHandler, NntpAttachment, NntpClient, NntpClientHandler, NntpConfig, NntpGreeting, NntpPostStream,
    NntpPoster, NntpService, NntpSession, PostStep,
};

struct Peak;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Peak {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grew(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        grew(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            grew(new_size - layout.size());
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: Peak = Peak;

fn reset_peak() -> usize {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    base
}

fn peak_above(base: usize) -> usize {
    PEAK.load(Ordering::SeqCst).saturating_sub(base)
}

const MIB: usize = 1024 * 1024;

/// Appends an article of about `size` octets to `misc/test`, a block at a time.
fn add_article(factory: &Arc<MaildirFactory>, name: &str, size: usize) {
    let mut store = factory.create_store();
    store.open("news").unwrap();
    let mut mb = store.open_mailbox("misc/test", false).unwrap();
    let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
    guard
        .append_content(format!("From: a@x.org\r\nSubject: {name}\r\nMessage-ID: <{name}@x.org>\r\n\r\n").as_bytes())
        .unwrap();
    let line = b"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789\r\n";
    let block: Vec<u8> = line.iter().copied().cycle().take(line.len() * 700).collect();
    let mut written = 0;
    while written < size {
        guard.append_content(&block).unwrap();
        written += block.len();
    }
    guard.commit().unwrap();
    mb.close(false).unwrap();
    store.close().unwrap();
}

/// Sends `command` and reads the whole of the multi-line answer, keeping one
/// block. Returns how many bytes the answer held.
fn read_multiline(stream: &mut BufReader<TcpStream>, command: &str) -> usize {
    stream.get_mut().write_all(command.as_bytes()).unwrap();
    let mut status = String::new();
    stream.read_line(&mut status).unwrap();
    assert!(status.starts_with("22"), "{command}: {status}");
    let mut block = vec![0u8; 64 * 1024];
    let mut total = 0;
    let mut tail = [0u8; 5];
    loop {
        let n = stream.read(&mut block).unwrap();
        assert!(n > 0, "the connection closed after {total} bytes");
        total += n;
        // The data block ends with CRLF "." CRLF, which may straddle reads.
        if n >= 5 {
            tail.copy_from_slice(&block[n - 5..n]);
        } else {
            tail.rotate_left(n);
            tail[5 - n..].copy_from_slice(&block[..n]);
        }
        if &tail == b"\r\n.\r\n" {
            return total;
        }
    }
}

fn measure(addr: std::net::SocketAddr, command: &str) -> (usize, usize) {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
    let mut stream = BufReader::with_capacity(4096, stream);
    let mut line = String::new();
    stream.read_line(&mut line).unwrap();
    stream.get_mut().write_all(b"GROUP misc.test\r\n").unwrap();
    line.clear();
    stream.read_line(&mut line).unwrap();
    assert!(line.starts_with("211 "), "{line}");
    let base = reset_peak();
    let bytes = read_multiline(&mut stream, command);
    let peak = peak_above(base);
    stream.get_mut().write_all(b"QUIT\r\n").unwrap();
    (bytes, peak)
}

/// Posts an article of about `size` octets, generated a block at a time, and
/// returns the peak of the heap above where it was when the post began.
fn measure_post(addr: std::net::SocketAddr, name: &str, size: usize) -> usize {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
    let mut stream = BufReader::with_capacity(4096, stream);
    let mut line = String::new();
    stream.read_line(&mut line).unwrap();
    stream.get_mut().write_all(b"POST\r\n").unwrap();
    line.clear();
    stream.read_line(&mut line).unwrap();
    assert!(line.starts_with("340 "), "{line}");
    let base = reset_peak();
    let head = format!("From: p@x.org\r\nNewsgroups: misc.test\r\nSubject: {name}\r\n\r\n");
    stream.get_mut().write_all(head.as_bytes()).unwrap();
    let text = b"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789\r\n";
    let block: Vec<u8> = text.iter().copied().cycle().take(text.len() * 700).collect();
    let mut sent = 0;
    while sent < size {
        stream.get_mut().write_all(&block).unwrap();
        sent += block.len();
    }
    stream.get_mut().write_all(b".\r\n").unwrap();
    line.clear();
    stream.read_line(&mut line).unwrap();
    assert!(line.starts_with("240 "), "{line}");
    let peak = peak_above(base);
    stream.get_mut().write_all(b"QUIT\r\n").unwrap();
    peak
}

// ---- the hopf client posting ----

/// Article text of `size` octets, a block at a time.
struct Generated {
    head: Vec<u8>,
    left: usize,
}

impl NntpPoster for Generated {
    fn next(&mut self, out: &mut NntpPostStream<'_>) -> PostStep {
        out.write(&std::mem::take(&mut self.head));
        let line = b"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789\n";
        let block: Vec<u8> = line.iter().copied().cycle().take(line.len() * 200).collect();
        let n = self.left.min(block.len());
        out.write(&block[..n]);
        self.left -= n;
        if self.left == 0 {
            PostStep::Done
        } else {
            PostStep::More
        }
    }
}

/// `size` bytes of a repeating pattern, read a block at a time.
struct Pattern {
    left: usize,
    at: u32,
}

impl AttachmentSource for Pattern {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.left.min(buf.len());
        for b in &mut buf[..n] {
            *b = (self.at % 251) as u8;
            self.at = self.at.wrapping_add(1);
        }
        self.left -= n;
        Ok(n)
    }
}

fn pattern_checksum(size: usize) -> u64 {
    (0..size as u32).fold(0u64, |sum, i| sum.wrapping_mul(31).wrapping_add(u64::from((i % 251) as u8)))
}

#[derive(Default)]
struct Done {
    posted: Option<Result<(), String>>,
    attached: Option<(u64, u64, bool)>,
    finished: bool,
}

struct Post {
    streamed: Option<usize>,
    attached: Option<usize>,
    done: Arc<Mutex<Done>>,
}

struct Count(Arc<Mutex<Done>>);

impl NntpArticleHandler for Count {
    fn attachment_begin(&mut self, _mode: u32, _name: &[u8]) {
        self.0.lock().unwrap().attached = Some((0, 0, false));
    }
    fn attachment_data(&mut self, data: &[u8]) {
        let mut d = self.0.lock().unwrap();
        let a = d.attached.as_mut().unwrap();
        a.0 += data.len() as u64;
        a.1 = data.iter().fold(a.1, |sum, &b| sum.wrapping_mul(31).wrapping_add(u64::from(b)));
    }
    fn attachment_end(&mut self, complete: bool) {
        self.0.lock().unwrap().attached.as_mut().unwrap().2 = complete;
    }
}

impl NntpClientHandler for Post {
    fn on_connected(&mut self, session: &NntpSession, _greeting: &NntpGreeting) {
        let d = Arc::clone(&self.done);
        let head = b"From: p@x.org\r\nNewsgroups: misc.test\r\nSubject: streamed\r\n\r\n";
        if let Some(size) = self.streamed {
            session.post_stream(Generated { head: head.to_vec(), left: size }, move |r| d.lock().unwrap().posted = Some(r.map_err(|e| e.to_string())));
        }
        if let Some(size) = self.attached {
            let d = Arc::clone(&self.done);
            session.post_with_attachments(
                b"From: p@x.org\r\nNewsgroups: misc.test\r\nSubject: attached\r\nMessage-ID: <attached@x.org>\r\n\r\nA file.\r\n",
                vec![NntpAttachment::from_source("data.bin", Pattern { left: size, at: 0 })],
                move |r| d.lock().unwrap().posted = Some(r.map_err(|e| e.to_string())),
            );
            // The last article in the group is the one just posted.
            let (s2, d2) = (session.clone(), Arc::clone(&self.done));
            session.group("misc.test", move |g| {
                let last = g.unwrap().last;
                let s3 = s2.clone();
                s2.article_with_attachments(last, Count(Arc::clone(&d2)), move |_| s3.quit());
            });
        } else {
            session.quit();
        }
    }
    fn on_error(&mut self, error: &io::Error) {
        self.done.lock().unwrap().posted = Some(Err(error.to_string()));
        self.done.lock().unwrap().finished = true;
    }
    fn on_disconnected(&mut self) {
        self.done.lock().unwrap().finished = true;
    }
}

use std::io;
use std::sync::Mutex;

/// Posts through the hopf client, and returns the peak of the heap above where
/// it was before, the client and the server in this process together.
fn measure_client(rt: &Arc<Runtime>, addr: std::net::SocketAddr, streamed: Option<usize>, attached: Option<usize>) -> (usize, Done) {
    let done: Arc<Mutex<Done>> = Arc::default();
    let base = reset_peak();
    NntpClient::from_addr(addr)
        .connect_with(rt, Box::new(Post { streamed, attached, done: Arc::clone(&done) }))
        .unwrap();
    let started = std::time::Instant::now();
    while !done.lock().unwrap().finished {
        assert!(started.elapsed() < Duration::from_secs(300), "the client never finished");
        std::thread::sleep(Duration::from_millis(20));
    }
    let peak = peak_above(base);
    let d = std::mem::take(&mut *done.lock().unwrap());
    (peak, d)
}

fn main() {
    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("news").unwrap();
        store.create_mailbox("misc/test").unwrap();
        store.close().unwrap();
    }
    add_article(&factory, "small", 64 * 1024);
    add_article(&factory, "large", 192 * MIB);

    let runtime = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let config = NntpConfig::new("127.0.0.1:0".parse().unwrap(), "news.example");
    let mut config = config;
    config.max_post_size = None;
    let service = NntpService::new(config, Arc::clone(&runtime), factory);
    let addr = service.start().unwrap();

    // Warm up: buffers that are made once are not what is being measured.
    let _ = measure(addr, "ARTICLE 1\r\n");

    let mut small_peak = 0;
    for command in ["ARTICLE 1\r\n", "BODY 1\r\n"] {
        let (bytes, peak) = measure(addr, command);
        println!("{} of {} bytes: peak {} KiB above baseline", command.trim_end(), bytes, peak / 1024);
        small_peak = small_peak.max(peak);
    }
    let mut large_peak = 0;
    for command in ["ARTICLE 2\r\n", "BODY 2\r\n"] {
        let (bytes, peak) = measure(addr, command);
        println!("{} of {} bytes: peak {} KiB above baseline", command.trim_end(), bytes, peak / 1024);
        assert!(bytes > 190 * MIB);
        large_peak = large_peak.max(peak);
    }
    assert!(large_peak < 2 * MIB, "a 192 MiB article took {large_peak} bytes of heap at its peak");
    assert!(
        large_peak < small_peak + MIB,
        "memory grew with the article: {small_peak} for 64 KiB, {large_peak} for 192 MiB"
    );
    let small_post = measure_post(addr, "post-small", 64 * 1024);
    let large_post = measure_post(addr, "post-large", 192 * MIB);
    println!("POST peak {} KiB for 64 KiB and {} KiB for 192 MiB", small_post / 1024, large_post / 1024);
    assert!(large_post < 2 * MIB, "posting a 192 MiB article took {large_post} bytes of heap at its peak");
    assert!(
        large_post < small_post + MIB,
        "memory grew with the posted article: {small_post} for 64 KiB, {large_post} for 192 MiB"
    );
    // The hopf client posting to the hopf server, both counted.
    let (small, d) = measure_client(&runtime, addr, Some(64 * 1024), None);
    assert_eq!(d.posted, Some(Ok(())));
    let (large, d) = measure_client(&runtime, addr, Some(128 * MIB), None);
    assert_eq!(d.posted, Some(Ok(())));
    println!("client post_stream peak {} KiB for 64 KiB and {} KiB for 128 MiB", small / 1024, large / 1024);
    assert!(large < 3 * MIB && large < small + 2 * MIB, "memory grew with the streamed article: {small} then {large}");

    let (small_a, d) = measure_client(&runtime, addr, None, Some(8 * MIB));
    assert_eq!(d.posted, Some(Ok(())));
    let size = 128 * MIB;
    let (large_a, d) = measure_client(&runtime, addr, None, Some(size));
    assert_eq!(d.posted, Some(Ok(())));
    println!("client attachment peak {} KiB for 8 MiB and {} KiB for 128 MiB", small_a / 1024, large_a / 1024);
    // (A client that is slower than the server lets its inbound ring fill, and
    // the ring grows to its limit of a megabyte: that is the 2 MiB over the
    // posting alone. It is the same for 8 MiB as for 128.)
    assert!(large_a < 4 * MIB && large_a < small_a + MIB / 2, "memory grew with the attachment: {small_a} then {large_a}");
    // And what came back out of the server, decoded as it arrived, is what went in.
    assert_eq!(d.attached, Some((size as u64, pattern_checksum(size), true)));

    println!("ok: peak {} KiB for a 64 KiB article and {} KiB for a 192 MiB one", small_peak / 1024, large_peak / 1024);
}
