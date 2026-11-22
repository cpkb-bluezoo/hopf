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
use hopf_nntp::{NntpConfig, NntpService};

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
    println!("ok: peak {} KiB for a 64 KiB article and {} KiB for a 192 MiB one", small_peak / 1024, large_peak / 1024);
}
