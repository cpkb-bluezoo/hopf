// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The client holds a constant amount of memory however large a reply is.
//!
//! Run with `cargo test -p hopf-redis --features integration --test memory_bound`.
//! It is its own binary with no test harness, because it measures the peak of the
//! live heap with a counting allocator and so must be alone in its process, and
//! because it runs itself again (`--serve`) as the server: a plain blocking
//! socket server in a child process, so the server's own memory is not counted
//! and a reply of hundreds of megabytes is generated block by block, never held.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command as Process, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hopf_core::{Runtime, RuntimeConfig};
use hopf_redis::{
    AggKind, Command, Deadline, Feed, Flow, RedisClient, RedisConfig, RedisError, ReplySink, RespLimits, RespParser, Scalar,
    StrKind,
};

// ---- the allocator: live bytes, and the highest they have been ----

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

/// Start measuring from what is live now.
fn reset_peak() -> usize {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    base
}

/// How far above `base` the heap has been since `reset_peak`.
fn peak_above(base: usize) -> usize {
    PEAK.load(Ordering::SeqCst).saturating_sub(base)
}

// ---- the server: a plain blocking one, in a child process ----

const HELLO_OK: &str = "%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n";

fn read_line(r: &mut impl BufRead) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    if r.read_until(b'\n', &mut line).ok()? == 0 {
        return None;
    }
    Some(line)
}

fn read_command(r: &mut impl BufRead) -> Option<Vec<Vec<u8>>> {
    let header = read_line(r)?;
    let n: usize = std::str::from_utf8(header.get(1..header.len().checked_sub(2)?)?).ok()?.parse().ok()?;
    let mut words = Vec::with_capacity(n);
    for _ in 0..n {
        let line = read_line(r)?;
        let len: usize = std::str::from_utf8(line.get(1..line.len().checked_sub(2)?)?).ok()?.parse().ok()?;
        let mut word = vec![0u8; len + 2];
        r.read_exact(&mut word).ok()?;
        word.truncate(len);
        words.push(word);
    }
    Some(words)
}

/// A bulk string of `size` bytes, written block by block.
fn write_bulk(s: &mut TcpStream, size: usize) -> std::io::Result<()> {
    s.write_all(format!("${size}\r\n").as_bytes())?;
    let block = vec![b'v'; 64 * 1024];
    let mut left = size;
    while left > 0 {
        let n = left.min(block.len());
        s.write_all(&block[..n])?;
        left -= n;
    }
    s.write_all(b"\r\n")
}

fn handle(mut s: TcpStream) {
    let mut reader = BufReader::new(s.try_clone().unwrap());
    while let Some(words) = read_command(&mut reader) {
        let name = String::from_utf8_lossy(&words[0]).to_ascii_uppercase();
        let ok = match name.as_str() {
            "HELLO" => s.write_all(HELLO_OK.as_bytes()),
            // `GET <size>`: the reply is that many bytes, after a pause long
            // enough for the client's command timeout to have passed.
            "GET" => {
                let size: usize = String::from_utf8_lossy(&words[1]).parse().unwrap();
                std::thread::sleep(Duration::from_millis(400));
                write_bulk(&mut s, size)
            }
            "PING" => s.write_all(b"+PONG\r\n"),
            _ => s.write_all(b"+OK\r\n"),
        };
        if ok.is_err() {
            return;
        }
    }
}

fn serve() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    println!("PORT {}", listener.local_addr().unwrap().port());
    std::io::stdout().flush().unwrap();
    // Run until the parent closes our stdin.
    std::thread::spawn(|| {
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        std::process::exit(0);
    });
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        std::thread::spawn(move || handle(stream));
    }
}

struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn start() -> Self {
        let mut child = Process::new(std::env::current_exe().unwrap())
            .arg("--serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the server process starts");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port = line.strip_prefix("PORT ").expect("the server says where it listens").trim().parse().unwrap();
        Self { child, port }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

// ---- the checks ----

const MIB: usize = 1024 * 1024;

fn runtime() -> Runtime {
    Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap()
}

fn call<T: Send + 'static>(start: impl FnOnce(Box<dyn FnOnce(T) + Send>)) -> T {
    let (tx, rx) = mpsc::channel();
    start(Box::new(move |v| {
        let _ = tx.send(v);
    }));
    rx.recv_timeout(Duration::from_secs(120)).expect("the callback ran")
}

/// A reply nobody is waiting for any more, because its command timed out, is
/// discarded as it arrives: 256 MiB in, and the heap does not move.
fn a_late_reply_to_a_timed_out_command_is_discarded_in_constant_memory() {
    let size: usize = std::env::var("MB").ok().and_then(|v| v.parse().ok()).unwrap_or(256) * MIB;
    let server = Server::start();
    let rt = runtime();
    let c = RedisClient::connect(
        rt.pick_worker(),
        RedisConfig::new("127.0.0.1", server.port)
            .command_timeout(Some(Duration::from_millis(100)))
            .ping_interval(None),
    );
    call(|cb| c.ping(move |r| cb(r))).expect("the connection is up");
    let base = reset_peak();

    let started = Instant::now();
    let err = call(|cb| c.get(size.to_string(), move |r| cb(r))).unwrap_err();
    assert_eq!(err, RedisError::Timeout);
    // The PING is answered after the whole of the reply to the GET, so when it
    // arrives the 256 MiB has been read.
    call(|cb| c.send_with_deadline(&Command::new("PING"), Deadline::After(Duration::from_secs(120)), move |r| cb(r)))
        .expect("the PING is answered");
    let above = peak_above(base);
    println!(
        "a late {} MiB reply to a timed-out command: peak heap {above} bytes above baseline, {:.1} s",
        size / MIB,
        started.elapsed().as_secs_f64()
    );
    assert!(above < 2 * MIB, "the heap rose by {above} bytes while a {size} byte reply was discarded");
    c.close();
    rt.shutdown();
}

// ---- the parser alone, on a reply far larger than the process could hold ----

/// Counts what it is given and keeps none of it.
#[derive(Default)]
struct Count {
    payload: u64,
    skip_after_first_chunk: bool,
    chunks: u64,
}

impl ReplySink for Count {
    fn scalar(&mut self, _v: Scalar<'_>) -> Flow {
        Flow::Continue
    }
    fn error(&mut self, _line: &str) -> Flow {
        Flow::Continue
    }
    fn begin_aggregate(&mut self, _kind: AggKind, _len: Option<usize>) -> Flow {
        Flow::Continue
    }
    fn end_aggregate(&mut self) -> Flow {
        Flow::Continue
    }
    fn begin_string(&mut self, _kind: StrKind, _len: Option<usize>) -> Flow {
        Flow::Continue
    }
    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        self.payload += data.len() as u64;
        self.chunks += 1;
        if self.skip_after_first_chunk {
            Flow::Skip
        } else {
            Flow::Continue
        }
    }
    fn end_string(&mut self) -> Flow {
        Flow::Continue
    }
}

/// Feed the parser a bulk string of `size` bytes, made as it goes, in pieces of
/// `piece` bytes; return what the sink saw and how far the heap rose.
fn feed_bulk(size: u64, piece: usize, limits: RespLimits, sink: &mut Count) -> (Result<Feed, hopf_redis::RespError>, usize) {
    let block = vec![b'v'; piece];
    let mut parser = RespParser::with_limits(limits);
    let base = reset_peak();
    let mut result = Ok(Feed::Consumed);
    let mut feed = |bytes: &[u8], parser: &mut RespParser| {
        let mut data = bytes;
        let r = parser.feed(&mut data, sink);
        assert!(r.is_err() || data.is_empty());
        r
    };
    result = result.and_then(|_| feed(format!("${size}\r\n").as_bytes(), &mut parser));
    let mut left = size;
    while left > 0 && result.is_ok() {
        let n = left.min(piece as u64) as usize;
        result = feed(&block[..n], &mut parser);
        left -= n as u64;
    }
    if result.is_ok() {
        result = feed(b"\r\n", &mut parser);
        assert!(parser.is_idle());
    }
    (result, peak_above(base))
}

fn the_parser_holds_a_constant_amount_however_large_the_reply() {
    const GIB: u64 = 1024 * 1024 * 1024;
    for piece in [4 * 1024, 64 * 1024] {
        // Streamed to a sink that keeps nothing: no limit applies, none is held.
        let mut sink = Count::default();
        let (result, above) = feed_bulk(GIB, piece, RespLimits::default(), &mut sink);
        assert_eq!(result, Ok(Feed::Consumed));
        assert_eq!(sink.payload, GIB, "every byte was handed on");
        println!("1 GiB reply in {piece}-byte reads, streamed: peak heap {above} bytes above baseline");
        assert!(above < 64 * 1024, "the heap rose by {above} bytes for a 1 GiB reply in {piece}-byte reads");

        // A sink that wants no more after the first chunk: discarded as it comes.
        let unlimited = RespLimits {
            max_skip: usize::MAX,
            ..RespLimits::default()
        };
        let mut sink = Count {
            skip_after_first_chunk: true,
            ..Count::default()
        };
        let (result, above) = feed_bulk(GIB, piece, unlimited, &mut sink);
        assert_eq!(result, Ok(Feed::Consumed));
        assert_eq!(sink.chunks, 1, "nothing is handed on after Skip");
        println!("1 GiB reply in {piece}-byte reads, skipped: peak heap {above} bytes above baseline");
        assert!(above < 64 * 1024, "the heap rose by {above} bytes skipping a 1 GiB reply");

        // Discarding is bounded: the default stops at 256 MiB.
        let mut sink = Count {
            skip_after_first_chunk: true,
            ..Count::default()
        };
        let (result, above) = feed_bulk(GIB, piece, RespLimits::default(), &mut sink);
        assert!(result.is_err(), "discarding 1 GiB goes past max_skip");
        assert!(above < 64 * 1024);
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--serve") {
        return serve();
    }
    the_parser_holds_a_constant_amount_however_large_the_reply();
    a_late_reply_to_a_timed_out_command_is_discarded_in_constant_memory();
    println!("memory_bound: ok");
}
