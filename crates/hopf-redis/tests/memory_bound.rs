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
use std::sync::Arc;
use std::time::{Duration, Instant};

use hopf_core::{Runtime, RuntimeConfig};
use hopf_redis::{
    ClusterConfig, RedisCluster, AggKind, ArgSource, BulkHandler, BulkSink, Command, Deadline, Feed, Flow, RedisClient, RedisConfig, RedisError, ReplySink,
    RespLimits, RespParser, Scalar, SourceCtl, SourceRead, StrKind, StreamArg, StreamHandle,
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

const MIB: usize = 1024 * 1024;

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
        if len > MIB {
            // Too large to hold: read it in blocks, keep none of it, and say how long it was.
            let mut left = len + 2;
            let mut block = vec![0u8; 64 * 1024];
            while left > 0 {
                let n = left.min(block.len());
                r.read_exact(&mut block[..n]).ok()?;
                left -= n;
            }
            words.push(format!("<{len} bytes>").into_bytes());
            continue;
        }
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

/// A pub/sub message to channel `c` whose body is `size` bytes, written block by block.
fn write_message(s: &mut TcpStream, size: usize) -> std::io::Result<()> {
    s.write_all(b">3\r\n$7\r\nmessage\r\n$1\r\nc\r\n")?;
    write_bulk(s, size)
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
                // `GET <size> now` answers at once.
                if words.len() < 3 {
                    std::thread::sleep(Duration::from_millis(400));
                }
                write_bulk(&mut s, size)
            }
            "PING" => s.write_all(b"+PONG\r\n"),
            // `SUBSCRIBE c <size>`: acknowledged, then a message of that size,
            // then a small one.
            "SUBSCRIBE" => {
                // The names are sent in sorted order, so which one is the size is found, not assumed.
                let size: usize = words[1..].iter().find_map(|w| String::from_utf8_lossy(w).parse().ok()).unwrap();
                s.write_all(b">3\r\n$9\r\nsubscribe\r\n$1\r\nc\r\n:1\r\n")
                    .and_then(|_| write_message(&mut s, size))
                    .and_then(|_| write_message(&mut s, 2))
            }
            // `PUSHME <size>`: a push of that size, which nobody asked for, then `+OK`.
            "PUSHME" => {
                let size: usize = String::from_utf8_lossy(&words[1]).parse().unwrap();
                write_message(&mut s, size).and_then(|_| s.write_all(b"+OK\r\n"))
            }
            // A cluster of one node, this one, serving every slot.
            "CLUSTER" if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case(b"SHARDS")) => {
                s.write_all(b"-ERR unknown subcommand 'SHARDS'\r\n")
            }
            "CLUSTER" => {
                let port = PORT.load(Ordering::SeqCst);
                s.write_all(format!("*1\r\n*3\r\n:0\r\n:16383\r\n*3\r\n$9\r\n127.0.0.1\r\n:{port}\r\n$4\r\nnode\r\n").as_bytes())
            }
            _ => s.write_all(b"+OK\r\n"),
        };
        if ok.is_err() {
            return;
        }
    }
}

static PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

fn serve() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    PORT.store(listener.local_addr().unwrap().port(), Ordering::SeqCst);
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
    let (tx, rx) = mpsc::channel();
    c.get(
        size.to_string(),
        Drain {
            bytes: Arc::new(AtomicUsize::new(0)),
            chunks: Arc::new(AtomicUsize::new(0)),
            pause_at_first: false,
            done: tx,
        },
    );
    let err = rx.recv_timeout(Duration::from_secs(120)).expect("the command finished").unwrap_err();
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

/// Counts what a streamed reply holds and keeps none of it; may pause once.
struct Drain {
    bytes: Arc<AtomicUsize>,
    chunks: Arc<AtomicUsize>,
    pause_at_first: bool,
    done: mpsc::Sender<Result<(), RedisError>>,
}

impl BulkHandler for Drain {
    fn chunk(&mut self, data: &[u8]) -> Flow {
        self.bytes.fetch_add(data.len(), Ordering::SeqCst);
        if self.chunks.fetch_add(1, Ordering::SeqCst) == 0 && self.pause_at_first {
            return Flow::Pause;
        }
        Flow::Continue
    }
    fn finished(&mut self, outcome: Result<(), RedisError>) {
        let _ = self.done.send(outcome);
    }
}

/// A 256 MiB value through `get_stream`: held for no longer than a chunk, with
/// or without the consumer pausing in the middle of it.
fn a_value_streams_through_a_client_in_constant_memory() {
    const SIZE: usize = 256 * MIB;
    let server = Server::start();
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", server.port));
    call(|cb| c.ping(move |r| cb(r))).expect("the connection is up");

    for pause in [false, true] {
        let base = reset_peak();
        let (tx, rx) = mpsc::channel();
        let (bytes, chunks) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let started = Instant::now();
        let handle: StreamHandle = c.send_streaming(
            &Command::new("GET").arg(SIZE.to_string()).arg("now"),
            BulkSink::new(Drain {
                bytes: Arc::clone(&bytes),
                chunks: Arc::clone(&chunks),
                pause_at_first: pause,
                done: tx,
            }),
        );
        if pause {
            // Stalled in the middle of a 256 MiB reply for a while: still nothing held.
            std::thread::sleep(Duration::from_millis(500));
            let held = bytes.load(Ordering::SeqCst);
            assert!(held < SIZE / 4, "{held} bytes were read while the consumer was paused");
            handle.resume();
        }
        let outcome = rx.recv_timeout(Duration::from_secs(120)).expect("the command finished");
        if let Err(e) = &outcome {
            panic!("the streamed command failed: {e:?} (paused: {pause}, {} bytes read)", bytes.load(Ordering::SeqCst));
        }
        assert_eq!(bytes.load(Ordering::SeqCst), SIZE);
        let above = peak_above(base);
        println!(
            "a 256 MiB value streamed{}: {} chunks, peak heap {above} bytes above baseline, {:.1} s",
            if pause { ", paused in the middle" } else { "" },
            chunks.load(Ordering::SeqCst),
            started.elapsed().as_secs_f64()
        );
        assert!(above < 256 * 1024, "the heap rose by {above} bytes streaming a {SIZE} byte value (paused: {pause})");
    }
    c.close();
    rt.shutdown();
}

/// A command bigger than the connection's outbound buffer (4 MiB by default) is
/// sent in blocks, each when the last has drained, and not in one write that
/// overflows the buffer and fails the connection.
fn a_command_larger_than_the_outbound_buffer_is_sent() {
    let server = Server::start();
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", server.port));
    call(|cb| c.ping(move |r| cb(r))).expect("the connection is up");
    let value = vec![b'x'; 12 * MIB];
    let reply = call(|cb| c.set("big", &value, move |r| cb(r)));
    assert_eq!(reply, Ok(()), "a 12 MiB value in memory");
    assert_eq!(call(|cb| c.ping(move |r| cb(r))), Ok(()), "and the connection is still in step");
    c.close();
    rt.shutdown();
}

/// A 256 MiB value through a cluster client, to a sink that keeps nothing: the
/// cluster holds back only the first event of a reply, to see if it is an error
/// to follow, and none of the value.
fn a_value_streams_through_a_cluster_in_constant_memory() {
    const SIZE: usize = 256 * MIB;
    let server = Server::start();
    let rt = runtime();
    let c = RedisCluster::connect(
        rt.pick_worker(),
        ClusterConfig::new([("127.0.0.1".to_string(), server.port)]),
    );
    for _ in 0..500 {
        if c.is_ready() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(c.is_ready(), "no layout");
    let base = reset_peak();
    let (tx, rx) = mpsc::channel();
    let (bytes, chunks) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    c.send_streaming(
        &Command::new("GET").arg(SIZE.to_string()).arg("now"),
        BulkSink::new(Drain {
            bytes: Arc::clone(&bytes),
            chunks: Arc::clone(&chunks),
            pause_at_first: false,
            done: tx,
        }),
    );
    let outcome = rx.recv_timeout(Duration::from_secs(120)).expect("the command finished");
    assert_eq!(outcome, Ok(()));
    assert_eq!(bytes.load(Ordering::SeqCst), SIZE);
    let above = peak_above(base);
    println!("a 256 MiB value streamed through a cluster: peak heap {above} bytes above baseline");
    assert!(above < 256 * 1024, "the heap rose by {above} bytes streaming a {SIZE} byte value through a cluster");
    c.close();
    rt.shutdown();
}

/// Makes `left` bytes as it is asked for them, and holds none.
struct Generator {
    left: u64,
}

impl ArgSource for Generator {
    fn read(&mut self, out: &mut [u8], _ctl: &mut SourceCtl<'_>) -> SourceRead {
        let n = (out.len() as u64).min(self.left) as usize;
        out[..n].fill(b'u');
        self.left -= n as u64;
        SourceRead::Data(n)
    }
}

/// A 256 MiB value out of a client, made as it is sent: the client holds a block
/// of it at a time, not the value.
fn a_value_streams_out_of_a_client_in_constant_memory() {
    const SIZE: u64 = 256 * MIB as u64;
    let server = Server::start();
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", server.port));
    call(|cb| c.ping(move |r| cb(r))).expect("the connection is up");
    let base = reset_peak();
    let started = Instant::now();
    let command = Command::new("SET").arg("k").arg_stream(StreamArg::once(SIZE, Generator { left: SIZE }));
    let reply = call(|cb| c.send(&command, move |r| cb(r)));
    assert!(reply.is_ok(), "{reply:?}");
    let above = peak_above(base);
    println!(
        "a 256 MiB value streamed out: peak heap {above} bytes above baseline, {:.1} s",
        started.elapsed().as_secs_f64()
    );
    assert!(above < 2 * MIB, "the heap rose by {above} bytes sending a {SIZE} byte value");
    assert_eq!(call(|cb| c.ping(move |r| cb(r))), Ok(()), "and the connection is in step");
    c.close();
    rt.shutdown();
}

/// A subscriber's handler that counts and keeps none of what it is given.
struct Tally {
    bytes: Arc<AtomicUsize>,
    chunks: Arc<AtomicUsize>,
    pause_at_first: bool,
    paused: bool,
    done: mpsc::Sender<usize>,
    up: mpsc::Sender<()>,
}

impl hopf_redis::SubscriberHandler for Tally {
    fn on_connected(&mut self, _reconnect: bool) {
        let _ = self.up.send(());
    }
    fn message_begin(&mut self, _header: &hopf_redis::MessageHeader<'_>, _len: Option<u64>) -> Flow {
        Flow::Continue
    }
    fn message_chunk(&mut self, data: &[u8]) -> Flow {
        self.bytes.fetch_add(data.len(), Ordering::SeqCst);
        self.chunks.fetch_add(1, Ordering::SeqCst);
        if self.pause_at_first && !self.paused {
            self.paused = true;
            return Flow::Pause;
        }
        Flow::Continue
    }
    fn message_end(&mut self) {
        let _ = self.done.send(self.bytes.load(Ordering::SeqCst));
    }
}

/// A 256 MiB message to a subscriber: given to its handler in chunks, held for
/// no longer than a chunk, with or without the handler pausing in the middle.
fn a_message_streams_through_a_subscriber_in_constant_memory() {
    const SIZE: usize = 256 * MIB;
    for pause in [false, true] {
        let server = Server::start();
        let rt = runtime();
        let (tx, rx) = mpsc::channel();
        let (up_tx, up) = mpsc::channel();
        let (bytes, chunks) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let sub = hopf_redis::RedisSubscriber::connect(
            rt.pick_worker(),
            RedisConfig::new("127.0.0.1", server.port).ping_interval(None),
            Tally {
                bytes: Arc::clone(&bytes),
                chunks: Arc::clone(&chunks),
                pause_at_first: pause,
                paused: false,
                done: tx,
                up: up_tx,
            },
        );
        // The connection is up before the baseline is taken, as the other checks
        // do: it is the message that is measured.
        up.recv_timeout(Duration::from_secs(30)).expect("the subscriber connected");
        let base = reset_peak();
        let started = Instant::now();
        sub.subscribe(&["c", SIZE.to_string().as_str()]);
        if pause {
            let deadline = Instant::now() + Duration::from_secs(30);
            while bytes.load(Ordering::SeqCst) == 0 {
                assert!(Instant::now() < deadline, "the message never began");
                std::thread::sleep(Duration::from_millis(5));
            }
            // Stalled in the middle of a 256 MiB message: still nothing held.
            std::thread::sleep(Duration::from_millis(500));
            let held = bytes.load(Ordering::SeqCst);
            assert!(held < SIZE / 4, "{held} bytes were read while the handler was paused");
            sub.resume();
        }
        let got = rx.recv_timeout(Duration::from_secs(120)).expect("the message ended");
        assert_eq!(got, SIZE);
        // And the small one after it.
        assert_eq!(rx.recv_timeout(Duration::from_secs(30)).expect("the next message"), SIZE + 2);
        let above = peak_above(base);
        println!(
            "a 256 MiB message to a subscriber{}: {} chunks, peak heap {above} bytes above baseline, {:.1} s",
            if pause { ", paused in the middle" } else { "" },
            chunks.load(Ordering::SeqCst),
            started.elapsed().as_secs_f64()
        );
        assert!(above < 256 * 1024, "the heap rose by {above} bytes receiving a {SIZE} byte message (paused: {pause})");
        sub.close();
        rt.shutdown();
    }
}

/// A 128 MiB push on a command connection with no sink to hear it is discarded as
/// it arrives, and the reply behind it is still the reply. (Discarding is bounded
/// by `max_skip`, 256 MiB by default; past that the connection is closed.)
fn a_push_nobody_wants_is_discarded_in_constant_memory() {
    const SIZE: usize = 128 * MIB;
    let server = Server::start();
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", server.port).ping_interval(None));
    call(|cb| c.ping(move |r| cb(r))).expect("the connection is up");
    let base = reset_peak();
    let started = Instant::now();
    let reply = call(|cb| {
        c.send_with_deadline(&Command::new("PUSHME").arg(SIZE.to_string()), Deadline::After(Duration::from_secs(120)), move |r| cb(r))
    });
    assert!(reply.is_ok(), "{reply:?}");
    let above = peak_above(base);
    println!(
        "a 128 MiB push nobody wanted: peak heap {above} bytes above baseline, {:.1} s",
        started.elapsed().as_secs_f64()
    );
    assert!(above < 256 * 1024, "the heap rose by {above} bytes discarding a {SIZE} byte push");
    c.close();
    rt.shutdown();
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--serve") {
        return serve();
    }
    the_parser_holds_a_constant_amount_however_large_the_reply();
    a_late_reply_to_a_timed_out_command_is_discarded_in_constant_memory();
    a_value_streams_through_a_client_in_constant_memory();
    a_command_larger_than_the_outbound_buffer_is_sent();
    a_value_streams_out_of_a_client_in_constant_memory();
    a_value_streams_through_a_cluster_in_constant_memory();
    a_message_streams_through_a_subscriber_in_constant_memory();
    a_push_nobody_wants_is_discarded_in_constant_memory();
    println!("memory_bound: ok");
}
