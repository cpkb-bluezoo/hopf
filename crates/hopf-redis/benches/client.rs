// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Benchmarks for the Redis client, with no dependency beyond the workspace's.
//!
//! ```text
//! cargo bench -p hopf-redis --bench client                  # everything
//! cargo bench -p hopf-redis --bench client -- cluster       # scenarios whose name contains "cluster"
//! cargo bench -p hopf-redis --bench client -- --scale 0.1   # a tenth of the operations
//! ```
//!
//! The server is a minimal RESP server in a child process (this binary run again
//! with `--serve`), so the numbers are the client's alone: allocations are
//! counted by a global allocator in this process, and CPU time is this
//! process's, user plus system, from `getrusage`. The server answers any key on
//! any node, so a cluster scenario never sees a redirection. It is not a
//! stand-in for Redis: what the numbers say is how much work the client does
//! per command, not how fast a real server answers.
//!
//! Every row is per operation, an operation being one command and its reply.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command as Process, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hopf_core::{Bytes, ClientTlsBuilder, Endpoint, ProtocolHandler, Runtime, RuntimeConfig, SharedTlsConnector, TcpListenerConfig};
use hopf_redis::{ClusterConfig, Command, RedisClient, RedisCluster, RedisConfig, RespParser, Value};

// ---- counting allocator ----

struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

fn note(size: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn cpu_time() -> Duration {
    let mut u = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given.
    let u = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, u.as_mut_ptr());
        u.assume_init()
    };
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, (t.tv_usec as u32) * 1000);
    tv(u.ru_utime) + tv(u.ru_stime)
}

/// What a measured stretch cost.
struct Window {
    wall: Instant,
    cpu: Duration,
    allocs: u64,
    bytes: u64,
}

impl Window {
    fn open() -> Self {
        ALLOCS.store(0, Ordering::SeqCst);
        BYTES.store(0, Ordering::SeqCst);
        COUNTING.store(true, Ordering::SeqCst);
        Self {
            wall: Instant::now(),
            cpu: cpu_time(),
            allocs: 0,
            bytes: 0,
        }
    }

    fn close(mut self, ops: u64) -> Row {
        let wall = self.wall.elapsed();
        let cpu = cpu_time() - self.cpu;
        COUNTING.store(false, Ordering::SeqCst);
        self.allocs = ALLOCS.load(Ordering::SeqCst);
        self.bytes = BYTES.load(Ordering::SeqCst);
        Row {
            ops,
            ops_per_sec: ops as f64 / wall.as_secs_f64(),
            allocs: self.allocs as f64 / ops as f64,
            bytes: self.bytes as f64 / ops as f64,
            cpu_us: cpu.as_secs_f64() * 1e6 / ops as f64,
        }
    }
}

struct Row {
    ops: u64,
    ops_per_sec: f64,
    allocs: f64,
    bytes: f64,
    cpu_us: f64,
}

// ---- the server (a child process) ----

struct ServerCfg {
    nodes: usize,
    get_reply: Vec<u8>,
    silent: bool,
    ports: OnceLock<Vec<u16>>,
}

impl ServerCfg {
    fn slots(&self) -> String {
        let ports = self.ports.get().expect("ports are known before the first command");
        let per = 16384 / self.nodes;
        let mut out = format!("*{}\r\n", self.nodes);
        for (i, port) in ports.iter().enumerate() {
            let (lo, hi) = (i * per, if i + 1 == self.nodes { 16383 } else { (i + 1) * per - 1 });
            let id = format!("node{i}");
            out += &format!("*3\r\n:{lo}\r\n:{hi}\r\n*3\r\n$9\r\n127.0.0.1\r\n:{port}\r\n${}\r\n{id}\r\n", id.len());
        }
        out
    }
}

struct Conn {
    parser: RespParser,
    cfg: Arc<ServerCfg>,
}

const HELLO_OK: &str = "%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n";

impl ProtocolHandler for Conn {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        let mut out = Vec::new();
        let cfg = Arc::clone(&self.cfg);
        hopf_core::with_slice(buf, |data| {
            let _ = self.parser.feed(data, &mut |v| {
                let Value::Array(words) = v else { return };
                let name = words[0].as_bytes().unwrap_or(b"");
                if name.eq_ignore_ascii_case(b"HELLO") {
                    out.extend_from_slice(HELLO_OK.as_bytes());
                } else if cfg.silent {
                    // Nothing after the handshake: a black hole.
                } else if name.eq_ignore_ascii_case(b"GET") {
                    out.extend_from_slice(&cfg.get_reply);
                } else if name.eq_ignore_ascii_case(b"PUBLISH") {
                    out.extend_from_slice(b":0\r\n");
                } else if name.eq_ignore_ascii_case(b"PING") {
                    out.extend_from_slice(b"+PONG\r\n");
                } else if name.eq_ignore_ascii_case(b"CLUSTER") {
                    if words.get(1).and_then(Value::as_bytes).is_some_and(|w| w.eq_ignore_ascii_case(b"SHARDS")) {
                        out.extend_from_slice(b"-ERR unknown subcommand 'SHARDS'\r\n");
                    } else {
                        out.extend_from_slice(cfg.slots().as_bytes());
                    }
                } else {
                    out.extend_from_slice(b"+OK\r\n");
                }
            });
        });
        if !out.is_empty() {
            endpoint.send(&out);
        }
    }
    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
}

/// `--serve <nodes> <value-size> <tls 0|1> <silent 0|1>`: listen, say where, and
/// run until stdin closes.
fn serve(args: &[String]) {
    let nodes: usize = args[0].parse().unwrap();
    let value_size: usize = args[1].parse().unwrap();
    let tls = args[2] == "1";
    let silent = args[3] == "1";
    let mut get_reply = format!("${value_size}\r\n").into_bytes();
    get_reply.extend(std::iter::repeat_n(b'v', value_size));
    get_reply.extend_from_slice(b"\r\n");
    let cfg = Arc::new(ServerCfg {
        nodes,
        get_reply,
        silent,
        ports: OnceLock::new(),
    });
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 2,
        ..Default::default()
    })
    .unwrap();
    let mut cert_hex = None;
    let acceptor = tls.then(|| {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["redis.test".to_string()]).unwrap().self_signed(&key).unwrap();
        cert_hex = Some(cert.der().iter().map(|b| format!("{b:02x}")).collect::<String>());
        let creds = hopf_core::server_credentials_from_pem_bytes(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        hopf_core::ServerTlsBuilder::new().credentials(creds).build().unwrap()
    });
    let mut ports = Vec::new();
    for _ in 0..nodes {
        let c = Arc::clone(&cfg);
        let mut listener = TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
            Box::new(Conn {
                parser: RespParser::new(),
                cfg: Arc::clone(&c),
            }) as Box<dyn ProtocolHandler>
        });
        if let Some(a) = &acceptor {
            listener = listener.with_tls(a.clone());
        }
        let (addr, _) = rt.add_tcp_listener(listener).unwrap();
        ports.push(addr.port());
    }
    cfg.ports.set(ports.clone()).unwrap();
    println!("PORTS {}", ports.iter().map(u16::to_string).collect::<Vec<_>>().join(" "));
    if let Some(hex) = cert_hex {
        println!("CERT {hex}");
    }
    std::io::stdout().flush().unwrap();
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    rt.shutdown();
}

struct RunningServer {
    child: Child,
    ports: Vec<u16>,
    cert: Option<Bytes>,
}

impl RunningServer {
    fn start(nodes: usize, value_size: usize, tls: bool, silent: bool) -> Self {
        let exe = std::env::current_exe().unwrap();
        let mut child = Process::new(exe)
            .args(["--serve", &nodes.to_string(), &value_size.to_string(), if tls { "1" } else { "0" }, if silent { "1" } else { "0" }])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the server process starts");
        let mut lines = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        lines.read_line(&mut line).unwrap();
        let ports = line.strip_prefix("PORTS ").expect("the server says where it listens").split_whitespace().map(|p| p.parse().unwrap()).collect();
        let cert = tls.then(|| {
            let mut line = String::new();
            lines.read_line(&mut line).unwrap();
            let hex = line.strip_prefix("CERT ").unwrap().trim();
            Bytes::from((0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
        });
        Self { child, ports, cert }
    }

    fn connector(&self) -> Option<SharedTlsConnector> {
        self.cert.as_ref().map(|c| ClientTlsBuilder::new().trust_anchors([c.clone()]).build())
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

// ---- the load ----

#[derive(Clone, Copy)]
enum Op {
    Get,
    Set(usize),
    Publish,
}

enum Target {
    Single(RedisClient),
    Cluster(RedisCluster),
}

impl Target {
    fn send(&self, command: &Command, callback: impl FnOnce(hopf_redis::Reply) + Send + 'static) {
        match self {
            Target::Single(c) => c.send(command, callback),
            Target::Cluster(c) => c.send(command, callback),
        }
    }
}

struct Run {
    target: Target,
    op: Op,
    keys: Vec<String>,
    value: Vec<u8>,
    total: usize,
    issued: AtomicUsize,
    done: AtomicUsize,
    errors: AtomicUsize,
    finished: mpsc::SyncSender<()>,
}

fn issue(run: &Arc<Run>) {
    let i = run.issued.fetch_add(1, Ordering::Relaxed);
    if i >= run.total {
        return;
    }
    let key = &run.keys[i % run.keys.len()];
    let command = match run.op {
        Op::Get => Command::new("GET").arg(key),
        Op::Set(_) => Command::new("SET").arg(key).arg(&run.value),
        Op::Publish => Command::new("PUBLISH").arg(key).arg("m"),
    };
    let next = Arc::clone(run);
    run.target.send(&command, move |reply| {
        if reply.is_err() {
            next.errors.fetch_add(1, Ordering::Relaxed);
        }
        if next.done.fetch_add(1, Ordering::Relaxed) + 1 == next.total {
            let _ = next.finished.try_send(());
        } else {
            issue(&next);
        }
    });
}

/// Run `total` operations with `depth` in flight, and say what the client spent.
fn drive(target: Target, op: Op, depth: usize, total: usize) -> Row {
    let (tx, rx) = mpsc::sync_channel(1);
    let run = Arc::new(Run {
        target,
        op,
        keys: (0..1024).map(|i| format!("bench:key:{i}")).collect(),
        value: match op {
            Op::Set(n) => vec![b'x'; n],
            _ => Vec::new(),
        },
        total,
        issued: AtomicUsize::new(0),
        done: AtomicUsize::new(0),
        errors: AtomicUsize::new(0),
        finished: tx,
    });
    let go = |run: &Arc<Run>, n: usize| {
        for _ in 0..depth.min(n) {
            issue(run);
        }
    };
    // Warm up: connections, layout, buffers.
    let warm = Arc::new(Run {
        total: (total / 10).clamp(100, 2000),
        issued: AtomicUsize::new(0),
        done: AtomicUsize::new(0),
        errors: AtomicUsize::new(0),
        keys: run.keys.clone(),
        value: run.value.clone(),
        op,
        target: match &run.target {
            Target::Single(c) => Target::Single(c.clone()),
            Target::Cluster(c) => Target::Cluster(c.clone()),
        },
        finished: run.finished.clone(),
    });
    go(&warm, warm.total);
    rx.recv_timeout(Duration::from_secs(60)).expect("the warm-up finished");
    assert_eq!(warm.errors.load(Ordering::Relaxed), 0, "the warm-up had errors");

    let window = Window::open();
    go(&run, total);
    rx.recv_timeout(Duration::from_secs(600)).expect("the run finished");
    let row = window.close(total as u64);
    assert_eq!(run.errors.load(Ordering::Relaxed), 0, "the run had errors");
    row
}

fn wait_ready(c: &RedisCluster) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !c.is_ready() {
        assert!(Instant::now() < deadline, "no cluster layout");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn single(server: &RunningServer, rt: &Runtime) -> Target {
    let mut config = RedisConfig::new("127.0.0.1", server.ports[0]);
    if let Some(connector) = server.connector() {
        config = config.tls(connector, "redis.test");
    }
    Target::Single(RedisClient::connect(rt.pick_worker(), config))
}

fn cluster(server: &RunningServer, rt: &Runtime) -> Target {
    let tls = server.connector();
    let mut config = ClusterConfig::new([("127.0.0.1".to_string(), server.ports[0])]).tls_server_name("redis.test");
    if let Some(connector) = tls {
        config = config.node_config(move |c| c.tls(connector, "redis.test"));
    }
    let c = RedisCluster::connect(rt.pick_worker(), config);
    wait_ready(&c);
    Target::Cluster(c)
}

// ---- scenarios ----

enum Kind {
    /// `reply` is the size of the value a `GET` returns.
    Single { op: Op, depth: usize, reply: usize },
    Cluster { op: Op, depth: usize },
    Parse { size: usize, chunk: usize },
    Timeouts { pending: usize },
}

struct Scenario {
    name: String,
    kind: Kind,
    tls: bool,
    ops: usize,
}

fn scenarios() -> Vec<Scenario> {
    let mut v = Vec::new();
    let mut add = |name: &str, kind: Kind, tls: bool, ops: usize| v.push(Scenario { name: name.into(), kind, tls, ops });
    for depth in [1, 16, 256] {
        add(&format!("single get 16B depth {depth}"), Kind::Single { op: Op::Get, depth, reply: 16 }, false, if depth == 1 { 20_000 } else { 200_000 });
    }
    add("single set 16B depth 16", Kind::Single { op: Op::Set(16), depth: 16, reply: 16 }, false, 200_000);
    add("single set 64KiB depth 16", Kind::Single { op: Op::Set(64 * 1024), depth: 16, reply: 16 }, false, 20_000);
    add("single get 64KiB depth 16", Kind::Single { op: Op::Get, depth: 16, reply: 64 * 1024 }, false, 20_000);
    for depth in [16, 256] {
        add(&format!("cluster get 16B depth {depth}"), Kind::Cluster { op: Op::Get, depth }, false, 200_000);
        add(&format!("cluster publish depth {depth}"), Kind::Cluster { op: Op::Publish, depth }, false, 200_000);
    }
    add("cluster set 64KiB depth 16", Kind::Cluster { op: Op::Set(64 * 1024), depth: 16 }, false, 20_000);
    add("tls single get 16B depth 16", Kind::Single { op: Op::Get, depth: 16, reply: 16 }, true, 100_000);
    add("tls single set 64KiB depth 16", Kind::Single { op: Op::Set(64 * 1024), depth: 16, reply: 16 }, true, 10_000);
    add("tls cluster publish depth 16", Kind::Cluster { op: Op::Publish, depth: 16 }, true, 100_000);
    for size in [1024, 64 * 1024, 1024 * 1024] {
        for chunk in [512, usize::MAX] {
            let label = if chunk == usize::MAX { "one read".to_string() } else { format!("{chunk}B reads") };
            let ops = if size >= 1024 * 1024 { 500 } else if size >= 64 * 1024 { 5_000 } else { 100_000 };
            add(&format!("parse {} reply, {label}", human(size)), Kind::Parse { size, chunk }, false, ops);
        }
    }
    for pending in [1024, 4096, 16384] {
        add(&format!("timeouts {pending} pending"), Kind::Timeouts { pending }, false, pending);
    }
    v
}

fn human(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{}MiB", n / 1024 / 1024)
    } else if n >= 1024 {
        format!("{}KiB", n / 1024)
    } else {
        format!("{n}B")
    }
}

fn parse_bench(size: usize, chunk: usize, ops: usize) -> Row {
    let mut reply = format!("${size}\r\n").into_bytes();
    reply.extend(std::iter::repeat_n(b'v', size));
    reply.extend_from_slice(b"\r\n");
    let mut parser = RespParser::new();
    let mut seen = 0usize;
    let one = |parser: &mut RespParser, seen: &mut usize| {
        for piece in reply.chunks(chunk.min(reply.len())) {
            let mut data: &[u8] = piece;
            parser.feed(&mut data, &mut |v| {
                std::hint::black_box(&v);
                *seen += 1;
            })
            .unwrap();
        }
    };
    for _ in 0..(ops / 10).max(10) {
        one(&mut parser, &mut seen);
    }
    let window = Window::open();
    for _ in 0..ops {
        one(&mut parser, &mut seen);
    }
    let row = window.close(ops as u64);
    assert!(seen >= ops);
    row
}

/// `pending` commands sent to a server that answers nothing after its handshake,
/// each with a 300 ms timeout: the time and work spent failing them all.
fn timeouts_bench(rt: &Runtime, pending: usize) -> Row {
    let server = RunningServer::start(1, 16, false, true);
    let config = RedisConfig::new("127.0.0.1", server.ports[0])
        .command_timeout(Some(Duration::from_millis(300)))
        .ping_interval(None);
    let c = RedisClient::connect(rt.pick_worker(), config);
    let (tx, rx) = mpsc::channel();
    // Let the connection come up, so every command is sent rather than waiting.
    let up = mpsc::channel();
    c.ping(move |_| {
        let _ = up.0.send(());
    });
    let _ = up.1.recv_timeout(Duration::from_secs(2)); // times out at 300 ms: the server is silent
    let window = Window::open();
    for _ in 0..pending {
        let tx = tx.clone();
        c.get("k", move |_| {
            let _ = tx.send(());
        });
    }
    for _ in 0..pending {
        rx.recv_timeout(Duration::from_secs(60)).expect("every command timed out");
    }
    let mut row = window.close(pending as u64);
    // The 300 ms every command waits is not work.
    row.ops_per_sec = pending as f64 / (pending as f64 / row.ops_per_sec - 0.3).max(1e-6);
    c.close();
    row
}

fn run(s: &Scenario, scale: f64, rt: &Runtime) -> Row {
    let ops = ((s.ops as f64 * scale) as usize).max(100);
    match &s.kind {
        Kind::Single { op, depth, reply } => {
            let server = RunningServer::start(1, *reply, s.tls, false);
            let row = drive(single(&server, rt), *op, *depth, ops);
            drop(server);
            row
        }
        Kind::Cluster { op, depth } => {
            let server = RunningServer::start(3, 16, s.tls, false);
            let row = drive(cluster(&server, rt), *op, *depth, ops);
            drop(server);
            row
        }
        Kind::Parse { size, chunk } => parse_bench(*size, *chunk, ops),
        Kind::Timeouts { pending } => timeouts_bench(rt, *pending),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--serve") {
        return serve(&args[1..]);
    }
    let mut scale = 1.0;
    let mut filters = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--scale" => scale = it.next().and_then(|s| s.parse().ok()).expect("--scale takes a number"),
            "--bench" => {}
            other if other.starts_with("--") => {}
            other => filters.push(other.to_string()),
        }
    }
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    println!("| scenario | ops | ops/s | allocs/op | bytes/op | cpu us/op |");
    println!("|---|---:|---:|---:|---:|---:|");
    for s in scenarios() {
        if !filters.is_empty() && !filters.iter().any(|f| s.name.contains(f.as_str())) {
            continue;
        }
        let row = run(&s, scale, &rt);
        println!(
            "| {} | {} | {:.0} | {:.1} | {:.0} | {:.2} |",
            s.name, row.ops, row.ops_per_sec, row.allocs, row.bytes, row.cpu_us
        );
        std::io::stdout().flush().unwrap();
    }
    rt.shutdown();
}
