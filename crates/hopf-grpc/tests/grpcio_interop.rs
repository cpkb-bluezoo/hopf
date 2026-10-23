// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Interoperability tests against grpcio, Python's C-core gRPC
//! implementation, in both directions: hopf's client against a grpcio
//! server, and a grpcio client against a hopf server. Both speak the Echo
//! service of `tests/grpcio/echo.proto` over prior-knowledge cleartext
//! HTTP/2.
//!
//! The grpcio side runs in a container built from `tests/grpcio`, with
//! podman or docker (`HOPF_CONTAINER_RUNTIME` names one explicitly). Where
//! there is no usable container runtime each test says so and passes
//! without running. Python and its packages are needed in the image only.
//!
//! Not part of the default CI job, which runs `--lib`. Run with:
//! `cargo test -p hopf-grpc --features integration --test grpcio_interop`.

#![cfg(feature = "integration")]

use std::net::SocketAddr;
use std::process::{self, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use hopf_core::{ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
use hopf_grpc::{
    ContentCoding, GrpcCall, GrpcCallHandler, GrpcCallOptions, GrpcClient, GrpcHandlerFactory,
    GrpcMetadata, GrpcResponseHandler, GrpcService, ProtoFileParser, ProtoMessageHandler,
    ProtoParseError, ScalarValue,
};
use hopf_http::{
    connect_http, CleartextHttpEndpoint, ClientHandlerFactory, DialSettings, HttpClientTimeouts,
    HttpLimits, ServerHandlerFactory,
};

const ECHO_PROTO: &str = include_str!("grpcio/echo.proto");
const HARNESS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/grpcio");
const IMAGE: &str = "hopf-grpc-grpcio-test";
const SERVICE: &str = "/hopftest.Echo/";

/// What a container sees the host as: podman defines the name itself,
/// docker needs to be told.
const HOST_NAME: &str = "host.containers.internal";

const WAIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Container runtime
// ---------------------------------------------------------------------------

/// The container runtime to use, or `None` if there is no working one.
fn container_runtime() -> Option<&'static str> {
    static RUNTIME: OnceLock<Option<String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            let candidates = match std::env::var("HOPF_CONTAINER_RUNTIME") {
                Ok(name) => vec![name],
                Err(_) => vec!["podman".to_string(), "docker".to_string()],
            };
            candidates.into_iter().find(|name| {
                Command::new(name)
                    .arg("version")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            })
        })
        .as_deref()
}

/// The runtime to use, or `None` after saying why the test is skipped.
fn runtime_or_skip() -> Option<&'static str> {
    let rt = container_runtime();
    if rt.is_none() {
        eprintln!("skipped: no working podman or docker (set HOPF_CONTAINER_RUNTIME to choose one)");
    }
    rt
}

fn run(rt: &str, args: &[&str]) -> Output {
    Command::new(rt)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{rt} {args:?}: {e}"))
}

fn run_ok(rt: &str, args: &[&str]) -> String {
    let out = run(rt, args);
    assert!(
        out.status.success(),
        "{rt} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Builds the image once per test run, however many tests need it.
fn ensure_image(rt: &str) {
    static BUILT: OnceLock<Result<(), String>> = OnceLock::new();
    let built = BUILT.get_or_init(|| {
        let out = run(rt, &["build", "-t", IMAGE, HARNESS_DIR]);
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    });
    if let Err(e) = built {
        panic!("building the {IMAGE} image with {rt} failed: {e}");
    }
}

/// A unique container name.
fn container_name() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    format!(
        "hopf-grpc-test-{}-{}",
        process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A grpcio Echo server in a container, removed when dropped.
struct GrpcioServer {
    rt: &'static str,
    name: String,
    port: u16,
}

impl GrpcioServer {
    fn start(rt: &'static str) -> Self {
        ensure_image(rt);
        let name = container_name();
        run_ok(
            rt,
            &["run", "-d", "--rm", "--name", &name, "-p", "127.0.0.1::50051", IMAGE],
        );
        // Dropping it from here on removes the container, whatever fails
        let mut server = GrpcioServer { rt, name, port: 0 };
        let mapping = run_ok(rt, &["port", &server.name, "50051/tcp"]);
        server.port = mapping
            .lines()
            .next()
            .and_then(|line| line.rsplit(':').next())
            .and_then(|port| port.trim().parse().ok())
            .unwrap_or_else(|| panic!("unexpected port mapping: {mapping:?}"));
        server.wait_ready();
        server
    }

    /// The port is mapped before the server inside listens, so ask the
    /// container itself.
    fn wait_ready(&self) {
        let probe = "import socket; socket.create_connection(('127.0.0.1', 50051), 1)";
        let start = Instant::now();
        while start.elapsed() < WAIT {
            let up = run(self.rt, &["exec", &self.name, "python3", "-c", probe])
                .status
                .success();
            if up {
                return;
            }
            thread::sleep(Duration::from_millis(200));
        }
        panic!("the grpcio server did not start in {WAIT:?}");
    }
}

impl Drop for GrpcioServer {
    fn drop(&mut self) {
        let _ = run(self.rt, &["rm", "-f", &self.name]);
    }
}

/// Runs the named scenarios of `client.py` in a container against a hopf
/// server listening on `port` of the host, and checks each one passed.
fn run_grpcio_client(rt: &str, port: u16, scenarios: &[&str]) {
    ensure_image(rt);
    let target = format!("{HOST_NAME}:{port}");
    let mut args = vec!["run", "--rm"];
    if rt == "docker" {
        args.extend(["--add-host", "host.containers.internal:host-gateway"]);
    }
    args.extend([IMAGE, "timeout", "120", "python3", "client.py", &target]);
    args.extend(scenarios);
    let out = run(rt, &args);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    for scenario in scenarios {
        assert!(
            stdout.lines().any(|line| line == format!("ok {scenario}")),
            "scenario {scenario} did not pass:\n{stdout}\n{stderr}"
        );
    }
    assert!(
        out.status.success(),
        "the client failed ({}):\n{stdout}\n{stderr}",
        out.status
    );
}

// ---------------------------------------------------------------------------
// The hopf server
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Method {
    SayEcho,
    AlwaysFail,
    Watch,
    Collect,
    Chat,
    Metadata,
    Compressed,
    Slow,
    Deadline,
}

impl Method {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "SayEcho" => Method::SayEcho,
            "AlwaysFail" => Method::AlwaysFail,
            "Watch" => Method::Watch,
            "Collect" => Method::Collect,
            "Chat" => Method::Chat,
            "Metadata" => Method::Metadata,
            "Compressed" => Method::Compressed,
            "Slow" => Method::Slow,
            "Deadline" => Method::Deadline,
            _ => return None,
        })
    }
}

/// What the hopf server saw that the client cannot tell.
#[derive(Default)]
struct Observed {
    slow_calls_cancelled: AtomicUsize,
}

struct EchoService {
    observed: Arc<Observed>,
}

impl GrpcService for EchoService {
    fn streaming_supported(&self) -> bool {
        true
    }

    fn start_call(&self, path: &str, call: GrpcCall) -> Option<Box<dyn GrpcCallHandler>> {
        let method = Method::from_name(path.strip_prefix(SERVICE)?)?;
        Some(Box::new(EchoHandler {
            call,
            method,
            message: String::new(),
            repeat_count: 0,
            reason: String::new(),
            collected: String::new(),
            cancelled: Arc::new(AtomicBool::new(false)),
            observed: Arc::clone(&self.observed),
        }))
    }
}

struct EchoHandler {
    call: GrpcCall,
    method: Method,
    /// The fields of the request message being received.
    message: String,
    repeat_count: i32,
    reason: String,
    /// What `Collect` has so far.
    collected: String,
    cancelled: Arc<AtomicBool>,
    observed: Arc<Observed>,
}

/// Sends an `EchoResponse`.
fn reply(call: &GrpcCall, message: &str, length: i32) -> Result<(), ProtoParseError> {
    let mut response = call.open_message(None).map_err(ProtoParseError::new)?;
    response
        .field("message", ScalarValue::String(message.to_string()))
        .map_err(ProtoParseError::new)?;
    response
        .field("length", ScalarValue::I32(length))
        .map_err(ProtoParseError::new)?;
    response.complete().map_err(ProtoParseError::new)
}

fn reply_text(call: &GrpcCall, text: &str) -> Result<(), ProtoParseError> {
    reply(call, text, text.chars().count() as i32)
}

impl ProtoMessageHandler for EchoHandler {
    fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
        self.message.clear();
        self.repeat_count = 0;
        self.reason.clear();
        Ok(())
    }

    fn end_message(&mut self) -> Result<(), ProtoParseError> {
        let repeat = self.repeat_count.max(1) as usize;
        match self.method {
            Method::SayEcho => reply_text(&self.call, &self.message.repeat(repeat)),
            Method::AlwaysFail => {
                self.call
                    .send_error(3, &format!("always fails: {}", self.reason));
                Ok(())
            }
            Method::Watch => {
                if self.message == "fail" {
                    reply_text(&self.call, "first")?;
                    self.call.close_with(5, "gone");
                } else {
                    for i in 1..=repeat {
                        reply_text(&self.call, &format!("{}{i}", self.message))?;
                    }
                    self.call.close();
                }
                Ok(())
            }
            Method::Collect => {
                self.collected.push_str(&self.message);
                Ok(())
            }
            Method::Chat => reply_text(&self.call, &format!("re {}", self.message)),
            Method::Metadata => {
                let request = self.call.request_metadata();
                let value = request.get("x-test").unwrap_or("").to_string();
                let binary = request.get_binary("x-test-bin");
                self.call.with_response_metadata(|m| {
                    m.add("x-echo", &value).unwrap();
                    if let Some(binary) = &binary {
                        m.add_binary("x-echo-bin", binary).unwrap();
                    }
                });
                self.call
                    .with_trailing_metadata(|m| m.add("x-trailer", "done").unwrap());
                reply_text(&self.call, &value)
            }
            Method::Compressed => {
                let count = self.repeat_count.max(0);
                reply(&self.call, &"a".repeat(count as usize), count)
            }
            Method::Slow => {
                let call = self.call.clone();
                let cancelled = Arc::clone(&self.cancelled);
                thread::spawn(move || {
                    let end = Instant::now() + Duration::from_secs(3);
                    let live = || call.is_open() && !cancelled.load(Ordering::SeqCst);
                    while Instant::now() < end && live() {
                        thread::sleep(Duration::from_millis(50));
                    }
                    if live() {
                        let _ = reply_text(&call, "slow");
                    }
                });
                Ok(())
            }
            Method::Deadline => {
                let millis = match self.call.deadline() {
                    None => -1,
                    Some(deadline) => deadline
                        .duration_since(SystemTime::now())
                        .map(|left| left.as_millis() as i32)
                        .unwrap_or(0),
                };
                reply(&self.call, "deadline", millis)
            }
        }
    }

    fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
        match (name, value) {
            ("message", ScalarValue::String(s)) => self.message = s,
            ("reason", ScalarValue::String(s)) => self.reason = s,
            ("repeat_count", ScalarValue::I32(n)) => self.repeat_count = n,
            _ => {}
        }
        Ok(())
    }

    fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
        Ok(())
    }

    fn end_field(&mut self) -> Result<(), ProtoParseError> {
        Ok(())
    }
}

impl GrpcCallHandler for EchoHandler {
    fn end_requests(&mut self) {
        match self.method {
            Method::Collect => {
                let _ = reply_text(&self.call, &self.collected);
            }
            Method::Chat => self.call.close(),
            _ => {}
        }
    }

    fn cancelled(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if self.method == Method::Slow {
            self.observed.slow_calls_cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A hopf gRPC server on every interface, so a container can reach it.
struct HopfServer {
    /// Held so the server keeps running for the test.
    _rt: Arc<Runtime>,
    addr: SocketAddr,
    observed: Arc<Observed>,
}

impl HopfServer {
    /// `encodings` are the compression algorithms the server offers.
    fn start(encodings: &[ContentCoding]) -> Self {
        let observed = Arc::new(Observed::default());
        let proto = ProtoFileParser::parse(ECHO_PROTO).unwrap();
        let service = Arc::new(EchoService { observed: Arc::clone(&observed) });
        let factory: Arc<dyn ServerHandlerFactory> =
            Arc::new(GrpcHandlerFactory::new(proto, service).encodings(encodings));
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "0.0.0.0:0".parse().unwrap(),
                move || {
                    Box::new(CleartextHttpEndpoint::new(
                        Arc::clone(&factory),
                        HttpLimits::default(),
                    )) as Box<dyn ProtocolHandler>
                },
            ))
            .unwrap();
        HopfServer { _rt: rt, addr, observed }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < WAIT, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// The grpcio client against the hopf server
// ---------------------------------------------------------------------------

const CALLS: &[&str] = &[
    "unary",
    "unary-empty-messages",
    "unary-error",
    "server-streaming",
    "server-streaming-error",
    "client-streaming",
    "client-streaming-empty",
    "bidirectional",
    "bidirectional-empty-messages",
    "metadata",
    "deadline",
    "deadline-propagated",
    "cancellation",
];

/// Every kind of RPC, metadata including `-bin`, `grpc-timeout`, empty
/// messages and an error status, called by grpcio.
#[test]
fn grpcio_client_calls_hopf_server() {
    let Some(rt) = runtime_or_skip() else { return };
    let server = HopfServer::start(&[ContentCoding::Gzip, ContentCoding::Deflate]);
    run_grpcio_client(rt, server.port(), CALLS);

    // The deadline expired and the call was cancelled: the server's
    // handlers heard of both
    wait_until("the cancelled Slow calls", || {
        server.observed.slow_calls_cancelled.load(Ordering::SeqCst) >= 2
    });
}

/// grpcio compresses requests with gzip and deflate, and the server
/// decodes them, refuses one that expands past the limit, and compresses
/// the response with gzip, the first of its algorithms the client accepts.
#[test]
fn grpcio_client_compression_with_gzip_preferred() {
    let Some(rt) = runtime_or_skip() else { return };
    let server = HopfServer::start(&[ContentCoding::Gzip, ContentCoding::Deflate]);
    run_grpcio_client(
        rt,
        server.port(),
        &[
            "gzip-request",
            "deflate-request",
            "compressed-response",
            "compressed-request-beyond-the-limit",
        ],
    );
}

/// A server that offers deflate only compresses its responses with deflate.
#[test]
fn grpcio_client_compression_with_deflate_only() {
    let Some(rt) = runtime_or_skip() else { return };
    let server = HopfServer::start(&[ContentCoding::Deflate]);
    run_grpcio_client(
        rt,
        server.port(),
        &["deflate-request", "compressed-response"],
    );
}

// ---------------------------------------------------------------------------
// The hopf client against the grpcio server
// ---------------------------------------------------------------------------

/// A decoded `EchoResponse`.
#[derive(Debug, Default, Clone, PartialEq)]
struct Echo {
    message: String,
    length: i32,
}

/// Everything a call delivered.
#[derive(Default)]
struct Outcome {
    messages: Vec<Echo>,
    errors: Vec<String>,
    initial: Option<GrpcMetadata>,
    trailing: Option<GrpcMetadata>,
    status: Option<(i32, String)>,
}

#[derive(Clone, Default)]
struct Shared(Arc<(Mutex<Outcome>, Condvar)>);

impl Shared {
    fn update(&self, f: impl FnOnce(&mut Outcome)) {
        let (lock, cond) = &*self.0;
        f(&mut lock.lock().unwrap());
        cond.notify_all();
    }

    /// Blocks until `done` holds of what has arrived so far.
    fn wait_for(&self, what: &str, done: impl Fn(&Outcome) -> bool) {
        let (lock, cond) = &*self.0;
        let start = Instant::now();
        let mut outcome = lock.lock().unwrap();
        while !done(&outcome) {
            let left = WAIT
                .checked_sub(start.elapsed())
                .unwrap_or_else(|| panic!("timed out waiting for {what}"));
            outcome = cond.wait_timeout(outcome, left).unwrap().0;
        }
    }

    /// Blocks until the call is over, then returns what it delivered.
    fn finish(&self) -> Outcome {
        self.wait_for("the call to complete", |o| o.status.is_some());
        std::mem::take(&mut *self.0 .0.lock().unwrap())
    }
}

struct Recorder(Shared);

impl GrpcResponseHandler for Recorder {
    fn start_message(&mut self, _type_name: Option<&str>) -> Option<Box<dyn ProtoMessageHandler>> {
        Some(Box::new(EchoDecoder { shared: self.0.clone(), echo: Echo::default() }))
    }

    fn on_error(&mut self, error: &str) {
        self.0.update(|o| o.errors.push(error.to_string()));
    }

    fn on_complete(&mut self, status: i32, message: &str) {
        self.0.update(|o| o.status = Some((status, message.to_string())));
    }

    fn on_initial_metadata(&mut self, metadata: &GrpcMetadata) {
        self.0.update(|o| o.initial = Some(metadata.clone()));
    }

    fn on_trailing_metadata(&mut self, metadata: &GrpcMetadata) {
        self.0.update(|o| o.trailing = Some(metadata.clone()));
    }
}

struct EchoDecoder {
    shared: Shared,
    echo: Echo,
}

impl ProtoMessageHandler for EchoDecoder {
    fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
        self.echo = Echo::default();
        Ok(())
    }

    fn end_message(&mut self) -> Result<(), ProtoParseError> {
        let echo = self.echo.clone();
        self.shared.update(|o| o.messages.push(echo));
        Ok(())
    }

    fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
        match (name, value) {
            ("message", ScalarValue::String(s)) => self.echo.message = s,
            ("length", ScalarValue::I32(n)) => self.echo.length = n,
            _ => {}
        }
        Ok(())
    }

    fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
        Ok(())
    }

    fn end_field(&mut self) -> Result<(), ProtoParseError> {
        Ok(())
    }
}

fn varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push((n as u8 & 0x7F) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// A wire-encoded `EchoRequest`, which is also a `FailRequest` when it
/// has a message only. Default values are left out, as protobuf does, so
/// the empty message is a zero-length frame.
fn echo_request(message: &str, repeat_count: u32) -> Vec<u8> {
    let mut out = Vec::new();
    if !message.is_empty() {
        out.push(0x0A);
        varint(message.len() as u64, &mut out);
        out.extend_from_slice(message.as_bytes());
    }
    if repeat_count != 0 {
        out.push(0x10);
        varint(u64::from(repeat_count), &mut out);
    }
    out
}

/// The hopf client side of a test: a runtime, a grpcio server to call and
/// a client for the Echo service.
struct ClientFixture {
    rt: Arc<Runtime>,
    server: GrpcioServer,
}

impl ClientFixture {
    fn start() -> Option<Self> {
        let rt = runtime_or_skip()?;
        let server = GrpcioServer::start(rt);
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        Some(ClientFixture { rt, server })
    }

    fn client(&self) -> GrpcClient {
        GrpcClient::new(ProtoFileParser::parse(ECHO_PROTO).unwrap())
            .authority(format!("127.0.0.1:{}", self.server.port))
    }

    fn dial(&self, factory: impl ClientHandlerFactory + 'static) {
        connect_http(
            &self.rt,
            "127.0.0.1",
            self.server.port,
            Arc::new(factory),
            true,
            DialSettings {
                limits: HttpLimits::default(),
                timeouts: HttpClientTimeouts::default(),
                resolver: None,
            },
        )
        .unwrap();
    }

    fn unary(
        &self,
        client: &GrpcClient,
        method: &str,
        request: Vec<u8>,
        options: GrpcCallOptions,
    ) -> Outcome {
        let shared = Shared::default();
        let call = client.unary_call_with_options(
            format!("{SERVICE}{method}"),
            request,
            Box::new(Recorder(shared.clone())),
            options,
        );
        self.dial(call);
        shared.finish()
    }

    /// Starts a streaming call; the caller sends its messages.
    fn streaming(&self, method: &str) -> (Shared, hopf_grpc::GrpcClientCall) {
        let shared = Shared::default();
        let (factory, call) = self
            .client()
            .streaming_call(format!("{SERVICE}{method}"), Box::new(Recorder(shared.clone())));
        self.dial(factory);
        (shared, call)
    }
}

macro_rules! fixture {
    () => {
        match ClientFixture::start() {
            Some(fixture) => fixture,
            None => return,
        }
    };
}

fn texts(outcome: &Outcome) -> Vec<&str> {
    outcome.messages.iter().map(|m| m.message.as_str()).collect()
}

fn assert_ok(outcome: &Outcome) {
    assert_eq!(outcome.status, Some((0, String::new())), "call status");
    assert!(outcome.errors.is_empty(), "errors: {:?}", outcome.errors);
}

#[test]
fn hopf_client_unary() {
    let f = fixture!();
    let out = f.unary(&f.client(), "SayEcho", echo_request("ab", 3), GrpcCallOptions::new());
    assert_ok(&out);
    assert_eq!(out.messages, vec![Echo { message: "ababab".into(), length: 6 }]);
}

#[test]
fn hopf_client_unary_empty_messages() {
    let f = fixture!();
    let out = f.unary(&f.client(), "SayEcho", echo_request("", 0), GrpcCallOptions::new());
    assert_ok(&out);
    assert_eq!(out.messages, vec![Echo::default()]);
}

#[test]
fn hopf_client_unary_error() {
    let f = fixture!();
    let out = f.unary(&f.client(), "AlwaysFail", echo_request("because", 0), GrpcCallOptions::new());
    assert_eq!(out.status, Some((3, "always fails: because".to_string())));
    assert!(out.messages.is_empty());
}

#[test]
fn hopf_client_server_streaming() {
    let f = fixture!();
    let (shared, call) = f.streaming("Watch");
    call.send(&echo_request("x", 3));
    call.half_close();
    let out = shared.finish();
    assert_ok(&out);
    assert_eq!(texts(&out), ["x1", "x2", "x3"]);
}

#[test]
fn hopf_client_server_streaming_error() {
    let f = fixture!();
    let (shared, call) = f.streaming("Watch");
    call.send(&echo_request("fail", 0));
    call.half_close();
    let out = shared.finish();
    assert_eq!(out.status, Some((5, "gone".to_string())));
    assert_eq!(texts(&out), ["first"]);
}

#[test]
fn hopf_client_client_streaming() {
    let f = fixture!();
    let (shared, call) = f.streaming("Collect");
    for m in ["a", "b", "c"] {
        call.send(&echo_request(m, 0));
    }
    call.half_close();
    let out = shared.finish();
    assert_ok(&out);
    assert_eq!(texts(&out), ["abc"]);
}

#[test]
fn hopf_client_client_streaming_empty() {
    let f = fixture!();
    let (shared, call) = f.streaming("Collect");
    call.half_close();
    let out = shared.finish();
    assert_ok(&out);
    assert_eq!(out.messages, vec![Echo::default()]);
}

/// Each request is answered before the next is sent: the two directions
/// really are open at the same time.
#[test]
fn hopf_client_bidirectional() {
    let f = fixture!();
    let (shared, call) = f.streaming("Chat");
    for (i, m) in ["a", "b", "c"].into_iter().enumerate() {
        call.send(&echo_request(m, 0));
        shared.wait_for("the reply", |o| o.messages.len() > i);
    }
    call.half_close();
    let out = shared.finish();
    assert_ok(&out);
    assert_eq!(texts(&out), ["re a", "re b", "re c"]);
}

#[test]
fn hopf_client_bidirectional_empty_messages() {
    let f = fixture!();
    let (shared, call) = f.streaming("Chat");
    for _ in 0..3 {
        call.send(&echo_request("", 0));
    }
    call.half_close();
    let out = shared.finish();
    assert_ok(&out);
    assert_eq!(texts(&out), ["re ", "re ", "re "]);
}

/// ASCII and `-bin` metadata go out with the request, and come back in the
/// initial and the trailing metadata.
#[test]
fn hopf_client_metadata() {
    let f = fixture!();
    let mut options = GrpcCallOptions::new();
    options.metadata_mut().add("x-test", "hello").unwrap();
    options
        .metadata_mut()
        .add_binary("x-test-bin", &[0x00, 0x01, 0x02, 0xFF])
        .unwrap();
    let out = f.unary(&f.client(), "Metadata", echo_request("m", 0), options);
    assert_ok(&out);
    assert_eq!(texts(&out), ["hello"]);
    let initial = out.initial.expect("initial metadata");
    assert_eq!(initial.get("x-echo"), Some("hello"));
    assert_eq!(initial.get_binary("x-echo-bin"), Some(vec![0x00, 0x01, 0x02, 0xFF]));
    let trailing = out.trailing.expect("trailing metadata");
    assert_eq!(trailing.get("x-trailer"), Some("done"));
}

/// A call that outlives its deadline ends `DEADLINE_EXCEEDED` (4) at the
/// deadline, not when the three-second server finally answers.
#[test]
fn hopf_client_deadline() {
    let f = fixture!();
    let start = Instant::now();
    let options = GrpcCallOptions::new().timeout(Duration::from_millis(500));
    let out = f.unary(&f.client(), "Slow", echo_request("s", 0), options);
    assert_eq!(out.status.map(|s| s.0), Some(4));
    assert!(start.elapsed() < Duration::from_millis(2500), "took {:?}", start.elapsed());
}

/// The deadline reaches the server as `grpc-timeout`.
#[test]
fn hopf_client_deadline_propagated() {
    let f = fixture!();
    let options = GrpcCallOptions::new().timeout(Duration::from_secs(20));
    let out = f.unary(&f.client(), "Deadline", echo_request("", 0), options);
    assert_ok(&out);
    let left = out.messages[0].length;
    assert!((1..=20_000).contains(&left), "{left} ms left");

    let out = f.unary(&f.client(), "Deadline", echo_request("", 0), GrpcCallOptions::new());
    assert_ok(&out);
    assert_eq!(out.messages[0].length, -1);
}

/// Requests compressed with gzip and deflate are decoded by grpcio.
#[test]
fn hopf_client_compressed_requests() {
    let f = fixture!();
    let text = "a".repeat(3000);
    for coding in [ContentCoding::Gzip, ContentCoding::Deflate] {
        let client = f.client().compression(coding);
        let out = f.unary(&client, "SayEcho", echo_request(&text, 0), GrpcCallOptions::new());
        assert_ok(&out);
        assert_eq!(out.messages, vec![Echo { message: text.clone(), length: 3000 }], "{coding:?}");
    }
}

/// Responses compressed by grpcio with gzip and deflate are decoded.
#[test]
fn hopf_client_compressed_responses() {
    let f = fixture!();
    for coding in ["gzip", "deflate"] {
        let out = f.unary(
            &f.client(),
            "Compressed",
            echo_request(coding, 3000),
            GrpcCallOptions::new(),
        );
        assert_ok(&out);
        assert_eq!(
            out.messages,
            vec![Echo { message: "a".repeat(3000), length: 3000 }],
            "{coding}"
        );
    }
}
