// Copyright (C) 2026 Chris Burdess <dog@gnu.org>
//
// quic-interop-runner endpoint for hopf (hq-interop + HTTP/3).

mod env;
mod testcase;

use std::fs::{self, File};
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hopf_core::tls::{CHACHA20_POLY1305_SHA256, KeyLogFile};
use hopf_core::Bytes;
use hopf_core::{Endpoint, HandlerFactory, ProtocolHandler, Runtime, RuntimeConfig};
use hopf_http::{
    connect_h3_by_name, listen_h3, ClientHandler, ClientHandlerFactory, Headers, HttpLimits,
    ServerHandler, ServerHandlerFactory, ServerWriter,
};
use hopf_quic::{
    apply_server_transport_options, client_config_from_pem_with, connect_quic, hopf_server_config,
    listen_quic, server_config_from_pem_with, HopfTlsBuildParams, QuicConnectConfig,
    QuicListenConfig, QuicListenHardening, QuicTlsOptions, QuicTransportOptions, QuicVersion,
};

use crate::env::InteropEnv;
use crate::testcase::{TestCase, EXIT_UNSUPPORTED};

const ALPN_HQ: &[u8] = b"hq-interop";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(90);

fn main() {
    if let Err(e) = run() {
        eprintln!("hopf interop: {e}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let interop = InteropEnv::from_env();
    let Some(case) = TestCase::from_wire(&interop.test_case) else {
        eprintln!("hopf interop: unknown test case: {}", interop.test_case);
        std::process::exit(EXIT_UNSUPPORTED);
    };
    env::enable_key_log();
    let _qlog = env::enable_qlog_pipeline();

    match interop.role.as_str() {
        "server" => {
            if !case.server_supported() {
                eprintln!("hopf interop server: unsupported test case: {}", interop.test_case);
                std::process::exit(EXIT_UNSUPPORTED);
            }
            if case == TestCase::Http3 {
                run_h3_server(&interop)?;
            } else {
                run_hq_server(&interop, case)?;
            }
        }
        "client" => {
            if !case.client_supported() {
                eprintln!("hopf interop client: unsupported test case: {}", interop.test_case);
                std::process::exit(EXIT_UNSUPPORTED);
            }
            fs::create_dir_all(&interop.downloads)?;
            let ok = if case == TestCase::Http3 {
                run_h3_client(&interop, case)?
            } else {
                run_hq_client(&interop, case)?
            };
            std::process::exit(if ok { 0 } else { 1 });
        }
        other => {
            eprintln!("hopf interop: unknown ROLE={other}");
            std::process::exit(1);
        }
    }
    Ok(())
}

fn bind_wildcard(port: u16) -> io::Result<SocketAddr> {
    use std::net::UdpSocket;
    let v6: SocketAddr = format!("[::]:{port}").parse().unwrap();
    if let Ok(sock) = UdpSocket::bind(v6) {
        return sock.local_addr();
    }
    UdpSocket::bind(format!("0.0.0.0:{port}"))?.local_addr()
}

fn build_server(
    interop: &InteropEnv,
    case: TestCase,
) -> io::Result<Arc<hopf_quic::QuicServerConfig>> {
    let mut tls = QuicTlsOptions::default();
    if case == TestCase::Zerortt {
        tls = tls.with_early_data();
    }
    let mut params = HopfTlsBuildParams::server(
        load_server_creds(interop)?,
        vec![Bytes::from_static(ALPN_HQ)],
    )
    .with_tls(tls);
    if case == TestCase::Chacha20 {
        params = params.with_cipher_suites(vec![CHACHA20_POLY1305_SHA256]);
    }
    if case == TestCase::Transfer {
        params = params.without_certificate_compression();
    }
    if let Ok(Some(log)) = KeyLogFile::from_environment() {
        params = params.with_key_log(Some(log));
    }
    let mut server = hopf_server_config(params);
    let versions = match case {
        TestCase::V2 => vec![QuicVersion::V2, QuicVersion::V1],
        _ => vec![QuicVersion::V1, QuicVersion::V2],
    };
    Arc::make_mut(&mut server).versions(&versions);
    if case == TestCase::Transfer {
        apply_server_transport_options(
            &mut server,
            &QuicTransportOptions::new()
                .receive_window(1024 * 1024)
                .stream_receive_window(256 * 1024),
        )?;
    }
    Ok(server)
}

fn build_client(
    interop: &InteropEnv,
    case: TestCase,
) -> io::Result<Arc<hopf_quic::QuicClientConfig>> {
    let mut tls = QuicTlsOptions::default();
    if case == TestCase::Zerortt {
        tls = tls.with_early_data();
    }
    if case == TestCase::Transfer || case == TestCase::Multiconnect {
        tls = tls.with_kx_policy(hopf_core::crypto::kx_policy::KxPolicy::classical_only());
    }
    let certs = fs::read(interop.ca_file())?;
    let anchors = hopf_core::pem::parse_certs(&certs);
    let mut trust = hopf_core::crypto::trust::TrustStore::new();
    for c in anchors {
        trust.add_anchor(Bytes::from(c));
    }
    let params = HopfTlsBuildParams {
        alpn: vec![Bytes::from_static(ALPN_HQ)],
        kx_policy: tls.kx_policy.clone(),
        server_name: None,
        trust_store: Some(trust),
        server: None,
        local_transport_parameters: None,
        tls,
        ticket_store: Some(hopf_core::tls::ClientTicketStore::shared()),
        ticket_key: None,
        anti_replay: None,
        key_log: KeyLogFile::from_environment()
            .ok()
            .flatten()
            .map(|k| k as Arc<dyn hopf_core::tls::KeyLog>),
        cipher_suites: if case == TestCase::Chacha20 {
            Some(vec![CHACHA20_POLY1305_SHA256])
        } else {
            None
        },
        certificate_compression: true,
    };
    let mut client = hopf_quic::hopf_client_config(params);
    let versions = match case {
        TestCase::V2 => vec![QuicVersion::V1, QuicVersion::V2],
        _ => vec![QuicVersion::V1, QuicVersion::V2],
    };
    Arc::make_mut(&mut client).versions(&versions);
    Ok(client)
}

fn listen_hardening(case: TestCase) -> QuicListenHardening {
    let mut h = QuicListenHardening::permissive();
    if case == TestCase::Retry {
        h = h.require_address_validation(true);
    }
    if case == TestCase::ConnectionMigration {
        h = h.migration(true);
    }
    h
}

fn run_hq_server(interop: &InteropEnv, case: TestCase) -> io::Result<()> {
    let www = Arc::new(interop.www.clone());
    let factory: HandlerFactory = Arc::new({
        let www = Arc::clone(&www);
        move || Box::new(HqServerStream::new(Arc::clone(&www))) as Box<dyn ProtocolHandler>
    });
    let server = build_server(interop, case)?;
    let addr = bind_wildcard(interop.port)?;
    eprintln!("hopf interop server listening on {addr} case {}", interop.test_case);
    let cfg = QuicListenConfig::new(addr, server, factory).with_hardening(listen_hardening(case));
    let handle = listen_quic(cfg)?;
    loop {
        thread::sleep(Duration::from_secs(3600));
        if !handle.is_active() {
            break;
        }
    }
    Ok(())
}

fn run_h3_server(interop: &InteropEnv) -> io::Result<()> {
    let server = server_config_from_pem_with(
        &interop.cert_file(),
        &interop.key_file(),
        &[hopf_quic::ALPN_H3],
        QuicTlsOptions::default(),
    )?;
    let www = interop.www.clone();
    let factory: Arc<dyn ServerHandlerFactory> = Arc::new(WwwFactory { www });
    let addr = bind_wildcard(interop.port)?;
    eprintln!("hopf interop HTTP/3 server on {addr}");
    let _handle = listen_h3(addr, server, factory, HttpLimits::default())?;
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

struct WwwFactory {
    www: PathBuf,
}

impl ServerHandlerFactory for WwwFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(WwwHandler {
            www: self.www.clone(),
            path: None,
        })
    }
}

struct WwwHandler {
    www: PathBuf,
    path: Option<PathBuf>,
}

impl ServerHandler for WwwHandler {
    fn headers(&mut self, _response: &mut dyn ServerWriter, headers: &Headers) {
        if let Some(p) = headers.path() {
            self.path = resolve_www(&self.www, p);
        }
    }

    fn request_body_content(&mut self, _response: &mut dyn ServerWriter, _chunk: &[u8]) {}

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        let Some(file) = self.path.take().and_then(|p| fs::read(&p).ok()) else {
            let mut h = Headers::new();
            h.status(404);
            response.headers(h);
            response.complete();
            return;
        };
        let mut h = Headers::new();
        h.status(200);
        h.set("Content-Length", file.len().to_string());
        response.headers(h);
        response.start_response_body();
        response.response_body_content(&file);
        response.end_response_body();
        response.complete();
    }
}

fn run_hq_client(interop: &InteropEnv, case: TestCase) -> io::Result<bool> {
    await_simulator();
    let urls = parse_requests(&interop.requests)?;
    if urls.is_empty() {
        return Ok(true);
    }
    if case == TestCase::Multiconnect {
        let mut ok = true;
        for url in urls {
            if !download_hq_batch(interop, case, &[url])? {
                ok = false;
            }
        }
        return Ok(ok);
    }
    if case == TestCase::Resumption || case == TestCase::Zerortt {
        let (first, rest) = urls.split_first().unwrap();
        if !download_hq_batch(interop, case, std::slice::from_ref(first))? {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(200));
        return download_hq_batch(interop, case, rest);
    }
    download_hq_batch(interop, case, &urls)
}

fn download_hq_batch(interop: &InteropEnv, case: TestCase, urls: &[RequestUrl]) -> io::Result<bool> {
    let client = build_client(interop, case)?;
    let tracker = Arc::new(Mutex::new(DownloadTracker::new(urls.len())));
    let first = &urls[0];
    let addr = format!("{}:{}", first.host, first.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "could not resolve server"))?;
    let server_name = first.host.clone();
    let pending = Arc::new(Mutex::new(urls.to_vec()));
    let downloads = interop.downloads.clone();
    let pending2 = Arc::clone(&pending);
    let tracker2 = Arc::clone(&tracker);
    let factory: HandlerFactory = Arc::new(move || {
        Box::new(HqClientStream {
            pending: Arc::clone(&pending2),
            tracker: Arc::clone(&tracker2),
            downloads: downloads.clone(),
            state: ClientStreamState::NeedRequest,
        }) as Box<dyn ProtocolHandler>
    });
    let handle = connect_quic(QuicConnectConfig::new(addr, client, server_name, factory))?;
    for _ in urls.iter().skip(1) {
        let pending3 = Arc::clone(&pending);
        let tracker3 = Arc::clone(&tracker);
        let downloads = interop.downloads.clone();
        handle.open_bi(Arc::new(move || {
            Box::new(HqClientStream {
                pending: Arc::clone(&pending3),
                tracker: Arc::clone(&tracker3),
                downloads: downloads.clone(),
                state: ClientStreamState::NeedRequest,
            }) as Box<dyn ProtocolHandler>
        }))?;
    }
    let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if tracker.lock().unwrap().done() {
            handle.shutdown();
            return Ok(tracker.lock().unwrap().success());
        }
        thread::sleep(Duration::from_millis(20));
    }
    handle.shutdown();
    Ok(false)
}

fn run_h3_client(interop: &InteropEnv, case: TestCase) -> io::Result<bool> {
    await_simulator();
    let urls = parse_requests(&interop.requests)?;
    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let mut tls = QuicTlsOptions::default();
    if case == TestCase::Zerortt {
        tls = tls.with_early_data();
    }
    let client = client_config_from_pem_with(&interop.ca_file(), &[hopf_quic::ALPN_H3], tls)?;
    let mut ok = true;
    for url in urls {
        let dest = interop.downloads.join(&url.file_name);
        let tracker = Arc::new(Mutex::new(Vec::new()));
        let got = Arc::clone(&tracker);
        let factory: Arc<dyn ClientHandlerFactory> = Arc::new(H3SaveFactory {
            body: got,
        });
        connect_h3_by_name(
            &rt,
            &url.host,
            url.port,
            client.clone(),
            Some(url.host.clone()),
            factory,
            hopf_http::H3DialSettings {
                limits: HttpLimits::default(),
                resolver: None,
            },
        )?;
        let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
        while std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
            let body = tracker.lock().unwrap().clone();
            if !body.is_empty() {
                fs::write(&dest, &body)?;
                break;
            }
        }
        if !dest.is_file() {
            ok = false;
        }
    }
    Ok(ok)
}

struct H3SaveFactory {
    body: Arc<Mutex<Vec<u8>>>,
}

impl ClientHandlerFactory for H3SaveFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(H3SaveHandler {
            body: Arc::clone(&self.body),
        })
    }
}

struct H3SaveHandler {
    body: Arc<Mutex<Vec<u8>>>,
}

impl ClientHandler for H3SaveHandler {
    fn start(&mut self, _request: &mut dyn hopf_http::ClientWriter) {}

    fn response_headers(&mut self, _request: &mut dyn hopf_http::ClientWriter, _headers: &Headers) {}

    fn response_body_content(&mut self, _request: &mut dyn hopf_http::ClientWriter, data: &[u8]) {
        self.body.lock().unwrap().extend_from_slice(data);
    }

    fn response_complete(&mut self, _request: &mut dyn hopf_http::ClientWriter) {}
}

fn await_simulator() {
    let Some(target) = std::env::var("INTEROP_WAIT_FOR").ok().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some((host, port)) = target.rsplit_once(':') else {
        return;
    };
    let port: u16 = port.parse().unwrap_or(57832);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect((host, port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestUrl {
    host: String,
    port: u16,
    path: String,
    file_name: String,
}

fn parse_requests(raw: &[String]) -> io::Result<Vec<RequestUrl>> {
    raw.iter().map(|u| parse_url(u)).collect()
}

fn parse_url(raw: &str) -> io::Result<RequestUrl> {
    let url = url::Url::parse(raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let host = url.host_str().unwrap_or("server").to_string();
    let port = url.port().unwrap_or(443);
    let path = url.path().to_string();
    let file_name = Path::new(path.trim_start_matches('/'))
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download")
        .to_string();
    Ok(RequestUrl {
        host,
        port,
        path,
        file_name,
    })
}

fn load_server_creds(interop: &InteropEnv) -> io::Result<hopf_core::tls::ServerCredentials> {
    let certs = hopf_core::pem::parse_certs(&fs::read(interop.cert_file())?);
    let mut keys = hopf_core::pem::parse_pkcs8_keys(&fs::read(interop.key_file())?);
    let Some(key) = keys.pop() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no private key"));
    };
    Ok(hopf_core::tls::ServerCredentials {
        cert_chain: certs.into_iter().map(Bytes::from).collect(),
        signing_key_pkcs8: Bytes::from(key),
    })
}

fn resolve_www(www: &Path, target: &str) -> Option<PathBuf> {
    let path = Path::new(target.trim_start_matches('/'));
    let mut out = www.to_path_buf();
    for c in path.components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    if out.starts_with(www) && out.is_file() {
        Some(out)
    } else {
        None
    }
}

struct HqServerStream {
    www: Arc<PathBuf>,
    buf: Vec<u8>,
    sent: bool,
}

impl HqServerStream {
    fn new(www: Arc<PathBuf>) -> Self {
        Self {
            www,
            buf: Vec::new(),
            sent: false,
        }
    }
}

impl ProtocolHandler for HqServerStream {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        if self.sent {
            return;
        }
        if let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&self.buf[..pos]).to_string();
            self.buf.clear();
            let path = line.strip_prefix("GET ").and_then(|s| s.split_whitespace().next());
            if let Some(p) = path {
                if let Some(file) = resolve_www(&self.www, p) {
                    if let Ok(bytes) = fs::read(&file) {
                        endpoint.send(&bytes);
                    }
                }
            }
            endpoint.close();
            self.sent = true;
        }
    }
}

struct HqClientStream {
    pending: Arc<Mutex<Vec<RequestUrl>>>,
    tracker: Arc<Mutex<DownloadTracker>>,
    downloads: PathBuf,
    state: ClientStreamState,
}

enum ClientStreamState {
    NeedRequest,
    Receiving { path: PathBuf, file: File },
    Done,
}

impl ProtocolHandler for HqClientStream {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if !matches!(self.state, ClientStreamState::NeedRequest) {
            return;
        }
        let url = self.pending.lock().unwrap().pop();
        let Some(url) = url else {
            self.state = ClientStreamState::Done;
            return;
        };
        let req = format!("GET {}\r\n", url.path);
        endpoint.send(req.as_bytes());
        let path = self.downloads.join(&url.file_name);
        let file = File::create(&path).expect("create download");
        self.state = ClientStreamState::Receiving { path, file };
    }

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if let ClientStreamState::Receiving { file, .. } = &mut self.state {
            if !data.is_empty() {
                file.write_all(data).ok();
                *data = &[];
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let ClientStreamState::Receiving { path, .. } = &self.state {
            let path = path.clone();
            self.state = ClientStreamState::Done;
            self.tracker.lock().unwrap().finish(path);
        }
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {
        self.tracker.lock().unwrap().mark_failed();
    }
}

struct DownloadTracker {
    remaining: usize,
    failed: bool,
}

impl DownloadTracker {
    fn new(n: usize) -> Self {
        Self {
            remaining: n,
            failed: false,
        }
    }
    fn finish(&mut self, path: PathBuf) {
        if !path.is_file() {
            self.failed = true;
        }
        self.remaining = self.remaining.saturating_sub(1);
    }
    fn done(&self) -> bool {
        self.remaining == 0
    }
    fn success(&self) -> bool {
        !self.failed
    }

    fn mark_failed(&mut self) {
        self.failed = true;
    }
}
