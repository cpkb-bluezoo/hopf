// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 service configuration and listener factory.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_auth::CredentialStore;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{BindingId, ProtocolHandler, Runtime, TcpListenerConfig};
use hopf_mailbox::MailboxFactory;

use crate::server::control::Pop3ControlHandler;
use crate::server::handler::{DefaultPop3HandlerFactory, Pop3HandlerFactory};
use crate::server::metrics::Pop3ServerMetrics;

/// Default transaction idle timeout (10 minutes).
pub const DEFAULT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(600);

/// POP3 server configuration.
#[derive(Clone)]
pub struct Pop3Config {
    /// Listen address (default typically `0.0.0.0:110`).
    pub listen: SocketAddr,
    /// Hostname for greetings and APOP timestamps.
    pub hostname: String,
    /// Credential store (USER/PASS, SASL).
    pub store: Arc<dyn CredentialStore>,
    /// Mailbox factory (opens INBOX after auth).
    pub mailbox_factory: Arc<dyn MailboxFactory>,
    /// Optional TLS acceptor (STLS / implicit).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Implicit TLS from accept (POP3S).
    pub implicit_tls: bool,
    /// Greeting text (without `+OK` prefix). Empty → built-in.
    pub greeting: String,
    /// Advertise and accept UTF8.
    pub enable_utf8: bool,
    /// Advertise PIPELINING in CAPA (pipelining always works).
    pub enable_pipelining: bool,
    /// Delay after a failed auth before the next attempt is accepted.
    pub login_delay: Duration,
    /// CAPA EXPIRE days (`None` = omit EXPIRE line).
    pub expire_days: Option<u32>,
    /// Idle timeout in TRANSACTION state.
    pub transaction_timeout: Duration,
}

impl Pop3Config {
    /// Plain POP3 with credential store and mailbox factory.
    pub fn new(
        listen: SocketAddr,
        hostname: impl Into<String>,
        store: Arc<dyn CredentialStore>,
        mailbox_factory: Arc<dyn MailboxFactory>,
    ) -> Self {
        Self {
            listen,
            hostname: hostname.into(),
            store,
            mailbox_factory,
            tls_acceptor: None,
            implicit_tls: false,
            greeting: String::new(),
            enable_utf8: true,
            enable_pipelining: false,
            login_delay: Duration::ZERO,
            expire_days: None,
            transaction_timeout: DEFAULT_TRANSACTION_TIMEOUT,
        }
    }

    /// Attach TLS acceptor.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Implicit TLS listener (POP3S).
    pub fn implicit_tls(mut self) -> Self {
        self.implicit_tls = true;
        self
    }

    /// Custom greeting banner text.
    pub fn with_greeting(mut self, greeting: impl Into<String>) -> Self {
        self.greeting = greeting.into();
        self
    }
}

/// Registers the POP3 listener on a [`Runtime`].
pub struct Pop3Service {
    config: Pop3Config,
    metrics: Arc<Pop3ServerMetrics>,
    handler_factory: Arc<dyn Pop3HandlerFactory>,
    runtime: Arc<Runtime>,
    otel_metrics: Option<Arc<hopf_otel::Pop3ServerMetrics>>,
    export: Option<hopf_otel::ExportHandle>,
    traces_enabled: bool,
    /// The listener [`Self::start`] registered, for [`Self::stop`].
    binding: Mutex<Option<BindingId>>,
}

impl Pop3Service {
    /// Stock default handler factory.
    pub fn new(config: Pop3Config, runtime: Arc<Runtime>) -> Self {
        let greeting = if config.greeting.is_empty() {
            format!("{} POP3 server ready", config.hostname)
        } else {
            config.greeting.clone()
        };
        let factory = Arc::new(DefaultPop3HandlerFactory::new(greeting));
        Self {
            config,
            metrics: Pop3ServerMetrics::shared(),
            handler_factory: factory,
            runtime,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            binding: Mutex::new(None),
        }
    }

    /// Custom application handler factory.
    pub fn with_handler_factory(
        config: Pop3Config,
        runtime: Arc<Runtime>,
        factory: Arc<dyn Pop3HandlerFactory>,
    ) -> Self {
        Self {
            config,
            metrics: Pop3ServerMetrics::shared(),
            handler_factory: factory,
            runtime,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            binding: Mutex::new(None),
        }
    }

    /// Wire OTLP/JSONL POP3 metrics and connection/retrieve traces from a pipeline.
    ///
    /// When traces are enabled, handlers see a W3C `traceparent` on
    /// [`Pop3ConnectionMetadata`](crate::Pop3ConnectionMetadata) for outbound
    /// HTTP via `hopf_otel::with_traceparent`.
    pub fn with_telemetry(mut self, pipeline: &hopf_otel::TelemetryPipeline) -> Self {
        let cfg = pipeline.config();
        if cfg.metrics_enabled {
            self.otel_metrics = Some(pipeline.pop3_metrics());
        }
        if cfg.traces_enabled {
            self.export = Some(pipeline.export_handle());
            self.traces_enabled = true;
        } else if cfg.metrics_enabled {
            self.export = Some(pipeline.export_handle());
        }
        self
    }

    /// Shared metrics.
    pub fn metrics(&self) -> &Arc<Pop3ServerMetrics> {
        &self.metrics
    }

    /// Build a [`TcpListenerConfig`] for the POP3 port.
    pub fn control_listener(&self) -> TcpListenerConfig {
        let factory = Arc::clone(&self.handler_factory);
        let metrics = Arc::clone(&self.metrics);
        let config = self.config.clone();
        let runtime = Arc::clone(&self.runtime);
        let otel_metrics = self.otel_metrics.clone();
        let export = self.export.clone();
        let traces_enabled = self.traces_enabled;
        let mut cfg = TcpListenerConfig::new(self.config.listen, move || {
            Box::new(
                Pop3ControlHandler::new(
                    factory.create(),
                    Arc::clone(&metrics),
                    config.clone(),
                    Arc::clone(&runtime),
                )
                .with_telemetry(otel_metrics.clone(), export.clone(), traces_enabled),
            ) as Box<dyn ProtocolHandler>
        });
        if let Some(tls) = &self.config.tls_acceptor {
            if self.config.implicit_tls {
                cfg = cfg.with_tls(Arc::clone(tls));
            } else {
                cfg = cfg.with_starttls_acceptor(Arc::clone(tls));
            }
        } else if self.config.implicit_tls {
            // POP3S was asked for and there is nothing to do TLS with. A
            // listener marked secure with no acceptor refuses every
            // connection, where leaving it plain would serve a cleartext
            // POP3 session on what its operator believes is a TLS port.
            cfg.secure = true;
        }
        cfg
    }

    /// Register the listener; returns bound address. Fails with
    /// `InvalidInput` if implicit TLS is configured without an acceptor.
    pub fn start(&self) -> std::io::Result<SocketAddr> {
        if self.config.implicit_tls && self.config.tls_acceptor.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "implicit TLS (POP3S) needs a TLS acceptor: use Pop3Config::with_tls",
            ));
        }
        let cfg = self.control_listener();
        let (addr, id) = self.runtime.add_tcp_listener(cfg)?;
        *self.binding.lock().unwrap() = Some(id);
        Ok(addr)
    }

    /// Stop accepting connections. Sessions already open carry on until they
    /// end; until they have, and this service is dropped, nothing else lets
    /// go of the [`Runtime`]. A service that was not started, or was already
    /// stopped, is left as it is.
    pub fn stop(&self) {
        if let Some(id) = self.binding.lock().unwrap().take() {
            self.runtime.remove_binding(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::io::{BufRead, BufReader, Write};
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::net::TcpStream;
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::time::Instant;

    use hopf_core::RuntimeConfig;

    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use crate::server::handler::{ClientConnected, ConnectedState, Pop3ConnectionMetadata};

    fn runtime() -> Arc<Runtime> {
        Arc::new(Runtime::start(RuntimeConfig::default()).unwrap())
    }

    /// A config on an ephemeral port over a Maildir under `root`, with one
    /// user, `u` with password `p`.
    fn config(root: &std::path::Path) -> Pop3Config {
        let store = Arc::new(hopf_auth::PasswordStore::new().with_user("u", "p"));
        let factory = Arc::new(hopf_mailbox::MaildirFactory::new(root));
        Pop3Config::new("127.0.0.1:0".parse().unwrap(), "mail.example", store, factory)
    }

    fn acceptor() -> SharedTlsAcceptor {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        hopf_core::acceptor_from_pem_bytes(cert.cert.pem().as_bytes(), cert.key_pair.serialize_pem().as_bytes(), &[]).unwrap()
    }

    /// A blocking client over a real connection.
    #[cfg(feature = "integration")]
    struct Client {
        reader: BufReader<TcpStream>,
    }

    #[cfg(feature = "integration")]
    impl Client {
        #[cfg(feature = "integration")]
        fn connect(addr: SocketAddr) -> Self {
            let stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            Self { reader: BufReader::new(stream) }
        }

        #[cfg(feature = "integration")]
        fn line(&mut self) -> String {
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap_or(0);
            line
        }

        /// Send `cmd` and read the reply: the status line, and for a
        /// multi-line one (`multi`) up to the lone dot.
        #[cfg(feature = "integration")]
        fn run(&mut self, cmd: &str, multi: bool) -> String {
            self.reader.get_mut().write_all(format!("{cmd}\r\n").as_bytes()).unwrap();
            let mut out = self.line();
            if multi && out.starts_with("+OK") {
                loop {
                    let line = self.line();
                    if line.is_empty() {
                        break;
                    }
                    let end = line == ".\r\n";
                    out.push_str(&line);
                    if end {
                        break;
                    }
                }
            }
            out
        }

        #[cfg(feature = "integration")]
        fn login(&mut self, user: &str, pass: &str) -> String {
            let u = self.run(&format!("USER {user}"), false);
            assert!(u.starts_with("+OK"), "{u}");
            self.run(&format!("PASS {pass}"), false)
        }

        #[cfg(feature = "integration")]
        fn at_eof(&mut self) -> bool {
            self.line().is_empty()
        }
    }

    #[cfg(feature = "integration")]
    fn wait(pred: impl Fn() -> bool) -> bool {
        for _ in 0..500 {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        pred()
    }

    // -- the configuration -----------------------------------------------------

    #[test]
    fn a_new_config_has_the_documented_defaults() {
        // No file is touched: the root is only recorded in the configuration.
        let dir = std::path::PathBuf::from("/srv/mail");
        let c = config(&dir);
        assert_eq!(c.hostname, "mail.example");
        assert!(c.tls_acceptor.is_none() && !c.implicit_tls && c.greeting.is_empty());
        assert!(c.enable_utf8 && !c.enable_pipelining);
        assert_eq!((c.login_delay, c.expire_days, c.transaction_timeout), (Duration::ZERO, None, DEFAULT_TRANSACTION_TIMEOUT));
        assert_eq!(DEFAULT_TRANSACTION_TIMEOUT, Duration::from_secs(600));
    }

    #[test]
    fn the_builders_set_what_they_say() {
        // No file is touched: the root is only recorded in the configuration.
        let dir = std::path::PathBuf::from("/srv/mail");
        let c = config(&dir).with_tls(acceptor()).implicit_tls().with_greeting("hello");
        assert!(c.tls_acceptor.is_some() && c.implicit_tls);
        assert_eq!(c.greeting, "hello");
    }

    // -- the listener ----------------------------------------------------------------

    #[test]
    fn the_listener_is_plain_stls_or_implicit_as_configured() {
        // No file is touched: the root is only recorded in the configuration.
        let dir = std::path::PathBuf::from("/srv/mail");
        let svc = |c: Pop3Config| Pop3Service::new(c, runtime()).control_listener();
        let plain = svc(config(&dir));
        assert!(!plain.secure && plain.tls.is_none());
        let stls = svc(config(&dir).with_tls(acceptor()));
        assert!(!stls.secure && stls.tls.is_some(), "STLS is offered, the handshake waits for it");
        let implicit = svc(config(&dir).with_tls(acceptor()).implicit_tls());
        assert!(implicit.secure && implicit.tls.is_some(), "the handshake starts on accept");
    }

    #[test]
    fn implicit_tls_with_no_acceptor_is_refused_not_served_in_clear() {
        // No file is touched: the root is only recorded in the configuration.
        let dir = std::path::PathBuf::from("/srv/mail");
        let svc = Pop3Service::new(config(&dir).implicit_tls(), runtime());
        let err = svc.start().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(svc.control_listener().secure, "composed by hand, every connection is refused");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_client_is_greeted_with_the_hostname_or_the_configured_greeting() {
        let dir = tempfile::tempdir().unwrap();
        let addr = Pop3Service::new(config(dir.path()), runtime()).start().unwrap();
        let greeting = Client::connect(addr).line();
        assert!(greeting.starts_with("+OK") && greeting.contains("mail.example POP3 server ready"), "{greeting}");
        let addr = Pop3Service::new(config(dir.path()).with_greeting("welcome to the test"), runtime()).start().unwrap();
        let greeting = Client::connect(addr).line();
        assert!(greeting.contains("welcome to the test") && !greeting.contains("server ready"), "{greeting}");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn the_capability_switches_and_the_acceptor_reach_the_capa_list() {
        let dir = tempfile::tempdir().unwrap();
        let capa = |c: Pop3Config| {
            let addr = Pop3Service::new(c, runtime()).start().unwrap();
            let mut client = Client::connect(addr);
            client.line();
            client.run("CAPA", true)
        };
        let plain = capa(config(dir.path()));
        assert!(plain.contains("UTF8") && !plain.contains("PIPELINING") && !plain.contains("EXPIRE") && !plain.contains("STLS"), "{plain}");
        let mut c = config(dir.path()).with_tls(acceptor());
        c.enable_utf8 = false;
        c.enable_pipelining = true;
        c.expire_days = Some(30);
        let tuned = capa(c);
        assert!(tuned.contains("PIPELINING") && tuned.contains("EXPIRE 30") && tuned.contains("STLS") && !tuned.contains("UTF8"), "{tuned}");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_failed_login_holds_off_the_next_attempt_for_the_configured_time() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config(dir.path());
        c.login_delay = Duration::from_millis(400);
        let addr = Pop3Service::new(c, runtime()).start().unwrap();
        let mut client = Client::connect(addr);
        client.line();
        assert!(client.login("u", "wrong").starts_with("-ERR"));
        let too_soon = client.login("u", "p");
        assert!(too_soon.contains("[LOGIN-DELAY]"), "an attempt inside the delay was not refused: {too_soon}");
        std::thread::sleep(Duration::from_millis(450));
        let later = client.login("u", "p");
        assert!(later.starts_with("+OK"), "{later}");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn an_idle_session_is_ended_by_the_server_after_the_transaction_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config(dir.path());
        c.transaction_timeout = Duration::from_millis(300);
        let addr = Pop3Service::new(c, runtime()).start().unwrap();
        let mut client = Client::connect(addr);
        client.line();
        assert!(client.login("u", "p").starts_with("+OK"));
        // The client says nothing: it is the server that must end the session.
        let started = Instant::now();
        let last = client.line();
        assert!(last.starts_with("-ERR") && last.contains("timeout"), "no timeout notice: {last:?}");
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
        assert!(client.at_eof(), "the session was not closed");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_session_that_keeps_working_is_not_timed_out() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config(dir.path());
        c.transaction_timeout = Duration::from_millis(400);
        let addr = Pop3Service::new(c, runtime()).start().unwrap();
        let mut client = Client::connect(addr);
        client.line();
        assert!(client.login("u", "p").starts_with("+OK"));
        // Twice the timeout in all, but never idle for the whole of it.
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(150));
            assert!(client.run("STAT", false).starts_with("+OK"), "a working session was cut off");
        }
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_connection_that_has_not_logged_in_is_not_subject_to_the_transaction_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config(dir.path());
        c.transaction_timeout = Duration::from_millis(200);
        let addr = Pop3Service::new(c, runtime()).start().unwrap();
        let mut client = Client::connect(addr);
        client.line();
        std::thread::sleep(Duration::from_millis(600));
        assert!(client.login("u", "p").starts_with("+OK"), "the timeout is for the transaction state");
    }

    // -- a handler per connection ---------------------------------------------------

    #[cfg(feature = "integration")]
    struct Counting {
        inner: DefaultPop3HandlerFactory,
        created: Arc<AtomicUsize>,
        ended: Arc<AtomicUsize>,
    }

    #[cfg(feature = "integration")]
    struct CountedEnd {
        inner: Box<dyn ClientConnected>,
        ended: Arc<AtomicUsize>,
    }

    #[cfg(feature = "integration")]
    impl ClientConnected for CountedEnd {
        fn connected(&mut self, state: &mut dyn ConnectedState, meta: &Pop3ConnectionMetadata) {
            self.inner.connected(state, meta);
        }
        fn disconnected(&mut self) {
            self.ended.fetch_add(1, Ordering::SeqCst);
            self.inner.disconnected();
        }
    }

    #[cfg(feature = "integration")]
    impl Pop3HandlerFactory for Counting {
        fn create(&self) -> Box<dyn ClientConnected> {
            self.created.fetch_add(1, Ordering::SeqCst);
            Box::new(CountedEnd { inner: self.inner.create(), ended: Arc::clone(&self.ended) })
        }
    }

    #[cfg(feature = "integration")]
    #[test]
    fn each_connection_gets_its_own_handler_and_its_end_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (created, ended) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let factory = Arc::new(Counting {
            inner: DefaultPop3HandlerFactory::new("hi"),
            created: Arc::clone(&created),
            ended: Arc::clone(&ended),
        });
        let svc = Pop3Service::with_handler_factory(config(dir.path()), runtime(), factory);
        let before = svc.metrics().connections.load(Ordering::Relaxed);
        let addr = svc.start().unwrap();
        let mut a = Client::connect(addr);
        let mut b = Client::connect(addr);
        assert!(a.line().starts_with("+OK") && b.line().starts_with("+OK"));
        assert_eq!(created.load(Ordering::SeqCst), 2);
        assert!(svc.metrics().connections.load(Ordering::Relaxed) >= before + 2);
        assert!(a.run("QUIT", false).starts_with("+OK"));
        assert!(wait(|| ended.load(Ordering::SeqCst) == 1), "the first connection's end was not reported");
        drop(b);
        assert!(wait(|| ended.load(Ordering::SeqCst) == 2), "a client that just goes away is also an end");
    }

    // -- storage and shutdown ----------------------------------------------------------

    #[cfg(feature = "integration")]
    #[test]
    fn a_mailbox_that_cannot_be_opened_refuses_the_login_and_leaves_the_connection_usable() {
        // The Maildir root is a file, so a user's mailbox cannot be made there.
        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("file");
        std::fs::write(&not_a_directory, b"x").unwrap();
        let addr = Pop3Service::new(config(&not_a_directory), runtime()).start().unwrap();
        let mut c = Client::connect(addr);
        c.line();
        let answer = c.login("u", "p");
        assert!(answer.starts_with("-ERR"), "{answer}");
        assert!(c.run("NOOP", false).starts_with("-ERR") || c.run("QUIT", false).starts_with("+OK"), "the server hung after the storage failure");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_stopped_service_refuses_new_connections_but_lets_open_sessions_finish_and_the_runtime_shut_down() {
        let dir = tempfile::tempdir().unwrap();
        let rt = runtime();
        let svc = Pop3Service::new(config(dir.path()), Arc::clone(&rt));
        let addr = svc.start().unwrap();
        let mut open = Client::connect(addr);
        assert!(open.line().starts_with("+OK"));

        svc.stop();
        svc.stop(); // a second stop is nothing
        assert!(wait(|| TcpStream::connect(addr).is_err()), "a stopped service still accepts connections");
        assert!(open.login("u", "p").starts_with("+OK"), "stopping cut an open session off");

        assert!(open.run("QUIT", false).starts_with("+OK"));
        assert!(open.at_eof());
        drop(open);
        drop(svc);
        assert!(wait(|| Arc::strong_count(&rt) == 1), "something still holds the runtime: {} references", Arc::strong_count(&rt));
        Arc::try_unwrap(rt).ok().expect("nothing else holds the runtime").shutdown();
    }
}
