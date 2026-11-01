// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP server configuration and listener factory.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_auth::CredentialStore;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{BindingId, ProtocolHandler, Runtime, TcpListenerConfig};
use hopf_mailbox::MailboxFactory;

use crate::server::handler::{DefaultImapHandlerFactory, ImapHandlerFactory};
use crate::server::quota::{QuotaManager, UnlimitedQuotaManager};
use crate::server::control::ImapControlHandler;

/// Default max command line (octets).
pub const DEFAULT_MAX_LINE: usize = crate::server::codec::MAX_COMMAND_LINE;

/// IMAP server configuration.
#[derive(Clone)]
pub struct ImapConfig {
    /// Listen address (default typically `0.0.0.0:143`).
    pub listen: SocketAddr,
    /// Hostname for greetings and capabilities.
    pub hostname: String,
    /// Credential store (LOGIN / AUTHENTICATE PLAIN).
    pub store: Arc<dyn CredentialStore>,
    /// Mailbox factory (opens store after auth).
    pub mailbox_factory: Arc<dyn MailboxFactory>,
    /// Optional TLS acceptor (STARTTLS / implicit).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Implicit TLS from accept (IMAPS).
    pub implicit_tls: bool,
    /// Greeting text (without untagged OK / capability prefix). Empty → built-in.
    pub greeting: String,
    /// When set, send a `PREAUTH` greeting and open this user's store
    /// (external authentication — RFC 9051 §7.1). Empty / `None` → normal `OK`.
    pub preauth_username: Option<String>,
    /// Max command-line length.
    pub max_line: usize,
    /// Advertise and accept IDLE (RFC 2177).
    pub enable_idle: bool,
    /// Maximum IDLE duration before the server ends the command with a tagged OK.
    /// Default: 29 minutes (RFC 2177 client guidance).
    pub idle_max_duration: std::time::Duration,
    /// Advertise and accept NAMESPACE (RFC 2342).
    pub enable_namespace: bool,
    /// Other-users namespace descriptors for NAMESPACE (empty → `NIL`).
    pub other_users_namespaces: Vec<NamespaceDesc>,
    /// Shared namespace descriptors for NAMESPACE (empty → `NIL`).
    pub shared_namespaces: Vec<NamespaceDesc>,
    /// Advertise and accept QUOTA (RFC 9208).
    pub enable_quota: bool,
    /// Advertise and accept MOVE (RFC 6851).
    pub enable_move: bool,
    /// Advertise CONDSTORE (RFC 7162); ENABLE required for session use.
    pub enable_condstore: bool,
    /// Advertise QRESYNC (RFC 7162); ENABLE required for session use.
    pub enable_qresync: bool,
    /// Advertise ENABLE (RFC 5161).
    pub enable_enable: bool,
    /// Advertise and accept COMPRESS DEFLATE (RFC 4978). Only ever
    /// advertised once authenticated and not already compressed.
    pub enable_compress: bool,
    /// Advertise and accept ENABLE UTF8=ACCEPT (RFC 6855).
    pub enable_utf8_accept: bool,
    /// Advertise and accept the SORT extension (RFC 5256).
    pub enable_sort: bool,
    /// Advertise and accept THREAD=ORDEREDSUBJECT (RFC 5256).
    pub enable_thread_ordered_subject: bool,
    /// Advertise and accept THREAD=REFERENCES (RFC 5256).
    pub enable_thread_references: bool,
    /// Advertise STATUS=SIZE (RFC 8438).
    pub enable_status_size: bool,
    /// Advertise and accept OBJECTID (RFC 8474: MAILBOXID / EMAILID).
    pub enable_objectid: bool,
    /// Advertise and accept METADATA (RFC 5464).
    pub enable_metadata: bool,
    /// Advertise and accept NOTIFY (RFC 5465). See [`crate::server::notify`]
    /// for which selectors/event-groups this implementation covers.
    pub enable_notify: bool,
    /// Quota backend (default: unlimited).
    pub quota_manager: Arc<dyn QuotaManager>,
    /// Server ID fields for the ID command (RFC 2971). Empty → built-in defaults.
    pub server_id: BTreeMap<String, String>,
}

/// One NAMESPACE triple: prefix + hierarchy delimiter (RFC 2342).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceDesc {
    /// Namespace prefix (e.g. `"#shared/"`).
    pub prefix: String,
    /// Hierarchy delimiter character.
    pub delimiter: char,
}

impl NamespaceDesc {
    /// Construct a namespace descriptor.
    pub fn new(prefix: impl Into<String>, delimiter: char) -> Self {
        Self {
            prefix: prefix.into(),
            delimiter,
        }
    }
}

impl ImapConfig {
    /// Plain IMAP with credential store and mailbox factory.
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
            preauth_username: None,
            max_line: DEFAULT_MAX_LINE,
            enable_idle: true,
            idle_max_duration: crate::server::idle::IDLE_MAX_DURATION,
            enable_namespace: true,
            other_users_namespaces: Vec::new(),
            shared_namespaces: Vec::new(),
            enable_quota: true,
            enable_move: true,
            enable_condstore: true,
            enable_qresync: true,
            enable_enable: true,
            enable_compress: true,
            enable_utf8_accept: true,
            enable_sort: true,
            enable_thread_ordered_subject: true,
            enable_thread_references: true,
            enable_status_size: true,
            enable_objectid: true,
            enable_metadata: true,
            enable_notify: true,
            quota_manager: Arc::new(UnlimitedQuotaManager),
            server_id: BTreeMap::new(),
        }
    }

    /// Attach TLS acceptor.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Implicit TLS listener (IMAPS).
    pub fn implicit_tls(mut self) -> Self {
        self.implicit_tls = true;
        self
    }

    /// Custom greeting banner text.
    pub fn with_greeting(mut self, greeting: impl Into<String>) -> Self {
        self.greeting = greeting.into();
        self
    }

    /// Emit a PREAUTH greeting and open `username`'s store (external auth).
    pub fn with_preauth(mut self, username: impl Into<String>) -> Self {
        self.preauth_username = Some(username.into());
        self
    }

    /// Other-users NAMESPACE entries (RFC 2342).
    pub fn with_other_users_namespaces(mut self, ns: Vec<NamespaceDesc>) -> Self {
        self.other_users_namespaces = ns;
        self
    }

    /// Shared NAMESPACE entries (RFC 2342).
    pub fn with_shared_namespaces(mut self, ns: Vec<NamespaceDesc>) -> Self {
        self.shared_namespaces = ns;
        self
    }

    /// Maximum IDLE duration before auto-completing the command.
    pub fn with_idle_max_duration(mut self, d: std::time::Duration) -> Self {
        self.idle_max_duration = d;
        self
    }

    /// Replace the quota manager.
    pub fn with_quota_manager(mut self, mgr: Arc<dyn QuotaManager>) -> Self {
        self.quota_manager = mgr;
        self
    }

    /// Set ID command fields.
    pub fn with_server_id(mut self, fields: BTreeMap<String, String>) -> Self {
        self.server_id = fields;
        self
    }
}

/// Registers the IMAP listener on a [`Runtime`].
pub struct ImapService {
    config: ImapConfig,
    metrics: Arc<crate::server::metrics::ImapServerMetrics>,
    handler_factory: Arc<dyn ImapHandlerFactory>,
    runtime: Arc<Runtime>,
    otel_metrics: Option<Arc<hopf_otel::ImapServerMetrics>>,
    export: Option<hopf_otel::ExportHandle>,
    traces_enabled: bool,
    /// The listener [`Self::start`] registered, for [`Self::stop`].
    binding: Mutex<Option<BindingId>>,
}

impl ImapService {
    /// Stock default handler factory.
    pub fn new(config: ImapConfig, runtime: Arc<Runtime>) -> Self {
        let greeting = if config.greeting.is_empty() {
            format!("{} IMAP4rev2 server ready", config.hostname)
        } else {
            config.greeting.clone()
        };
        let factory = Arc::new(DefaultImapHandlerFactory::new(greeting).with_preauth(
            config.preauth_username.clone(),
        ));
        Self {
            config,
            metrics: crate::server::metrics::ImapServerMetrics::shared(),
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
        config: ImapConfig,
        runtime: Arc<Runtime>,
        factory: Arc<dyn ImapHandlerFactory>,
    ) -> Self {
        Self {
            config,
            metrics: crate::server::metrics::ImapServerMetrics::shared(),
            handler_factory: factory,
            runtime,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            binding: Mutex::new(None),
        }
    }

    /// Wire OTLP/JSONL IMAP metrics and connection/command traces from a pipeline.
    ///
    /// When traces are enabled, handlers see a W3C `traceparent` on
    /// [`ImapConnectionMetadata`](crate::ImapConnectionMetadata) for outbound
    /// HTTP via `hopf_otel::with_traceparent`.
    pub fn with_telemetry(mut self, pipeline: &hopf_otel::TelemetryPipeline) -> Self {
        let cfg = pipeline.config();
        if cfg.metrics_enabled {
            self.otel_metrics = Some(pipeline.imap_metrics());
        }
        if cfg.traces_enabled {
            self.export = Some(pipeline.export_handle());
            self.traces_enabled = true;
        } else if cfg.metrics_enabled {
            self.export = Some(pipeline.export_handle());
        }
        self
    }

    /// Shared process-local metrics.
    pub fn metrics(&self) -> &Arc<crate::server::metrics::ImapServerMetrics> {
        &self.metrics
    }

    /// Build a [`TcpListenerConfig`] for the IMAP port.
    pub fn control_listener(&self) -> TcpListenerConfig {
        let factory = Arc::clone(&self.handler_factory);
        let config = self.config.clone();
        let runtime = Arc::clone(&self.runtime);
        let metrics = Arc::clone(&self.metrics);
        let otel_metrics = self.otel_metrics.clone();
        let export = self.export.clone();
        let traces_enabled = self.traces_enabled;
        let mut cfg = TcpListenerConfig::new(self.config.listen, move || {
            Box::new(
                ImapControlHandler::new(
                    factory.create(),
                    config.clone(),
                    Arc::clone(&runtime),
                    Arc::clone(&metrics),
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
            // IMAPS was asked for and there is nothing to do TLS with. A
            // listener marked secure with no acceptor refuses every
            // connection, where leaving it plain would serve a cleartext
            // IMAP session on what its operator believes is a TLS port.
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
                "implicit TLS (IMAPS) needs a TLS acceptor: use ImapConfig::with_tls",
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use hopf_core::RuntimeConfig;

    use crate::server::handler::{ClientConnected, ConnectedState, ImapConnectionMetadata};

    fn runtime() -> Arc<Runtime> {
        Arc::new(Runtime::start(RuntimeConfig::default()).unwrap())
    }

    /// A config on an ephemeral port over a Maildir under `root`, with one
    /// user, `u` with password `p`.
    fn config(root: &std::path::Path) -> ImapConfig {
        let store = Arc::new(hopf_auth::PasswordStore::new().with_user("u", "p"));
        let factory = Arc::new(hopf_mailbox::MaildirFactory::new(root));
        ImapConfig::new("127.0.0.1:0".parse().unwrap(), "mail.example", store, factory)
    }

    /// A TLS acceptor for the wiring tests (the handshakes themselves are
    /// exercised by the integration tests).
    fn acceptor(dir: &std::path::Path) -> SharedTlsAcceptor {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        hopf_core::acceptor_from_pem(&cert_path, &key_path, &[]).unwrap()
    }

    /// A blocking client over a real connection.
    struct Client {
        reader: BufReader<TcpStream>,
    }

    impl Client {
        fn connect(addr: SocketAddr) -> Self {
            let stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            Self { reader: BufReader::new(stream) }
        }

        fn line(&mut self) -> String {
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap_or(0);
            line
        }

        /// Send `cmd` and read up to and including the tagged answer.
        fn run(&mut self, tag: &str, cmd: &str) -> String {
            self.reader.get_mut().write_all(format!("{tag} {cmd}\r\n").as_bytes()).unwrap();
            let mut out = String::new();
            loop {
                let line = self.line();
                if line.is_empty() {
                    return out;
                }
                let done = line.starts_with(&format!("{tag} "));
                out.push_str(&line);
                if done {
                    return out;
                }
            }
        }

        /// The server has closed the connection.
        fn at_eof(&mut self) -> bool {
            self.line().is_empty()
        }
    }

    // -- the configuration -----------------------------------------------------

    #[test]
    fn a_new_config_has_the_documented_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(dir.path());
        assert_eq!(c.hostname, "mail.example");
        assert!(c.tls_acceptor.is_none() && !c.implicit_tls && c.greeting.is_empty() && c.preauth_username.is_none());
        assert_eq!(c.max_line, DEFAULT_MAX_LINE);
        assert_eq!(c.idle_max_duration, crate::server::idle::IDLE_MAX_DURATION);
        assert!(c.other_users_namespaces.is_empty() && c.shared_namespaces.is_empty() && c.server_id.is_empty());
        for (name, on) in [
            ("idle", c.enable_idle),
            ("namespace", c.enable_namespace),
            ("quota", c.enable_quota),
            ("move", c.enable_move),
            ("condstore", c.enable_condstore),
            ("qresync", c.enable_qresync),
            ("enable", c.enable_enable),
            ("compress", c.enable_compress),
            ("utf8", c.enable_utf8_accept),
            ("sort", c.enable_sort),
            ("thread=orderedsubject", c.enable_thread_ordered_subject),
            ("thread=references", c.enable_thread_references),
            ("status=size", c.enable_status_size),
            ("objectid", c.enable_objectid),
            ("metadata", c.enable_metadata),
            ("notify", c.enable_notify),
        ] {
            assert!(on, "{name} is on by default");
        }
    }

    #[test]
    fn the_builders_set_what_they_say() {
        let dir = tempfile::tempdir().unwrap();
        let ns = vec![NamespaceDesc::new("#shared/", '/')];
        let mut id = BTreeMap::new();
        id.insert("name".to_string(), "hopf".to_string());
        let c = config(dir.path())
            .with_tls(acceptor(dir.path()))
            .implicit_tls()
            .with_greeting("hello")
            .with_preauth("u")
            .with_other_users_namespaces(ns.clone())
            .with_shared_namespaces(ns.clone())
            .with_idle_max_duration(Duration::from_secs(5))
            .with_server_id(id.clone());
        assert!(c.tls_acceptor.is_some() && c.implicit_tls);
        assert_eq!((c.greeting.as_str(), c.preauth_username.as_deref()), ("hello", Some("u")));
        assert_eq!((c.other_users_namespaces, c.shared_namespaces), (ns.clone(), ns));
        assert_eq!(c.idle_max_duration, Duration::from_secs(5));
        assert_eq!(c.server_id, id);
    }

    // -- the listener ----------------------------------------------------------------

    #[test]
    fn the_listener_is_plain_starttls_or_implicit_as_configured() {
        let dir = tempfile::tempdir().unwrap();
        let svc = |c: ImapConfig| ImapService::new(c, runtime()).control_listener();
        let plain = svc(config(dir.path()));
        assert!(!plain.secure && plain.tls.is_none(), "no acceptor: plain");
        let starttls = svc(config(dir.path()).with_tls(acceptor(dir.path())));
        assert!(!starttls.secure && starttls.tls.is_some(), "an acceptor: STARTTLS is offered, the handshake waits for it");
        let implicit = svc(config(dir.path()).with_tls(acceptor(dir.path())).implicit_tls());
        assert!(implicit.secure && implicit.tls.is_some(), "implicit: the handshake starts on accept");
    }

    #[test]
    fn implicit_tls_with_no_acceptor_is_refused_not_served_in_clear() {
        // IMAPS asked for, and nothing to do TLS with: the port must not quietly
        // become a cleartext one.
        let dir = tempfile::tempdir().unwrap();
        let svc = ImapService::new(config(dir.path()).implicit_tls(), runtime());
        let err = svc.start().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(svc.control_listener().secure, "composed by hand, every connection is refused");
    }

    #[test]
    fn a_connected_client_is_greeted_with_the_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let addr = ImapService::new(config(dir.path()), runtime()).start().unwrap();
        let mut c = Client::connect(addr);
        let greeting = c.line();
        assert!(greeting.starts_with("* OK"), "{greeting}");
        assert!(greeting.contains("mail.example IMAP4rev2 server ready"), "{greeting}");
    }

    #[test]
    fn a_configured_greeting_replaces_the_built_in_one() {
        let dir = tempfile::tempdir().unwrap();
        let addr = ImapService::new(config(dir.path()).with_greeting("welcome to the test"), runtime()).start().unwrap();
        let greeting = Client::connect(addr).line();
        assert!(greeting.contains("welcome to the test") && !greeting.contains("server ready"), "{greeting}");
    }

    #[test]
    fn a_preauth_config_greets_with_preauth_and_the_users_store_is_open() {
        let dir = tempfile::tempdir().unwrap();
        let addr = ImapService::new(config(dir.path()).with_preauth("u"), runtime()).start().unwrap();
        let mut c = Client::connect(addr);
        let greeting = c.line();
        assert!(greeting.starts_with("* PREAUTH"), "{greeting}");
        let list = c.run("a1", "LIST \"\" \"*\"");
        assert!(list.contains("INBOX") && list.contains("a1 OK"), "no LOGIN needed: {list}");
    }

    #[test]
    fn the_extension_switches_reach_the_capability_list() {
        let dir = tempfile::tempdir().unwrap();
        // Most extensions are advertised once the client is logged in.
        let caps = |c: ImapConfig| {
            let addr = ImapService::new(c, runtime()).start().unwrap();
            let mut client = Client::connect(addr);
            client.line();
            assert!(client.run("l1", "LOGIN u p").contains("l1 OK"));
            client.run("c1", "CAPABILITY")
        };
        let all = caps(config(dir.path()));
        assert!(all.contains("IDLE") && all.contains("NAMESPACE") && all.contains("MOVE") && all.contains("SORT"), "{all}");
        let mut c = config(dir.path());
        c.enable_idle = false;
        c.enable_namespace = false;
        c.enable_move = false;
        c.enable_sort = false;
        let some = caps(c);
        for gone in ["IDLE", "NAMESPACE", "MOVE", "SORT"] {
            assert!(!some.contains(gone), "{gone} should be off: {some}");
        }
    }

    #[test]
    fn starttls_is_advertised_only_when_there_is_an_acceptor_to_use() {
        let dir = tempfile::tempdir().unwrap();
        let caps = |c: ImapConfig| {
            let addr = ImapService::new(c, runtime()).start().unwrap();
            let mut client = Client::connect(addr);
            client.line();
            client.run("c1", "CAPABILITY")
        };
        assert!(!caps(config(dir.path())).contains("STARTTLS"));
        assert!(caps(config(dir.path()).with_tls(acceptor(dir.path()))).contains("STARTTLS"));
    }

    #[test]
    fn an_idle_that_runs_past_the_configured_time_is_ended_by_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let addr = ImapService::new(config(dir.path()).with_idle_max_duration(Duration::from_millis(300)), runtime()).start().unwrap();
        let mut client = Client::connect(addr);
        client.line();
        assert!(client.run("l1", "LOGIN u p").contains("l1 OK"));
        assert!(client.run("s1", "SELECT INBOX").contains("s1 OK"));
        client.reader.get_mut().write_all(b"i1 IDLE\r\n").unwrap();
        assert!(client.line().starts_with('+'), "IDLE was not accepted");
        // the client now says nothing: the server must end the command itself
        let started = std::time::Instant::now();
        let mut out = String::new();
        loop {
            let line = client.line();
            if line.is_empty() {
                break;
            }
            out.push_str(&line);
            if line.starts_with("i1 ") {
                break;
            }
        }
        assert!(out.contains("i1 OK"), "IDLE was never ended by the server: {out:?}");
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
        assert!(client.run("n1", "NOOP").contains("n1 OK"), "the session should go on");
    }

    #[test]
    fn a_command_line_longer_than_the_limit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config(dir.path());
        c.max_line = 64;
        let addr = ImapService::new(c, runtime()).start().unwrap();
        let mut client = Client::connect(addr);
        client.line();
        let answer = client.run("x1", &format!("NOOP {}", "a".repeat(200)));
        assert!(!answer.contains("x1 OK"), "an over-long line was accepted: {answer}");
        assert!(answer.contains("BAD") || answer.contains("BYE") || client.at_eof(), "{answer}");
    }

    // -- a handler per connection ---------------------------------------------------

    /// The stock handler, counting how many it is asked for and how many end.
    struct Counting {
        inner: DefaultImapHandlerFactory,
        created: Arc<AtomicUsize>,
        ended: Arc<AtomicUsize>,
    }

    struct CountedEnd {
        inner: Box<dyn ClientConnected>,
        ended: Arc<AtomicUsize>,
    }

    impl ClientConnected for CountedEnd {
        fn connected(&mut self, state: &mut dyn ConnectedState, meta: &ImapConnectionMetadata) {
            self.inner.connected(state, meta);
        }
        fn disconnected(&mut self) {
            self.ended.fetch_add(1, Ordering::SeqCst);
            self.inner.disconnected();
        }
    }

    impl ImapHandlerFactory for Counting {
        fn create(&self) -> Box<dyn ClientConnected> {
            self.created.fetch_add(1, Ordering::SeqCst);
            Box::new(CountedEnd { inner: self.inner.create(), ended: Arc::clone(&self.ended) })
        }
    }

    fn wait(pred: impl Fn() -> bool) -> bool {
        for _ in 0..500 {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        pred()
    }

    #[test]
    fn each_connection_gets_its_own_handler_and_its_end_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (created, ended) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let factory = Arc::new(Counting {
            inner: DefaultImapHandlerFactory::new("hi"),
            created: Arc::clone(&created),
            ended: Arc::clone(&ended),
        });
        let svc = ImapService::with_handler_factory(config(dir.path()), runtime(), factory);
        let before = svc.metrics().connections.load(Ordering::Relaxed);
        let addr = svc.start().unwrap();

        let mut a = Client::connect(addr);
        let mut b = Client::connect(addr);
        assert!(a.line().starts_with("* OK") && b.line().starts_with("* OK"));
        assert_eq!(created.load(Ordering::SeqCst), 2, "one handler per connection, not one per service");
        assert!(svc.metrics().connections.load(Ordering::Relaxed) >= before + 2);

        assert!(a.run("l1", "LOGOUT").contains("l1 OK"));
        assert!(wait(|| ended.load(Ordering::SeqCst) == 1), "the first connection's end was not reported");
        drop(b);
        assert!(wait(|| ended.load(Ordering::SeqCst) == 2), "a client that just goes away is also an end");
    }

    // -- storage and shutdown ----------------------------------------------------------

    #[test]
    fn a_mailbox_store_that_cannot_be_opened_refuses_the_login_and_leaves_the_connection_usable() {
        // The Maildir root is a file, so a user's store cannot be made there.
        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("file");
        std::fs::write(&not_a_directory, b"x").unwrap();
        let addr = ImapService::new(config(&not_a_directory), runtime()).start().unwrap();
        let mut c = Client::connect(addr);
        c.line();
        let answer = c.run("l1", "LOGIN u p");
        assert!(answer.contains("l1 NO") || answer.contains("l1 BAD") || answer.contains("BYE"), "{answer}");
        assert!(!answer.contains("l1 OK"), "{answer}");
        if !answer.contains("BYE") {
            assert!(c.run("n1", "NOOP").contains("n1 OK"), "the server hung or died after the storage failure");
        }
    }

    #[test]
    fn a_stopped_service_refuses_new_connections_but_lets_open_sessions_finish_and_the_runtime_shut_down() {
        let dir = tempfile::tempdir().unwrap();
        let rt = runtime();
        let svc = ImapService::new(config(dir.path()), Arc::clone(&rt));
        let addr = svc.start().unwrap();
        let mut open = Client::connect(addr);
        assert!(open.line().starts_with("* OK"));

        svc.stop();
        svc.stop(); // a second stop is nothing
        assert!(wait(|| TcpStream::connect(addr).is_err()), "a stopped service still accepts connections");
        assert!(open.run("n1", "NOOP").contains("n1 OK"), "stopping cut an open session off");

        // Until the session ends the runtime is still in use.
        assert!(open.run("o1", "LOGOUT").contains("o1 OK"));
        assert!(open.at_eof());
        drop(open);
        drop(svc);
        assert!(
            wait(|| Arc::strong_count(&rt) == 1),
            "something still holds the runtime: {} references",
            Arc::strong_count(&rt)
        );
        Arc::try_unwrap(rt).ok().expect("nothing else holds the runtime").shutdown();
    }
}
