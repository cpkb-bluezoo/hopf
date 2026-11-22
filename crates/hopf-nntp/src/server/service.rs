// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NNTP service configuration and listener factory.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_auth::CredentialStore;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{BindingId, ProtocolHandler, Runtime, TcpListenerConfig};
use hopf_mailbox::MailboxFactory;

use crate::server::control::NntpControlHandler;
use crate::server::handler::NntpHandlerFactory;
use crate::server::mailbox::DefaultNntpHandlerFactory;
use crate::server::metrics::NntpServerMetrics;

/// How long a connection may be silent, in either direction, before the
/// server closes it, unless told otherwise (RFC 3977 section 5.4 asks for
/// at least three minutes).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// How long an answer may wait for a client that is not reading it before the
/// connection is closed, unless told otherwise.
pub const DEFAULT_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(120);

/// The largest article `POST` accepts unless told otherwise.
pub const DEFAULT_MAX_POST_SIZE: u64 = 64 * 1024 * 1024;

/// Credentials a connection may have refused, unless told otherwise.
pub const DEFAULT_MAX_AUTH_FAILURES: u32 = 3;

/// NNTP server configuration.
#[derive(Clone)]
pub struct NntpConfig {
    /// Where to listen (119, or 563 for implicit TLS, by convention).
    pub listen: SocketAddr,
    /// The server's name, for the default greeting.
    pub hostname: String,
    /// Are clients told they may post?
    pub posting_allowed: bool,
    /// The acceptor for TLS (`STARTTLS`, or from the first byte when
    /// `implicit_tls`).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Is TLS begun as soon as a client connects (NNTPS)?
    pub implicit_tls: bool,
    /// Close a connection that has neither sent nor received for this long.
    /// `None` leaves idle connections open.
    pub idle_timeout: Option<Duration>,
    /// Close a connection that has not taken what is waiting to be sent to it
    /// for this long.
    pub write_stall_timeout: Duration,
    /// The largest article, in octets, that `POST` accepts; a larger one is
    /// read and thrown away, and refused. `None` sets no limit.
    pub max_post_size: Option<u64>,
    /// Who may log in, and how. Without it the server offers no `AUTHINFO`.
    pub credentials: Option<Arc<dyn CredentialStore>>,
    /// Must a client authenticate before it reads or posts news?
    pub authentication_required: bool,
    /// May a password (`AUTHINFO USER`/`PASS`, or a SASL mechanism that sends
    /// one in the clear) be sent on a connection that is not encrypted?
    /// Default no: a client has to `STARTTLS` first.
    pub allow_cleartext_auth: bool,
    /// Credentials one connection may have refused before it is closed with a
    /// `400`. `0` means no limit. Default 3.
    pub max_auth_failures: u32,
}

impl NntpConfig {
    /// Plain NNTP on `listen`.
    pub fn new(listen: SocketAddr, hostname: impl Into<String>) -> Self {
        Self {
            listen,
            hostname: hostname.into(),
            posting_allowed: true,
            tls_acceptor: None,
            implicit_tls: false,
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            write_stall_timeout: DEFAULT_WRITE_STALL_TIMEOUT,
            max_post_size: Some(DEFAULT_MAX_POST_SIZE),
            credentials: None,
            authentication_required: false,
            allow_cleartext_auth: false,
            max_auth_failures: DEFAULT_MAX_AUTH_FAILURES,
        }
    }

    /// Attaches a TLS acceptor.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Begins TLS as soon as a client connects (NNTPS).
    pub fn implicit_tls(mut self) -> Self {
        self.implicit_tls = true;
        self
    }

    /// Offers `AUTHINFO` against `store`.
    pub fn with_credentials(mut self, store: Arc<dyn CredentialStore>) -> Self {
        self.credentials = Some(store);
        self
    }

    /// Requires clients to authenticate before they read or post news.
    pub fn require_authentication(mut self) -> Self {
        self.authentication_required = true;
        self
    }

    /// Lets a password be sent on a connection that is not encrypted.
    pub fn allow_cleartext_auth(mut self) -> Self {
        self.allow_cleartext_auth = true;
        self
    }

    /// Whether clients are told they may post.
    pub fn with_posting_allowed(mut self, allowed: bool) -> Self {
        self.posting_allowed = allowed;
        self
    }
}

/// Registers the NNTP listener on a [`Runtime`].
pub struct NntpService {
    config: NntpConfig,
    metrics: Arc<NntpServerMetrics>,
    handler_factory: Arc<dyn NntpHandlerFactory>,
    runtime: Arc<Runtime>,
    /// The listener [`Self::start`] registered, for [`Self::stop`].
    binding: Mutex<Option<BindingId>>,
}

impl NntpService {
    /// Serves the mailboxes of the stores `mailboxes` makes as newsgroups,
    /// with the stock handler.
    pub fn new(config: NntpConfig, runtime: Arc<Runtime>, mailboxes: Arc<dyn MailboxFactory>) -> Self {
        let greeting = format!("{} NNTP server ready", config.hostname);
        let factory = DefaultNntpHandlerFactory::new(greeting, mailboxes).with_posting_allowed(config.posting_allowed)
            .with_hostname(config.hostname.clone());
        Self::with_handler_factory(config, runtime, Arc::new(factory))
    }

    /// Serves with the application's own handlers.
    pub fn with_handler_factory(
        config: NntpConfig,
        runtime: Arc<Runtime>,
        factory: Arc<dyn NntpHandlerFactory>,
    ) -> Self {
        Self {
            config,
            metrics: NntpServerMetrics::shared(),
            handler_factory: factory,
            runtime,
            binding: Mutex::new(None),
        }
    }

    /// The service's counters.
    pub fn metrics(&self) -> &Arc<NntpServerMetrics> {
        &self.metrics
    }

    /// The listener configuration, for composing by hand.
    pub fn control_listener(&self) -> TcpListenerConfig {
        let factory = Arc::clone(&self.handler_factory);
        let metrics = Arc::clone(&self.metrics);
        let config = self.config.clone();
        let runtime = Arc::clone(&self.runtime);
        let mut cfg = TcpListenerConfig::new(self.config.listen, move || {
            Box::new(NntpControlHandler::new(
                factory.create(),
                Arc::clone(&metrics),
                config.clone(),
                Arc::clone(&runtime),
            )) as Box<dyn ProtocolHandler>
        })
        .idle_timeout(self.config.idle_timeout);
        if let Some(tls) = &self.config.tls_acceptor {
            if self.config.implicit_tls {
                cfg = cfg.with_tls(Arc::clone(tls));
            } else {
                cfg = cfg.with_starttls_acceptor(Arc::clone(tls));
            }
        } else if self.config.implicit_tls {
            // NNTPS was asked for and there is nothing to do TLS with. A
            // listener marked secure with no acceptor refuses every
            // connection, where leaving it plain would serve a cleartext
            // session on what its operator believes is a TLS port.
            cfg.secure = true;
        }
        cfg
    }

    /// Registers the listener and returns the address it is bound to. Fails
    /// with `InvalidInput` if implicit TLS is configured without an acceptor.
    pub fn start(&self) -> std::io::Result<SocketAddr> {
        if self.config.implicit_tls && self.config.tls_acceptor.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "implicit TLS (NNTPS) needs a TLS acceptor: use NntpConfig::with_tls",
            ));
        }
        let (addr, id) = self.runtime.add_tcp_listener(self.control_listener())?;
        *self.binding.lock().unwrap() = Some(id);
        Ok(addr)
    }

    /// Stops accepting connections. Sessions already open carry on until they
    /// end. A service that was not started, or was already stopped, is left
    /// as it is.
    pub fn stop(&self) {
        if let Some(id) = self.binding.lock().unwrap().take() {
            self.runtime.remove_binding(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::RuntimeConfig;

    fn runtime() -> Arc<Runtime> {
        Arc::new(Runtime::start(RuntimeConfig::default()).unwrap())
    }

    fn config() -> NntpConfig {
        NntpConfig::new("127.0.0.1:0".parse().unwrap(), "news.example")
    }

    fn mailboxes() -> Arc<dyn MailboxFactory> {
        Arc::new(hopf_mailbox::MaildirFactory::new("/srv/news"))
    }

    fn acceptor() -> SharedTlsAcceptor {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        hopf_core::acceptor_from_pem_bytes(cert.cert.pem().as_bytes(), cert.key_pair.serialize_pem().as_bytes(), &[]).unwrap()
    }

    #[test]
    fn a_new_config_has_the_documented_defaults() {
        let c = config();
        assert!(c.posting_allowed && !c.implicit_tls && c.tls_acceptor.is_none());
        assert_eq!(c.idle_timeout, Some(DEFAULT_IDLE_TIMEOUT));
        assert_eq!(c.write_stall_timeout, DEFAULT_WRITE_STALL_TIMEOUT);
        assert_eq!(c.max_post_size, Some(DEFAULT_MAX_POST_SIZE));
        assert!(c.credentials.is_none() && !c.authentication_required && !c.allow_cleartext_auth);
        assert_eq!(c.max_auth_failures, DEFAULT_MAX_AUTH_FAILURES);
    }

    #[test]
    fn the_listener_is_plain_starttls_or_implicit_as_configured() {
        let svc = |c: NntpConfig| NntpService::new(c, runtime(), mailboxes()).control_listener();
        let plain = svc(config());
        assert!(!plain.secure && plain.tls.is_none());
        assert_eq!(plain.idle_timeout, Some(DEFAULT_IDLE_TIMEOUT));
        let starttls = svc(config().with_tls(acceptor()));
        assert!(!starttls.secure && starttls.tls.is_some());
        let implicit = svc(config().with_tls(acceptor()).implicit_tls());
        assert!(implicit.secure && implicit.tls.is_some());
    }

    #[test]
    fn implicit_tls_with_no_acceptor_is_refused_not_served_in_clear() {
        let svc = NntpService::new(config().implicit_tls(), runtime(), mailboxes());
        let err = svc.start().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(svc.control_listener().secure);
    }

    // -- real connections ----------------------------------------------------

    #[cfg(feature = "integration")]
    mod live {
        use super::*;
        use std::collections::BTreeSet;
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpStream;
        use std::time::Instant;

        /// A news spool with `misc.test` holding `articles`.
        fn spool(root: &std::path::Path, articles: &[String]) -> Arc<dyn MailboxFactory> {
            let factory = Arc::new(hopf_mailbox::MaildirFactory::new(root));
            let mut store = factory.create_store();
            store.open("news").unwrap();
            store.create_mailbox("misc/test").unwrap();
            let mut mb = store.open_mailbox("misc/test", false).unwrap();
            for text in articles {
                let mut guard = hopf_mailbox::AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
                guard.append_content(text.as_bytes()).unwrap();
                guard.commit().unwrap();
            }
            mb.close(false).unwrap();
            store.close().unwrap();
            factory
        }

        fn article(subject: &str, body: &str) -> String {
            format!("From: a@x.org\r\nSubject: {subject}\r\nMessage-ID: <{subject}@x.org>\r\n\r\n{body}")
        }

        struct Client {
            reader: BufReader<TcpStream>,
        }

        impl Client {
            fn connect(addr: SocketAddr) -> Self {
                let stream = TcpStream::connect(addr).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
                Self { reader: BufReader::new(stream) }
            }

            fn line(&mut self) -> String {
                let mut line = String::new();
                self.reader.read_line(&mut line).unwrap();
                line
            }

            fn send(&mut self, text: &str) {
                self.reader.get_mut().write_all(text.as_bytes()).unwrap();
            }
        }

        #[test]
        fn a_reader_selects_a_group_and_reads_an_article_over_a_real_connection() {
            let dir = tempfile::tempdir().unwrap();
            let factory = spool(dir.path(), &[article("one", "hello\r\n.dot\r\n")]);
            let svc = NntpService::new(config(), runtime(), factory);
            let addr = svc.start().unwrap();
            let mut c = Client::connect(addr);
            assert!(c.line().starts_with("200 news.example NNTP server ready"));
            c.send("GROUP misc.test\r\nARTICLE 1\r\nQUIT\r\n");
            assert_eq!(c.line(), "211 1 1 1 misc.test\r\n");
            assert_eq!(c.line(), "220 1 <one@x.org> Article follows\r\n");
            let mut text = String::new();
            loop {
                let l = c.line();
                text.push_str(&l);
                if l == ".\r\n" {
                    break;
                }
            }
            assert_eq!(text, "From: a@x.org\r\nSubject: one\r\nMessage-ID: <one@x.org>\r\n\r\nhello\r\n..dot\r\n.\r\n");
            assert_eq!(c.line(), "205 Connection closing\r\n");
        }

        #[test]
        fn an_article_posted_over_a_real_connection_can_be_read_back() {
            let dir = tempfile::tempdir().unwrap();
            let factory = spool(dir.path(), &[article("one", "hello\r\n")]);
            let svc = NntpService::new(config(), runtime(), factory);
            let addr = svc.start().unwrap();
            let mut c = Client::connect(addr);
            c.line();
            c.send("POST\r\n");
            assert!(c.line().starts_with("340 "));
            c.send("From: p@x.org\r\nNewsgroups: misc.test\r\nSubject: posted\r\nMessage-ID: <posted@x.org>\r\n\r\nbody\r\n..dot\r\n.\r\nGROUP misc.test\r\nBODY 2\r\nQUIT\r\n");
            assert_eq!(c.line(), "240 Article received OK\r\n");
            assert_eq!(c.line(), "211 2 1 2 misc.test\r\n");
            assert_eq!(c.line(), "222 2 <posted@x.org> Body follows\r\n");
            assert_eq!(c.line(), "body\r\n");
            assert_eq!(c.line(), "..dot\r\n");
            assert_eq!(c.line(), ".\r\n");
        }

        #[test]
        fn a_large_article_reaches_a_slow_reader_whole() {
            let body: String = (0..200_000).map(|i| format!("line {i} of a very long article\r\n")).collect();
            let dir = tempfile::tempdir().unwrap();
            let factory = spool(dir.path(), &[article("big", &body)]);
            let svc = NntpService::new(config(), runtime(), factory);
            let addr = svc.start().unwrap();
            let mut c = Client::connect(addr);
            c.line();
            c.send("GROUP misc.test\r\nBODY 1\r\nDATE\r\n");
            c.line();
            assert!(c.line().starts_with("222 1 <big@x.org>"));
            // Read slowly, in small pieces, so that the server is held up.
            let started = Instant::now();
            let mut got = Vec::new();
            let mut buf = [0u8; 8192];
            while !got.ends_with(b"\r\n.\r\n") {
                let n = c.reader.read(&mut buf).unwrap();
                assert!(n > 0, "the connection closed after {} bytes", got.len());
                got.extend_from_slice(&buf[..n]);
                if got.len() < 600_000 {
                    std::thread::sleep(Duration::from_micros(200));
                }
            }
            assert!(started.elapsed() < Duration::from_secs(30));
            assert_eq!(got.len(), body.len() + ".\r\n".len());
            assert!(c.line().starts_with("111 "), "the pipelined DATE was answered after the article");
        }
    }
}
