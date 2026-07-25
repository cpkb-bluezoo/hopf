// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Composition XML loader (tractrix). Elements and attributes only.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tractrix::{FeatureSet, ParseError, ParseResult, Parser, XmlHandler};

use crate::acl::{AcceptRateLimit, IpNet, PeerAcl};
use crate::connector::TcpConnectorConfig;
use crate::listener::{
    HandlerFactory, TcpListenerConfig, DEFAULT_MAX_NET_IN, DEFAULT_MAX_NET_OUT,
};
use crate::runtime::RuntimeConfig;
use crate::storage::StorageConfig;

use super::{Composition, CompositionRegistry};

/// Result of loading composition XML.
pub type CompositionXmlResult<T> = Result<T, CompositionXmlError>;

/// Errors from composition XML parse / schema / registry resolution.
#[derive(Debug)]
pub enum CompositionXmlError {
    /// Well-formedness or tractrix parse failure.
    Parse(String),
    /// Unknown element/attribute or invalid value.
    Schema(String),
    /// `handler` name not in the registry.
    Registry(String),
    /// Filesystem error ([`Composition::from_xml_path`](super::Composition::from_xml_path)).
    Io(io::Error),
}

impl fmt::Display for CompositionXmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(m) | Self::Schema(m) | Self::Registry(m) => write!(f, "{m}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CompositionXmlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ParseError> for CompositionXmlError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e.to_string())
    }
}

/// Parse bytes into a [`Composition`] using `registry` for `handler` lookup.
///
/// Starts the Runtime and applies every parsed binding immediately (the
/// returned `Composition` is already running); `telemetry` must be supplied
/// here since it can only be attached at Runtime start.
pub(super) fn parse_composition(
    bytes: &[u8],
    registry: &CompositionRegistry,
    telemetry: Option<std::sync::Arc<dyn crate::telemetry::TelemetryHook>>,
) -> CompositionXmlResult<Composition> {
    let doc = parse_document(bytes)?;
    let resolved = doc.resolve(registry)?;

    let mut comp = Composition::new_with_telemetry(resolved.config, telemetry)
        .map_err(CompositionXmlError::Io)?;
    for cfg in resolved.listens {
        comp.listen_tcp(cfg).map_err(CompositionXmlError::Io)?;
    }
    for cfg in resolved.dials {
        comp.dial_tcp(cfg).map_err(CompositionXmlError::Io)?;
    }
    Ok(comp)
}

/// Parse bytes into a [`CompositionDocument`] (attributes only — no registry
/// lookup, no Runtime). Split out from [`parse_composition`] so attribute
/// parsing is testable without registering handlers or starting reactors.
fn parse_document(bytes: &[u8]) -> CompositionXmlResult<CompositionDocument> {
    let mut handler = CompositionXmlHandler::new();
    let features = FeatureSet::default();
    {
        let mut parser = Parser::new(&mut handler, &features, None, None, None)
            .map_err(CompositionXmlError::from)?;
        parser
            .parse_all(Bytes::copy_from_slice(bytes))
            .map_err(CompositionXmlError::from)?;
    }
    if let Some(err) = handler.error.take() {
        return Err(err);
    }
    handler
        .doc
        .take()
        .ok_or_else(|| CompositionXmlError::Schema("missing root <composition>".into()))
}

#[derive(Default)]
struct CompositionDocument {
    worker_threads: Option<usize>,
    storage_threads: Option<usize>,
    listens: Vec<ListenDoc>,
    dials: Vec<DialDoc>,
}

#[derive(Default)]
struct ListenDoc {
    addr: Option<String>,
    handler: Option<String>,
    max_net_in: Option<usize>,
    max_net_out: Option<usize>,
    idle_timeout_ms: Option<u64>,
    allow: Vec<String>,
    deny: Vec<String>,
    rate_limit: Option<RateDoc>,
}

#[derive(Default)]
struct DialDoc {
    addr: Option<String>,
    handler: Option<String>,
    max_net_in: Option<usize>,
    max_net_out: Option<usize>,
    idle_timeout_ms: Option<u64>,
    connect_timeout_ms: Option<u64>,
}

#[derive(Default)]
struct RateDoc {
    per_source: Option<u32>,
    window_ms: Option<u64>,
    global: Option<u32>,
}

/// Fully-resolved bindings from a parsed `<composition>` document — defaults
/// applied, `handler` names looked up in the registry — but not yet applied
/// to a live Runtime. Kept separate from [`Composition`] so attribute
/// parsing can be tested without starting reactor threads.
struct ResolvedComposition {
    config: RuntimeConfig,
    listens: Vec<TcpListenerConfig>,
    dials: Vec<TcpConnectorConfig>,
}

impl CompositionDocument {
    fn resolve(self, registry: &CompositionRegistry) -> CompositionXmlResult<ResolvedComposition> {
        let mut config = RuntimeConfig::default();
        if let Some(n) = self.worker_threads {
            config.worker_threads = n;
        }
        if let Some(n) = self.storage_threads {
            config.storage = StorageConfig {
                threads: n.max(1),
                ..StorageConfig::default()
            };
        }

        let mut listens = Vec::with_capacity(self.listens.len());
        let mut dials = Vec::with_capacity(self.dials.len());

        for listen in self.listens {
            let addr = parse_addr(
                listen
                    .addr
                    .as_deref()
                    .ok_or_else(|| CompositionXmlError::Schema(
                        "<listen-tcp> requires addr".into(),
                    ))?,
            )?;
            let factory = resolve_handler(
                registry,
                listen
                    .handler
                    .as_deref()
                    .ok_or_else(|| CompositionXmlError::Schema(
                        "<listen-tcp> requires handler".into(),
                    ))?,
            )?;
            let mut cfg = TcpListenerConfig {
                addr,
                factory,
                max_net_in: listen.max_net_in.unwrap_or(DEFAULT_MAX_NET_IN),
                max_net_out: listen.max_net_out.unwrap_or(DEFAULT_MAX_NET_OUT),
                idle_timeout: listen
                    .idle_timeout_ms
                    .map(Duration::from_millis),
                secure: false,
                tls: None,
                acl: PeerAcl::open(),
                rate_limit: None,
            };
            let mut acl = PeerAcl::open();
            for c in &listen.allow {
                acl.allow.push(parse_cidr(c)?);
            }
            for c in &listen.deny {
                acl.deny.push(parse_cidr(c)?);
            }
            cfg.acl = acl;
            if let Some(rate) = listen.rate_limit {
                let per_source = rate.per_source.ok_or_else(|| {
                    CompositionXmlError::Schema("<rate-limit> requires per-source".into())
                })?;
                let window_ms = rate.window_ms.ok_or_else(|| {
                    CompositionXmlError::Schema("<rate-limit> requires window-ms".into())
                })?;
                let global = rate.global.unwrap_or(0);
                cfg.rate_limit = Some(AcceptRateLimit::new(
                    per_source,
                    Duration::from_millis(window_ms),
                    global,
                ));
            }
            listens.push(cfg);
        }

        for dial in self.dials {
            let addr = parse_addr(
                dial.addr
                    .as_deref()
                    .ok_or_else(|| CompositionXmlError::Schema(
                        "<dial-tcp> requires addr".into(),
                    ))?,
            )?;
            let factory = resolve_handler(
                registry,
                dial.handler
                    .as_deref()
                    .ok_or_else(|| CompositionXmlError::Schema(
                        "<dial-tcp> requires handler".into(),
                    ))?,
            )?;
            let cfg = TcpConnectorConfig {
                addr,
                factory,
                max_net_in: dial.max_net_in.unwrap_or(DEFAULT_MAX_NET_IN),
                max_net_out: dial.max_net_out.unwrap_or(DEFAULT_MAX_NET_OUT),
                idle_timeout: dial.idle_timeout_ms.map(Duration::from_millis),
                connect_timeout: dial.connect_timeout_ms.map(Duration::from_millis),
                secure: false,
                tls: None,
                server_name: None,
            };
            dials.push(cfg);
        }

        Ok(ResolvedComposition {
            config,
            listens,
            dials,
        })
    }
}

fn resolve_handler(
    registry: &CompositionRegistry,
    name: &str,
) -> CompositionXmlResult<HandlerFactory> {
    registry.get(name).cloned().ok_or_else(|| {
        CompositionXmlError::Registry(format!("unknown handler {name:?}"))
    })
}

fn parse_addr(s: &str) -> CompositionXmlResult<SocketAddr> {
    s.parse()
        .map_err(|e| CompositionXmlError::Schema(format!("invalid addr {s:?}: {e}")))
}

fn parse_cidr(s: &str) -> CompositionXmlResult<IpNet> {
    IpNet::parse(s).ok_or_else(|| CompositionXmlError::Schema(format!("invalid cidr {s:?}")))
}

fn parse_usize(name: &str, v: &str) -> CompositionXmlResult<usize> {
    v.parse()
        .map_err(|_| CompositionXmlError::Schema(format!("invalid {name} value {v:?}")))
}

fn parse_u64(name: &str, v: &str) -> CompositionXmlResult<u64> {
    v.parse()
        .map_err(|_| CompositionXmlError::Schema(format!("invalid {name} value {v:?}")))
}

fn parse_u32(name: &str, v: &str) -> CompositionXmlResult<u32> {
    v.parse()
        .map_err(|_| CompositionXmlError::Schema(format!("invalid {name} value {v:?}")))
}

struct CompositionXmlHandler {
    stack: Vec<String>,
    pending_attrs: HashMap<String, String>,
    cur_attr: Option<(String, String)>,
    doc: Option<CompositionDocument>,
    current_listen: Option<ListenDoc>,
    current_dial: Option<DialDoc>,
    error: Option<CompositionXmlError>,
}

impl CompositionXmlHandler {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            pending_attrs: HashMap::new(),
            cur_attr: None,
            doc: None,
            current_listen: None,
            current_dial: None,
            error: None,
        }
    }

    fn fail(&mut self, err: CompositionXmlError) -> ParseResult<()> {
        if self.error.is_none() {
            self.error = Some(err);
        }
        Err(ParseError::new(
            self.error
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "composition xml error".into()),
        ))
    }

    fn parent(&self) -> Option<&str> {
        if self.stack.len() >= 2 {
            Some(self.stack[self.stack.len() - 2].as_str())
        } else {
            None
        }
    }

    fn open_element(&mut self, name: &str, attrs: HashMap<String, String>) -> ParseResult<()> {
        match name {
            "composition" => {
                if self.doc.is_some() {
                    return self.fail(CompositionXmlError::Schema(
                        "duplicate <composition> root".into(),
                    ));
                }
                if !self.stack.is_empty() && self.stack.len() != 1 {
                    return self.fail(CompositionXmlError::Schema(
                        "<composition> must be the document root".into(),
                    ));
                }
                let mut doc = CompositionDocument::default();
                for (k, v) in attrs {
                    match k.as_str() {
                        "worker-threads" => {
                            doc.worker_threads = Some(match parse_usize(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "storage-threads" => {
                            doc.storage_threads = Some(match parse_usize(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        other => {
                            return self.fail(CompositionXmlError::Schema(format!(
                                "unknown <composition> attribute {other:?}"
                            )));
                        }
                    }
                }
                self.doc = Some(doc);
            }
            "listen-tcp" => {
                if self.parent() != Some("composition") {
                    return self.fail(CompositionXmlError::Schema(
                        "<listen-tcp> must be a child of <composition>".into(),
                    ));
                }
                if self.current_listen.is_some() || self.current_dial.is_some() {
                    return self.fail(CompositionXmlError::Schema(
                        "nested <listen-tcp> is not allowed".into(),
                    ));
                }
                let mut listen = ListenDoc::default();
                for (k, v) in attrs {
                    match k.as_str() {
                        "addr" => listen.addr = Some(v),
                        "handler" => listen.handler = Some(v),
                        "max-net-in" => {
                            listen.max_net_in = Some(match parse_usize(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "max-net-out" => {
                            listen.max_net_out = Some(match parse_usize(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "idle-timeout-ms" => {
                            listen.idle_timeout_ms = Some(match parse_u64(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "secure" | "tls-cert" | "tls-key" | "tls" => {
                            return self.fail(CompositionXmlError::Schema(format!(
                                "attribute {k:?} is not supported in composition XML v1"
                            )));
                        }
                        other => {
                            return self.fail(CompositionXmlError::Schema(format!(
                                "unknown <listen-tcp> attribute {other:?}"
                            )));
                        }
                    }
                }
                self.current_listen = Some(listen);
            }
            "dial-tcp" => {
                if self.parent() != Some("composition") {
                    return self.fail(CompositionXmlError::Schema(
                        "<dial-tcp> must be a child of <composition>".into(),
                    ));
                }
                if self.current_listen.is_some() || self.current_dial.is_some() {
                    return self.fail(CompositionXmlError::Schema(
                        "nested <dial-tcp> is not allowed".into(),
                    ));
                }
                let mut dial = DialDoc::default();
                for (k, v) in attrs {
                    match k.as_str() {
                        "addr" => dial.addr = Some(v),
                        "handler" => dial.handler = Some(v),
                        "max-net-in" => {
                            dial.max_net_in = Some(match parse_usize(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "max-net-out" => {
                            dial.max_net_out = Some(match parse_usize(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "idle-timeout-ms" => {
                            dial.idle_timeout_ms = Some(match parse_u64(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "connect-timeout-ms" => {
                            dial.connect_timeout_ms = Some(match parse_u64(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "secure" | "tls-cert" | "tls-key" | "tls" | "server-name" => {
                            return self.fail(CompositionXmlError::Schema(format!(
                                "attribute {k:?} is not supported in composition XML v1"
                            )));
                        }
                        other => {
                            return self.fail(CompositionXmlError::Schema(format!(
                                "unknown <dial-tcp> attribute {other:?}"
                            )));
                        }
                    }
                }
                self.current_dial = Some(dial);
            }
            "allow" | "deny" => {
                if self.parent() != Some("listen-tcp") {
                    return self.fail(CompositionXmlError::Schema(format!(
                        "<{name}> must be a child of <listen-tcp>"
                    )));
                }
                let cidr = attrs.get("cidr").cloned().ok_or_else(|| {
                    ParseError::new(format!("<{name}> requires cidr attribute"))
                })?;
                if attrs.keys().any(|k| k != "cidr") {
                    return self.fail(CompositionXmlError::Schema(format!(
                        "<{name}> only accepts cidr"
                    )));
                }
                let listen = self.current_listen.as_mut().ok_or_else(|| {
                    ParseError::new(format!("<{name}> without open <listen-tcp>"))
                })?;
                if name == "allow" {
                    listen.allow.push(cidr);
                } else {
                    listen.deny.push(cidr);
                }
            }
            "rate-limit" => {
                if self.parent() != Some("listen-tcp") {
                    return self.fail(CompositionXmlError::Schema(
                        "<rate-limit> must be a child of <listen-tcp>".into(),
                    ));
                }
                let mut rate = RateDoc::default();
                for (k, v) in attrs {
                    match k.as_str() {
                        "per-source" => {
                            rate.per_source = Some(match parse_u32(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "window-ms" => {
                            rate.window_ms = Some(match parse_u64(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        "global" => {
                            rate.global = Some(match parse_u32(&k, &v) {
                                Ok(n) => n,
                                Err(e) => return self.fail(e),
                            });
                        }
                        other => {
                            return self.fail(CompositionXmlError::Schema(format!(
                                "unknown <rate-limit> attribute {other:?}"
                            )));
                        }
                    }
                }
                let listen = self.current_listen.as_mut().ok_or_else(|| {
                    ParseError::new("<rate-limit> without open <listen-tcp>")
                })?;
                if listen.rate_limit.is_some() {
                    return self.fail(CompositionXmlError::Schema(
                        "duplicate <rate-limit> on <listen-tcp>".into(),
                    ));
                }
                listen.rate_limit = Some(rate);
            }
            other => {
                return self.fail(CompositionXmlError::Schema(format!(
                    "unknown element <{other}>"
                )));
            }
        }
        Ok(())
    }

    fn close_element(&mut self, name: &str) -> ParseResult<()> {
        match name {
            "listen-tcp" => {
                let listen = self.current_listen.take().ok_or_else(|| {
                    ParseError::new("</listen-tcp> without open element")
                })?;
                let doc = self.doc.as_mut().ok_or_else(|| {
                    ParseError::new("<listen-tcp> outside <composition>")
                })?;
                doc.listens.push(listen);
            }
            "dial-tcp" => {
                let dial = self.current_dial.take().ok_or_else(|| {
                    ParseError::new("</dial-tcp> without open element")
                })?;
                let doc = self.doc.as_mut().ok_or_else(|| {
                    ParseError::new("<dial-tcp> outside <composition>")
                })?;
                doc.dials.push(dial);
            }
            "composition" | "allow" | "deny" | "rate-limit" => {}
            _ => {}
        }
        Ok(())
    }
}

impl XmlHandler for CompositionXmlHandler {
    fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
        if self.error.is_some() {
            return Err(ParseError::new("composition xml error"));
        }
        self.stack.push(q_name.to_string());
        self.pending_attrs.clear();
        self.cur_attr = None;
        Ok(())
    }

    fn start_attribute(
        &mut self,
        name: &str,
        _ty: &str,
        _declared: bool,
        _specified: bool,
    ) -> ParseResult<()> {
        self.cur_attr = Some((name.to_string(), String::new()));
        Ok(())
    }

    fn attribute_value_content(&mut self, value: &str, end: bool) -> ParseResult<()> {
        if let Some((_, ref mut buf)) = self.cur_attr {
            buf.push_str(value);
        }
        if end {
            if let Some((name, val)) = self.cur_attr.take() {
                self.pending_attrs.insert(name, val);
            }
        }
        Ok(())
    }

    fn end_attributes(&mut self) -> ParseResult<()> {
        let name = self
            .stack
            .last()
            .cloned()
            .ok_or_else(|| ParseError::new("end_attributes with empty stack"))?;
        let attrs = std::mem::take(&mut self.pending_attrs);
        self.open_element(&name, attrs)
    }

    fn characters(&mut self, text: &str, _ignorable: bool, _end: bool) -> ParseResult<()> {
        if text.chars().any(|c| !c.is_whitespace()) {
            return self.fail(CompositionXmlError::Schema(
                "composition XML does not allow character data".into(),
            ));
        }
        Ok(())
    }

    fn end_element(&mut self) -> ParseResult<()> {
        let name = self
            .stack
            .pop()
            .ok_or_else(|| ParseError::new("end_element with empty stack"))?;
        self.close_element(&name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[cfg(feature = "integration")]
    use std::io::{Read, Write};
    #[cfg(feature = "integration")]
    use std::net::TcpStream;
    #[cfg(feature = "integration")]
    use std::thread;
    #[cfg(feature = "integration")]
    use std::time::Duration;

    use crate::endpoint::Endpoint;
    use crate::handler::ProtocolHandler;

    struct Echo;
    impl ProtocolHandler for Echo {
        fn connected(&mut self, _: &mut dyn Endpoint) {}
        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            endpoint.send(data);
            *data = &[];
        }
        fn disconnected(&mut self, _: &mut dyn Endpoint) {}
        fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
    }

    fn echo_registry() -> CompositionRegistry {
        let mut reg = CompositionRegistry::new();
        reg.register(
            "echo",
            Arc::new(|| Box::new(Echo) as Box<dyn ProtocolHandler>),
        );
        reg
    }

    #[test]
    fn parse_listen_and_dial_attrs() {
        let xml = r#"<?xml version="1.0"?>
<composition worker-threads="2" storage-threads="4">
  <listen-tcp addr="127.0.0.1:0" handler="echo"
              max-net-in="1024" max-net-out="2048" idle-timeout-ms="1000">
    <allow cidr="10.0.0.0/8"/>
    <deny cidr="192.0.2.0/24"/>
    <rate-limit per-source="10" window-ms="1000" global="100"/>
  </listen-tcp>
  <dial-tcp addr="127.0.0.1:9" handler="echo" max-net-in="512" connect-timeout-ms="3000"/>
</composition>"#;
        let doc = parse_document(xml.as_bytes()).expect("parse");
        let resolved = doc.resolve(&echo_registry()).expect("resolve");
        assert_eq!(resolved.config.worker_threads, 2);
        assert_eq!(resolved.config.storage.threads, 4);
        assert_eq!(resolved.listens.len(), 1);
        assert_eq!(resolved.dials.len(), 1);
        let listen = &resolved.listens[0];
        assert_eq!(listen.max_net_in, 1024);
        assert_eq!(listen.max_net_out, 2048);
        assert_eq!(listen.idle_timeout, Some(Duration::from_millis(1000)));
        assert_eq!(listen.acl.allow.len(), 1);
        assert_eq!(listen.acl.deny.len(), 1);
        assert!(listen.rate_limit.is_some());
        assert_eq!(resolved.dials[0].max_net_in, 512);
        assert_eq!(resolved.dials[0].max_net_out, DEFAULT_MAX_NET_OUT);
        assert_eq!(
            resolved.dials[0].connect_timeout,
            Some(Duration::from_millis(3000))
        );
    }

    #[test]
    fn unknown_handler() {
        let xml = r#"<composition><listen-tcp addr="127.0.0.1:0" handler="nope"/></composition>"#;
        let err = match Composition::from_xml_str(xml, &echo_registry()) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(matches!(err, CompositionXmlError::Registry(_)), "{err}");
    }

    #[test]
    fn reject_character_data() {
        let xml = r#"<composition>hello</composition>"#;
        let err = match Composition::from_xml_str(xml, &echo_registry()) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(err.to_string().contains("character data"), "{err}");
    }

    #[test]
    fn reject_secure_attr() {
        let xml =
            r#"<composition><listen-tcp addr="127.0.0.1:0" handler="echo" secure="true"/></composition>"#;
        let err = match Composition::from_xml_str(xml, &echo_registry()) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(err.to_string().contains("v1"), "{err}");
    }

    #[test]
    fn bad_addr() {
        let xml =
            r#"<composition><listen-tcp addr="not-an-addr" handler="echo"/></composition>"#;
        let err = match Composition::from_xml_str(xml, &echo_registry()) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(matches!(err, CompositionXmlError::Schema(_)), "{err}");
    }

    #[test]
    #[cfg(feature = "integration")]
    fn build_echo_from_xml() {
        let xml = r#"<composition worker-threads="2">
  <listen-tcp addr="127.0.0.1:0" handler="echo"/>
</composition>"#;
        let comp = Composition::from_xml_str(xml, &echo_registry()).expect("parse+build");
        let addr = comp.primary_addr().unwrap();
        thread::sleep(Duration::from_millis(50));
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        comp.shutdown();
    }
}
