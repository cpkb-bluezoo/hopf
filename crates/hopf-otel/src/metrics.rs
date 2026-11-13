// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Server metrics instruments (HTTP + SMTP) for OTLP/JSONL export.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::batch::ExportHandle;

/// One metric data point for export.
#[derive(Debug, Clone)]
pub enum MetricPoint {
    /// Counter increment.
    Counter {
        /// Name.
        name: &'static str,
        /// Attributes.
        attributes: Vec<(String, String)>,
        /// Delta.
        value: u64,
    },
    /// Histogram observation.
    Histogram {
        /// Name.
        name: &'static str,
        /// Unit.
        unit: &'static str,
        /// Attributes.
        attributes: Vec<(String, String)>,
        /// Observed value.
        value: f64,
    },
    /// UpDown absolute (for gauges we export as sum non-monotonic snapshot — simplified).
    UpDown {
        /// Name.
        name: &'static str,
        /// Attributes.
        attributes: Vec<(String, String)>,
        /// Current value.
        value: i64,
    },
}

/// HTTP server metrics instruments.
pub struct HttpServerMetrics {
    export: ExportHandle,
    active_requests: AtomicI64,
    active_connections: AtomicI64,
}

impl HttpServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self {
            export,
            active_requests: AtomicI64::new(0),
            active_connections: AtomicI64::new(0),
        })
    }

    /// Connection accepted (transport may also call separately).
    pub fn connection_opened(&self) {
        let v = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "http.server.active_connections",
            attributes: Vec::new(),
            value: v,
        });
    }

    /// Connection closed.
    pub fn connection_closed(&self) {
        let v = self.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "http.server.active_connections",
            attributes: Vec::new(),
            value: v.max(0),
        });
    }

    /// Request started.
    pub fn request_started(&self, method: &str) {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        let active = self.active_requests.load(Ordering::Relaxed);
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "http.server.active_requests",
            attributes: vec![("http.method".into(), method.into())],
            value: active,
        });
    }

    /// Request completed.
    pub fn request_completed(
        &self,
        method: &str,
        status: u16,
        duration: std::time::Duration,
        request_size: u64,
        response_size: u64,
    ) {
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
        let method_a = ("http.method".into(), method.to_string());
        let status_a = ("http.status_code".into(), status.to_string());
        self.export.try_send_metric(MetricPoint::Counter {
            name: "http.server.requests",
            attributes: vec![method_a.clone(), status_a.clone()],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "http.server.request.duration",
            unit: "ms",
            attributes: vec![method_a.clone(), status_a.clone()],
            value: duration.as_secs_f64() * 1000.0,
        });
        if request_size > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "http.server.request.size",
                unit: "By",
                attributes: vec![method_a.clone()],
                value: request_size as f64,
            });
        }
        if response_size > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "http.server.response.size",
                unit: "By",
                attributes: vec![method_a, status_a],
                value: response_size as f64,
            });
        }
        let active = self.active_requests.load(Ordering::Relaxed);
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "http.server.active_requests",
            attributes: vec![("http.method".into(), method.into())],
            value: active.max(0),
        });
    }
}

/// SMTP server metrics instruments (OTLP export).
pub struct SmtpServerMetrics {
    export: ExportHandle,
    active_connections: AtomicI64,
}

impl SmtpServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self {
            export,
            active_connections: AtomicI64::new(0),
        })
    }

    /// Control connection accepted.
    pub fn connection_opened(&self) {
        let v = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.export.try_send_metric(MetricPoint::Counter {
            name: "smtp.server.connections",
            attributes: Vec::new(),
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "smtp.server.active_connections",
            attributes: Vec::new(),
            value: v,
        });
    }

    /// Control connection closed.
    pub fn connection_closed(&self) {
        let v = self.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "smtp.server.active_connections",
            attributes: Vec::new(),
            value: v.max(0),
        });
    }

    /// AUTH attempt finished.
    pub fn auth(&self, ok: bool) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "smtp.server.auth",
            attributes: vec![(
                "result".into(),
                if ok { "ok" } else { "fail" }.into(),
            )],
            value: 1,
        });
    }

    /// STARTTLS completed.
    pub fn starttls(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "smtp.server.starttls",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// Mail transaction finished (MAIL FROM → DATA end / RSET / disconnect).
    ///
    /// `outcome` is typically `"accepted"` or `"aborted"`.
    pub fn transaction_completed(
        &self,
        outcome: &str,
        duration: std::time::Duration,
        message_size: u64,
    ) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "smtp.server.messages",
            attributes: vec![("outcome".into(), outcome.into())],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "smtp.server.transaction.duration",
            unit: "ms",
            attributes: vec![("outcome".into(), outcome.into())],
            value: duration.as_secs_f64() * 1000.0,
        });
        if outcome == "accepted" && message_size > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "smtp.server.message.size",
                unit: "By",
                attributes: Vec::new(),
                value: message_size as f64,
            });
        }
    }
}

/// FTP server metrics instruments (OTLP export).
pub struct FtpServerMetrics {
    export: ExportHandle,
    active_connections: AtomicI64,
}

impl FtpServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self {
            export,
            active_connections: AtomicI64::new(0),
        })
    }

    /// Control connection accepted.
    pub fn connection_opened(&self) {
        let v = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.export.try_send_metric(MetricPoint::Counter {
            name: "ftp.server.connections",
            attributes: Vec::new(),
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "ftp.server.active_connections",
            attributes: Vec::new(),
            value: v,
        });
    }

    /// Control connection closed.
    pub fn connection_closed(&self) {
        let v = self.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "ftp.server.active_connections",
            attributes: Vec::new(),
            value: v.max(0),
        });
    }

    /// USER/PASS authentication attempt finished.
    pub fn auth(&self, ok: bool) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "ftp.server.auth",
            attributes: vec![(
                "result".into(),
                if ok { "ok" } else { "fail" }.into(),
            )],
            value: 1,
        });
    }

    /// One control command processed.
    pub fn command(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "ftp.server.commands",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// PASV/EPSV listener bound.
    pub fn pasv_bind(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "ftp.server.pasv_binds",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// Data transfer finished (RETR/STOR/LIST/…).
    ///
    /// `direction` is typically `"download"`, `"upload"`, or `"listing"`.
    /// `outcome` is `"ok"` or `"fail"`.
    pub fn transfer_completed(
        &self,
        direction: &str,
        outcome: &str,
        duration: std::time::Duration,
        bytes: u64,
    ) {
        let dir_a = ("ftp.transfer.direction".into(), direction.into());
        let out_a = ("outcome".into(), outcome.into());
        self.export.try_send_metric(MetricPoint::Counter {
            name: "ftp.server.transfers",
            attributes: vec![dir_a.clone(), out_a.clone()],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "ftp.server.transfer.duration",
            unit: "ms",
            attributes: vec![dir_a.clone(), out_a],
            value: duration.as_secs_f64() * 1000.0,
        });
        if outcome == "ok" && bytes > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "ftp.server.transfer.size",
                unit: "By",
                attributes: vec![dir_a],
                value: bytes as f64,
            });
        }
    }
}

/// POP3 server metrics instruments (OTLP export).
pub struct Pop3ServerMetrics {
    export: ExportHandle,
    active_connections: AtomicI64,
}

impl Pop3ServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self {
            export,
            active_connections: AtomicI64::new(0),
        })
    }

    /// Control connection accepted.
    pub fn connection_opened(&self) {
        let v = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.export.try_send_metric(MetricPoint::Counter {
            name: "pop3.server.connections",
            attributes: Vec::new(),
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "pop3.server.active_connections",
            attributes: Vec::new(),
            value: v,
        });
    }

    /// Control connection closed.
    pub fn connection_closed(&self) {
        let v = self.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "pop3.server.active_connections",
            attributes: Vec::new(),
            value: v.max(0),
        });
    }

    /// USER/PASS / AUTH attempt finished.
    pub fn auth(&self, ok: bool) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "pop3.server.auth",
            attributes: vec![(
                "result".into(),
                if ok { "ok" } else { "fail" }.into(),
            )],
            value: 1,
        });
    }

    /// STLS upgrade completed.
    pub fn stls(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "pop3.server.stls",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// DELE mark applied.
    pub fn dele(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "pop3.server.dele",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// RETR or TOP retrieve finished.
    ///
    /// `kind` is typically `"retr"` or `"top"`. `outcome` is `"ok"` or `"fail"`.
    pub fn retrieve_completed(
        &self,
        kind: &str,
        outcome: &str,
        duration: std::time::Duration,
        bytes: u64,
    ) {
        let kind_a = ("pop3.retrieve.kind".into(), kind.into());
        let out_a = ("outcome".into(), outcome.into());
        self.export.try_send_metric(MetricPoint::Counter {
            name: "pop3.server.retrieves",
            attributes: vec![kind_a.clone(), out_a.clone()],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "pop3.server.retrieve.duration",
            unit: "ms",
            attributes: vec![kind_a.clone(), out_a],
            value: duration.as_secs_f64() * 1000.0,
        });
        if outcome == "ok" && bytes > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "pop3.server.retrieve.size",
                unit: "By",
                attributes: vec![kind_a],
                value: bytes as f64,
            });
        }
    }
}

/// IMAP server metrics instruments (OTLP export).
pub struct ImapServerMetrics {
    export: ExportHandle,
    active_connections: AtomicI64,
}

impl ImapServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self {
            export,
            active_connections: AtomicI64::new(0),
        })
    }

    /// Control connection accepted.
    pub fn connection_opened(&self) {
        let v = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.export.try_send_metric(MetricPoint::Counter {
            name: "imap.server.connections",
            attributes: Vec::new(),
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "imap.server.active_connections",
            attributes: Vec::new(),
            value: v,
        });
    }

    /// Control connection closed.
    pub fn connection_closed(&self) {
        let v = self.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "imap.server.active_connections",
            attributes: Vec::new(),
            value: v.max(0),
        });
    }

    /// LOGIN / AUTHENTICATE attempt finished.
    pub fn auth(&self, ok: bool) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "imap.server.auth",
            attributes: vec![(
                "result".into(),
                if ok { "ok" } else { "fail" }.into(),
            )],
            value: 1,
        });
    }

    /// STARTTLS completed.
    pub fn starttls(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "imap.server.starttls",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// COMPRESS DEFLATE negotiated.
    pub fn compress(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "imap.server.compress",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// One tagged command finished.
    ///
    /// `verb` is the IMAP command name (e.g. `"FETCH"`). `outcome` is `"ok"` or `"fail"`.
    pub fn command_completed(
        &self,
        verb: &str,
        outcome: &str,
        duration: std::time::Duration,
    ) {
        let verb_a = ("imap.command.verb".into(), verb.into());
        let out_a = ("outcome".into(), outcome.into());
        self.export.try_send_metric(MetricPoint::Counter {
            name: "imap.server.commands",
            attributes: vec![verb_a.clone(), out_a.clone()],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "imap.server.command.duration",
            unit: "ms",
            attributes: vec![verb_a, out_a],
            value: duration.as_secs_f64() * 1000.0,
        });
    }
}

/// MQTT server metrics instruments (OTLP export).
pub struct MqttServerMetrics {
    export: ExportHandle,
    active_connections: AtomicI64,
}

impl MqttServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self {
            export,
            active_connections: AtomicI64::new(0),
        })
    }

    /// Control connection accepted.
    pub fn connection_opened(&self) {
        let v = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.export.try_send_metric(MetricPoint::Counter {
            name: "mqtt.server.connections",
            attributes: Vec::new(),
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "mqtt.server.active_connections",
            attributes: Vec::new(),
            value: v,
        });
    }

    /// Control connection closed.
    pub fn connection_closed(&self) {
        let v = self.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "mqtt.server.active_connections",
            attributes: Vec::new(),
            value: v.max(0),
        });
    }

    /// CONNECT authorization finished.
    pub fn auth(&self, ok: bool) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "mqtt.server.auth",
            attributes: vec![(
                "result".into(),
                if ok { "ok" } else { "fail" }.into(),
            )],
            value: 1,
        });
    }

    /// SUBSCRIBE processed (one packet, may contain multiple filters).
    pub fn subscribe(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "mqtt.server.subscribes",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// Client PUBLISH finished (after payload streamed).
    ///
    /// `qos` is `"0"`, `"1"`, or `"2"`. `outcome` is `"ok"` or `"fail"`.
    pub fn publish_completed(
        &self,
        qos: &str,
        outcome: &str,
        duration: std::time::Duration,
        bytes: u64,
    ) {
        let qos_a = ("mqtt.publish.qos".into(), qos.into());
        let out_a = ("outcome".into(), outcome.into());
        self.export.try_send_metric(MetricPoint::Counter {
            name: "mqtt.server.publishes",
            attributes: vec![qos_a.clone(), out_a.clone()],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "mqtt.server.publish.duration",
            unit: "ms",
            attributes: vec![qos_a.clone(), out_a],
            value: duration.as_secs_f64() * 1000.0,
        });
        if outcome == "ok" && bytes > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "mqtt.server.publish.size",
                unit: "By",
                attributes: vec![qos_a],
                value: bytes as f64,
            });
        }
    }
}

/// Timing helper for one request / transaction.
#[derive(Debug)]
pub struct RequestTimer {
    start: Instant,
}

impl RequestTimer {
    /// Start.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Elapsed.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}

/// The standard name of a DNS response code, for the `dns.response.code`
/// attribute; a code with no name is `RCODE<n>`.
fn rcode_name(rcode: u16) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        6 => "YXDOMAIN".into(),
        7 => "YXRRSET".into(),
        8 => "NXRRSET".into(),
        9 => "NOTAUTH".into(),
        10 => "NOTZONE".into(),
        other => format!("RCODE{other}"),
    }
}

/// DNS server metrics instruments (OTLP export).
///
/// Every point carries a `dns.transport` attribute (`udp`, `tcp`, `dot` or
/// `doq`). Names:
///
/// | Name | Kind | Meaning |
/// |---|---|---|
/// | `dns.server.queries` | counter | messages received |
/// | `dns.server.responses` | counter | answers sent, with `dns.response.code` |
/// | `dns.server.query.duration` | histogram, ms | time from receipt to the answer being ready |
/// | `dns.server.cache.hits` | counter | answers served from the cache |
/// | `dns.server.upstream.queries` | counter | queries forwarded to an upstream |
/// | `dns.server.stale_served` | counter | answers served stale because the upstream failed |
/// | `dns.server.aggressive_nsec_hits` | counter | negative answers built from cached NSEC/NSEC3 proofs |
/// | `dns.server.errors` | counter | handler errors |
/// | `dns.server.cookies.presented` | counter | queries carrying a DNS Cookie |
/// | `dns.server.cookies.verified` | counter | of those, with a verified server cookie |
/// | `dns.server.mqtype.queries` | counter | RFC 10029 multiple-QTYPE queries acted on |
/// | `dns.server.mqtype.subqueries` | counter | sub-queries those were expanded into |
pub struct DnsServerMetrics {
    export: ExportHandle,
}

impl DnsServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self { export })
    }

    fn count(&self, name: &'static str, transport: &str, value: u64) {
        self.export.try_send_metric(MetricPoint::Counter {
            name,
            attributes: vec![("dns.transport".into(), transport.into())],
            value,
        });
    }

    /// A message was received.
    pub fn query_received(&self, transport: &str) {
        self.count("dns.server.queries", transport, 1);
    }

    /// An answer is ready to send, `duration` after the message arrived.
    pub fn response_sent(&self, transport: &str, rcode: u16, duration: std::time::Duration) {
        let transport_a = ("dns.transport".to_string(), transport.to_string());
        self.export.try_send_metric(MetricPoint::Counter {
            name: "dns.server.responses",
            attributes: vec![transport_a.clone(), ("dns.response.code".into(), rcode_name(rcode))],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "dns.server.query.duration",
            unit: "ms",
            attributes: vec![transport_a],
            value: duration.as_secs_f64() * 1000.0,
        });
    }

    /// An answer was served from the cache.
    pub fn cache_hit(&self, transport: &str) {
        self.count("dns.server.cache.hits", transport, 1);
    }

    /// A query was forwarded to an upstream.
    pub fn upstream_query(&self, transport: &str) {
        self.count("dns.server.upstream.queries", transport, 1);
    }

    /// An answer was served stale (RFC 8767) because the upstream failed.
    pub fn stale_served(&self, transport: &str) {
        self.count("dns.server.stale_served", transport, 1);
    }

    /// A negative answer was built from cached NSEC/NSEC3 proofs (RFC 8198).
    pub fn aggressive_nsec_hit(&self, transport: &str) {
        self.count("dns.server.aggressive_nsec_hits", transport, 1);
    }

    /// A handler error.
    pub fn error(&self, transport: &str) {
        self.count("dns.server.errors", transport, 1);
    }

    /// A query carried a DNS Cookie (RFC 7873).
    pub fn cookie_presented(&self, transport: &str) {
        self.count("dns.server.cookies.presented", transport, 1);
    }

    /// A presented server cookie was verified.
    pub fn cookie_verified(&self, transport: &str) {
        self.count("dns.server.cookies.verified", transport, 1);
    }

    /// A multiple-QTYPE query (RFC 10029) was expanded into `subqueries`.
    pub fn multi_qtype(&self, transport: &str, subqueries: u64) {
        self.count("dns.server.mqtype.queries", transport, 1);
        if subqueries > 0 {
            self.count("dns.server.mqtype.subqueries", transport, subqueries);
        }
    }
}

/// DNS upstream client metrics instruments (OTLP export), one set of points
/// per upstream.
///
/// Every point carries `dns.upstream` (the resolver's address) and
/// `dns.transport` (`dot` or `doq`). Names:
///
/// | Name | Kind | Meaning |
/// |---|---|---|
/// | `dns.upstream.queries` | counter | queries sent |
/// | `dns.upstream.responses` | counter | answers received |
/// | `dns.upstream.query.duration` | histogram, ms | time to an answer |
/// | `dns.upstream.timeouts` | counter | queries that timed out |
/// | `dns.upstream.failures` | counter | queries that failed for another reason |
/// | `dns.upstream.retries` | counter | queries sent again after a lost connection |
/// | `dns.upstream.connects` | counter | connections established |
/// | `dns.upstream.connect_failures` | counter | connections that did not come up |
/// | `dns.upstream.reconnects` | counter | connections opened after an earlier one |
/// | `dns.upstream.connections` | up-down | connections open (the pool size) |
/// | `dns.upstream.in_flight` | up-down | queries sent or waiting, not yet completed |
pub struct DnsUpstreamMetrics {
    export: ExportHandle,
}

impl DnsUpstreamMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self { export })
    }

    fn attrs(upstream: &str, transport: &str) -> Vec<(String, String)> {
        vec![
            ("dns.upstream".into(), upstream.into()),
            ("dns.transport".into(), transport.into()),
        ]
    }

    /// Increment the counter `name` for this upstream.
    pub fn count(&self, name: &'static str, upstream: &str, transport: &str) {
        self.export.try_send_metric(MetricPoint::Counter {
            name,
            attributes: Self::attrs(upstream, transport),
            value: 1,
        });
    }

    /// An answer arrived `duration` after the query was made.
    pub fn response(&self, upstream: &str, transport: &str, duration: std::time::Duration) {
        self.count("dns.upstream.responses", upstream, transport);
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "dns.upstream.query.duration",
            unit: "ms",
            attributes: Self::attrs(upstream, transport),
            value: duration.as_secs_f64() * 1000.0,
        });
    }

    /// The number of open connections is now `value`.
    pub fn connections(&self, upstream: &str, transport: &str, value: i64) {
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "dns.upstream.connections",
            attributes: Self::attrs(upstream, transport),
            value,
        });
    }

    /// The number of queries sent or waiting is now `value`.
    pub fn in_flight(&self, upstream: &str, transport: &str, value: i64) {
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "dns.upstream.in_flight",
            attributes: Self::attrs(upstream, transport),
            value,
        });
    }
}

#[cfg(all(test, feature = "integration"))]
mod tests {
    use super::*;
    use crate::batch::spawn_worker;
    use crate::config::OtelConfig;

    #[test]
    fn smtp_transaction_emits_duration_to_jsonl() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-smtp-tx-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("smtp-tx-test").with_jsonl_metrics(&dir);
        let (handle, join, _running) = spawn_worker(cfg);
        let metrics = SmtpServerMetrics::new(handle.clone());
        metrics.connection_opened();
        metrics.transaction_completed(
            "accepted",
            std::time::Duration::from_millis(12),
            100,
        );
        metrics.connection_closed();
        handle.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        handle.shutdown();
        let _ = join.join();
        let body = std::fs::read_to_string(&dir).unwrap_or_default();
        assert!(
            body.contains("smtp.server.transaction.duration"),
            "missing duration metric: {body}"
        );
        assert!(body.contains("smtp.server.messages"), "{body}");
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn ftp_transfer_emits_duration_to_jsonl() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-ftp-tx-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("ftp-tx-test").with_jsonl_metrics(&dir);
        let (handle, join, _running) = spawn_worker(cfg);
        let metrics = FtpServerMetrics::new(handle.clone());
        metrics.connection_opened();
        metrics.transfer_completed(
            "download",
            "ok",
            std::time::Duration::from_millis(5),
            42,
        );
        metrics.connection_closed();
        handle.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        handle.shutdown();
        let _ = join.join();
        let body = std::fs::read_to_string(&dir).unwrap_or_default();
        assert!(
            body.contains("ftp.server.transfer.duration"),
            "missing duration metric: {body}"
        );
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn pop3_retrieve_emits_duration_to_jsonl() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-pop3-tx-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("pop3-tx-test").with_jsonl_metrics(&dir);
        let (handle, join, _running) = spawn_worker(cfg);
        let metrics = Pop3ServerMetrics::new(handle.clone());
        metrics.connection_opened();
        metrics.retrieve_completed(
            "retr",
            "ok",
            std::time::Duration::from_millis(7),
            100,
        );
        metrics.connection_closed();
        handle.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        handle.shutdown();
        let _ = join.join();
        let body = std::fs::read_to_string(&dir).unwrap_or_default();
        assert!(
            body.contains("pop3.server.retrieve.duration"),
            "missing duration metric: {body}"
        );
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn imap_command_emits_duration_to_jsonl() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-imap-cmd-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("imap-cmd-test").with_jsonl_metrics(&dir);
        let (handle, join, _running) = spawn_worker(cfg);
        let metrics = ImapServerMetrics::new(handle.clone());
        metrics.connection_opened();
        metrics.command_completed(
            "FETCH",
            "ok",
            std::time::Duration::from_millis(9),
        );
        metrics.connection_closed();
        handle.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        handle.shutdown();
        let _ = join.join();
        let body = std::fs::read_to_string(&dir).unwrap_or_default();
        assert!(
            body.contains("imap.server.command.duration"),
            "missing duration metric: {body}"
        );
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn mqtt_publish_emits_duration_to_jsonl() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-mqtt-pub-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("mqtt-pub-test").with_jsonl_metrics(&dir);
        let (handle, join, _running) = spawn_worker(cfg);
        let metrics = MqttServerMetrics::new(handle.clone());
        metrics.connection_opened();
        metrics.publish_completed(
            "0",
            "ok",
            std::time::Duration::from_millis(4),
            32,
        );
        metrics.connection_closed();
        handle.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        handle.shutdown();
        let _ = join.join();
        let body = std::fs::read_to_string(&dir).unwrap_or_default();
        assert!(
            body.contains("mqtt.server.publish.duration"),
            "missing duration metric: {body}"
        );
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn dns_server_metrics_emit_transport_and_response_code() {
        let path = std::env::temp_dir().join(format!("hopf-otel-dns-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cfg = OtelConfig::new("dns-test").with_jsonl_metrics(&path);
        let (handle, join, _running) = spawn_worker(cfg);
        let m = DnsServerMetrics::new(handle.clone());
        m.query_received("udp");
        m.response_sent("udp", 3, std::time::Duration::from_millis(7));
        m.cache_hit("dot");
        m.multi_qtype("tcp", 2);
        handle.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        handle.shutdown();
        let _ = join.join();
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        for needle in [
            "dns.server.queries",
            "dns.server.responses",
            "NXDOMAIN",
            "dns.server.query.duration",
            "dns.server.cache.hits",
            "dns.server.mqtype.subqueries",
            "dns.transport",
        ] {
            assert!(body.contains(needle), "missing {needle}: {body}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dns_upstream_metrics_emit_the_upstream_and_transport() {
        let path = std::env::temp_dir().join(format!("hopf-otel-dnsup-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cfg = OtelConfig::new("dnsup-test").with_jsonl_metrics(&path);
        let (handle, join, _running) = spawn_worker(cfg);
        let m = DnsUpstreamMetrics::new(handle.clone());
        m.count("dns.upstream.queries", "192.0.2.1:853", "dot");
        m.response("192.0.2.1:853", "dot", std::time::Duration::from_millis(3));
        m.connections("192.0.2.1:853", "dot", 1);
        m.in_flight("192.0.2.1:853", "dot", 2);
        handle.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        handle.shutdown();
        let _ = join.join();
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        for needle in ["dns.upstream.queries", "dns.upstream.query.duration", "dns.upstream.connections", "dns.upstream.in_flight", "192.0.2.1:853", "dns.upstream"] {
            assert!(body.contains(needle), "missing {needle}: {body}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn runtime_state_and_drain_reach_the_metrics_sink() {
        let path = std::env::temp_dir().join(format!("hopf-otel-runtime-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let pipeline =
            crate::pipeline::TelemetryPipeline::start(OtelConfig::new("runtime-test").with_jsonl_metrics(&path)).unwrap();
        let hook = pipeline.hook();
        hook.on_runtime_state(true, false);
        hook.on_bind_failure("0.0.0.0:25", "address in use");
        hook.on_runtime_state(false, true);
        hook.on_drain_complete(3, std::time::Duration::from_millis(250));
        pipeline.export_handle().flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        for needle in [
            "hopf.runtime.ready",
            "hopf.runtime.draining",
            "hopf.runtime.bind_failures",
            "0.0.0.0:25",
            "hopf.runtime.drain.forced_connections",
            "hopf.runtime.drain.duration",
        ] {
            assert!(body.contains(needle), "missing {needle}: {body}");
        }
        let _ = std::fs::remove_file(&path);
    }
}

impl hopf_dns::telemetry::DnsServerTelemetry for DnsServerMetrics {
    fn query_received(&self, transport: &str) {
        DnsServerMetrics::query_received(self, transport);
    }
    fn response_sent(&self, transport: &str, rcode: u16, duration: std::time::Duration) {
        DnsServerMetrics::response_sent(self, transport, rcode, duration);
    }
    fn cache_hit(&self, transport: &str) {
        DnsServerMetrics::cache_hit(self, transport);
    }
    fn upstream_query(&self, transport: &str) {
        DnsServerMetrics::upstream_query(self, transport);
    }
    fn stale_served(&self, transport: &str) {
        DnsServerMetrics::stale_served(self, transport);
    }
    fn aggressive_nsec_hit(&self, transport: &str) {
        DnsServerMetrics::aggressive_nsec_hit(self, transport);
    }
    fn error(&self, transport: &str) {
        DnsServerMetrics::error(self, transport);
    }
    fn cookie_presented(&self, transport: &str) {
        DnsServerMetrics::cookie_presented(self, transport);
    }
    fn cookie_verified(&self, transport: &str) {
        DnsServerMetrics::cookie_verified(self, transport);
    }
    fn multi_qtype(&self, transport: &str, subqueries: u64) {
        DnsServerMetrics::multi_qtype(self, transport, subqueries);
    }
}

impl hopf_dns::telemetry::DnsUpstreamTelemetry for DnsUpstreamMetrics {
    fn event(&self, upstream: &str, transport: &str, event: hopf_dns::telemetry::UpstreamEvent) {
        use hopf_dns::telemetry::UpstreamEvent as E;
        let name = match event {
            E::Query => "dns.upstream.queries",
            E::Timeout => "dns.upstream.timeouts",
            E::Failure => "dns.upstream.failures",
            E::Retry => "dns.upstream.retries",
            E::Connect => "dns.upstream.connects",
            E::ConnectFailure => "dns.upstream.connect_failures",
            E::Reconnect => "dns.upstream.reconnects",
            // A kind added to the (non-exhaustive) enum later is counted
            // under a generic name rather than lost.
            _ => "dns.upstream.events",
        };
        self.count(name, upstream, transport);
    }
    fn response(&self, upstream: &str, transport: &str, duration: std::time::Duration) {
        DnsUpstreamMetrics::response(self, upstream, transport, duration);
    }
    fn connections(&self, upstream: &str, transport: &str, value: i64) {
        DnsUpstreamMetrics::connections(self, upstream, transport, value);
    }
    fn in_flight(&self, upstream: &str, transport: &str, value: i64) {
        DnsUpstreamMetrics::in_flight(self, upstream, transport, value);
    }
}
