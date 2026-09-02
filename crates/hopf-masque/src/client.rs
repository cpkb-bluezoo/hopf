// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Client side of RFC 9298 CONNECT-UDP: establish a tunnel to a proxy and
//! exchange UDP-payload datagrams with it, over whichever of h1/h2/h3 the
//! shared, transport-negotiating dial path ends up using — see
//! [`connect_udp`].

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Runtime};
use hopf_dns::DnsResolver;
use hopf_http::capsule::{capsule_protocol_enabled, Capsule};
use hopf_http::{
    connect_auto, context_id, ClientHandler, ClientHandlerFactory, ClientWriter, Headers,
    HttpClientTimeouts, HttpFallback, HttpLimits, HttpVersion, ProtocolUpgradeHandler,
};

use crate::target;

/// App callbacks for an outbound CONNECT-UDP tunnel — kept deliberately
/// separate from [`ConnectUdpSession`] (the crate hands the app one of
/// each, not one type playing both roles): they'd both want a no-argument
/// `close`-shaped method with opposite meanings ("I'm done" vs. "please
/// stop"), which is exactly the kind of thing that's easy to merge by
/// accident and get backwards.
pub trait ConnectUdpEventHandler: Send {
    /// The tunnel is open; `session` sends datagrams / asks the proxy to
    /// close it.
    fn opened(&mut self, session: Arc<dyn ConnectUdpSession>);

    /// A UDP payload arrived from the target, via the proxy.
    fn datagram_received(&mut self, data: &[u8]) {
        let _ = data;
    }

    /// The tunnel closed (peer FIN, or the effect of
    /// [`ConnectUdpSession::close`] landing). Default: ignore.
    fn closed(&mut self) {}

    /// The request failed before ever opening — the proxy rejected it, or
    /// the underlying connection failed. Default: ignore.
    fn error(&mut self, err: &io::Error) {
        let _ = err;
    }
}

/// App-facing handle for an open CONNECT-UDP tunnel, handed to
/// [`ConnectUdpEventHandler::opened`]. Safe to hold and call from any
/// thread, not just the one `opened` itself ran on.
pub trait ConnectUdpSession: Send + Sync {
    /// Queue a UDP payload to send to the target, through the proxy.
    fn send_datagram(&self, payload: &[u8]);

    /// Ask the proxy to close this tunnel.
    fn close(&self);
}

struct ClientShared {
    /// Payloads queued by [`ConnectUdpSession::send_datagram`], drained by
    /// [`ProtocolUpgradeHandler::take_outbound`].
    outbound: Mutex<VecDeque<Vec<u8>>>,
    closing: AtomicBool,
    /// Re-enters the HTTP connection's own handler on send/close, so a
    /// datagram queued from the app's own thread — not necessarily the
    /// connection's — gets flushed out promptly via `take_outbound` instead
    /// of only whenever the connection next hears from the peer. Available
    /// from the moment [`ClientShared`] exists (unlike the server-side
    /// relay's `RelayShared`, which has to wait for a `ConnHandle` that
    /// isn't ready yet at construction time — see its own docs): the
    /// client's [`ConnHandle`] comes from `switching_protocols`, which is
    /// exactly where this struct is built.
    conn: ConnHandle,
}

struct ClientSessionHandle {
    shared: Arc<ClientShared>,
}

impl ConnectUdpSession for ClientSessionHandle {
    fn send_datagram(&self, payload: &[u8]) {
        self.shared.outbound.lock().unwrap().push_back(payload.to_vec());
        self.shared.conn.poke();
    }

    fn close(&self) {
        self.shared.closing.store(true, Ordering::Release);
        self.shared.conn.poke();
    }
}

/// [`ProtocolUpgradeHandler`] for an accepted CONNECT-UDP tunnel — bridges
/// the HTTP Datagram / Context ID layer to [`ConnectUdpEventHandler`].
/// Capsule-vs-native-datagram framing is entirely the transport layer's
/// concern (gated on the response's `Capsule-Protocol` header, which this
/// crate's request always sends): this handler only ever sees the decoded
/// HTTP Datagram payload, Context ID and all.
struct ConnectUdpClientUpgrade {
    event: Box<dyn ConnectUdpEventHandler>,
    shared: Arc<ClientShared>,
    opened: bool,
}

impl ConnectUdpClientUpgrade {
    fn ensure_opened(&mut self) {
        if self.opened {
            return;
        }
        self.opened = true;
        let session: Arc<dyn ConnectUdpSession> = Arc::new(ClientSessionHandle {
            shared: Arc::clone(&self.shared),
        });
        self.event.opened(session);
    }
}

impl ProtocolUpgradeHandler for ConnectUdpClientUpgrade {
    fn receive(&mut self, _data: &[u8]) {
        // Real payloads always arrive via `datagram_received` — Capsule
        // Protocol is mandatory for this tunnel (`start` below always
        // requests it), so the transport layer never hands raw bytes to
        // this method with anything in them. A non-empty call would mean
        // the peer sent bytes outside that contract; nothing to recover
        // there. An empty call is the poke signal used to re-enter after
        // cross-thread `ConnectUdpSession` activity — `ensure_opened` plus
        // `take_outbound` draining below cover it either way.
        self.ensure_opened();
    }

    fn take_outbound(&mut self) -> Vec<u8> {
        self.ensure_opened();
        let mut out = Vec::new();
        let mut queue = self.shared.outbound.lock().unwrap();
        while let Some(payload) = queue.pop_front() {
            let with_context = context_id::encode(context_id::REGISTERED_CONTEXT_ID, &payload);
            Capsule::datagram(with_context).encode(&mut out);
        }
        out
    }

    fn closed(&mut self) {
        self.event.closed();
    }

    fn wants_close(&self) -> bool {
        self.shared.closing.load(Ordering::Acquire)
    }

    fn wants_datagrams(&self) -> bool {
        true
    }

    fn datagram_received(&mut self, data: &[u8]) {
        self.ensure_opened();
        let Some((cid, payload)) = context_id::decode(data) else {
            return;
        };
        // RFC 9298 §5: ignore a datagram for a Context ID we don't use,
        // rather than treating it as an error.
        if cid == context_id::REGISTERED_CONTEXT_ID {
            self.event.datagram_received(payload);
        }
    }
}

/// [`ClientHandler`] that builds the CONNECT-UDP request and, once the
/// proxy accepts, installs [`ConnectUdpClientUpgrade`].
struct ConnectUdpClientHandler {
    target_host: String,
    target_port: u16,
    event: Option<Box<dyn ConnectUdpEventHandler>>,
}

impl ClientHandler for ConnectUdpClientHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let path = target::encode(&self.target_host, self.target_port);
        let mut h = Headers::new();
        // The request *shape* genuinely differs by transport — H1 has no
        // `:protocol` pseudo-header (RFC 9110 §7.8 reserves `Upgrade` to
        // H1), H2/H3 use Extended CONNECT (RFC 9220) instead of a literal
        // `Upgrade:` — unlike a plain request, which looks the same
        // everywhere, so this is the one place a CONNECT-UDP client
        // actually needs to know which transport it landed on.
        match request.version() {
            HttpVersion::Http10 | HttpVersion::Http11 => {
                h.set(":method", "GET");
                h.set(":path", &path);
                h.set("Upgrade", "connect-udp");
                h.set("Connection", "Upgrade");
            }
            HttpVersion::Http2 | HttpVersion::Http3 => {
                h.set(":method", "CONNECT");
                h.set(":protocol", "connect-udp");
                h.set(":path", &path);
            }
        }
        h.set("Capsule-Protocol", "?1");
        request.headers(h);
        request.complete_request();
    }

    fn switching_protocols(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        // H2/H3 only ever call this for a `2xx` response to our own
        // Extended CONNECT request in the first place; H1 calls it for
        // any `101`, so check the `Upgrade` token actually matches what
        // we asked for.
        let h1_shape_ok = !matches!(request.version(), HttpVersion::Http10 | HttpVersion::Http11)
            || headers
                .get("upgrade")
                .is_some_and(|u| u.split(',').map(str::trim).any(|p| p.eq_ignore_ascii_case("connect-udp")));
        if !h1_shape_ok || !capsule_protocol_enabled(headers) {
            if let Some(mut event) = self.event.take() {
                event.error(&io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy accepted with an unexpected response shape",
                ));
            }
            return;
        }
        let Some(event) = self.event.take() else {
            return;
        };
        let shared = Arc::new(ClientShared {
            outbound: Mutex::new(VecDeque::new()),
            closing: AtomicBool::new(false),
            conn: request.conn_handle(),
        });
        let handler = ConnectUdpClientUpgrade {
            event,
            shared,
            opened: false,
        };
        request.upgrade(Box::new(handler));
    }

    fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        if let Some(mut event) = self.event.take() {
            event.error(&io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("CONNECT-UDP request rejected: {}", headers.status_code()),
            ));
        }
    }

    fn response_complete(&mut self, _request: &mut dyn ClientWriter) {}

    fn request_failed(&mut self, _request: &mut dyn ClientWriter, err: &io::Error) {
        if let Some(mut event) = self.event.take() {
            event.error(err);
        }
    }
}

struct ConnectUdpClientFactory {
    target_host: String,
    target_port: u16,
    event: Arc<Mutex<Option<Box<dyn ConnectUdpEventHandler>>>>,
}

impl ClientHandlerFactory for ConnectUdpClientFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        // `connect_auto` may construct a handler per dial attempt (h3 tier
        // 1, tier 2, tier 3 fallback) — only the attempt that actually
        // succeeds should get the app's real event handler; the rest see
        // `None` and quietly do nothing on failure (the *next* attempt is
        // what reports the outcome).
        let event = self.event.lock().unwrap().take();
        Box::new(ConnectUdpClientHandler {
            target_host: self.target_host.clone(),
            target_port: self.target_port,
            event,
        })
    }
}

/// Establish a CONNECT-UDP tunnel to the proxy at `proxy_host:proxy_port`,
/// relaying to `target_host:target_port`.
///
/// Transport is negotiated the same way any other request through
/// [`hopf_http::connect_auto`] is — an h3 attempt first (when
/// `quic_client_config` is supplied), falling back to `fallback` — the
/// caller never picks h1/h2/h3 for this any more than for a plain request;
/// see [`HttpFallback`] for what's actually available for the fallback tier
/// (TLS+ALPN is the right choice whenever the proxy might also be reached
/// over h3, since an origin that speaks h3 at all is HTTPS-only).
#[allow(clippy::too_many_arguments)]
pub fn connect_udp(
    rt: &Arc<Runtime>,
    proxy_host: &str,
    proxy_port: u16,
    target_host: impl Into<String>,
    target_port: u16,
    fallback: HttpFallback,
    event_handler: Box<dyn ConnectUdpEventHandler>,
    quic_client_config: Option<Arc<hopf_quic::QuicClientConfig>>,
    alt_svc_cache: Arc<hopf_http::AltSvcCache>,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(ConnectUdpClientFactory {
        target_host: target_host.into(),
        target_port,
        event: Arc::new(Mutex::new(Some(event_handler))),
    });
    connect_auto(
        rt,
        proxy_host,
        proxy_port,
        factory,
        HttpLimits::default(),
        fallback,
        timeouts,
        resolver,
        quic_client_config,
        alt_svc_cache,
    )
}
