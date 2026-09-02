// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The accepted CONNECT-UDP session: relays datagrams between the client
//! (as HTTP Datagrams / Capsule Protocol DATAGRAM capsules) and the
//! resolved target (as real UDP), for the life of the request.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{ConnHandle, ReactorHandle, UdpDatagramHandler};
use hopf_http::capsule::Capsule;
use hopf_http::context_id;
use hopf_http::ProtocolUpgradeHandler;
use mio::Token;

/// State shared between the [`ProtocolUpgradeHandler`] (driven by the HTTP
/// connection's own reactor) and the [`UdpDatagramHandler`] (driven by
/// whichever worker reactor the outbound UDP socket landed on — not
/// necessarily the same thread, and constructed *before* either of those
/// two exists: see [`crate::handler`] for why (opening the outbound socket
/// happens off any reactor thread, to avoid a same-thread deadlock on
/// `ReactorHandle::register_udp`'s blocking round trip; the
/// [`ConnHandle`] to poke only becomes available once the HTTP side
/// accepts, afterward).
pub(crate) struct RelayShared {
    /// Datagrams received from the target, awaiting delivery to the HTTP
    /// peer via [`ProtocolUpgradeHandler::take_outbound`].
    inbound_from_target: Mutex<VecDeque<Vec<u8>>>,
    /// Re-enters the HTTP connection's handler once attached (so a
    /// datagram arriving on the *UDP socket's* thread gets flushed out to
    /// the HTTP peer promptly, not just whenever the connection happens to
    /// next hear from the client) — the same mechanism
    /// `hopf_websocket::WsUpgradeHandler` uses for its own cross-thread
    /// `poke`. `None` until [`attach_conn`] runs; a datagram arriving in
    /// that narrow window still queues normally, just without the prompt
    /// wake-up (the next real activity flushes it).
    conn: Mutex<Option<ConnHandle>>,
    /// Set by either direction's traffic; cleared and checked by the
    /// self-rearming idle timer in [`arm_idle_timer`].
    activity: AtomicBool,
    /// Set once the idle timeout actually elapses with no activity —
    /// checked by [`ProtocolUpgradeHandler::wants_close`].
    expired: AtomicBool,
}

impl RelayShared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inbound_from_target: Mutex::new(VecDeque::new()),
            conn: Mutex::new(None),
            activity: AtomicBool::new(false),
            expired: AtomicBool::new(false),
        })
    }

    fn poke(&self) {
        if let Some(conn) = self.conn.lock().unwrap().as_ref() {
            conn.poke();
        }
    }
}

struct RelayUdpHandler {
    shared: Arc<RelayShared>,
}

impl UdpDatagramHandler for RelayUdpHandler {
    fn on_datagram(&mut self, _peer: SocketAddr, data: &[u8]) {
        // `_peer` is always the one fixed target this socket was ever sent
        // to (RFC 9298 scopes one CONNECT-UDP request to one target) — no
        // further filtering needed.
        self.shared.activity.store(true, Ordering::Release);
        self.shared
            .inbound_from_target
            .lock()
            .unwrap()
            .push_back(data.to_vec());
        self.shared.poke();
    }
}

/// Attach the now-available [`ConnHandle`] (from the HTTP side accepting
/// the request) and start the self-rearming idle timer — both need it,
/// and neither could exist before now (see [`RelayShared`]'s docs).
fn attach_conn(shared: &Arc<RelayShared>, conn: ConnHandle, idle_timeout: Duration) {
    *shared.conn.lock().unwrap() = Some(conn);
    arm_idle_timer(Arc::clone(shared), idle_timeout);
}

/// Self-rearming idle timer (there's no repeating-timer primitive in
/// `hopf_core` to lean on instead): re-arms itself for another
/// `idle_timeout` whenever it finds [`RelayShared::activity`] set (and
/// clears it for the next round), or marks the relay expired once a full
/// `idle_timeout` elapses with none.
fn arm_idle_timer(shared: Arc<RelayShared>, idle_timeout: Duration) {
    let conn = shared
        .conn
        .lock()
        .unwrap()
        .clone()
        .expect("attach_conn always runs before the first arm_idle_timer call");
    let cb_shared = Arc::clone(&shared);
    conn.schedule_timer(
        idle_timeout,
        Box::new(move || {
            if cb_shared.activity.swap(false, Ordering::AcqRel) {
                arm_idle_timer(cb_shared, idle_timeout);
            } else {
                cb_shared.expired.store(true, Ordering::Release);
                cb_shared.poke();
            }
        }),
    );
}

/// [`ProtocolUpgradeHandler`] for an accepted CONNECT-UDP request.
pub(crate) struct ConnectUdpRelay {
    reactor: ReactorHandle,
    udp_token: Token,
    target: SocketAddr,
    shared: Arc<RelayShared>,
}

impl ConnectUdpRelay {
    /// Build the pair to hand to [`hopf_core::ReactorHandle::register_udp`]
    /// — call this **before** registering, and from a thread that is not
    /// itself any reactor worker (registration must not run on one, see
    /// [`crate::handler`]). The returned [`ConnectUdpRelay`] isn't usable
    /// yet ([`ConnHandle`]-dependent behaviour — the idle timer, and
    /// prompt cross-thread wake-ups — stays inert) until
    /// [`Self::accept`] runs, once the HTTP side is ready to install it.
    pub(crate) fn prepare() -> (Arc<RelayShared>, Box<dyn UdpDatagramHandler>) {
        let shared = RelayShared::new();
        let udp_handler: Box<dyn UdpDatagramHandler> = Box::new(RelayUdpHandler {
            shared: Arc::clone(&shared),
        });
        (shared, udp_handler)
    }

    /// Finish building the relay once the outbound socket is registered
    /// (`reactor`/`udp_token`) and the HTTP side has a [`ConnHandle`] to
    /// hand over (`conn`) — install the result via
    /// [`hopf_http::stream::server::ServerWriter::upgrade`].
    pub(crate) fn accept(
        shared: Arc<RelayShared>,
        reactor: ReactorHandle,
        udp_token: Token,
        target: SocketAddr,
        conn: ConnHandle,
        idle_timeout: Duration,
    ) -> Self {
        attach_conn(&shared, conn, idle_timeout);
        Self {
            reactor,
            udp_token,
            target,
            shared,
        }
    }
}

impl ProtocolUpgradeHandler for ConnectUdpRelay {
    fn receive(&mut self, _data: &[u8]) {
        // Real payloads always arrive via `datagram_received` (Capsule
        // Protocol is mandatory for this relay — see `handler.rs`'s accept
        // response) — a non-empty call here would mean the peer sent raw
        // bytes outside the capsule stream, which nothing currently does.
        // An empty call is the cross-thread poke signal; nothing to do
        // here for it either, since `take_outbound` below always drains
        // whatever's queued regardless of what triggered re-entry.
    }

    fn take_outbound(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut queue = self.shared.inbound_from_target.lock().unwrap();
        while let Some(payload) = queue.pop_front() {
            let with_context = context_id::encode(context_id::REGISTERED_CONTEXT_ID, &payload);
            Capsule::datagram(with_context).encode(&mut out);
        }
        out
    }

    fn closed(&mut self) {
        self.reactor.deregister_udp(self.udp_token);
    }

    fn wants_close(&self) -> bool {
        self.shared.expired.load(Ordering::Acquire)
    }

    fn wants_datagrams(&self) -> bool {
        true
    }

    fn datagram_received(&mut self, data: &[u8]) {
        let Some((context_id, payload)) = context_id::decode(data) else {
            return;
        };
        // RFC 9298 §5: ignore a datagram for a Context ID we don't use,
        // rather than treating it as an error.
        if context_id != context_id::REGISTERED_CONTEXT_ID {
            return;
        }
        self.shared.activity.store(true, Ordering::Release);
        self.reactor.udp_send(self.udp_token, self.target, payload.to_vec());
    }
}
