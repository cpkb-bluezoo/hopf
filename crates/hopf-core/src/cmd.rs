// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Cross-thread commands for a worker reactor.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use mio::net::{TcpStream, UdpSocket};
use mio::{Token, Waker};

use crate::connection::TcpConnection;
use crate::connector::TcpConnParams;
use crate::handler::ProtocolHandler;
use crate::telemetry::TelemetryHook;
use crate::udp::UdpDatagramHandler;

/// Commands delivered to a worker reactor (cross-thread).
pub(crate) enum ReactorCmd {
    /// Register a newly accepted or dialed connection on this reactor.
    Register {
        /// TCP stream.
        stream: TcpStream,
        /// Protocol handler.
        handler: Box<dyn ProtocolHandler>,
        /// Connection parameters.
        params: TcpConnParams,
        /// When true, defer [`ProtocolHandler::connected`] until TCP connect completes.
        connecting: bool,
        /// Optional telemetry hook (on_close / on_error).
        telemetry: Option<Arc<dyn TelemetryHook>>,
    },
    /// Register a UDP socket with a datagram callback.
    RegisterUdp {
        /// Bound (or unbound) UDP socket.
        socket: UdpSocket,
        /// Handler for inbound datagrams.
        handler: Box<dyn UdpDatagramHandler>,
        /// Filled with the assigned token once registered (oneshot via channel).
        token_tx: Sender<Token>,
    },
    /// Send a UDP datagram on a registered socket.
    UdpSend {
        /// Socket token.
        token: Token,
        /// Destination.
        peer: SocketAddr,
        /// Payload.
        data: Vec<u8>,
    },
    /// Deregister and drop a UDP socket.
    DeregisterUdp {
        /// Socket token.
        token: Token,
    },
    /// Run on the reactor thread (from [`crate::Endpoint::execute`] or internal).
    Task(Box<dyn FnOnce() + Send>),
    /// Run on the reactor thread with a specific connection as [`crate::Endpoint`].
    WithConn {
        /// Connection token.
        token: Token,
        /// Task.
        task: Box<dyn FnOnce(&mut TcpConnection) + Send>,
    },
    /// Schedule a timer on this reactor's timer queue.
    ScheduleTimer {
        /// Delay.
        delay: Duration,
        /// Callback.
        callback: Box<dyn FnOnce() + Send>,
        /// Cancel flag.
        cancelled: Arc<AtomicBool>,
    },
    /// Shut down the reactor.
    Shutdown,
}

/// Cloneable handle to enqueue work on a worker reactor.
#[derive(Clone)]
pub struct ReactorHandle {
    tx: Sender<ReactorCmd>,
    waker: Arc<Waker>,
}

impl ReactorHandle {
    /// Enqueue a command and wake the reactor.
    pub(crate) fn send(&self, cmd: ReactorCmd) {
        let _ = self.tx.send(cmd);
        let _ = self.waker.wake();
    }

    /// Queue a task on the reactor thread.
    pub fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        self.send(ReactorCmd::Task(task));
    }

    /// Schedule a timer; returns a cancel flag (`true` = cancelled).
    pub fn schedule_timer(
        &self,
        delay: Duration,
        callback: Box<dyn FnOnce() + Send>,
    ) -> Arc<AtomicBool> {
        let cancelled = Arc::new(AtomicBool::new(false));
        self.send(ReactorCmd::ScheduleTimer {
            delay,
            callback,
            cancelled: Arc::clone(&cancelled),
        });
        cancelled
    }

    /// Register a UDP socket; blocks briefly until the reactor assigns a token.
    pub fn register_udp(
        &self,
        socket: UdpSocket,
        handler: Box<dyn UdpDatagramHandler>,
    ) -> std::io::Result<Token> {
        let (token_tx, token_rx) = mpsc::channel();
        self.send(ReactorCmd::RegisterUdp {
            socket,
            handler,
            token_tx,
        });
        token_rx
            .recv()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "reactor gone"))
    }

    /// Send a datagram on a registered UDP socket.
    pub fn udp_send(&self, token: Token, peer: SocketAddr, data: Vec<u8>) {
        self.send(ReactorCmd::UdpSend { token, peer, data });
    }

    /// Deregister a UDP socket.
    pub fn deregister_udp(&self, token: Token) {
        self.send(ReactorCmd::DeregisterUdp { token });
    }
}

pub(crate) fn channel(waker: Arc<Waker>) -> (ReactorHandle, Receiver<ReactorCmd>) {
    let (tx, rx) = mpsc::channel();
    (
        ReactorHandle {
            tx,
            waker,
        },
        rx,
    )
}
