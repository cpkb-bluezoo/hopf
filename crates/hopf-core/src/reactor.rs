// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-core mio reactor (Gumdrop `SelectorLoop`).

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use mio::net::{TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Token, Waker};

use crate::bufpool::BufferPool;
use crate::cmd::{channel, ReactorCmd, ReactorHandle};
use crate::connection::{ReadOutcome, TcpConnection, WriteOutcome};
use crate::connector::TcpConnParams;
use crate::endpoint::Endpoint;
use crate::handler::ProtocolHandler;
use crate::timer::TimerQueue;
use crate::udp::UdpDatagramHandler;

const WAKER_TOKEN: Token = Token(0);
const FIRST_CONN_TOKEN: usize = 1;

struct UdpRegistration {
    socket: UdpSocket,
    handler: Box<dyn UdpDatagramHandler>,
}

pub(crate) struct Reactor {
    poll: Poll,
    events: Events,
    rx: Receiver<ReactorCmd>,
    handle: ReactorHandle,
    pool: Arc<BufferPool>,
    conns: HashMap<Token, TcpConnection>,
    udps: HashMap<Token, UdpRegistration>,
    next_token: usize,
    timers: TimerQueue,
    active: Arc<AtomicBool>,
}

impl Reactor {
    pub fn spawn(
        id: usize,
        active: Arc<AtomicBool>,
    ) -> io::Result<(ReactorHandle, JoinHandle<()>)> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKER_TOKEN)?);
        let (handle, rx) = channel(Arc::clone(&waker));
        let handle_for_thread = handle.clone();
        let thread = thread::Builder::new()
            .name(format!("hopf-reactor-{id}"))
            .spawn(move || {
                let _id = id;
                // One pool per reactor thread, never shared across threads —
                // every buffer acquire/release for a connection happens on
                // the single reactor thread that owns it for life, so a
                // global lock here has nothing to protect against.
                let pool = Arc::new(BufferPool::default());
                let mut reactor = Reactor {
                    poll,
                    events: Events::with_capacity(256),
                    rx,
                    handle: handle_for_thread,
                    pool,
                    conns: HashMap::new(),
                    udps: HashMap::new(),
                    next_token: FIRST_CONN_TOKEN,
                    timers: TimerQueue::new(),
                    active,
                };
                if let Err(e) = reactor.run() {
                    eprintln!("hopf: reactor {_id} exited with error: {e}");
                }
            })?;
        Ok((handle, thread))
    }

    fn run(&mut self) -> io::Result<()> {
        while self.active.load(Ordering::Acquire) {
            self.drain_commands()?;
            self.timers.fire_due();

            let timeout = self.timers.poll_timeout();
            match self.poll.poll(&mut self.events, timeout) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }

            let mut readable = Vec::new();
            let mut writable = Vec::new();
            let mut wake = false;
            for event in self.events.iter() {
                let token = event.token();
                if token == WAKER_TOKEN {
                    wake = true;
                    continue;
                }
                if event.is_readable() {
                    readable.push(token);
                }
                if event.is_writable() {
                    writable.push(token);
                }
            }
            let _ = wake;

            for token in readable {
                if self.udps.contains_key(&token) {
                    self.handle_udp_readable(token)?;
                } else {
                    self.handle_readable(token)?;
                }
            }
            for token in writable {
                if !self.udps.contains_key(&token) {
                    self.handle_writable(token)?;
                }
            }
        }
        let tokens: Vec<_> = self.conns.keys().copied().collect();
        for token in tokens {
            self.close_conn(token);
        }
        let udp_tokens: Vec<_> = self.udps.keys().copied().collect();
        for token in udp_tokens {
            self.deregister_udp(token);
        }
        Ok(())
    }

    fn drain_commands(&mut self) -> io::Result<()> {
        loop {
            match self.rx.try_recv() {
                Ok(cmd) => self.handle_cmd(cmd)?,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.active.store(false, Ordering::Release);
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_cmd(&mut self, cmd: ReactorCmd) -> io::Result<()> {
        match cmd {
            ReactorCmd::Register {
                stream,
                handler,
                params,
                connecting,
                telemetry,
            } => self.register_connection(stream, handler, params, connecting, telemetry)?,
            ReactorCmd::RegisterUdp {
                socket,
                handler,
                token_tx,
            } => {
                let token = self.register_udp(socket, handler)?;
                let _ = token_tx.send(token);
            }
            ReactorCmd::UdpSend { token, peer, data } => {
                if let Some(reg) = self.udps.get_mut(&token) {
                    let _ = reg.socket.send_to(&data, peer);
                }
            }
            ReactorCmd::DeregisterUdp { token } => {
                self.deregister_udp(token);
            }
            ReactorCmd::Task(task) => task(),
            ReactorCmd::WithConn { token, task } => {
                if let Some(conn) = self.conns.get_mut(&token) {
                    task(conn);
                }
                self.sync_or_close(token)?;
            }
            ReactorCmd::ScheduleTimer {
                delay,
                callback,
                cancelled,
            } => {
                self.timers
                    .schedule_with_cancel(delay, callback, cancelled);
            }
            ReactorCmd::Shutdown => {
                self.active.store(false, Ordering::Release);
            }
        }
        Ok(())
    }

    fn alloc_token(&mut self) -> Token {
        let token = Token(self.next_token);
        self.next_token = self.next_token.wrapping_add(1).max(FIRST_CONN_TOKEN);
        token
    }

    fn register_udp(
        &mut self,
        mut socket: UdpSocket,
        handler: Box<dyn UdpDatagramHandler>,
    ) -> io::Result<Token> {
        let token = self.alloc_token();
        self.poll
            .registry()
            .register(&mut socket, token, Interest::READABLE)?;
        self.udps.insert(token, UdpRegistration { socket, handler });
        Ok(token)
    }

    fn deregister_udp(&mut self, token: Token) {
        if let Some(mut reg) = self.udps.remove(&token) {
            let _ = self.poll.registry().deregister(&mut reg.socket);
        }
    }

    fn handle_udp_readable(&mut self, token: Token) -> io::Result<()> {
        let Some(reg) = self.udps.get_mut(&token) else {
            return Ok(());
        };
        let mut buf = [0u8; 65535];
        loop {
            match reg.socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    let data = buf[..n].to_vec();
                    reg.handler.on_datagram(peer, &data);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        Ok(())
    }

    fn register_connection(
        &mut self,
        mut stream: TcpStream,
        handler: Box<dyn ProtocolHandler>,
        params: TcpConnParams,
        connecting: bool,
        telemetry: Option<std::sync::Arc<dyn crate::telemetry::TelemetryHook>>,
    ) -> io::Result<()> {
        let token = self.alloc_token();
        let connect_timeout = params.connect_timeout;

        let interest = if connecting {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        self.poll.registry().register(&mut stream, token, interest)?;

        let mut conn = TcpConnection::new(
            token,
            stream,
            handler,
            params,
            self.handle.clone(),
            Arc::clone(&self.pool),
            connecting,
            telemetry,
        )?;
        conn.interest = interest;
        conn.registered = true;
        if !connecting {
            conn.call_connected();
        } else {
            let _ = conn.flush_tls_outbound();
            if let Some(timeout) = connect_timeout {
                let cancelled = Arc::new(AtomicBool::new(false));
                conn.set_connect_timeout_cancel(Arc::clone(&cancelled));
                let handle = self.handle.clone();
                self.timers.schedule_with_cancel(
                    timeout,
                    Box::new(move || {
                        handle.send(ReactorCmd::WithConn {
                            token,
                            task: Box::new(|conn| conn.on_connect_timeout()),
                        });
                    }),
                    cancelled,
                );
            }
        }
        if !conn.is_open() {
            let _ = self.poll.registry().deregister(&mut conn.stream);
            conn.release_buffers();
            return Ok(());
        }
        if conn.interest_dirty {
            sync_interest(&self.poll, &mut conn)?;
        }
        self.conns.insert(token, conn);
        Ok(())
    }

    fn handle_readable(&mut self, token: Token) -> io::Result<()> {
        let Some(conn) = self.conns.get_mut(&token) else {
            return Ok(());
        };
        if !conn.is_open() {
            return Ok(());
        }
        if conn.poll_connect() {
            conn.call_connected();
            if !conn.is_open() {
                return Ok(());
            }
        }
        if conn.is_connecting() {
            return Ok(());
        }
        loop {
            match conn.read_from_socket() {
                Ok(ReadOutcome::Bytes) => {
                    conn.process_inbound();
                    if !conn.is_open() {
                        break;
                    }
                }
                Ok(ReadOutcome::Eof) => {
                    conn.force_close();
                    break;
                }
                Ok(ReadOutcome::WouldBlock) => break,
                Err(e) => {
                    conn.call_error(&e);
                    conn.force_close();
                    break;
                }
            }
        }
        if conn.is_open() {
            match conn.write_to_socket() {
                Ok(WriteOutcome::Drained) | Ok(WriteOutcome::WouldBlock) => {}
                Ok(WriteOutcome::CloseAfterFlush) | Ok(WriteOutcome::Closed) => {
                    conn.force_close();
                }
                Err(e) => {
                    conn.call_error(&e);
                    conn.force_close();
                }
            }
        }
        self.sync_or_close(token)
    }

    fn handle_writable(&mut self, token: Token) -> io::Result<()> {
        let Some(conn) = self.conns.get_mut(&token) else {
            return Ok(());
        };
        if !conn.is_open() && !conn.is_closing() {
            return Ok(());
        }
        if conn.poll_connect() {
            conn.call_connected();
            if !conn.is_open() {
                return Ok(());
            }
        }
        match conn.write_to_socket() {
            Ok(WriteOutcome::Drained) | Ok(WriteOutcome::WouldBlock) => {}
            Ok(WriteOutcome::CloseAfterFlush) | Ok(WriteOutcome::Closed) => {
                conn.force_close();
            }
            Err(e) => {
                conn.call_error(&e);
                conn.force_close();
            }
        }
        self.sync_or_close(token)
    }

    /// Reconcile one connection's state after touching it: close it if it's
    /// no longer open, else apply a dirty interest change. O(1) — looked up
    /// by the token that was just handled, never a scan over `conns`.
    fn sync_or_close(&mut self, token: Token) -> io::Result<()> {
        let (open, dirty) = match self.conns.get(&token) {
            Some(conn) => (conn.is_open(), conn.interest_dirty),
            None => return Ok(()),
        };
        if !open {
            self.close_conn(token);
        } else if dirty {
            if let Some(conn) = self.conns.get_mut(&token) {
                sync_interest(&self.poll, conn)?;
            }
        }
        Ok(())
    }

    fn close_conn(&mut self, token: Token) {
        let Some(mut conn) = self.conns.remove(&token) else {
            return;
        };
        if conn.registered {
            let _ = self.poll.registry().deregister(&mut conn.stream);
            conn.registered = false;
        }
        conn.finish_close();
        conn.release_buffers();
    }
}

fn sync_interest(poll: &Poll, conn: &mut TcpConnection) -> io::Result<()> {
    conn.interest_dirty = false;
    if !conn.is_open() {
        return Ok(());
    }
    let desired = conn.compute_interest();
    match (conn.registered, desired) {
        (true, Some(interest)) if interest != conn.interest => {
            poll.registry()
                .reregister(&mut conn.stream, conn.token, interest)?;
            conn.interest = interest;
        }
        (true, Some(interest)) => {
            conn.interest = interest;
        }
        (true, None) => {
            poll.registry().deregister(&mut conn.stream)?;
            conn.registered = false;
        }
        (false, Some(interest)) => {
            poll.registry()
                .register(&mut conn.stream, conn.token, interest)?;
            conn.registered = true;
            conn.interest = interest;
        }
        (false, None) => {}
    }
    Ok(())
}
