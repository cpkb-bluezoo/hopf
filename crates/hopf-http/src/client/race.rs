// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Connecting to the several addresses a name resolves to (RFC 8305, "Happy
//! Eyeballs" version 2).
//!
//! Dialing only the first address fails a request that another address would
//! have served: an IPv6 address on an IPv4-only network, or a dead A record.
//! [`connect_any`] tries them in the order RFC 8305 section 4 gives (the
//! address families alternating, starting with the first the resolver
//! returned), starts the next when the previous has not connected after a
//! short delay (section 5, 250 ms by default), and starts it at once when the
//! previous has failed. The first connection to be established wins; the
//! others are closed, or never started.
//!
//! The application's handler is made only for the winner (the dial's handler
//! is wrapped in a [`Gated`] one that holds back every event until its
//! connection wins), so it is never told about an attempt that lost, and a
//! handler factory is called once however many addresses were tried. The
//! application hears of a failure only when every address has failed.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Endpoint, LoopBuf, ProtocolHandler, Runtime, SecurityInfo};

/// RFC 8305 section 5: the "Connection Attempt Delay" a client should use.
pub(crate) const DEFAULT_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Dials one address; the handler it connects with must be one made by
/// [`Attempt::gate`].
pub(crate) type Dial = Arc<dyn Fn(SocketAddr, Attempt) -> io::Result<()> + Send + Sync>;

/// Called, once, if no address could be connected.
pub(crate) type Failure = Box<dyn FnOnce(io::Error) + Send>;

/// Makes the handler for the connection that wins.
pub(crate) type MakeHandler = Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync>;

/// `addrs` in the order to try them: the families alternating, starting with
/// the family of the first, each family in the order given (RFC 8305 section
/// 4). An address given twice is tried once.
pub(crate) fn order(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut unique: Vec<SocketAddr> = Vec::with_capacity(addrs.len());
    for a in addrs {
        if !unique.contains(&a) {
            unique.push(a);
        }
    }
    let Some(first) = unique.first().copied() else {
        return unique;
    };
    let (same, other): (Vec<_>, Vec<_>) = unique.into_iter().partition(|a| a.is_ipv4() == first.is_ipv4());
    let (mut same, mut other) = (same.into_iter(), other.into_iter());
    let mut out = Vec::new();
    loop {
        match (same.next(), other.next()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}

struct State {
    /// The index of the next address to start.
    next: usize,
    /// Attempts started that have neither won nor failed.
    outstanding: usize,
    won: bool,
    last_error: Option<(io::ErrorKind, String)>,
}

/// One connection race over a list of addresses.
pub(crate) struct Race {
    rt: Arc<Runtime>,
    addrs: Vec<SocketAddr>,
    delay: Duration,
    dial: Dial,
    state: Mutex<State>,
    on_failure: Mutex<Option<Failure>>,
}

/// The right to make one attempt of a [`Race`]: what the dial turns into the
/// handler for its connection.
pub(crate) struct Attempt(Arc<Race>);

impl Attempt {
    /// The handler to connect with: it holds `make`'s handler back until this
    /// connection has won the race, and only then makes it.
    pub(crate) fn gate(self, make: MakeHandler) -> Box<dyn ProtocolHandler> {
        Box::new(Gated { race: self.0, make, inner: None, phase: Phase::Pending })
    }
}

/// Connect to the first of `addrs` to answer, and make the winning
/// connection's handler with the dial's `make`. See the module documentation.
/// `on_failure` is called, once, if there are no addresses or none connects.
pub(crate) fn connect_any(rt: &Arc<Runtime>, addrs: Vec<SocketAddr>, delay: Duration, dial: Dial, on_failure: Failure) {
    let addrs = order(addrs);
    if addrs.is_empty() {
        on_failure(io::Error::new(io::ErrorKind::NotFound, "no address to connect to"));
        return;
    }
    let race = Arc::new(Race {
        rt: Arc::clone(rt),
        addrs,
        delay,
        dial,
        state: Mutex::new(State { next: 0, outstanding: 0, won: false, last_error: None }),
        on_failure: Mutex::new(Some(on_failure)),
    });
    race.launch(0);
}

enum Next {
    Launch(usize),
    Fail(io::Error),
    Nothing,
}

impl Race {
    /// Start attempt `index`, if it has not been started (by a failure ahead
    /// of the timer) and the race is not over, and arrange for the one after
    /// it to start if this one has not connected by then.
    fn launch(self: &Arc<Self>, index: usize) {
        let addr = {
            let mut st = self.state.lock().unwrap();
            if st.won || st.next != index {
                return;
            }
            st.next += 1;
            st.outstanding += 1;
            self.addrs[index]
        };
        if index + 1 < self.addrs.len() {
            let race = Arc::clone(self);
            self.rt.pick_worker().schedule_timer(self.delay, Box::new(move || race.launch(index + 1)));
        }
        if let Err(e) = (self.dial)(addr, Attempt(Arc::clone(self))) {
            self.attempt_failed(&e);
        }
    }

    /// This connection is established. True if it is the first to be, and so
    /// the one to use.
    fn claim(&self) -> bool {
        let mut st = self.state.lock().unwrap();
        !std::mem::replace(&mut st.won, true)
    }

    /// An attempt failed before it connected: go on to the next address at
    /// once (RFC 8305 section 5), or, if that was the last chance, fail.
    fn attempt_failed(self: &Arc<Self>, err: &io::Error) {
        let next = {
            let mut st = self.state.lock().unwrap();
            st.outstanding = st.outstanding.saturating_sub(1);
            st.last_error = Some((err.kind(), err.to_string()));
            if st.won {
                Next::Nothing
            } else if st.next < self.addrs.len() {
                Next::Launch(st.next)
            } else if st.outstanding == 0 {
                let (kind, why) = st.last_error.clone().unwrap_or((io::ErrorKind::Other, String::new()));
                let tried = self.addrs.len();
                let msg = if tried > 1 { format!("{why} (tried {tried} addresses)") } else { why };
                Next::Fail(io::Error::new(kind, msg))
            } else {
                Next::Nothing
            }
        };
        match next {
            Next::Launch(i) => self.launch(i),
            Next::Fail(e) => {
                if let Some(f) = self.on_failure.lock().unwrap().take() {
                    f(e);
                }
            }
            Next::Nothing => {}
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Phase {
    /// Dialing: not connected, not failed.
    Pending,
    /// This connection won the race: its events go to the real handler.
    Won,
    /// This attempt failed or lost: its events go nowhere.
    Out,
}

/// The handler for one attempt: it reports a failure to the race and passes
/// nothing on until it has won.
struct Gated {
    race: Arc<Race>,
    make: MakeHandler,
    inner: Option<Box<dyn ProtocolHandler>>,
    phase: Phase,
}

impl Gated {
    /// The connection is up: true if the real handler is to be told.
    fn claim(&mut self, endpoint: &mut dyn Endpoint) -> bool {
        match self.phase {
            Phase::Won => true,
            Phase::Out => false,
            Phase::Pending if self.race.claim() => {
                self.phase = Phase::Won;
                self.inner = Some((self.make)());
                true
            }
            Phase::Pending => {
                // Another address connected first.
                self.phase = Phase::Out;
                endpoint.close();
                false
            }
        }
    }

    fn failed(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        if self.phase == Phase::Pending {
            self.phase = Phase::Out;
            self.race.attempt_failed(err);
        }
        endpoint.close();
    }
}

impl ProtocolHandler for Gated {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.claim(endpoint) {
            if let Some(inner) = self.inner.as_mut() {
                inner.connected(endpoint);
            }
        }
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        if self.claim(endpoint) {
            if let Some(inner) = self.inner.as_mut() {
                inner.security_established(endpoint, info);
            }
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut LoopBuf) {
        if let Some(inner) = self.inner.as_mut() {
            inner.receive(endpoint, buf);
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        match self.inner.as_mut() {
            Some(inner) => inner.disconnected(endpoint),
            None if self.phase == Phase::Pending => {
                self.failed(endpoint, &io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed before it was established"));
            }
            None => {}
        }
    }

    fn migrated(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(inner) = self.inner.as_mut() {
            inner.migrated(endpoint);
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        match self.inner.as_mut() {
            Some(inner) => inner.error(endpoint, err),
            None => self.failed(endpoint, err),
        }
    }

    fn datagram_received(&mut self, endpoint: &mut dyn Endpoint, data: &[u8]) {
        if let Some(inner) = self.inner.as_mut() {
            inner.datagram_received(endpoint, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::testing::Peer;
    use hopf_core::{NopHandler, RuntimeConfig};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_alternate_between_the_families_starting_with_the_first() {
        let v6 = |n: u16| a(&format!("[2001:db8::{n}]:80"));
        let v4 = |n: u8| a(&format!("192.0.2.{n}:80"));
        assert_eq!(order(vec![v6(1), v6(2), v6(3), v4(1), v4(2)]), [v6(1), v4(1), v6(2), v4(2), v6(3)]);
        assert_eq!(order(vec![v4(1), v4(2), v6(1)]), [v4(1), v6(1), v4(2)], "the family of the first address leads");
        assert_eq!(order(vec![v4(1), v4(2), v4(3)]), [v4(1), v4(2), v4(3)]);
        assert_eq!(order(vec![v6(1), v6(1), v4(1), v4(1)]), [v6(1), v4(1)], "an address given twice is tried once");
        assert!(order(vec![]).is_empty());
        assert_eq!(order(vec![v4(1)]), [v4(1)]);
    }

    /// A race over `n` addresses whose dial only records the attempt, with the
    /// handlers it gets kept to be driven by the test.
    struct Rig {
        rt: Arc<Runtime>,
        launched: Arc<Mutex<Vec<(SocketAddr, Instant)>>>,
        handlers: Arc<Mutex<Vec<Arc<Mutex<Box<dyn ProtocolHandler>>>>>>,
        made: Arc<AtomicUsize>,
        failures: Arc<Mutex<Vec<io::Error>>>,
    }

    impl Rig {
        fn start(n: u8, delay: Duration) -> Self {
            let rig = Self {
                rt: Arc::new(Runtime::start(RuntimeConfig::default()).unwrap()),
                launched: Arc::default(),
                handlers: Arc::default(),
                made: Arc::default(),
                failures: Arc::default(),
            };
            let (launched, handlers, made) = (Arc::clone(&rig.launched), Arc::clone(&rig.handlers), Arc::clone(&rig.made));
            let dial: Dial = Arc::new(move |addr, attempt| {
                launched.lock().unwrap().push((addr, Instant::now()));
                let made = Arc::clone(&made);
                let make: MakeHandler = Arc::new(move || {
                    made.fetch_add(1, Ordering::SeqCst);
                    Box::new(NopHandler) as Box<dyn ProtocolHandler>
                });
                handlers.lock().unwrap().push(Arc::new(Mutex::new(attempt.gate(make))));
                Ok(())
            });
            let failures = Arc::clone(&rig.failures);
            let addrs = (1..=n).map(|i| a(&format!("192.0.2.{i}:80"))).collect();
            connect_any(&rig.rt, addrs, delay, dial, Box::new(move |e| failures.lock().unwrap().push(e)));
            rig
        }

        fn launched(&self) -> usize {
            self.launched.lock().unwrap().len()
        }

        /// Wait up to `ms` for `n` attempts to have been started.
        fn wait_launched(&self, n: usize, ms: u64) -> bool {
            wait(|| self.launched() >= n, ms)
        }

        /// Run `f` on attempt `i`'s handler with a fresh endpoint.
        fn drive<R>(&self, i: usize, f: impl FnOnce(&mut dyn ProtocolHandler, &mut dyn Endpoint) -> R) -> (R, bool) {
            let mut peer = Peer::connect(NopHandler, |_| false);
            // Only this handler is locked while it runs: a failure starts the
            // next attempt, whose dial adds to the list.
            let handler = Arc::clone(&self.handlers.lock().unwrap()[i]);
            let r = f(handler.lock().unwrap().as_mut(), peer.endpoint());
            (r, peer.is_closed())
        }

        fn fail(&self, i: usize, kind: io::ErrorKind) {
            self.drive(i, |h, ep| h.error(ep, &io::Error::new(kind, "no route")));
        }
    }

    fn wait(pred: impl Fn() -> bool, ms: u64) -> bool {
        let end = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < end {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        pred()
    }

    #[test]
    fn the_next_address_is_started_when_the_previous_has_not_connected_after_the_delay() {
        let rig = Rig::start(3, Duration::from_millis(60));
        assert_eq!(rig.launched(), 1, "one at a time at first");
        assert!(rig.wait_launched(3, 2000));
        let times: Vec<Instant> = rig.launched.lock().unwrap().iter().map(|(_, t)| *t).collect();
        assert!(times[1] - times[0] >= Duration::from_millis(55), "{:?}", times[1] - times[0]);
        assert!(times[2] - times[1] >= Duration::from_millis(55), "{:?}", times[2] - times[1]);
        assert!(rig.failures.lock().unwrap().is_empty(), "attempts under way are not a failure");
    }

    #[test]
    fn a_failed_attempt_starts_the_next_at_once_not_after_the_delay() {
        let rig = Rig::start(2, Duration::from_secs(30));
        assert_eq!(rig.launched(), 1);
        rig.fail(0, io::ErrorKind::ConnectionRefused);
        assert!(rig.wait_launched(2, 1000), "the second address was not tried until the delay ended");
        assert!(rig.failures.lock().unwrap().is_empty());
    }

    #[test]
    fn the_first_to_connect_wins_and_the_others_are_closed_and_never_hear_of_it() {
        let rig = Rig::start(2, Duration::from_millis(20));
        assert!(rig.wait_launched(2, 1000));
        let (_, closed) = rig.drive(1, |h, ep| h.connected(ep));
        assert!(!closed, "the winner is kept");
        assert_eq!(rig.made.load(Ordering::SeqCst), 1, "its handler is made");
        // the other one connects too, late
        let (_, closed) = rig.drive(0, |h, ep| h.connected(ep));
        assert!(closed, "the loser is closed");
        assert_eq!(rig.made.load(Ordering::SeqCst), 1, "no handler is made for it");
        // and its closing, or a failure, is nothing to anyone
        rig.fail(0, io::ErrorKind::ConnectionReset);
        assert!(rig.failures.lock().unwrap().is_empty());
    }

    #[test]
    fn a_win_stops_the_addresses_not_yet_started() {
        let rig = Rig::start(3, Duration::from_millis(80));
        rig.drive(0, |h, ep| h.connected(ep));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(rig.launched(), 1, "the timers found the race over");
    }

    #[test]
    fn a_tls_connection_that_establishes_security_first_also_wins() {
        let rig = Rig::start(1, Duration::from_millis(20));
        let info = SecurityInfo::plaintext();
        rig.drive(0, |h, ep| h.security_established(ep, &info));
        assert_eq!(rig.made.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn when_every_address_fails_the_caller_is_told_once_with_the_last_error() {
        let rig = Rig::start(3, Duration::from_secs(30));
        rig.fail(0, io::ErrorKind::TimedOut);
        assert!(rig.wait_launched(2, 1000));
        rig.fail(1, io::ErrorKind::ConnectionReset);
        assert!(rig.wait_launched(3, 1000));
        assert!(rig.failures.lock().unwrap().is_empty(), "one address is left");
        rig.fail(2, io::ErrorKind::ConnectionRefused);
        let failures = rig.failures.lock().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind(), io::ErrorKind::ConnectionRefused);
        assert!(failures[0].to_string().contains("tried 3 addresses"), "{}", failures[0]);
        assert_eq!(rig.made.load(Ordering::SeqCst), 0, "the application's handler was never made");
    }

    #[test]
    fn a_single_address_that_fails_is_reported_as_it_failed() {
        let rig = Rig::start(1, Duration::from_millis(10));
        rig.fail(0, io::ErrorKind::ConnectionRefused);
        let failures = rig.failures.lock().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].to_string(), "no route");
    }

    #[test]
    fn no_addresses_is_a_failure_at_once() {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let failures: Arc<Mutex<Vec<io::Error>>> = Arc::default();
        let f2 = Arc::clone(&failures);
        let dial: Dial = Arc::new(|_, _| unreachable!("there is nothing to dial"));
        connect_any(&rt, vec![], Duration::from_millis(10), dial, Box::new(move |e| f2.lock().unwrap().push(e)));
        assert_eq!(failures.lock().unwrap()[0].kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_dial_that_cannot_even_start_counts_as_a_failure_and_the_next_is_tried() {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let launched: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
        let failures: Arc<Mutex<Vec<io::Error>>> = Arc::default();
        let (l2, f2) = (Arc::clone(&launched), Arc::clone(&failures));
        let dial: Dial = Arc::new(move |addr, _attempt| {
            l2.lock().unwrap().push(addr);
            Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "no route to host"))
        });
        connect_any(&rt, vec![a("[::1]:80"), a("127.0.0.1:80")], Duration::from_secs(30), dial, Box::new(move |e| f2.lock().unwrap().push(e)));
        assert!(wait(|| failures.lock().unwrap().len() == 1, 1000), "both were tried, without waiting for the delay");
        assert_eq!(*launched.lock().unwrap(), [a("[::1]:80"), a("127.0.0.1:80")]);
        assert_eq!(failures.lock().unwrap()[0].kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[test]
    fn an_attempt_that_closes_before_it_connects_is_a_failure() {
        let rig = Rig::start(1, Duration::from_millis(10));
        rig.drive(0, |h, ep| h.disconnected(ep));
        let failures = rig.failures.lock().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn the_winners_events_reach_the_real_handler_and_a_failures_do_not() {
        struct Count(Arc<Mutex<Vec<&'static str>>>);
        impl ProtocolHandler for Count {
            fn connected(&mut self, _: &mut dyn Endpoint) {
                self.0.lock().unwrap().push("connected");
            }
            fn receive(&mut self, _: &mut dyn Endpoint, _: &mut LoopBuf) {
                self.0.lock().unwrap().push("receive");
            }
            fn disconnected(&mut self, _: &mut dyn Endpoint) {
                self.0.lock().unwrap().push("disconnected");
            }
            fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {
                self.0.lock().unwrap().push("error");
            }
        }
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let seen: Arc<Mutex<Vec<&'static str>>> = Arc::default();
        let gates: Arc<Mutex<Vec<Box<dyn ProtocolHandler>>>> = Arc::default();
        let (g2, s2) = (Arc::clone(&gates), Arc::clone(&seen));
        let dial: Dial = Arc::new(move |_, attempt| {
            let s = Arc::clone(&s2);
            g2.lock().unwrap().push(attempt.gate(Arc::new(move || Box::new(Count(Arc::clone(&s))) as Box<dyn ProtocolHandler>)));
            Ok(())
        });
        connect_any(&rt, vec![a("192.0.2.1:80")], Duration::from_millis(10), dial, Box::new(|_| {}));
        let mut peer = Peer::connect(NopHandler, |_| false);
        let mut ring = LoopBuf::with_capacity(16);
        let mut gates = gates.lock().unwrap();
        gates[0].receive(peer.endpoint(), &mut ring);
        assert!(seen.lock().unwrap().is_empty(), "nothing before the connection has won");
        gates[0].connected(peer.endpoint());
        gates[0].receive(peer.endpoint(), &mut ring);
        gates[0].error(peer.endpoint(), &io::Error::other("late"));
        gates[0].disconnected(peer.endpoint());
        assert_eq!(*seen.lock().unwrap(), ["connected", "receive", "error", "disconnected"]);
    }
}
