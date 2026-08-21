// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! mDNS responder (RFC 6762 §8: probing, announcing, goodbye) + querier,
//! tying together [`crate::socket`] and [`crate::cache`]. A close port of
//! Gumdrop's `MDNSService`, single-threaded-by-convention there because it
//! *is* the transport listener's callback object; here the equivalent
//! state (`Shared`) is behind one `Mutex` instead, since [`MdnsService`]'s
//! public methods (`register_service`, `query`, …) may reasonably be
//! called from any thread, not just the reactor's. The mutex only ever
//! guards fast, synchronous, in-memory mutation — every actual send goes
//! through [`hopf_core::ReactorHandle::udp_send`] (enqueue-only) and every
//! wait through a self-rearming [`hopf_core::ReactorHandle::schedule_timer`],
//! so it's never held across I/O.
//!
//! All the orchestration below is written as free functions taking
//! `&Arc<Mutex<Shared>>` rather than `&self` methods on [`MdnsService`] —
//! deliberately, so nothing ever constructs a throwaway second
//! `MdnsService` handle just to call one (that would corrupt
//! [`MdnsService`]'s `Drop`, which counts *its own* `Arc` clones to decide
//! whether it's the last handle standing and should send a goodbye).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mio::Token;
use hopf_core::{ReactorHandle, Runtime, UdpDatagramHandler};
use hopf_dns::wire::{DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, FLAG_AA, FLAG_QR};

use crate::bits::{unicast_response_requested, with_cache_flush};
use crate::cache::{MdnsCache, ScheduledStage};
use crate::socket::{listen_mdns_udp, MDNS_GROUP, MDNS_PORT};

/// Tunable timings — defaults match RFC 6762 exactly; tests shrink them so
/// the full probe→announce cycle doesn't take 2+ real seconds per run.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// RFC 6762 §8.1: random initial delay before the first probe, drawn
    /// from `0..=probe_initial_delay_max`.
    pub probe_initial_delay_max: Duration,
    /// RFC 6762 §8.1: delay between probes.
    pub probe_interval: Duration,
    /// RFC 6762 §8.1: number of probes sent before announcing.
    pub probe_count: u32,
    /// RFC 6762 §8.2: wait before retrying after losing a simultaneous-probe tie-break.
    pub probe_conflict_wait: Duration,
    /// RFC 6762 §8.3: delay between announcements.
    pub announce_interval: Duration,
    /// RFC 6762 §8.3: number of announcements sent.
    pub announce_count: u32,
    /// Default TTL applied to published records (not RFC-mandated as a
    /// single value — 120s is the commonly used default for host/service
    /// records; PTR records conventionally use a longer TTL, but a single
    /// default keeps this a straightforward first version).
    pub record_ttl: u32,
    /// How long [`MdnsService::query`] waits before resolving from
    /// whatever's cached by then, rather than racing to resolve the
    /// instant a matching answer arrives (see the module docs on why
    /// that's an acceptable v1 simplification, not an oversight).
    pub query_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            probe_initial_delay_max: Duration::from_millis(250),
            probe_interval: Duration::from_millis(250),
            probe_count: 3,
            probe_conflict_wait: Duration::from_secs(1),
            announce_interval: Duration::from_secs(1),
            announce_count: 2,
            record_ttl: 120,
            query_timeout: Duration::from_millis(750),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Probing,
    Announced,
}

pub(crate) struct Shared {
    state: State,
    timing: Timing,
    hostname_label: String,
    name_conflict_suffix: u32,
    current_name: String,
    own_addresses: Vec<Ipv4Addr>,
    /// Records registered via DNS-SD (`crate::dnssd`) — combined with the
    /// hostname's own A record(s) to form the published RRset. Kept
    /// separate from the hostname records so a conflict-rename only needs
    /// to rebuild the latter.
    pub(crate) dynamic_records: Vec<DnsResourceRecord>,
    probes_sent: u32,
    announces_sent: u32,
    /// At most one outstanding timer at a time — matches Gumdrop's single
    /// `timerHandle` field; each new phase cancels whatever's pending
    /// before arming its own.
    timer: Option<Arc<AtomicBool>>,
    reactor: ReactorHandle,
    peer: SocketAddr,
    token: Token,
    cache: MdnsCache,
}

impl Shared {
    pub(crate) fn reactor_handle(&self) -> ReactorHandle {
        self.reactor.clone()
    }

    pub(crate) fn cache_lookup(&self, name: &str, qtype: DnsType) -> Vec<DnsResourceRecord> {
        self.cache.lookup(name, qtype)
    }

    fn hostname_records(&self) -> Vec<DnsResourceRecord> {
        self.own_addresses
            .iter()
            .map(|addr| with_cache_flush(DnsResourceRecord::a(&self.current_name, self.timing.record_ttl, *addr)))
            .collect()
    }

    fn published_records(&self) -> Vec<DnsResourceRecord> {
        let mut records = self.hostname_records();
        records.extend(self.dynamic_records.iter().cloned());
        records
    }

    fn build_candidate_name(&self) -> String {
        if self.name_conflict_suffix <= 1 {
            format!("{}.local", self.hostname_label)
        } else {
            format!("{}-{}.local", self.hostname_label, self.name_conflict_suffix)
        }
    }

    fn cancel_timer(&mut self) {
        if let Some(flag) = self.timer.take() {
            flag.store(true, Ordering::Release);
        }
    }

    fn send(&self, msg: &DnsMessage, dest: SocketAddr) {
        if let Ok(bytes) = msg.serialize() {
            self.reactor.udp_send(self.token, dest, bytes);
        }
    }

    fn send_multicast(&self, msg: &DnsMessage) {
        self.send(msg, self.peer);
    }
}

fn random_delay_up_to(max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    let mut buf = [0u8; 8];
    let _ = getrandom::getrandom(&mut buf);
    let r = u64::from_le_bytes(buf);
    let max_millis = max.as_millis().max(1) as u64;
    Duration::from_millis(r % max_millis)
}

/// Unsigned byte-wise comparison of two equal-length rdata blobs — RFC
/// 6762 §8.2's simultaneous-probe tie-break. Matches Gumdrop's own
/// documented simplification of comparing one representative record
/// rather than the full lexicographic RRset ordering RFC 6762 technically
/// specifies.
fn compare_unsigned(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.cmp(b)
}

#[derive(Clone, Copy)]
enum Phase {
    Probe,
    Announce,
    RestartProbing,
}

fn arm(shared: &Arc<Mutex<Shared>>, g: &mut Shared, delay: Duration, phase: Phase) {
    g.cancel_timer();
    let shared2 = Arc::clone(shared);
    let flag = g.reactor.schedule_timer(
        delay,
        Box::new(move || match phase {
            Phase::Probe => send_next_probe(&shared2),
            Phase::Announce => send_next_announcement(&shared2),
            Phase::RestartProbing => begin_probing(&shared2),
        }),
    );
    g.timer = Some(flag);
}

// -- probing --

fn begin_probing(shared: &Arc<Mutex<Shared>>) {
    let mut g = shared.lock().unwrap();
    g.cancel_timer();
    g.state = State::Probing;
    g.probes_sent = 0;
    g.current_name = g.build_candidate_name();
    let delay = random_delay_up_to(g.timing.probe_initial_delay_max);
    arm(shared, &mut g, delay, Phase::Probe);
}

fn send_next_probe(shared: &Arc<Mutex<Shared>>) {
    let (msg, dest) = {
        let mut g = shared.lock().unwrap();
        let question = DnsQuestion::in_class(&g.current_name, DnsType::A);
        let authorities = g.hostname_records();
        let msg = DnsMessage::new(0, 0, vec![question], Vec::new(), authorities, Vec::new());
        g.probes_sent += 1;
        (msg, g.peer)
    };
    shared.lock().unwrap().send(&msg, dest);

    let mut g = shared.lock().unwrap();
    if g.probes_sent >= g.timing.probe_count {
        drop(g);
        begin_announcing(shared);
    } else {
        let delay = g.timing.probe_interval;
        arm(shared, &mut g, delay, Phase::Probe);
    }
}

/// A probe *answer* (someone already owns this name) arrived during
/// probing — RFC 6762 §8.1: pick a new name and restart probing from
/// scratch.
fn restart_probing_after_conflict(shared: &Arc<Mutex<Shared>>) {
    shared.lock().unwrap().name_conflict_suffix += 1;
    begin_probing(shared);
}

/// Another host is probing for the *same* name we are, simultaneously
/// (RFC 6762 §8.2) — tie-break by comparing one representative address;
/// if we lose, wait out `probe_conflict_wait` and retry the *same* name
/// (not a rename — the other host lost equally, so nothing says they'll
/// keep contesting it).
fn handle_simultaneous_probe(shared: &Arc<Mutex<Shared>>, their_rdata: &[u8]) {
    let mut g = shared.lock().unwrap();
    let Some(our_addr) = g.own_addresses.first() else { return };
    let ours = our_addr.octets();
    if compare_unsigned(their_rdata, &ours) == std::cmp::Ordering::Greater {
        let delay = g.timing.probe_conflict_wait;
        arm(shared, &mut g, delay, Phase::RestartProbing);
    }
    // Otherwise we win the tie-break: keep probing as scheduled.
}

// -- announcing --

fn begin_announcing(shared: &Arc<Mutex<Shared>>) {
    let mut g = shared.lock().unwrap();
    g.state = State::Announced;
    g.announces_sent = 0;
    arm(shared, &mut g, Duration::ZERO, Phase::Announce);
}

fn send_next_announcement(shared: &Arc<Mutex<Shared>>) {
    let (msg, dest) = {
        let mut g = shared.lock().unwrap();
        let records = g.published_records();
        let msg = DnsMessage::new(0, FLAG_QR | FLAG_AA, Vec::new(), records, Vec::new(), Vec::new());
        g.announces_sent += 1;
        (msg, g.peer)
    };
    shared.lock().unwrap().send(&msg, dest);

    let mut g = shared.lock().unwrap();
    if g.announces_sent < g.timing.announce_count {
        let delay = g.timing.announce_interval;
        arm(shared, &mut g, delay, Phase::Announce);
    }
}

/// RFC 6762 §10.1: an unsolicited TTL-0 response for every published
/// record, telling the network to drop them now rather than waiting out
/// their normal TTL.
fn send_goodbye(shared: &Arc<Mutex<Shared>>) {
    let (msg, dest) = {
        let mut g = shared.lock().unwrap();
        g.cancel_timer();
        let records: Vec<DnsResourceRecord> =
            g.published_records().into_iter().map(|mut rr| { rr.ttl = 0; rr }).collect();
        g.state = State::Idle;
        let msg = DnsMessage::new(0, FLAG_QR | FLAG_AA, Vec::new(), records, Vec::new(), Vec::new());
        (msg, g.peer)
    };
    shared.lock().unwrap().send(&msg, dest);
}

// -- DNS-SD support (crate::dnssd) --

/// The TTL new records should be published with — [`crate::dnssd`] needs
/// this to build matching PTR/SRV/TXT records.
pub(crate) fn record_ttl(shared: &Arc<Mutex<Shared>>) -> u32 {
    shared.lock().unwrap().timing.record_ttl
}

/// Add records to the published dynamic (DNS-SD) set and re-announce —
/// see [`MdnsService::register_service`].
pub(crate) fn add_dynamic_records(shared: &Arc<Mutex<Shared>>, records: Vec<DnsResourceRecord>) {
    {
        let mut g = shared.lock().unwrap();
        g.dynamic_records.extend(records);
    }
    begin_announcing(shared);
}

/// Remove every dynamic record matching `predicate` and re-announce (or
/// send a targeted goodbye for just what was removed, if still
/// announced) — see [`crate::dnssd::ServiceHandle`]'s `Drop`.
pub(crate) fn remove_dynamic_records(shared: &Arc<Mutex<Shared>>, predicate: impl Fn(&DnsResourceRecord) -> bool) {
    let (removed, dest, still_announced) = {
        let mut g = shared.lock().unwrap();
        let (removed, kept): (Vec<_>, Vec<_>) = g.dynamic_records.drain(..).partition(|rr| predicate(rr));
        g.dynamic_records = kept;
        (removed, g.peer, g.state == State::Announced)
    };
    if removed.is_empty() || !still_announced {
        return;
    }
    let goodbye_records: Vec<DnsResourceRecord> = removed.into_iter().map(|mut rr| { rr.ttl = 0; rr }).collect();
    let msg = DnsMessage::new(0, FLAG_QR | FLAG_AA, Vec::new(), goodbye_records, Vec::new(), Vec::new());
    shared.lock().unwrap().send(&msg, dest);
}

/// Fire an mDNS query and resolve `cb` once the timeout elapses — the
/// free-function core of [`MdnsService::query`], also used by
/// [`crate::dnssd::poll_browse`] (which must not construct a second
/// `MdnsService` just to call this: see this module's top-level docs on
/// why).
pub(crate) fn send_query(
    shared: &Arc<Mutex<Shared>>,
    name: &str,
    qtype: DnsType,
    cb: Box<dyn FnOnce(Vec<DnsResourceRecord>) + Send>,
) {
    let (msg, timeout, reactor) = {
        let g = shared.lock().unwrap();
        let question = DnsQuestion::in_class(name, qtype);
        let msg = DnsMessage::query(0, question, false);
        (msg, g.timing.query_timeout, g.reactor.clone())
    };
    shared.lock().unwrap().send_multicast(&msg);

    let shared2 = Arc::clone(shared);
    let name = name.to_string();
    reactor.schedule_timer(
        timeout,
        Box::new(move || {
            let results = shared2.lock().unwrap().cache.lookup(&name, qtype);
            cb(results);
        }),
    );
}

// -- incoming datagrams --

struct MdnsHandler {
    shared: Arc<Mutex<Shared>>,
}

impl UdpDatagramHandler for MdnsHandler {
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        let Ok(msg) = DnsMessage::parse(data) else { return };
        if msg.flags & FLAG_QR != 0 {
            handle_response(&self.shared, &msg);
        } else {
            handle_query(&self.shared, &msg, peer);
        }
    }
}

fn handle_query(shared: &Arc<Mutex<Shared>>, msg: &DnsMessage, peer: SocketAddr) {
    let state = shared.lock().unwrap().state;

    // During probing, an incoming *query* for our own candidate name
    // (from another host also probing for it) is the simultaneous-probe
    // case (RFC 6762 §8.2) only when it carries a matching proposed
    // record in the Authority section; a plain query isn't a conflict
    // signal by itself.
    if state == State::Probing {
        for q in &msg.questions {
            if q.raw_qtype != DnsType::A.value() {
                continue;
            }
            let ours = shared.lock().unwrap().current_name.clone();
            if !q.name.eq_ignore_ascii_case(&ours) {
                continue;
            }
            for rr in &msg.authorities {
                if rr.rtype == Some(DnsType::A) {
                    handle_simultaneous_probe(shared, &rr.rdata);
                }
            }
        }
        return;
    }

    if state != State::Announced {
        return;
    }

    let (records, unicast_reply_to) = {
        let g = shared.lock().unwrap();
        let published = g.published_records();
        let mut answers = Vec::new();
        let mut any_unicast_requested = false;
        for q in &msg.questions {
            if unicast_response_requested(q) {
                any_unicast_requested = true;
            }
            for rr in &published {
                if !rr.name.eq_ignore_ascii_case(&q.name) {
                    continue;
                }
                if q.raw_qtype != DnsType::Any.value() && Some(q.raw_qtype) != rr.rtype.map(DnsType::value) {
                    continue;
                }
                // RFC 6762 §7.1 known-answer suppression: skip if the
                // querier already listed this exact record with more
                // than half its TTL still remaining.
                let already_known = msg.answers.iter().any(|known| {
                    known.name.eq_ignore_ascii_case(&rr.name)
                        && known.rtype == rr.rtype
                        && known.rdata == rr.rdata
                        && known.ttl > rr.ttl / 2
                });
                if !already_known {
                    answers.push(rr.clone());
                }
            }
        }
        let dest = if any_unicast_requested { Some(peer) } else { None };
        (answers, dest)
    };

    if records.is_empty() {
        return;
    }
    let response = DnsMessage::new(0, FLAG_QR | FLAG_AA, Vec::new(), records, Vec::new(), Vec::new());
    let g = shared.lock().unwrap();
    match unicast_reply_to {
        Some(dest) => g.send(&response, dest),
        None => g.send_multicast(&response),
    }
}

fn handle_response(shared: &Arc<Mutex<Shared>>, msg: &DnsMessage) {
    // A probe answer during our own probing, for our own candidate name,
    // is a real conflict (someone already has this name) -- separate from
    // the simultaneous-probe case (which arrives as a *query* with
    // proposed records, handled in `handle_query`).
    let (state, ours) = {
        let g = shared.lock().unwrap();
        (g.state, g.current_name.clone())
    };
    if state == State::Probing {
        let conflict = msg
            .answers
            .iter()
            .any(|rr| rr.rtype == Some(DnsType::A) && rr.name.eq_ignore_ascii_case(&ours));
        if conflict {
            restart_probing_after_conflict(shared);
            return;
        }
    }

    let (goodbyes, live): (Vec<_>, Vec<_>) = msg.answers.iter().cloned().partition(|rr| rr.ttl == 0);

    let (scheduled, grace) = {
        let mut g = shared.lock().unwrap();
        let mut result = g.cache.ingest(&live);
        for rr in &goodbyes {
            if let Some(removal) = g.cache.goodbye(rr) {
                result.1.push(removal);
            }
        }
        result
    };

    for (name, qtype, stages) in scheduled {
        arm_cache_stages(shared, name, qtype, stages);
    }
    for (name, qtype, rdata, generation) in grace {
        arm_grace_removal(shared, name, qtype, rdata, generation);
    }
}

fn arm_cache_stages(shared: &Arc<Mutex<Shared>>, name: String, qtype: DnsType, stages: [ScheduledStage; 5]) {
    for stage in stages {
        let shared2 = Arc::clone(shared);
        let reactor = shared.lock().unwrap().reactor.clone();
        let name = name.clone();
        reactor.schedule_timer(
            stage.delay,
            Box::new(move || {
                if stage.is_expiry {
                    // Expiry needs the rdata to identify the exact record;
                    // look it up fresh since it may have changed shape
                    // entirely by now (the generation guard handles "did
                    // it actually change").
                    let mut g = shared2.lock().unwrap();
                    let matching: Vec<_> = g.cache.lookup(&name, qtype).into_iter().map(|rr| rr.rdata).collect();
                    for rdata in matching {
                        g.cache.expire_due(&name, qtype, &rdata, stage.generation);
                    }
                } else {
                    let refresh = {
                        let g = shared2.lock().unwrap();
                        let matching: Vec<_> = g.cache.lookup(&name, qtype).into_iter().map(|rr| rr.rdata).collect();
                        matching.into_iter().find_map(|rdata| g.cache.refresh_due(&name, qtype, &rdata, stage.generation))
                    };
                    if let Some((name, qtype)) = refresh {
                        let g = shared2.lock().unwrap();
                        let msg = DnsMessage::query(0, DnsQuestion::in_class(&name, qtype), false);
                        g.send_multicast(&msg);
                    }
                }
            }),
        );
    }
}

fn arm_grace_removal(shared: &Arc<Mutex<Shared>>, name: String, qtype: DnsType, rdata: Vec<u8>, generation: u64) {
    let shared2 = Arc::clone(shared);
    let reactor = shared.lock().unwrap().reactor.clone();
    reactor.schedule_timer(
        crate::cache::GRACE_PERIOD,
        Box::new(move || {
            shared2.lock().unwrap().cache.grace_remove_due(&name, qtype, &rdata, generation);
        }),
    );
}

/// Handle applications hold: starts probing/announcing a hostname on
/// construction, and is the entry point for DNS-SD registration
/// ([`crate::dnssd`]) and querying.
pub struct MdnsService {
    pub(crate) shared: Arc<Mutex<Shared>>,
}

impl MdnsService {
    /// Start advertising `hostname_label` (published as `"<label>.local"`,
    /// or `"<label>-N.local"` if a conflict is detected) over mDNS,
    /// resolving to `addresses`. Hopf has no interface-enumeration utility
    /// today, so — matching this crate's push-rather-than-pull design
    /// throughout — the caller supplies its own routable address(es)
    /// rather than this function guessing at them.
    pub fn start(rt: &Arc<Runtime>, hostname_label: &str, addresses: Vec<Ipv4Addr>) -> std::io::Result<Self> {
        Self::start_with_timing(rt, hostname_label, addresses, Timing::default(), None)
    }

    /// [`Self::start`] with non-default [`Timing`] and, optionally, a
    /// single local interface to scope mDNS to (see
    /// [`crate::socket::listen_mdns_udp`]) — for tests, and for
    /// multi-homed hosts that want mDNS confined to one interface.
    pub fn start_with_timing(
        rt: &Arc<Runtime>,
        hostname_label: &str,
        addresses: Vec<Ipv4Addr>,
        timing: Timing,
        multicast_if: Option<Ipv4Addr>,
    ) -> std::io::Result<Self> {
        let reactor = rt.pick_worker().clone();
        let placeholder_token = Token(usize::MAX);
        let shared = Arc::new(Mutex::new(Shared {
            state: State::Idle,
            timing,
            hostname_label: hostname_label.to_string(),
            name_conflict_suffix: 1,
            current_name: format!("{hostname_label}.local"),
            own_addresses: addresses,
            dynamic_records: Vec::new(),
            probes_sent: 0,
            announces_sent: 0,
            timer: None,
            reactor: reactor.clone(),
            peer: SocketAddr::new(MDNS_GROUP.into(), MDNS_PORT),
            token: placeholder_token,
            cache: MdnsCache::new(),
        }));

        let handler = Box::new(MdnsHandler { shared: Arc::clone(&shared) });
        let (_, token) = listen_mdns_udp(&reactor, handler, multicast_if)?;
        shared.lock().unwrap().token = token;

        begin_probing(&shared);
        Ok(Self { shared })
    }

    /// Whether the responder has finished probing/announcing and is live
    /// under its current name.
    pub fn is_announced(&self) -> bool {
        self.shared.lock().unwrap().state == State::Announced
    }

    /// The name currently being probed/announced (may have a `-N` suffix
    /// if a conflict was detected).
    pub fn current_name(&self) -> String {
        self.shared.lock().unwrap().current_name.clone()
    }

    /// Synchronous cache peek — see [`MdnsCache::lookup`].
    pub fn lookup(&self, name: &str, qtype: DnsType) -> Vec<DnsResourceRecord> {
        self.shared.lock().unwrap().cache.lookup(name, qtype)
    }

    /// Fire an mDNS query for `name`/`qtype` and resolve `cb` with
    /// whatever's cached once [`Timing::query_timeout`] elapses (see the
    /// module docs for why this waits out a fixed timeout rather than
    /// racing to resolve the instant a matching answer arrives).
    pub fn query(&self, name: &str, qtype: DnsType, cb: Box<dyn FnOnce(Vec<DnsResourceRecord>) + Send>) {
        send_query(&self.shared, name, qtype, cb);
    }

    /// RFC 6762 §10.1 goodbye — see the free function of the same
    /// purpose; exposed as a method since applications call this
    /// directly (`Drop` also calls it, best-effort, if this is the last
    /// handle and it's still announced).
    pub fn goodbye(&self) {
        send_goodbye(&self.shared);
    }
}

impl Drop for MdnsService {
    fn drop(&mut self) {
        // `MdnsService` doesn't implement `Clone` -- this is always *the*
        // one application-facing handle going away (not one of several;
        // `MdnsHandler`, held by the reactor for the socket's lifetime,
        // and every timer closure hold `Arc<Mutex<Shared>>` directly,
        // never a second `MdnsService`), so a best-effort goodbye is
        // always appropriate here if we're still announced.
        let announced = self.shared.lock().map(|g| g.state == State::Announced).unwrap_or(false);
        if announced {
            self.goodbye();
        }
    }
}
