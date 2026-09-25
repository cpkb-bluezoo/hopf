// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Background zone maintenance: everything that must not run on a listener
//! thread because it blocks.
//!
//! One thread per [`AuthoritativeZoneHandler`](super::AuthoritativeZoneHandler)
//! does, for the zones it serves:
//!
//! - *primary*: after a change, write the zone file (read-write mode) and
//!   NOTIFY the secondaries (RFC 1996);
//! - *secondary*: refresh from the primary at start, on NOTIFY, and on the
//!   SOA REFRESH/RETRY timers, and expire the zone after EXPIRE without a
//!   successful contact (RFC 1035 §3.3.13, RFC 1034 §4.3.5).
//!
//! Work is sequential on this thread, each network step bounded by a short
//! timeout, so one dead peer delays but never wedges maintenance.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::authoritative::{Inner, ZoneSlot};
use super::client::{Transfer, ZoneClient};
use super::model::{serial_gt, Zone};
use super::options::{NotifyTarget, ZoneFileMode};
use crate::wire::normalize_name;

/// Retry interval while a secondary has no zone and so no SOA to read one from.
const INITIAL_RETRY: Duration = Duration::from_secs(5);
/// NOTIFY attempts per peer (RFC 1996 §3.5 suggests retrying until answered).
const NOTIFY_ATTEMPTS: usize = 3;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) enum Cmd {
    /// A primary's zone changed.
    Changed(String),
    /// A secondary's primary sent NOTIFY.
    Notified(String),
    Shutdown,
}

pub(super) struct Maintainer {
    tx: Sender<Cmd>,
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

impl Maintainer {
    pub(super) fn spawn(inner: Arc<Inner>) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("hopf-dns-zones".into())
            .spawn(move || run(inner, rx, stop2))?;
        Ok(Self { tx, stop, join })
    }

    pub(super) fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }

    pub(super) fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.tx.send(Cmd::Shutdown);
        let _ = self.join.join();
    }
}

struct State {
    /// Next refresh time per secondary origin.
    due: HashMap<String, Instant>,
    /// Last successful contact with the primary, per secondary origin.
    last_ok: HashMap<String, Instant>,
}

fn run(inner: Arc<Inner>, rx: mpsc::Receiver<Cmd>, stop: Arc<AtomicBool>) {
    let mut st = State {
        due: HashMap::new(),
        last_ok: HashMap::new(),
    };
    let now = Instant::now();
    for slot in inner.slots.iter().filter(|s| s.primary.is_some()) {
        st.due.insert(slot.origin.clone(), now);
        // A zone loaded from its persisted file is served until EXPIRE runs
        // out, counted from now.
        if slot.zone.read().unwrap().is_some() {
            st.last_ok.insert(slot.origin.clone(), now);
        }
    }
    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        let ready: Vec<String> = st.due.iter().filter(|(_, t)| **t <= now).map(|(o, _)| o.clone()).collect();
        for origin in ready {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            if let Some(slot) = inner.slots.iter().find(|s| s.origin == origin) {
                let next = refresh(&mut st, slot);
                st.due.insert(origin, next);
            }
        }
        let wait = st
            .due
            .values()
            .min()
            .map_or(Duration::from_secs(3600), |t| t.saturating_duration_since(Instant::now()));
        let mut changed: HashSet<String> = HashSet::new();
        let first = match rx.recv_timeout(wait) {
            Ok(c) => Some(c),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        // Coalesce a burst of commands before doing the slow work.
        for cmd in first.into_iter().chain(std::iter::from_fn(|| rx.try_recv().ok())) {
            match cmd {
                Cmd::Shutdown => return,
                Cmd::Changed(o) => {
                    changed.insert(o);
                }
                Cmd::Notified(o) => {
                    st.due.insert(o, Instant::now());
                }
            }
        }
        for origin in changed {
            if let Some(slot) = inner.slots.iter().find(|s| s.origin == origin) {
                persist(slot);
                notify_peers(slot, &stop);
            }
        }
    }
}

/// A client that signs with the zone's TSIG key, if it has one.
fn client_for(slot: &ZoneSlot) -> ZoneClient {
    let client = ZoneClient::new().with_timeout(IO_TIMEOUT);
    match &slot.options.tsig_key {
        Some(key) => client.with_tsig(key.clone()),
        None => client,
    }
}

/// Write the zone back to its file if it is configured read-write.
fn persist(slot: &ZoneSlot) {
    let Some((path, ZoneFileMode::ReadWrite)) = &slot.options.persist else {
        return;
    };
    let snapshot = slot.zone.read().unwrap().clone();
    if let Some(zone) = snapshot {
        if let Err(e) = zone.write_zone_file(path) {
            eprintln!("hopf-dns: cannot write zone {:?}: {e}", slot.origin);
        }
    }
}

/// Where to send NOTIFY for `zone`: the explicit list plus the in-zone name
/// servers with address records (port 53), except the primary itself, which
/// is the SOA MNAME (RFC 1996 §2).
pub(super) fn notify_targets(
    zone: &Zone,
    also: &[NotifyTarget],
    use_ns: bool,
    resolve: &dyn Fn(&str, u16) -> Vec<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for t in also {
        let addrs = match t {
            NotifyTarget::Addr(a) => vec![*a],
            NotifyTarget::Host(h, p) => resolve(h, *p),
        };
        for a in addrs {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    if use_ns {
        let mname = normalize_name(&zone.soa().mname);
        let mut own: HashSet<IpAddr> = HashSet::new();
        for rr in zone.rrset(&mname, 1).iter().chain(zone.rrset(&mname, 28).iter()) {
            if let Some(ip) = rr.as_a().map(IpAddr::V4).or_else(|| rr.as_aaaa().map(IpAddr::V6)) {
                own.insert(ip);
            }
        }
        for g in zone.glue_for(&zone.ns_records()) {
            if g.name == mname {
                continue;
            }
            if let Some(ip) = g.as_a().map(IpAddr::V4).or_else(|| g.as_aaaa().map(IpAddr::V6)) {
                let addr = SocketAddr::new(ip, 53);
                if !own.contains(&ip) && !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }
    out
}

fn system_resolve(host: &str, port: u16) -> Vec<SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, port).to_socket_addrs().map(Iterator::collect).unwrap_or_default()
}

fn notify_peers(slot: &ZoneSlot, stop: &AtomicBool) {
    let client = client_for(slot);
    let Some(zone) = slot.zone.read().unwrap().clone() else {
        return;
    };
    let targets = notify_targets(&zone, &slot.options.also_notify, slot.options.notify_ns_records, &system_resolve);
    for peer in targets {
        for _ in 0..NOTIFY_ATTEMPTS {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            if client.notify(peer, &slot.origin).is_ok() {
                break;
            }
        }
    }
}

/// One refresh attempt for a secondary; returns when to try next.
fn refresh(st: &mut State, slot: &Arc<ZoneSlot>) -> Instant {
    let primary = slot.primary.expect("only secondaries are refreshed");
    let outcome = try_refresh(&client_for(slot), slot, primary);
    let now = Instant::now();
    let timers = slot.zone.read().unwrap().as_ref().map(|z| z.soa().clone());
    match outcome {
        Ok(()) => {
            st.last_ok.insert(slot.origin.clone(), now);
            slot.expired.store(false, Ordering::Relaxed);
            let secs = timers.map_or(INITIAL_RETRY.as_secs(), |s| u64::from(s.refresh).max(1));
            now + Duration::from_secs(secs)
        }
        Err(e) => {
            eprintln!("hopf-dns: refresh of zone {:?} from {primary} failed: {e}", slot.origin);
            let secs = timers.as_ref().map_or(INITIAL_RETRY.as_secs(), |s| u64::from(s.retry).max(1));
            if let (Some(t), Some(ok)) = (&timers, st.last_ok.get(&slot.origin)) {
                if now.duration_since(*ok) >= Duration::from_secs(u64::from(t.expire)) {
                    slot.expired.store(true, Ordering::Relaxed);
                }
            }
            now + Duration::from_secs(secs)
        }
    }
}

fn try_refresh(client: &ZoneClient, slot: &ZoneSlot, primary: SocketAddr) -> io::Result<()> {
    let have = slot.zone.read().unwrap().as_ref().map(Zone::serial);
    let theirs = client.soa_serial(primary, &slot.origin)?;
    if have.is_some_and(|h| !serial_gt(theirs, h)) {
        return Ok(()); // still current
    }
    let mut transfer = client.transfer(primary, &slot.origin, have)?;
    let updated = loop {
        match transfer {
            Transfer::UpToDate => return Ok(()),
            Transfer::Full(records) => {
                let ttl = records.first().and_then(|r| r.as_soa()).map_or(0, |s| s.minimum);
                break Zone::from_records(&slot.origin, ttl, records).map_err(io::Error::from)?;
            }
            Transfer::Incremental(diffs) => {
                let mut zone = slot.zone.read().unwrap().clone().expect("IXFR was asked from a held zone");
                let applied = diffs.into_iter().try_for_each(|d| zone.apply_diff(d.deleted, d.added));
                match applied {
                    Ok(()) => break zone,
                    // A difference that does not fit: start over with a full copy.
                    Err(_) => transfer = client.transfer(primary, &slot.origin, None)?,
                }
            }
        }
    };
    *slot.zone.write().unwrap() = Some(updated);
    persist(slot);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_targets_use_glue_but_skip_the_primary_and_dedupe() {
        let z = Zone::from_zone_text(
            "$TTL 60\n@ SOA ns1 h 1 2 3 4 5\n NS ns1\n NS ns2\n NS ns3.other.net.\nns1 A 192.0.2.1\nns2 A 192.0.2.2\nns2 AAAA 2001:db8::2\n",
            Some("example.com"),
        )
        .unwrap();
        let a = |s: &str| NotifyTarget::Addr(s.parse().unwrap());
        let also = vec![
            a("192.0.2.2:53"),
            a("203.0.113.5:5300"),
            NotifyTarget::Host("replicas.svc".into(), 5301),
        ];
        let resolve = |host: &str, port: u16| -> Vec<SocketAddr> {
            assert_eq!(host, "replicas.svc");
            vec![
                SocketAddr::new("10.0.0.1".parse().unwrap(), port),
                SocketAddr::new("10.0.0.2".parse().unwrap(), port),
                SocketAddr::new("10.0.0.1".parse().unwrap(), port),
            ]
        };
        let t = notify_targets(&z, &also, true, &resolve);
        assert_eq!(
            t,
            vec![
                "192.0.2.2:53".parse().unwrap(),
                "203.0.113.5:5300".parse().unwrap(),
                "10.0.0.1:5301".parse().unwrap(),
                "10.0.0.2:5301".parse().unwrap(),
                "[2001:db8::2]:53".parse().unwrap()
            ],
            "a name notifies every address it resolves to (deduped); ns1 is the MNAME so it is skipped; ns3 has no glue"
        );
        let single = notify_targets(&z, &also[..1], false, &resolve);
        assert_eq!(single, vec!["192.0.2.2:53".parse().unwrap()], "one address, one NOTIFY");
    }
}
