// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-SD (RFC 6763): push-based service advertisement and browsing.
//!
//! Gumdrop's `DNSSDAdvertiser` *pulls* the list of services to advertise
//! from the whole server's own listener registry
//! (`Gumdrop.getInstance().getServices()`). Hopf has no such registry —
//! every protocol is an independent crate — so [`MdnsService::register_service`]
//! is explicit: the application tells this crate what to advertise, the
//! same way it tells `hopf-http`/`hopf-smtp`/etc. what to listen on.
//! [`MdnsService::browse`] is the discovery-side counterpart, which
//! Gumdrop's server-centric design doesn't really need but a p2p-leaning
//! library does.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_dns::wire::{DnsResourceRecord, DnsType};

use crate::bits::with_cache_flush;
use crate::responder::{MdnsService, Shared};

/// One service instance to advertise.
#[derive(Debug, Clone)]
pub struct ServiceRegistration {
    /// e.g. `"_http._tcp"` (RFC 6763 §4.1.2: `_service._proto`).
    pub service_type: String,
    /// The user-facing instance name (RFC 6763 §4.1.1) — need not be
    /// DNS-safe as-is; this crate doesn't currently escape RFC 6763 §4.3
    /// special characters (`.`, `\`) in the instance name, so avoid them
    /// for now (documented limitation, not silently mishandled: unescaped
    /// input just produces a technically-invalid but still-usable-in-
    /// practice owner name).
    pub instance_name: String,
    /// Port the service listens on.
    pub port: u16,
    /// TXT record key/value attributes (RFC 6763 §6).
    pub txt: Vec<(String, String)>,
}

fn encode_txt(pairs: &[(String, String)]) -> Vec<u8> {
    if pairs.is_empty() {
        // RFC 6763 §6.1: a TXT record with no meaningful data still needs
        // one (zero-length) character-string, not an empty rdata.
        return vec![0u8];
    }
    let mut out = Vec::new();
    for (k, v) in pairs {
        let entry = format!("{k}={v}");
        let bytes = entry.as_bytes();
        // RFC 6763 §6.1: each character-string is capped at 255 bytes;
        // silently truncating would corrupt the attribute, so drop the
        // whole attribute instead of emitting a malformed one.
        if bytes.len() > 255 {
            continue;
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out
}

fn build_records(reg: &ServiceRegistration, target_host: &str, ttl: u32) -> (Vec<DnsResourceRecord>, String) {
    let service_name = format!("{}.local", reg.service_type);
    let instance_fqdn = format!("{}.{}", reg.instance_name, service_name);

    let mut records = Vec::new();
    // PTR: shared (not unique to us — other instances share the same
    // owner name), never cache-flush, per RFC 6763 §10.1.
    if let Ok(ptr) = DnsResourceRecord::ptr(&service_name, ttl, &instance_fqdn) {
        records.push(ptr);
    }
    // SRV + TXT: unique to this instance, cache-flush.
    if let Ok(srv) = DnsResourceRecord::srv(&instance_fqdn, ttl, 0, 0, reg.port, target_host) {
        records.push(with_cache_flush(srv));
    }
    let txt_rdata = encode_txt(&reg.txt);
    records.push(with_cache_flush(DnsResourceRecord::new(
        instance_fqdn.clone(),
        DnsType::Txt,
        hopf_dns::wire::DnsClass::In,
        ttl,
        txt_rdata,
    )));
    // RFC 6763 §9: meta-query PTR so `_services._dns-sd._udp.local`
    // enumerates every service *type* this responder advertises. Shared,
    // never cache-flush.
    if let Ok(meta) = DnsResourceRecord::ptr("_services._dns-sd._udp.local", ttl, &service_name) {
        records.push(meta);
    }

    (records, instance_fqdn)
}

/// Handle for one registered service — [`Self::unregister`] (or dropping
/// it) removes its records and announces the change.
pub struct ServiceHandle {
    shared: Arc<Mutex<Shared>>,
    /// The SRV/TXT owner name — every record this registration published
    /// is either owned by this name (SRV, TXT) or targets it (PTR), so
    /// it's enough to identify "this registration's records" for removal.
    instance_fqdn: String,
}

impl ServiceHandle {
    /// Remove this service's records and announce the change.
    pub fn unregister(self) {
        // `Drop` does the actual work; this just makes the intent explicit
        // at the call site and consumes `self` so it can't be used again.
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        crate::responder::remove_dynamic_records(&self.shared, |rr| {
            rr.name.eq_ignore_ascii_case(&self.instance_fqdn)
                || matches!(rr.as_domain_name(), Some(target) if target.eq_ignore_ascii_case(&self.instance_fqdn))
        });
    }
}

impl MdnsService {
    /// Advertise a service via DNS-SD (RFC 6763): builds and publishes
    /// its PTR/SRV/TXT records (target host = this responder's own
    /// current name) plus a `_services._dns-sd._udp.local` meta-PTR for
    /// its type, then re-announces. Matches RFC 6763 §8.3's "adding a new
    /// instance" flow closely enough for a first version by republishing
    /// the whole current RRset rather than a true incremental add — the
    /// SRV target (this responder's own hostname) was already probed for
    /// conflicts, so a fresh probe cycle for the new records isn't
    /// warranted.
    pub fn register_service(&self, reg: ServiceRegistration) -> ServiceHandle {
        let target_host = self.current_name();
        let ttl = crate::responder::record_ttl(&self.shared);
        let (records, instance_fqdn) = build_records(&reg, &target_host, ttl);
        crate::responder::add_dynamic_records(&self.shared, records);
        ServiceHandle { shared: Arc::clone(&self.shared), instance_fqdn }
    }
}

/// One discovered (or lost) service instance.
#[derive(Debug, Clone)]
pub enum BrowseEvent {
    /// A new instance of the browsed service type was found (or one
    /// already known was refreshed with new details).
    Found {
        /// The instance's full name (`<instance>.<service>.local`).
        instance: String,
        /// SRV target host.
        host: String,
        /// SRV port.
        port: u16,
        /// Decoded TXT attributes (RFC 6763 §6.4) — entries without an
        /// `=` are reported with an empty value.
        txt: Vec<(String, String)>,
    },
    /// A previously found instance is no longer advertised (its PTR
    /// entry aged out of the cache or was flushed/said goodbye).
    Lost {
        /// The instance's full name.
        instance: String,
    },
}

/// A running browse for one service type — stops on drop.
pub struct BrowseHandle {
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for BrowseHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
    }
}

fn decode_txt(rdata: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            break;
        }
        let entry = String::from_utf8_lossy(&rdata[i..i + len]);
        i += len;
        if entry.is_empty() {
            continue;
        }
        match entry.split_once('=') {
            Some((k, v)) => out.push((k.to_string(), v.to_string())),
            None => out.push((entry.into_owned(), String::new())),
        }
    }
    out
}

impl MdnsService {
    /// Browse for instances of `service_type` (e.g. `"_http._tcp"`),
    /// delivering [`BrowseEvent`]s to `cb` as they're found or lost.
    /// Re-queries periodically (a simplified, fixed-interval stand-in for
    /// RFC 6762 §5.2's per-record active-refresh timing, which already
    /// drives the underlying cache — this is *on top of* that, ensuring
    /// new instances are discovered even before any of their records are
    /// close to expiring) until the returned [`BrowseHandle`] is dropped.
    pub fn browse(&self, service_type: &str, cb: impl FnMut(BrowseEvent) + Send + 'static) -> BrowseHandle {
        let service_name = format!("{service_type}.local");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cb = Arc::new(Mutex::new(cb));
        let known = Arc::new(Mutex::new(HashSet::<String>::new()));

        let handle = BrowseHandle { stop: Arc::clone(&stop) };
        poll_browse(self.shared.clone(), service_name, stop, cb, known);
        handle
    }
}

fn poll_browse(
    shared: Arc<Mutex<Shared>>,
    service_name: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    cb: Arc<Mutex<dyn FnMut(BrowseEvent) + Send>>,
    known: Arc<Mutex<HashSet<String>>>,
) {
    if stop.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let service_name2 = service_name.clone();
    let shared2 = Arc::clone(&shared);
    let stop2 = Arc::clone(&stop);
    let cb2 = Arc::clone(&cb);
    let known2 = Arc::clone(&known);
    crate::responder::send_query(
        &shared,
        &service_name,
        DnsType::Ptr,
        Box::new(move |ptrs| {
            let mut current = HashSet::new();
            for ptr in &ptrs {
                let Some(instance) = ptr.as_domain_name() else { continue };
                current.insert(instance.clone());

                let srv = service_ptr_lookup(&shared2, &instance, DnsType::Srv);
                let txt = service_ptr_lookup(&shared2, &instance, DnsType::Txt);
                if let Some((host, port)) = srv.first().and_then(|rr| rr.as_srv()).map(|(_, _, port, target)| (target, port)) {
                    let attrs = txt.first().map(|rr| decode_txt(&rr.rdata)).unwrap_or_default();
                    (cb2.lock().unwrap())(BrowseEvent::Found { instance, host, port, txt: attrs });
                }
            }

            let mut known_guard = known2.lock().unwrap();
            let lost: Vec<String> = known_guard.difference(&current).cloned().collect();
            for instance in lost {
                (cb2.lock().unwrap())(BrowseEvent::Lost { instance });
            }
            *known_guard = current;
            drop(known_guard);

            if !stop2.load(std::sync::atomic::Ordering::Acquire) {
                let reactor = shared2.lock().unwrap().reactor_handle();
                reactor.schedule_timer(
                    Duration::from_secs(10),
                    Box::new(move || poll_browse(shared2, service_name2, stop2, cb2, known2)),
                );
            }
        }),
    );
}

fn service_ptr_lookup(shared: &Arc<Mutex<Shared>>, instance: &str, qtype: DnsType) -> Vec<DnsResourceRecord> {
    shared.lock().unwrap().cache_lookup(instance, qtype)
}
