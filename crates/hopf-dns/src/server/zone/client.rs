// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Blocking zone-maintenance client: NOTIFY (RFC 1996), SOA polling,
//! AXFR/IXFR (RFC 5936, RFC 1995) and dynamic UPDATE (RFC 2136).
//!
//! Every call blocks its thread on the network, so run them from a worker
//! thread, never from a reactor. The zone maintenance threads of
//! [`AuthoritativeZoneHandler`](super::AuthoritativeZoneHandler) do exactly
//! that.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use super::model::serial_gt;
use crate::tsig::{self, Chain, TsigKey, TsigKeyring};
use crate::wire::{
    normalize_name, DnsMessage, DnsQuestion, DnsQueryIdGenerator, DnsResourceRecord, DnsType,
    FLAG_AA, OPCODE_NOTIFY, OPCODE_UPDATE, RCODE_NOERROR,
};

const TYPE_SOA: u16 = 6;
const TYPE_IXFR: u16 = 251;
const TYPE_AXFR: u16 = 252;
/// Refuse absurd transfers instead of exhausting memory.
const MAX_RECORDS: usize = 5_000_000;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// One IXFR difference: what to remove and what to add, each side led by
/// its SOA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneDiff {
    /// Records removed (starting with the old SOA).
    pub deleted: Vec<DnsResourceRecord>,
    /// Records added (starting with the new SOA).
    pub added: Vec<DnsResourceRecord>,
}

/// Result of a zone transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transfer {
    /// The primary has nothing newer than what we asked from.
    UpToDate,
    /// The whole zone, SOA first (the trailing SOA is dropped).
    Full(Vec<DnsResourceRecord>),
    /// Journalled differences to apply in order.
    Incremental(Vec<ZoneDiff>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    First,
    Second,
    Full,
    Deleting,
    Adding,
}

/// Incremental reader of a transfer's messages: feed each message, and it
/// reports when the transfer is complete. I/O-free so it is tested directly.
pub(crate) struct XfrCollector {
    ixfr_from: Option<u32>,
    mode: Mode,
    target: u32,
    records: Vec<DnsResourceRecord>,
    diffs: Vec<ZoneDiff>,
    cur: Option<ZoneDiff>,
    seen: usize,
}

impl XfrCollector {
    pub(crate) fn new(ixfr_from: Option<u32>) -> Self {
        Self {
            ixfr_from,
            mode: Mode::First,
            target: 0,
            records: Vec::new(),
            diffs: Vec::new(),
            cur: None,
            seen: 0,
        }
    }

    /// Feed one response message; `Some` when the transfer is complete.
    pub(crate) fn push(&mut self, msg: &DnsMessage) -> io::Result<Option<Transfer>> {
        if msg.rcode() != RCODE_NOERROR {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("transfer refused: rcode {}", msg.rcode()),
            ));
        }
        for rr in &msg.answers {
            self.seen += 1;
            if self.seen > MAX_RECORDS {
                return Err(invalid("transfer exceeds record limit"));
            }
            if let Some(done) = self.step(rr.clone())? {
                return Ok(Some(done));
            }
        }
        // An IXFR answer of exactly one SOA means "nothing newer".
        if self.mode == Mode::Second && self.ixfr_from.is_some() {
            return Ok(Some(Transfer::UpToDate));
        }
        Ok(None)
    }

    fn soa_serial(rr: &DnsResourceRecord) -> io::Result<u32> {
        rr.as_soa().map(|s| s.serial).ok_or_else(|| invalid("malformed SOA in transfer"))
    }

    fn step(&mut self, mut rr: DnsResourceRecord) -> io::Result<Option<Transfer>> {
        rr.name = normalize_name(&rr.name);
        let is_soa = rr.raw_type == TYPE_SOA;
        match self.mode {
            Mode::First => {
                if !is_soa {
                    return Err(invalid("transfer does not begin with an SOA"));
                }
                self.target = Self::soa_serial(&rr)?;
                if let Some(from) = self.ixfr_from {
                    if !serial_gt(self.target, from) {
                        return Ok(Some(Transfer::UpToDate));
                    }
                }
                self.records.push(rr);
                self.mode = Mode::Second;
            }
            Mode::Second => {
                if is_soa {
                    let serial = Self::soa_serial(&rr)?;
                    if self.ixfr_from == Some(serial) {
                        self.cur = Some(ZoneDiff { deleted: vec![rr], added: Vec::new() });
                        self.mode = Mode::Deleting;
                    } else if serial == self.target {
                        // An empty zone: SOA then the closing SOA.
                        return Ok(Some(Transfer::Full(std::mem::take(&mut self.records))));
                    } else {
                        return Err(invalid("unexpected SOA in transfer"));
                    }
                } else {
                    self.records.push(rr);
                    self.mode = Mode::Full;
                }
            }
            Mode::Full => {
                if is_soa && Self::soa_serial(&rr)? == self.target {
                    return Ok(Some(Transfer::Full(std::mem::take(&mut self.records))));
                }
                self.records.push(rr);
            }
            Mode::Deleting => {
                let cur = self.cur.as_mut().expect("diff in progress");
                if is_soa {
                    cur.added.push(rr);
                    self.mode = Mode::Adding;
                } else {
                    cur.deleted.push(rr);
                }
            }
            Mode::Adding => {
                if is_soa {
                    let serial = Self::soa_serial(&rr)?;
                    self.diffs.push(self.cur.take().expect("diff in progress"));
                    if serial == self.target {
                        return Ok(Some(Transfer::Incremental(std::mem::take(&mut self.diffs))));
                    }
                    self.cur = Some(ZoneDiff { deleted: vec![rr], added: Vec::new() });
                    self.mode = Mode::Deleting;
                } else {
                    self.cur.as_mut().expect("diff in progress").added.push(rr);
                }
            }
        }
        Ok(None)
    }
}

/// A blocking client for one zone-maintenance conversation at a time.
#[derive(Debug, Clone)]
pub struct ZoneClient {
    timeout: Duration,
    tsig: Option<TsigKey>,
}

impl Default for ZoneClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneClient {
    /// A client with a 5 second I/O timeout.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            tsig: None,
        }
    }

    /// Sign every request with `key` (RFC 8945) and require every response
    /// to verify under it.
    pub fn with_tsig(mut self, key: TsigKey) -> Self {
        self.tsig = Some(key);
        self
    }

    /// Serialise `msg`, signing it when a key is set. Returns the bytes and
    /// the request MAC responses are chained to.
    fn encode_request(&self, msg: &DnsMessage) -> io::Result<(Vec<u8>, Option<Vec<u8>>)> {
        let bytes = msg.serialize().map_err(|e| invalid(e.to_string()))?;
        match &self.tsig {
            None => Ok((bytes, None)),
            Some(key) => {
                let (signed, mac) = tsig::sign(&bytes, key, Chain::default(), false, tsig::now());
                Ok((signed, Some(mac)))
            }
        }
    }

    /// Check a single-message response against the request MAC.
    fn check_response(&self, raw: &[u8], request_mac: Option<&[u8]>) -> io::Result<()> {
        let (Some(key), Some(mac)) = (&self.tsig, request_mac) else {
            return Ok(());
        };
        let ring = TsigKeyring::new().with_key(key.clone());
        let chain = Chain { prior_mac: Some(mac), unsigned_since: &[] };
        // An error answer (for instance NOTAUTH because our key was refused)
        // is unsigned by design; surface it as such rather than as BADSIG.
        if tsig::locate(raw).is_none() {
            return match DnsMessage::parse(raw) {
                Ok(m) if m.rcode() != RCODE_NOERROR => Ok(()),
                _ => Err(invalid("response is not TSIG-signed")),
            };
        }
        tsig::verify(raw, &ring, chain, false, tsig::now())
            .map(|_| ())
            .map_err(|e| invalid(format!("TSIG verification failed: {e:?}")))
    }

    /// Per-operation network timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn udp_exchange(&self, server: SocketAddr, msg: &DnsMessage) -> io::Result<DnsMessage> {
        let (bytes, request_mac) = self.encode_request(msg)?;
        let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
        let sock = UdpSocket::bind(bind)?;
        sock.set_read_timeout(Some(self.timeout))?;
        sock.connect(server)?;
        sock.send(&bytes)?;
        let mut buf = vec![0u8; 65535];
        loop {
            let n = sock.recv(&mut buf)?;
            match DnsMessage::parse(&buf[..n]) {
                Ok(resp) if resp.id == msg.id && resp.is_response() => {
                    self.check_response(&buf[..n], request_mac.as_deref())?;
                    return Ok(resp);
                }
                _ => continue, // not ours; keep waiting until the timeout
            }
        }
    }

    fn tcp_connect(&self, server: SocketAddr) -> io::Result<TcpStream> {
        let s = TcpStream::connect_timeout(&server, self.timeout)?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        Ok(s)
    }

    /// Send a NOTIFY for `origin` (RFC 1996 §3.7) and wait for the answer.
    pub fn notify(&self, peer: SocketAddr, origin: &str) -> io::Result<()> {
        let id = DnsQueryIdGenerator::new().next_id();
        let mut m = DnsMessage::new(
            id,
            (OPCODE_NOTIFY << 11) | FLAG_AA,
            vec![DnsQuestion::in_class(origin, DnsType::Soa)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        m.flags &= !crate::wire::FLAG_QR;
        let resp = self.udp_exchange(peer, &m)?;
        if resp.opcode() != OPCODE_NOTIFY {
            return Err(invalid("response is not a NOTIFY answer"));
        }
        if resp.rcode() != RCODE_NOERROR {
            return Err(io::Error::other(format!("NOTIFY answered with rcode {}", resp.rcode())));
        }
        Ok(())
    }

    /// Ask `server` for the SOA serial of `origin` (the cheap "am I stale?"
    /// probe of RFC 1034 §4.3.5).
    pub fn soa_serial(&self, server: SocketAddr, origin: &str) -> io::Result<u32> {
        let q = DnsMessage::query(
            DnsQueryIdGenerator::new().next_id(),
            DnsQuestion::in_class(origin, DnsType::Soa),
            false,
        );
        let mut resp = self.udp_exchange(server, &q)?;
        if resp.is_truncated() {
            resp = self.tcp_exchange(server, &q)?;
        }
        if resp.rcode() != RCODE_NOERROR {
            return Err(io::Error::other(format!("SOA query answered with rcode {}", resp.rcode())));
        }
        resp.answers
            .iter()
            .find(|r| r.raw_type == TYPE_SOA)
            .and_then(|r| r.as_soa())
            .map(|s| s.serial)
            .ok_or_else(|| invalid("no SOA in answer"))
    }

    fn tcp_exchange(&self, server: SocketAddr, msg: &DnsMessage) -> io::Result<DnsMessage> {
        let (bytes, request_mac) = self.encode_request(msg)?;
        let mut s = self.tcp_connect(server)?;
        write_raw(&mut s, &bytes)?;
        let raw = read_raw(&mut s)?;
        self.check_response(&raw, request_mac.as_deref())?;
        DnsMessage::parse(&raw).map_err(|e| invalid(e.to_string()))
    }

    /// Transfer `origin` from `server`. With `have_serial` an IXFR is asked
    /// for and the primary may answer with differences; without, a full AXFR.
    pub fn transfer(
        &self,
        server: SocketAddr,
        origin: &str,
        have_serial: Option<u32>,
    ) -> io::Result<Transfer> {
        let id = DnsQueryIdGenerator::new().next_id();
        let qtype = if have_serial.is_some() { TYPE_IXFR } else { TYPE_AXFR };
        let mut q = DnsMessage::new(
            id,
            0,
            vec![DnsQuestion::opaque(origin, qtype, 1)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        if let Some(serial) = have_serial {
            // RFC 1995 §3: the client's SOA rides in the authority section.
            q.authorities.push(
                DnsResourceRecord::soa(origin, 0, ".", ".", serial, 0, 0, 0, 0)
                    .map_err(|e| invalid(e.to_string()))?,
            );
        }
        let (bytes, request_mac) = self.encode_request(&q)?;
        let mut s = self.tcp_connect(server)?;
        write_raw(&mut s, &bytes)?;
        let mut collector = XfrCollector::new(have_serial);
        let mut chain = TransferChain::new(self.tsig.as_ref(), request_mac);
        loop {
            let raw = read_raw(&mut s)?;
            let msg = DnsMessage::parse(&raw).map_err(|e| invalid(e.to_string()))?;
            if msg.id != id {
                return Err(invalid("transfer response has the wrong ID"));
            }
            chain.accept(&raw, msg.rcode() != RCODE_NOERROR)?;
            if let Some(done) = collector.push(&msg)? {
                chain.finish()?;
                return Ok(done);
            }
        }
    }

    /// Send an UPDATE message and return the primary's answer.
    pub fn update(&self, server: SocketAddr, update: &DnsMessage) -> io::Result<DnsMessage> {
        debug_assert_eq!(update.opcode(), OPCODE_UPDATE);
        self.udp_exchange(server, update)
    }
}

/// Build an UPDATE for `zone` (RFC 2136 §2): prerequisites then updates.
pub fn build_update(
    zone: &str,
    prerequisites: Vec<DnsResourceRecord>,
    updates: Vec<DnsResourceRecord>,
) -> DnsMessage {
    DnsMessage::new(
        DnsQueryIdGenerator::new().next_id(),
        OPCODE_UPDATE << 11,
        vec![DnsQuestion::in_class(zone, DnsType::Soa)],
        prerequisites,
        updates,
        Vec::new(),
    )
}

fn write_raw(s: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    s.write_all(&out)
}

fn read_raw(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

/// TSIG verification across a multi-message transfer (RFC 8945 §5.3.1).
///
/// A primary may leave up to 99 messages unsigned between signed ones (BIND
/// does), so unsigned messages are accumulated and covered by the next
/// signature; the last message of the transfer must itself be signed.
pub(crate) struct TransferChain {
    ring: Option<TsigKeyring>,
    prior_mac: Option<Vec<u8>>,
    unsigned: Vec<u8>,
    unsigned_count: usize,
    first: bool,
    last_signed: bool,
}

impl TransferChain {
    pub(crate) fn new(key: Option<&TsigKey>, request_mac: Option<Vec<u8>>) -> Self {
        Self {
            ring: key.map(|k| TsigKeyring::new().with_key(k.clone())),
            prior_mac: request_mac,
            unsigned: Vec::new(),
            unsigned_count: 0,
            first: true,
            last_signed: true,
        }
    }

    /// Check one received message. `is_error` marks an error answer, which is
    /// legitimately unsigned.
    pub(crate) fn accept(&mut self, raw: &[u8], is_error: bool) -> io::Result<()> {
        let Some(ring) = &self.ring else {
            return Ok(());
        };
        if is_error {
            return Ok(());
        }
        if tsig::locate(raw).is_some() {
            let chain = Chain {
                prior_mac: self.prior_mac.as_deref(),
                unsigned_since: &self.unsigned,
            };
            let v = tsig::verify(raw, ring, chain, !self.first, tsig::now())
                .map_err(|e| invalid(format!("TSIG verification failed: {e:?}")))?;
            self.prior_mac = Some(v.mac);
            self.unsigned.clear();
            self.unsigned_count = 0;
            self.last_signed = true;
        } else {
            if self.first {
                return Err(invalid("first transfer message is not TSIG-signed"));
            }
            self.unsigned_count += 1;
            if self.unsigned_count > 99 {
                return Err(invalid("more than 99 unsigned transfer messages"));
            }
            self.unsigned.extend_from_slice(raw);
            self.last_signed = false;
        }
        self.first = false;
        Ok(())
    }

    /// The transfer is complete: its last message must have been signed.
    pub(crate) fn finish(&self) -> io::Result<()> {
        if self.ring.is_some() && !self.last_signed {
            return Err(invalid("transfer does not end with a TSIG-signed message"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::zone::{update, xfr, Zone};
    use std::net::Ipv4Addr;

    fn zone() -> Zone {
        Zone::from_zone_text(
            "$TTL 60\n@ SOA ns h 10 3600 900 604800 60\n NS ns\nns A 192.0.2.1\nhost A 192.0.2.10\n",
            Some("example.com"),
        )
        .unwrap()
    }

    fn q(ty: u16) -> DnsMessage {
        DnsMessage::new(1, 0, vec![DnsQuestion::opaque("example.com", ty, 1)], vec![], vec![], vec![])
    }

    fn feed(mut c: XfrCollector, msgs: &[DnsMessage]) -> io::Result<Option<Transfer>> {
        for m in msgs {
            // Wire round trip, as the real client sees it.
            let m = DnsMessage::parse(&m.serialize().unwrap()).unwrap();
            if let Some(t) = c.push(&m)? {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }

    #[test]
    fn axfr_from_the_server_side_reassembles() {
        let z = zone();
        let got = feed(XfrCollector::new(None), &xfr::axfr(&q(TYPE_AXFR), &z)).unwrap();
        match got {
            Some(Transfer::Full(rrs)) => assert_eq!(rrs, z.records()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ixfr_differences_and_up_to_date_and_fallback() {
        let mut z = zone();
        let base = z.serial();
        let add = |name: &str, i: u8| DnsResourceRecord::a(name, 60, Ipv4Addr::new(1, 1, 1, i));
        for (n, i) in [("a.example.com", 1u8), ("b.example.com", 2)] {
            let upd = build_update("example.com", vec![], vec![add(n, i)]);
            assert!(update::apply(&mut z, &upd).changed);
        }
        match feed(XfrCollector::new(Some(base)), &xfr::ixfr(&q(TYPE_IXFR), &z, base)).unwrap() {
            Some(Transfer::Incremental(diffs)) => {
                assert_eq!(diffs.len(), 2);
                let mut copy = zone();
                for d in diffs {
                    copy.apply_diff(d.deleted, d.added).unwrap();
                }
                assert_eq!(copy.records(), z.records());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            feed(XfrCollector::new(Some(z.serial())), &xfr::ixfr(&q(TYPE_IXFR), &z, z.serial())).unwrap(),
            Some(Transfer::UpToDate)
        );
        // Journal does not reach back: an AXFR-style answer to an IXFR.
        match feed(XfrCollector::new(Some(3)), &xfr::ixfr(&q(TYPE_IXFR), &z, 3)).unwrap() {
            Some(Transfer::Full(rrs)) => assert_eq!(rrs, z.records()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_large_multi_message_transfer_is_collected_across_messages() {
        let mut text = String::from("$TTL 60\n@ SOA ns h 1 2 3 4 5\n NS ns\nns A 192.0.2.1\n");
        for i in 0..1500 {
            text.push_str(&format!("host{i}.long-owner-name-so-messages-fill-up A 10.0.{}.{}\n", i / 250, i % 250));
        }
        let z = Zone::from_zone_text(&text, Some("example.com")).unwrap();
        let msgs = xfr::axfr(&q(TYPE_AXFR), &z);
        assert!(msgs.len() > 1);
        match feed(XfrCollector::new(None), &msgs).unwrap() {
            Some(Transfer::Full(rrs)) => assert_eq!(rrs.len(), z.record_count()),
            other => panic!("{other:?}"),
        }
        // Truncated: nothing reported complete.
        assert_eq!(feed(XfrCollector::new(None), &msgs[..msgs.len() - 1]).unwrap(), None);
    }

    #[test]
    fn a_refusal_or_garbage_is_an_error() {
        let refused = q(TYPE_AXFR).response_template(crate::wire::RCODE_REFUSED);
        assert!(feed(XfrCollector::new(None), &[refused]).is_err());
        let mut junk = q(TYPE_AXFR).response_template(0);
        junk.answers.push(DnsResourceRecord::a("x.example.com", 1, Ipv4Addr::LOCALHOST));
        assert!(feed(XfrCollector::new(None), &[junk]).is_err(), "must start with SOA");
    }

    /// A key with a random secret, fixed for the life of the test process
    /// (the tests only need every call to agree, not a particular value).
    fn key() -> TsigKey {
        static SECRET: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        let secret = SECRET.get_or_init(|| {
            let mut b = [0u8; 32];
            getrandom::getrandom(&mut b).expect("OS RNG");
            b
        });
        TsigKey::new("k", crate::tsig::TsigAlgorithm::HmacSha256, secret.to_vec())
    }

    /// Signed, unsigned-intermediate and final-signed transfer messages as a
    /// server that signs only some of them would send them.
    fn signed_sequence(sign_which: &[bool]) -> (Vec<Vec<u8>>, Vec<u8>) {
        let z = {
            let mut text = String::from("$TTL 60\n@ SOA ns h 1 2 3 4 5\n NS ns\nns A 192.0.2.1\n");
            for i in 0..1500 {
                text.push_str(&format!("host{i}.long-owner-name-so-messages-fill-up A 10.0.{}.{}\n", i / 250, i % 250));
            }
            Zone::from_zone_text(&text, Some("example.com")).unwrap()
        };
        let msgs = xfr::axfr(&q(TYPE_AXFR), &z);
        assert!(msgs.len() >= sign_which.len(), "{} messages", msgs.len());
        let request = q(TYPE_AXFR).serialize().unwrap();
        let (_, request_mac) = tsig::sign(&request, &key(), Chain::default(), false, tsig::now());
        let mut prior = request_mac.clone();
        let mut unsigned: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        for (i, m) in msgs.iter().enumerate() {
            let bytes = m.serialize().unwrap();
            let signed = sign_which.get(i).copied().unwrap_or(i + 1 == msgs.len());
            if signed {
                let chain = Chain { prior_mac: Some(&prior), unsigned_since: &unsigned };
                let (b, mac) = tsig::sign(&bytes, &key(), chain, i > 0, tsig::now());
                out.push(b);
                prior = mac;
                unsigned.clear();
            } else {
                unsigned.extend_from_slice(&bytes);
                out.push(bytes);
            }
        }
        (out, request_mac)
    }

    fn run_chain(msgs: &[Vec<u8>], request_mac: Vec<u8>) -> io::Result<()> {
        let mut chain = TransferChain::new(Some(&key()), Some(request_mac));
        for m in msgs {
            chain.accept(m, false)?;
        }
        chain.finish()
    }

    #[test]
    fn transfer_chain_verifies_every_message_signed_or_with_unsigned_intermediates() {
        let (all, mac) = signed_sequence(&[true, true, true, true, true, true]);
        run_chain(&all, mac).unwrap();
        // Only the first and the last are signed; the middle ones are covered
        // by the next signature.
        let (some, mac) = signed_sequence(&[true, false, false]);
        run_chain(&some, mac).unwrap();
    }

    #[test]
    fn transfer_chain_rejects_tampering_a_missing_final_signature_and_an_unsigned_start() {
        let (mut msgs, mac) = signed_sequence(&[true, false, false]);
        // Corrupt an unsigned intermediate: the next signature no longer covers it.
        msgs[1][20] ^= 1;
        assert!(run_chain(&msgs, mac).is_err());

        let (msgs, mac) = signed_sequence(&[true, true, true]);
        // Drop the signature of the last message by stripping its TSIG.
        let last = msgs.last().unwrap();
        let rec = tsig::locate(last).unwrap();
        let mut stripped = last[..rec.start].to_vec();
        let ar = u16::from_be_bytes([stripped[10], stripped[11]]) - 1;
        stripped[10..12].copy_from_slice(&ar.to_be_bytes());
        let mut truncated = msgs[..msgs.len() - 1].to_vec();
        truncated.push(stripped);
        assert!(run_chain(&truncated, mac.clone()).is_err(), "must end signed");

        let (msgs, mac) = signed_sequence(&[false, true, true]);
        let _ = mac;
        let (_, mac2) = signed_sequence(&[true]);
        assert!(run_chain(&msgs, mac2).is_err(), "the first message must be signed");
    }
}
