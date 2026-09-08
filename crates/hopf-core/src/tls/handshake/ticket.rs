// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opaque hopf session tickets for TLS 1.3 PSK resumption / 0-RTT.
//!
//! Ticket ciphertext is hopf-private (AES-GCM sealed identity). Wire-visible
//! PSK age, lifetime, and early-data checks follow RFC 8446 / RFC 9001.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use aws_lc_rs::digest::{digest, SHA256};
use bytes::{BufMut, Bytes, BytesMut};
use getrandom::getrandom;

use super::key_schedule::derive_resumption_psk;
use super::messages::{build_new_session_ticket, HandshakeMessage};
use super::transport_params::RememberedTransportLimits;

/// Lifetime advertised in NewSessionTicket (seconds).
pub const TICKET_LIFETIME_SECS: u32 = 24 * 60 * 60;

/// Default max ticket age for accepting 0-RTT (milliseconds).
pub const DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS: u32 = 30_000;

/// Sealed ticket plaintext version (issued_at / lifetime / age_add / remembered TPs).
const TICKET_PAYLOAD_VERSION: u8 = 0x02;
const TICKET_PAYLOAD_VERSION_V1: u8 = 0x01;

/// Material the client caches after receiving a NewSessionTicket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTicket {
    /// Opaque ticket identity presented in `pre_shared_key`.
    pub identity: Bytes,
    /// Resumption PSK (32 bytes).
    pub psk: [u8; 32],
    /// Max early data from the ticket's `early_data` extension (0 = no 0-RTT).
    pub max_early_data_size: u32,
    /// ALPN negotiated when the ticket was issued.
    pub alpn: Bytes,
    /// `ticket_age_add` from NewSessionTicket (RFC 8446 §4.6.1).
    pub ticket_age_add: u32,
    /// Ticket lifetime from NewSessionTicket (seconds).
    pub lifetime_secs: u32,
    /// When the client received / cached this ticket.
    pub received_at: Instant,
    /// Peer (server) transport limits from the connection that minted this ticket.
    pub remembered_peer_limits: Option<RememberedTransportLimits>,
}

impl StoredTicket {
    /// True when the ticket is past its advertised lifetime.
    pub fn is_expired(&self) -> bool {
        self.received_at.elapsed().as_secs() > u64::from(self.lifetime_secs)
    }

    /// RFC 8446 §4.2.11 `obfuscated_ticket_age`.
    pub fn obfuscated_ticket_age(&self) -> u32 {
        let age_ms = saturating_millis(self.received_at.elapsed());
        age_ms.wrapping_add(self.ticket_age_add)
    }
}

/// Recover plaintext ticket age from the obfuscated wire value.
pub fn recover_ticket_age(obfuscated_ticket_age: u32, ticket_age_add: u32) -> u32 {
    obfuscated_ticket_age.wrapping_sub(ticket_age_add)
}

fn saturating_millis(d: Duration) -> u32 {
    let ms = d.as_millis();
    if ms > u128::from(u32::MAX) {
        u32::MAX
    } else {
        ms as u32
    }
}

fn unix_now_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// Shared client-side ticket cache keyed by server name (SNI).
#[derive(Debug, Default)]
pub struct ClientTicketStore {
    inner: Mutex<HashMap<String, StoredTicket>>,
}

impl ClientTicketStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap in an `Arc` for sharing across dials of one [`super::super::HandshakeConfig`].
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Insert / replace the ticket for `server_name`.
    pub fn put(&self, server_name: &str, ticket: StoredTicket) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(server_name.to_string(), ticket);
        }
    }

    /// Look up a ticket for `server_name`, clearing it if expired.
    pub fn get(&self, server_name: &str) -> Option<StoredTicket> {
        let mut g = self.inner.lock().ok()?;
        let expired = g.get(server_name).map(|t| t.is_expired()).unwrap_or(false);
        if expired {
            g.remove(server_name);
            return None;
        }
        g.get(server_name).cloned()
    }

    /// Remove a ticket (e.g. after a failed resume).
    pub fn remove(&self, server_name: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(server_name);
        }
    }
}

/// Plaintext sealed inside an opaque hopf ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPayload {
    /// Unix millis when the ticket was minted.
    pub issued_at_ms: u64,
    /// Lifetime in seconds (same as NST).
    pub lifetime_secs: u32,
    /// `ticket_age_add` so the server can recover age without trusting the client.
    pub ticket_age_add: u32,
    /// Resumption PSK.
    pub psk: [u8; 32],
    /// Max early data size.
    pub max_early_data_size: u32,
    /// ALPN at issue time.
    pub alpn: Bytes,
    /// Server limits sealed for 0-RTT consistency (RFC 9000 §7.4.1).
    pub remembered_limits: Option<RememberedTransportLimits>,
}

/// Seal a ticket with the server's 32-byte ticket key (AES-128-GCM; first 16 bytes of key).
pub fn seal_ticket(ticket_key: &[u8; 32], payload: &TicketPayload) -> Option<Bytes> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &ticket_key[..16]).ok()?);
    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes).ok()?;
    let mut plain = BytesMut::with_capacity(1 + 8 + 4 + 4 + 4 + 2 + payload.alpn.len() + 32 + 56);
    plain.put_u8(TICKET_PAYLOAD_VERSION);
    plain.put_u64(payload.issued_at_ms);
    plain.put_u32(payload.lifetime_secs);
    plain.put_u32(payload.ticket_age_add);
    plain.put_u32(payload.max_early_data_size);
    plain.put_u16(payload.alpn.len() as u16);
    plain.extend_from_slice(&payload.alpn);
    plain.extend_from_slice(&payload.psk);
    if let Some(limits) = &payload.remembered_limits {
        plain.extend_from_slice(&limits.encode_fixed());
    } else {
        plain.extend_from_slice(&[0u8; 56]);
    }
    let mut body = plain.to_vec();
    let tag = key
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce_bytes), Aad::empty(), &mut body)
        .ok()?;
    let mut out = BytesMut::with_capacity(12 + body.len() + 16);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&body);
    out.extend_from_slice(tag.as_ref());
    Some(out.freeze())
}

/// Open an opaque ticket sealed by [`seal_ticket`].
pub fn open_ticket(ticket_key: &[u8; 32], identity: &[u8]) -> Option<TicketPayload> {
    if identity.len() < 12 + 16 {
        return None;
    }
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &ticket_key[..16]).ok()?);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&identity[..12]);
    let mut buf = identity[12..].to_vec();
    key.open_in_place(Nonce::assume_unique_for_key(nonce_bytes), Aad::empty(), &mut buf)
        .ok()?;
    let plain_len = buf.len().checked_sub(16)?;
    let plain = &buf[..plain_len];
    if plain.is_empty() {
        return None;
    }
    let version = plain[0];
    if version != TICKET_PAYLOAD_VERSION && version != TICKET_PAYLOAD_VERSION_V1 {
        return None;
    }
    // version(1) + issued_at(8) + lifetime(4) + age_add(4) + max_early(4) + alpn_len(2) + psk(32)
    if plain.len() < 1 + 8 + 4 + 4 + 4 + 2 + 32 {
        return None;
    }
    let issued_at_ms = u64::from_be_bytes(plain[1..9].try_into().ok()?);
    let lifetime_secs = u32::from_be_bytes(plain[9..13].try_into().ok()?);
    let ticket_age_add = u32::from_be_bytes(plain[13..17].try_into().ok()?);
    let max_early_data_size = u32::from_be_bytes(plain[17..21].try_into().ok()?);
    let alpn_len = u16::from_be_bytes(plain[21..23].try_into().ok()?) as usize;
    if plain.len() < 23 + alpn_len + 32 {
        return None;
    }
    let alpn = Bytes::copy_from_slice(&plain[23..23 + alpn_len]);
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&plain[23 + alpn_len..23 + alpn_len + 32]);
    let remembered_limits = if version == TICKET_PAYLOAD_VERSION {
        let tail = &plain[23 + alpn_len + 32..];
        RememberedTransportLimits::decode_fixed(tail)
    } else {
        None
    };
    Some(TicketPayload {
        issued_at_ms,
        lifetime_secs,
        ticket_age_add,
        psk,
        max_early_data_size,
        alpn,
        remembered_limits,
    })
}

/// SHA-256 of ticket identity bytes (anti-replay map key).
pub fn ticket_identity_hash(identity: &[u8]) -> [u8; 32] {
    let d = digest(&SHA256, identity);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Server-side early-data anti-replay cache (ticket identity → expiry).
#[derive(Debug)]
pub struct AntiReplay {
    window: Duration,
    seen: Mutex<HashMap<[u8; 32], Instant>>,
}

impl AntiReplay {
    /// Create with a freshness window (typically equals max early-data age).
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Shared instance for all connections of one server config.
    pub fn shared(window: Duration) -> Arc<Self> {
        Arc::new(Self::new(window))
    }

    /// Default window matching [`DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS`].
    pub fn shared_default() -> Arc<Self> {
        Self::shared(Duration::from_millis(u64::from(
            DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
        )))
    }

    /// Record a first-seen ticket for early data. Returns `false` if this
    /// identity was already accepted within the window (replay → reject 0-RTT).
    pub fn check_and_record(&self, identity: &[u8]) -> bool {
        let key = ticket_identity_hash(identity);
        let Ok(mut g) = self.seen.lock() else {
            return false;
        };
        let now = Instant::now();
        g.retain(|_, exp| *exp > now);
        if let Some(exp) = g.get(&key) {
            if *exp > now {
                return false;
            }
        }
        g.insert(key, now + self.window);
        true
    }
}

/// Mint a NewSessionTicket message and the client-side [`StoredTicket`] material.
pub fn mint_new_session_ticket(
    ticket_key: &[u8; 32],
    resumption_master: &[u8; 32],
    max_early_data_size: u32,
    alpn: &[u8],
    remembered_limits: Option<RememberedTransportLimits>,
) -> Option<(HandshakeMessage, StoredTicket)> {
    let mut ticket_nonce = [0u8; 8];
    getrandom(&mut ticket_nonce).ok()?;
    let psk = derive_resumption_psk(resumption_master, &ticket_nonce);
    let mut age_add = [0u8; 4];
    getrandom(&mut age_add).ok()?;
    let ticket_age_add = u32::from_be_bytes(age_add);
    let issued_at_ms = unix_now_ms()?;
    let identity = seal_ticket(
        ticket_key,
        &TicketPayload {
            issued_at_ms,
            lifetime_secs: TICKET_LIFETIME_SECS,
            ticket_age_add,
            psk,
            max_early_data_size,
            alpn: Bytes::copy_from_slice(alpn),
            remembered_limits,
        },
    )?;
    let msg = build_new_session_ticket(
        TICKET_LIFETIME_SECS,
        ticket_age_add,
        &ticket_nonce,
        identity.as_ref(),
        max_early_data_size,
    );
    let stored = StoredTicket {
        identity,
        psk,
        max_early_data_size,
        alpn: Bytes::copy_from_slice(alpn),
        ticket_age_add,
        lifetime_secs: TICKET_LIFETIME_SECS,
        received_at: Instant::now(),
        remembered_peer_limits: remembered_limits,
    };
    Some((msg, stored))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x55u8; 32];
        let payload = TicketPayload {
            issued_at_ms: 1_700_000_000_000,
            lifetime_secs: TICKET_LIFETIME_SECS,
            ticket_age_add: 0xdead_beef,
            psk: [0xaau8; 32],
            max_early_data_size: u32::MAX,
            alpn: Bytes::from_static(b"hq-interop"),
            remembered_limits: Some(RememberedTransportLimits::default_missing()),
        };
        let id = seal_ticket(&key, &payload).unwrap();
        let opened = open_ticket(&key, &id).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn obfuscated_age_roundtrip() {
        let age_add = 0x1234_5678u32;
        let age_ms = 12_345u32;
        let obfuscated = age_ms.wrapping_add(age_add);
        assert_eq!(recover_ticket_age(obfuscated, age_add), age_ms);
        // wrapping edge
        let age_add2 = u32::MAX - 10;
        let age_ms2 = 20u32;
        let obf2 = age_ms2.wrapping_add(age_add2);
        assert_eq!(recover_ticket_age(obf2, age_add2), age_ms2);
    }

    #[test]
    fn ticket_store_put_get() {
        let store = ClientTicketStore::new();
        let t = StoredTicket {
            identity: Bytes::from_static(b"id"),
            psk: [1u8; 32],
            max_early_data_size: 100,
            alpn: Bytes::from_static(b"h3"),
            ticket_age_add: 42,
            lifetime_secs: 3600,
            received_at: Instant::now(),
            remembered_peer_limits: None,
        };
        store.put("localhost", t.clone());
        assert_eq!(store.get("localhost"), Some(t));
    }

    #[test]
    fn expired_ticket_not_offered() {
        let store = ClientTicketStore::new();
        let t = StoredTicket {
            identity: Bytes::from_static(b"id"),
            psk: [1u8; 32],
            max_early_data_size: 100,
            alpn: Bytes::from_static(b"h3"),
            ticket_age_add: 1,
            lifetime_secs: 0,
            // Already older than lifetime_secs (0) once Instant advances.
            received_at: Instant::now() - Duration::from_secs(2),
            remembered_peer_limits: None,
        };
        store.put("localhost", t);
        assert!(store.get("localhost").is_none());
    }

    #[test]
    fn anti_replay_rejects_second_use() {
        let ar = AntiReplay::new(Duration::from_secs(30));
        let id = b"ticket-bytes";
        assert!(ar.check_and_record(id));
        assert!(!ar.check_and_record(id));
    }
}
