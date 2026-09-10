// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 5077 session tickets — TLS 1.2's stateless resumption mechanism.
//!
//! Deliberately separate from [`super::super::handshake::ticket`] (the TLS
//! 1.3 PSK/0-RTT ticket module): the two protocols' ticket contents differ
//! in kind, not just detail — TLS 1.2 seals the actual 48-byte
//! `master_secret` verbatim (there is no per-resumption PSK derivation like
//! TLS 1.3's `resumption_master_secret` → per-ticket PSK scheme), so a
//! leaked TLS 1.2 ticket-encryption key or ticket exposes every resumed
//! session's traffic directly, with no forward secrecy across resumptions.
//! Short ticket lifetimes and real key rotation are the only mitigation;
//! see crypto-migration-plan.md's Phase 5 write-up.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use bytes::{Bytes, BytesMut};
use getrandom::getrandom;

use super::messages::build_new_session_ticket;

/// Lifetime advertised in `NewSessionTicket` (seconds) and enforced on open.
pub const TICKET_LIFETIME_SECS: u32 = 24 * 60 * 60;

const TICKET_PAYLOAD_VERSION: u8 = 0x01;

/// Plaintext sealed inside an opaque TLS 1.2 session ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12TicketPayload {
    /// The full negotiated master secret (RFC 5246 §8.1) — resuming skips
    /// key exchange entirely and reuses this verbatim.
    pub master_secret: [u8; 48],
    /// Cipher suite the original full handshake negotiated; a resumption
    /// MUST reuse the same suite (its PRF hash choice is baked into the
    /// sealed master secret's derivation).
    pub cipher_suite: u16,
    /// Unix millis when the ticket was minted.
    pub issued_at_ms: u64,
    /// Lifetime in seconds (same value advertised in `NewSessionTicket`).
    pub lifetime_secs: u32,
}

impl Tls12TicketPayload {
    /// True once the ticket has outlived its advertised lifetime.
    pub fn is_expired(&self) -> bool {
        let Some(now_ms) = unix_now_ms() else {
            return true; // no reliable clock: fail closed
        };
        now_ms.saturating_sub(self.issued_at_ms) > u64::from(self.lifetime_secs) * 1000
    }
}

fn unix_now_ms() -> Option<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis() as u64)
}

/// Seal a ticket with the server's 32-byte ticket key (AES-128-GCM; first 16 bytes of key).
pub fn seal_ticket(ticket_key: &[u8; 32], payload: &Tls12TicketPayload) -> Option<Bytes> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &ticket_key[..16]).ok()?);
    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes).ok()?;
    let mut plain = BytesMut::with_capacity(1 + 48 + 2 + 8 + 4);
    plain.extend_from_slice(&[TICKET_PAYLOAD_VERSION]);
    plain.extend_from_slice(&payload.master_secret);
    plain.extend_from_slice(&payload.cipher_suite.to_be_bytes());
    plain.extend_from_slice(&payload.issued_at_ms.to_be_bytes());
    plain.extend_from_slice(&payload.lifetime_secs.to_be_bytes());
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
pub fn open_ticket(ticket_key: &[u8; 32], ticket: &[u8]) -> Option<Tls12TicketPayload> {
    if ticket.len() < 12 + 16 {
        return None;
    }
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &ticket_key[..16]).ok()?);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&ticket[..12]);
    let mut buf = ticket[12..].to_vec();
    key.open_in_place(Nonce::assume_unique_for_key(nonce_bytes), Aad::empty(), &mut buf).ok()?;
    let plain_len = buf.len().checked_sub(16)?;
    let plain = &buf[..plain_len];
    if plain.len() != 1 + 48 + 2 + 8 + 4 || plain[0] != TICKET_PAYLOAD_VERSION {
        return None;
    }
    let mut master_secret = [0u8; 48];
    master_secret.copy_from_slice(&plain[1..49]);
    let cipher_suite = u16::from_be_bytes([plain[49], plain[50]]);
    let issued_at_ms = u64::from_be_bytes(plain[51..59].try_into().ok()?);
    let lifetime_secs = u32::from_be_bytes(plain[59..63].try_into().ok()?);
    Some(Tls12TicketPayload { master_secret, cipher_suite, issued_at_ms, lifetime_secs })
}

/// Seal a fresh ticket and build the `NewSessionTicket` wire message in one
/// step, for the server's post-`Finished` full-handshake flight.
pub fn mint_new_session_ticket(ticket_key: &[u8; 32], master_secret: &[u8; 48], cipher_suite: u16) -> Option<Bytes> {
    let issued_at_ms = unix_now_ms()?;
    let payload = Tls12TicketPayload {
        master_secret: *master_secret,
        cipher_suite,
        issued_at_ms,
        lifetime_secs: TICKET_LIFETIME_SECS,
    };
    let ticket = seal_ticket(ticket_key, &payload)?;
    Some(build_new_session_ticket(TICKET_LIFETIME_SECS, &ticket))
}

/// Material the client caches after receiving a `NewSessionTicket`, and
/// offers back on the next connection to the same server name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTls12Ticket {
    /// Opaque ticket bytes, replayed verbatim in a future `ClientHello`.
    pub ticket: Bytes,
    /// Master secret sealed under this ticket, needed locally to derive
    /// the resumed connection's key material without a fresh key exchange.
    pub master_secret: [u8; 48],
    /// Cipher suite the ticket was issued under; a resumption offer only
    /// makes sense if the server still selects this exact suite.
    pub cipher_suite: u16,
    /// When the client received / cached this ticket.
    pub received_at: Instant,
    /// Ticket lifetime in seconds, from the server's lifetime hint (falls
    /// back to [`TICKET_LIFETIME_SECS`] if the server sent `0`, RFC 5077
    /// §3.3's "unspecified" value).
    pub lifetime_secs: u32,
}

impl StoredTls12Ticket {
    /// True when the ticket is past its advertised lifetime.
    pub fn is_expired(&self) -> bool {
        self.received_at.elapsed().as_secs() > u64::from(self.lifetime_secs)
    }
}

/// Shared client-side ticket cache keyed by server name (SNI).
#[derive(Debug, Default)]
pub struct Tls12ClientTicketStore {
    inner: Mutex<HashMap<String, StoredTls12Ticket>>,
}

impl Tls12ClientTicketStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap in an `Arc` for sharing across dials of one [`super::engine::Config`].
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Insert / replace the ticket for `server_name`.
    pub fn put(&self, server_name: &str, ticket: StoredTls12Ticket) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(server_name.to_string(), ticket);
        }
    }

    /// Look up a ticket for `server_name`, clearing it if expired.
    pub fn get(&self, server_name: &str) -> Option<StoredTls12Ticket> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn payload() -> Tls12TicketPayload {
        Tls12TicketPayload {
            master_secret: [0x42u8; 48],
            cipher_suite: 0xC02F,
            issued_at_ms: unix_now_ms().unwrap(),
            lifetime_secs: TICKET_LIFETIME_SECS,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x55u8; 32];
        let p = payload();
        let ticket = seal_ticket(&key, &p).unwrap();
        let opened = open_ticket(&key, &ticket).unwrap();
        assert_eq!(opened, p);
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let key = [0x55u8; 32];
        let other_key = [0x66u8; 32];
        let ticket = seal_ticket(&key, &payload()).unwrap();
        assert!(open_ticket(&other_key, &ticket).is_none());
    }

    #[test]
    fn tampered_ticket_fails_to_open() {
        let key = [0x55u8; 32];
        let mut ticket = seal_ticket(&key, &payload()).unwrap().to_vec();
        let n = ticket.len();
        ticket[n - 1] ^= 0xff; // flip a tag byte
        assert!(open_ticket(&key, &ticket).is_none());
    }

    #[test]
    fn expired_payload_reports_expired() {
        let mut p = payload();
        p.issued_at_ms = 1; // 1970, long expired
        p.lifetime_secs = 60;
        assert!(p.is_expired());
    }

    #[test]
    fn mint_produces_a_new_session_ticket_message() {
        let key = [0x77u8; 32];
        let msg = mint_new_session_ticket(&key, &[0xabu8; 48], 0xC02B).unwrap();
        // 1-byte type (NewSessionTicket=4) + 3-byte length header.
        assert_eq!(msg[0], 4);
    }

    #[test]
    fn client_store_put_get_remove() {
        let store = Tls12ClientTicketStore::new();
        let t = StoredTls12Ticket {
            ticket: Bytes::from_static(b"opaque"),
            master_secret: [1u8; 48],
            cipher_suite: 0xC02F,
            received_at: Instant::now(),
            lifetime_secs: 3600,
        };
        store.put("localhost", t.clone());
        assert_eq!(store.get("localhost"), Some(t));
        store.remove("localhost");
        assert_eq!(store.get("localhost"), None);
    }

    #[test]
    fn expired_client_ticket_not_offered() {
        let store = Tls12ClientTicketStore::new();
        let t = StoredTls12Ticket {
            ticket: Bytes::from_static(b"opaque"),
            master_secret: [1u8; 48],
            cipher_suite: 0xC02F,
            received_at: Instant::now() - Duration::from_secs(2),
            lifetime_secs: 0,
        };
        store.put("localhost", t);
        assert!(store.get("localhost").is_none());
    }
}
