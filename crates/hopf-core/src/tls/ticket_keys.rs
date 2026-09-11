// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Session-ticket encryption keyring, shared by TLS 1.3's and TLS 1.2's
//! ticket code (`handshake::ticket`/`tls12::ticket`) — both seal tickets
//! as `nonce || AES-128-GCM(payload) || tag` under a raw `[u8; 32]` key
//! with no key ID anywhere in the ciphertext. That means there is no way
//! to tell, on decrypt, which key a given ticket was sealed under — the
//! only option is to try candidates in turn until one authenticates.
//!
//! [`TicketKeys`] is that small keyring: one key new tickets are sealed
//! under, plus the single most-recently-rotated-away key so tickets
//! minted just before a rotation don't instantly stop resuming. Rotation
//! *cadence* (e.g. "weekly") is deliberately not this type's job — there's
//! no timer-tick entry point in the TCP/QUIC TLS engines to drive it
//! autonomously, and deciding *when* to rotate is a caller/deployment
//! policy, not something a synchronous handshake engine should own (see
//! `crypto-migration-plan.md`'s RFC 9325 entry for the fuller reasoning).

/// A server's local ticket-encryption key (AES-128-GCM sealing/opening of
/// session tickets) — distinct from the protocol-derived secrets
/// (`ResumptionMasterSecret`, `PskSecret`) that get sealed inside a
/// ticket, so `mint_new_session_ticket`/`open_ticket` can't have the two
/// transposed: sealing a ticket under protocol secret material, or
/// deriving a PSK from the local ticket key, would both be silent,
/// exploitable mistakes rather than compiler errors.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TicketKey([u8; 32]);

impl TicketKey {
    /// Wrap a raw 32-byte ticket key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw key octets.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TicketKey(..)")
    }
}

/// A ticket-encryption key plus the one key rotated away from most
/// recently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketKeys {
    current: TicketKey,
    previous: Option<TicketKey>,
}

impl TicketKeys {
    /// A keyring with just one key — a drop-in replacement for the old
    /// bare `[u8; 32]` config field for every caller that doesn't need
    /// rotation.
    pub fn single(key: [u8; 32]) -> Self {
        Self { current: TicketKey::from_bytes(key), previous: None }
    }

    /// The key new tickets are sealed under.
    pub fn current(&self) -> &TicketKey {
        &self.current
    }

    /// Every key worth trying to decrypt a ticket against, current first.
    pub fn decrypt_candidates(&self) -> impl Iterator<Item = &TicketKey> {
        std::iter::once(&self.current).chain(self.previous.iter())
    }

    /// Rotate: `new_key` becomes [`Self::current`], the old current key
    /// becomes the (single) key still accepted for decryption, and
    /// whatever was accepted before that is dropped.
    pub fn rotate(&mut self, new_key: [u8; 32]) {
        self.previous = Some(std::mem::replace(&mut self.current, TicketKey::from_bytes(new_key)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_only_offers_the_one_key() {
        let keys = TicketKeys::single([1u8; 32]);
        assert_eq!(keys.current().as_bytes(), &[1u8; 32]);
        assert_eq!(
            keys.decrypt_candidates().map(TicketKey::as_bytes).collect::<Vec<_>>(),
            vec![&[1u8; 32]]
        );
    }

    #[test]
    fn rotate_keeps_exactly_the_immediately_prior_key() {
        let mut keys = TicketKeys::single([1u8; 32]);
        keys.rotate([2u8; 32]);
        assert_eq!(keys.current().as_bytes(), &[2u8; 32]);
        assert_eq!(
            keys.decrypt_candidates().map(TicketKey::as_bytes).collect::<Vec<_>>(),
            vec![&[2u8; 32], &[1u8; 32]],
            "must still accept tickets sealed under the just-rotated-away key"
        );

        keys.rotate([3u8; 32]);
        assert_eq!(
            keys.decrypt_candidates().map(TicketKey::as_bytes).collect::<Vec<_>>(),
            vec![&[3u8; 32], &[2u8; 32]],
            "a second rotation must drop the now-two-generations-old key"
        );
    }
}
