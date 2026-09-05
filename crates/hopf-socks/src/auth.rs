// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 1929 username/password authentication seam.

/// Verifies RFC 1929 username/password credentials offered during SOCKS5
/// authentication sub-negotiation.
///
/// When no authenticator is configured, a SOCKS5 listener offers only the
/// no-auth method and SOCKS4/4a requests are accepted as-is (SOCKS4 has no
/// credential field). Configuring one has two effects: SOCKS5 clients are
/// required to authenticate (no-auth is no longer offered, even if the
/// client asks for it), and SOCKS4/4a requests are rejected outright,
/// since there is no way to honor a real credential check against a
/// protocol that carries none.
pub trait SocksAuthenticator: Send + Sync {
    /// Whether `username`/`password` are valid.
    fn verify(&self, username: &str, password: &str) -> bool;
}
