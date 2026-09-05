# hopf-socks

SOCKS proxy for Hopf: SOCKS4, SOCKS4a, and SOCKS5 (RFC 1928), built on
[`hopf-core`](../hopf-core) for its listener/connector infrastructure and
[`hopf-dns`](../hopf-dns) for asynchronous target resolution.

Currently implemented: version detection, SOCKS5 method negotiation with
RFC 1929 username/password authentication, and the CONNECT command,
server-side.
