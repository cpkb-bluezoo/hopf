# hopf-masque

MASQUE for Hopf: RFC 9298 (Proxying UDP in HTTP) and RFC 9484 (Proxying IP
in HTTP), built on [`hopf-http`](../hopf-http)'s Capsule Protocol and
`ProtocolUpgradeHandler` machinery — the same pattern
[`hopf-websocket`](../hopf-websocket) uses for its own upgrade.

Currently implemented: the RFC 9298 CONNECT-UDP relay, server-side.
