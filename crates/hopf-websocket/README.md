# hopf-websocket

WebSocket (RFC 6455) framing and HTTP handshake helpers for Hopf.

Bootstraps via HTTP/1.1 Upgrade, HTTP/2 Extended CONNECT (RFC 8441), or
HTTP/3 Extended CONNECT (RFC 9220) using `hopf-http` protocol upgrade
seams. Frame parsing is push-incremental with handler callbacks.
