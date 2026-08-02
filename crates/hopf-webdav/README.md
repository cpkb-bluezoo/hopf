# hopf-webdav

WebDAV (RFC 4918) filesystem handler for Hopf HTTP servers.

LOCK on an unmapped URL creates a locked empty resource (RFC 4918 §7.3)
rather than a deprecated lock-null that vanishes on UNLOCK.

See `examples/webdav` for a minimal cleartext server.
