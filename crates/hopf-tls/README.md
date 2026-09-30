# hopf-tls

**DEPRECATED as of 0.4.0.** Do not add this crate as a dependency.

Use [`hopf-core::tls`](https://docs.rs/hopf-core/latest/hopf_core/tls/index.html) (or the
[`acceptor_from_pem`](https://docs.rs/hopf-core/latest/hopf_core/fn.acceptor_from_pem.html) /
[`connector_from_pem`](https://docs.rs/hopf-core/latest/hopf_core/fn.connector_from_pem.html)
helpers at the `hopf-core` crate root) for production TLS.

This crate remains in the Hopf repository only as a **workspace-internal**
`rustls` interop test harness for `hopf-core::tls`. Version **0.4.0** is the
final crates.io release; after it is published, `publish = false` is set here
and the crate is no longer uploaded.

See [docs/tls.html](../../docs/tls.html) for the full `hopf-core::tls` reference.
