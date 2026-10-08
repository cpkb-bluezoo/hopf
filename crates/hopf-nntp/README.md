# hopf-nntp

NNTP / NNTPS **async client** for [Hopf](https://cpkb-bluezoo.github.io/hopf/)
(RFC 3977, with STARTTLS per RFC 4642 and AUTHINFO per RFC 4643).

## Client features

- **Async:** non-blocking, built on the hopf-core `Runtime` / `ProtocolHandler`
- **DNS:** async hostname resolution via hopf-dns (`DnsResolver`)
- **TLS:** implicit NNTPS (port 563) and STARTTLS, required or opportunistic
- **Auth:** AUTHINFO USER/PASS and AUTHINFO SASL (SCRAM-SHA-256, CRAM-MD5,
  PLAIN, LOGIN) chosen from CAPABILITIES
- **Session:** a cloneable `NntpSession` queues commands from any thread;
  replies, multi-line bodies (dot-unstuffed) and completions come back as
  callbacks
- **Helpers:** LIST ACTIVE, GROUP, OVER, ARTICLE, HEAD, POST, QUIT, and any
  raw command

## Quick start

```rust,no_run
use std::sync::Arc;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_nntp::{NntpClient, NntpClientHandler, NntpGreeting, NntpSession};

struct ListGroups;

impl NntpClientHandler for ListGroups {
    fn on_connected(&mut self, session: &NntpSession, greeting: &NntpGreeting) {
        println!("connected, posting allowed: {}", greeting.posting_allowed);
        session.list_active("comp.*", |g| println!("{} {}-{}", g.name, g.low, g.high), |r| {
            println!("LIST ACTIVE: {r:?}");
        });
        session.quit();
    }
    fn on_error(&mut self, error: &std::io::Error) {
        eprintln!("nntp: {error}");
    }
}

let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
NntpClient::new("news.example.com", 119)
    .credentials("alice", "secret")
    .connect_with(&rt, Box::new(ListGroups))
    .unwrap();
```

See the [documentation](https://cpkb-bluezoo.github.io/hopf/nntp.html).
