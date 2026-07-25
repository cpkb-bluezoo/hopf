# hopf-pop3

POP3 / POP3S **server and async client** for [Hopf](https://cpkb-bluezoo.github.io/hopf/)
(Gumdrop `pop3` port).

## Server features

- **Commands:** USER/PASS, APOP, AUTH (SASL), STAT, LIST, RETR, DELE, RSET,
  TOP, UIDL, CAPA, NOOP, QUIT, STLS, UTF8
- **Auth:** `CredentialStore` + staged handler SPI; default handler opens
  `INBOX` via `MailboxFactory`
- **TLS:** STLS and implicit POP3S
- **Codec:** incremental `ByteStreamLexer` (`KEYWORD [SP TEXT] CRLF`)

## Client features

- **Async:** non-blocking, built on the hopf-core `Runtime` / `ProtocolHandler`
- **DNS:** async hostname resolution via hopf-dns (`DnsResolver`)
- **Auth:** USER/PASS, APOP (MD5 digest), AUTH PLAIN; `prefer_apop` flag
- **TLS:** STLS (explicit) and POP3S (implicit)
- **Pipeline:** `Pop3Fetch` auto-pilot — CAPA → auth → STAT → LIST → RETR → QUIT
- **Custom drivers:** `Pop3ClientDriver` + `Pop3ClientHandlerFactory` traits

## Quick start

```toml
[dependencies]
hopf-pop3 = "0.1"
hopf-core = "0.1"
```

### Server

```rust,no_run
use std::sync::Arc;
use hopf_auth::PasswordStore;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::MaildirFactory;
use hopf_pop3::{Pop3Config, Pop3Service};

let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
let factory = Arc::new(MaildirFactory::new("./mail"));
let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
let config = Pop3Config::new("0.0.0.0:110".parse().unwrap(), "pop3.example.com", store, factory);
Pop3Service::new(config, Arc::clone(&rt)).start().unwrap();
```

### Client

```rust,no_run
use std::sync::Arc;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_pop3::{Pop3Client, Pop3Fetch};

let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
let fetch = Pop3Fetch::new()
    .credentials("alice", "secret")
    .on_message(Box::new(|id, _uid, bytes| {
        println!("message {id}: {} bytes", bytes.len());
    }))
    .on_complete(Box::new(|ok| println!("done: {ok}")));
Pop3Client::new("pop3.example.com", 110)
    .connect(&rt, Arc::new(fetch))
    .unwrap();
```

See [docs/pop3.html](https://cpkb-bluezoo.github.io/hopf/pop3.html).
