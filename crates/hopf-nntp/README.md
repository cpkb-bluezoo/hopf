# hopf-nntp

NNTP / NNTPS **news reader server** and **async client** for
[Hopf](https://cpkb-bluezoo.github.io/hopf/) (RFC 3977, with STARTTLS per RFC
4642 and AUTHINFO per RFC 4643).

## Server features

- **Newsgroups from a mailbox store:** each mailbox is a group, each UID an
  article number; or implement `ReaderHandler` for any other source
- **Commands:** CAPABILITIES, MODE READER, DATE, HELP, QUIT, GROUP, LISTGROUP,
  LAST, NEXT, ARTICLE, HEAD, BODY, STAT, LIST (ACTIVE, NEWSGROUPS,
  OVERVIEW.FMT), NEWGROUPS, OVER and HDR (and XOVER, XHDR), POST, with wildmats
- **Constant memory:** articles are dot-stuffed by a state machine that holds no
  line and travel through a bounded pipe, so a slow client slows the read of
  the store; a posted article reaches a `PostSink` in pieces of at most 64 KiB
  and one write at a time. A 192 MiB article peaks at about 127 KiB of heap
- **Security:** STARTTLS and implicit TLS, AUTHINFO USER/PASS and SASL against a
  `CredentialStore`, `require_authentication`, passwords refused in the clear
  by default
- **Telemetry:** OTLP metrics and per-connection traces through
  `NntpService::with_telemetry`

```rust,ignore
let service = NntpService::new(
    NntpConfig::new("0.0.0.0:119".parse()?, "news.example.com").with_tls(acceptor),
    runtime,
    Arc::new(MaildirFactory::new("/var/spool/news")),
);
service.start()?;
```

## Client features

- **Async:** non-blocking, built on the hopf-core `Runtime` / `ProtocolHandler`
- **DNS:** async hostname resolution via hopf-dns (`DnsResolver`)
- **TLS:** implicit NNTPS (port 563) and STARTTLS, required or opportunistic
- **Auth:** AUTHINFO USER/PASS and AUTHINFO SASL (SCRAM-SHA-256, PLAIN,
  LOGIN) chosen from CAPABILITIES, or the mechanisms you name
  (`sasl_mechanisms`, `bearer_token` for OAUTHBEARER / XOAUTH2,
  `sasl_external` for a client certificate)
- **Posting in constant memory:** `post_stream` takes an `NntpPoster` asked for
  the article a piece at a time as the connection drains;
  `post_with_attachments` uuencodes files as they are read;
  `article_with_attachments` tells you the text and each file as an article
  arrives
- **Session:** a cloneable `NntpSession` queues commands from any thread;
  replies and completions come back as callbacks
- **Parsing:** one pass over the connection's ring, nothing buffered whole.
  `GROUP` and `STAT` replies, LIST ACTIVE and OVER lines are read into typed
  values field by field as the bytes arrive (one callback per entry); article,
  head and body text is passed on as it arrives, dot-unstuffed, in whatever
  pieces the connection delivers it, with no limit on line length
- **Helpers:** LIST ACTIVE, GROUP, STAT, OVER, ARTICLE, HEAD, BODY, POST,
  QUIT, and any raw command

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
