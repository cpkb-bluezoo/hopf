# hopf-smtp

SMTP / SMTPS **server** and callback-driven **client** for Hopf — Gumdrop
`org.bluezoo.gumdrop.smtp` port.

Protocol engine, staged connection-handler SPI, STARTTLS / AUTH PLAIN,
DATA (dot-stuffing) and BDAT. Stock handlers:

- `AcceptAllSmtpHandler` — accept and discard
- `SimpleRelayService` / `SimpleRelayHandler` — open MX relay via `hopf-dns`
  (dev/test only)
- `LocalDeliveryService` / `LocalDeliveryHandler` — deliver to local INBOXes
  via `hopf-mailbox` (mbox or Maildir++)

## Async client

- `SmtpClient` — builder + `connect(&Arc<Runtime>, factory)`; returns immediately
- `SmtpClientTimeouts` — `dns` / `connect` / `stage` / `message`
- `SmtpSend` — auto-pilot pipeline (EHLO → MAIL → RCPT → DATA → QUIT) with
  `on_complete` callback

```rust
use std::sync::Arc;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_smtp::{SmtpClient, SmtpSend};

let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
let send = SmtpSend::new("client.example")
    .mail_from("from@example.com")
    .rcpt_to("to@example.com")
    .message(b"Subject: hi\r\n\r\nHello\r\n".to_vec())
    .on_complete(Box::new(|ok| eprintln!("delivery: {ok}")));
SmtpClient::new("127.0.0.1", 2525).connect(&rt, Arc::new(send))?;
```

## Local delivery

```rust
use std::sync::Arc;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::MaildirFactory;
use hopf_smtp::{LocalDeliveryService, SmtpConfig};

let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
let factory = Arc::new(MaildirFactory::new("/var/mail"));
let config = SmtpConfig::new("0.0.0.0:25".parse()?, "mail.example.com");
let svc = LocalDeliveryService::new(config, Arc::clone(&rt), factory, "example.com");
svc.start(rt)?;
```

Properties: `local_domain` (required), `hostname` / size / AUTH / TLS from
`SmtpConfig`, plus a `MailboxFactory`. Non-local RCPT TO is rejected with
relay denied; delivery APPENDs on the Runtime storage pool.
