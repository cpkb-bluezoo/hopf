# hopf-imap

IMAP4rev2 / IMAPS server and callback-driven client for
[Hopf](https://cpkb-bluezoo.github.io/hopf/).

The server uses a staged policy SPI over `hopf-mailbox`. Storage work runs on
the Runtime storage pool (never on the reactor). Advertised capabilities match
implemented support only.

## Server extensions

| Capability | Notes |
|---|---|
| `IDLE` | Continuation + `DONE`; mailbox EXISTS/RECENT polled off-reactor |
| `UIDPLUS` | `APPENDUID`, `COPYUID`, `UID EXPUNGE` |
| `MOVE` | Copy + `\Deleted` + expunge with `COPYUID` |
| `NAMESPACE` | Personal namespace from the mailbox store |
| `ENABLE` | `CONDSTORE` / `QRESYNC` per session |
| `CONDSTORE` | `HIGHESTMODSEQ` on SELECT when enabled; `CHANGEDSINCE` FETCH; `MODSEQ` when backend provides modseqs |
| `QRESYNC` | Degrades safely — no fabricated `VANISHED (EARLIER)` history |
| `UNSELECT` | Deselect without expunge |
| `ID` | RFC 2971 server identity |
| `LIST-EXTENDED` / `LIST-STATUS` / `CHILDREN` | Selection/return options; `RETURN (STATUS (…))` |
| `STATUS` | Standalone STATUS |
| `QUOTA` | `GETQUOTA` / `GETQUOTAROOT` / `SETQUOTA` via pluggable `QuotaManager` (default unlimited) |

The client supports tag-correlated pipelining (STATUS+LIST outstanding
simultaneously), asynchronous DNS, STARTTLS/IMAPS, production IDLE
(`ImapIdle`), ENABLE/CONDSTORE/QRESYNC tracking, and unsolicited mailbox
events via `MailboxEventListener`.

## Server quick start

```rust,ignore
use std::sync::Arc;
use hopf_auth::PasswordStore;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_imap::{ImapConfig, ImapService};
use hopf_mailbox::MaildirFactory;

let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
let factory = Arc::new(MaildirFactory::new("./mail"));
let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
let config = ImapConfig::new("127.0.0.1:1143".parse()?, "localhost", store, factory);
let svc = ImapService::new(config, Arc::clone(&rt));
svc.start()?;
```

Add `.with_tls(acceptor)` for STARTTLS, plus `.implicit_tls()` for IMAPS.
Extension advertisement is controlled by the `enable_*` config flags.
Application policy hooks in via `ImapService::with_handler_factory` and the
staged traits (`ClientConnected` → `NotAuthenticatedHandler` →
`AuthenticatedHandler` → `SelectedHandler`); the stock
`DefaultImapHandlerFactory` accepts everything the config allows.

Example binary: `cargo run -p imap -- 127.0.0.1:1143 localhost ./mail`.

## Client quick start

`ImapFetch` is the auto-pilot pipeline: greeting → CAPABILITY → (STARTTLS →
CAPABILITY) → LOGIN / AUTHENTICATE PLAIN → SELECT → FETCH → LOGOUT.

```rust,ignore
use std::sync::Arc;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_imap::{ImapClient, ImapFetch};

let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);

ImapClient::new("mail.example.com", 143)
    .connect(
        &rt,
        Arc::new(
            ImapFetch::new()
                .credentials("alice", "secret")
                .on_message(Box::new(|seq, uid, body| {
                    println!("message {seq} uid={uid:?} ({} bytes)", body.len());
                }))
                .on_complete(Box::new(|ok| println!("done: {ok}"))),
        ),
    )?;
```

`ImapIdle` drives the same preamble then IDLE, delivering unsolicited
EXISTS/EXPUNGE/FLAGS through a `MailboxEventListener` (with optional
`done_on_event` to leave IDLE after the first event). Use
`.starttls(connector, name)` / `.implicit_tls(connector, name)` on
`ImapClient` for TLS.

Example binary: `cargo run -p imap-fetch -- 127.0.0.1 1143 alice secret`.

## Callback / pipelining model

Custom sessions implement `ImapClientDriver`. Every server event is a
callback (`on_greeting`, `on_capability`, `on_authenticated`, `on_selected`,
`on_fetch_data`, `on_status_data`, `on_list_entry`, `on_idle_started`, …) and
receives the staged state reference (`ImapClientNotAuthenticated` →
`ImapClientAuthenticated` → `ImapClientSelected` / `ImapClientIdle`) whose
methods issue the commands legal in that state.

Up to `max_pipeline` (default 8) tagged commands may be outstanding at once;
untagged replies are classified by prefix and routed to the oldest compatible
pending command, so tagged completions may arrive in any order.
`pipeline_status_and_list` demonstrates STATUS+LIST issued back-to-back.

## Timeouts

`ImapClientTimeouts` per-phase deadlines: `dns` (5 s), `connect` (dial →
greeting, 30 s), `stage` (per outstanding tagged command, 60 s), and
`message` (FETCH literal transfer, 600 s). On expiry `on_timeout` fires and
the connection closes.

## Testing

Unit tests: `cargo test -p hopf-imap --lib` (CI default). Opt-in loopback
TCP / TLS / filesystem integration tests:

```bash
cargo test -p hopf-imap --features integration
```
