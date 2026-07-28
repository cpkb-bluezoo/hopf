# Issues

Locally tracked gaps found while auditing Hopf's client-side staged-handler
APIs (`crates/hopf-{smtp,pop3,imap}/src/client/`) against Gumdrop's reference
implementation (`../gumdrop/src/org/bluezoo/gumdrop/{smtp,pop3,imap}/client/`).
Hopf deliberately consolidates Gumdrop's ~20-30 separate per-state/per-reply
interfaces into one `XClientDriver` trait per protocol (see each crate's
`client/handlers.rs`) — that consolidation is intentional and not itself a
gap. Everything below is a genuine capability gap: a Gumdrop interface or
behaviour with no Hopf equivalent, found by a file-by-file comparison.

Status values: **Open** (not started), **In Progress**, **Done**.

Format mirrors `.github-issue-smtp-auth-pipeline.md` (kept lighter per-item
since these are narrower than that one).

---

## SMTP client (`crates/hopf-smtp/src/client/`)

### SMTP-1: No VRFY/EXPN support

- **Status:** Open
- **Gumdrop reference:** `smtp/client/handler/ClientSession.java` (`vrfy()`/`expn()`), `ServerReplyHandler.handleReply`
- **Gap:** `SmtpClientSession` (`client/state.rs`) and `SmtpClientDriver` have no VRFY/EXPN methods or callbacks at all.
- **Suggested fix:** Add `vrfy(&mut self, address: &str)` / `expn(&mut self, list: &str)` to the session-stage trait, plus `on_vrfy_complete`/`on_expn_complete` driver callbacks.

### SMTP-2: `mail_from` doesn't expose extension parameters

- **Status:** Open
- **Gumdrop reference:** `smtp/client/handler/MailFromParams.java` — SIZE, BODY, SMTPUTF8, DSN RET/ENVID, REQUIRETLS, MT-PRIORITY, FUTURERELEASE, DELIVERBY
- **Gap:** `mail_from(sender: Option<&str>)` in `client/state.rs` takes only the address; none of Gumdrop's `MailFromParams` fields are settable.
- **Suggested fix:** Add a `MailFromParams`-equivalent struct (builder-style, matching the existing `DeliveryRequirements`/`DsnRecipientParams` types already ported server-side in `server/delivery.rs`) and thread it through `mail_from`.

### SMTP-3: `rcpt_to` doesn't expose DSN parameters

- **Status:** Open
- **Gumdrop reference:** `smtp/client/handler/ClientEnvelopeState.java` — NOTIFY/ORCPT overload
- **Gap:** `rcpt_to(recipient: &str)` is address-only; no way to set per-recipient DSN NOTIFY/ORCPT.
- **Suggested fix:** Same shape as SMTP-2 — reuse `DsnRecipientParams` (already exists server-side, `server/delivery.rs`) client-side.

### SMTP-4: EHLO capability parsing misses several extensions

- **Status:** Open
- **Gumdrop reference:** `smtp/client/handler/ClientSession.java` capability query methods
- **Gap:** `parse_ehlo_caps` (`client/endpoint.rs`) never captures BINARYMIME, MT-PRIORITY, FUTURERELEASE, DELIVERBY, or RFC 9422 LIMITS.
- **Suggested fix:** Extend `SmtpCapabilities` (`client/state.rs` or wherever it's defined) with fields for these, parsed the same way SIZE/8BITMIME/etc. already are.

### SMTP-5: No quit-early hook at Hello/PostTls stage

- **Status:** Open
- **Gumdrop reference:** `smtp/client/handler/ClientHelloState.java`, `ClientPostTls.java` — both allow aborting before EHLO
- **Gap:** `SmtpClientHello`/`SmtpClientPostTls` traits have no quit/close method at those stages.
- **Suggested fix:** Add a `quit()` (or `close()`) method to both staged-state traits, mirroring what's available once a session is established.

### SMTP-6: DATA rejection routes to a callback missing envelope access

- **Status:** Open
- **Gumdrop reference:** `smtp/client/handler/ClientEnvelopeReady.java` — rejected DATA still allows rcpt_to/reset/retry
- **Gap:** Hopf's `dispatch_data_command` funnels a rejected DATA verb into `on_message_rejected(session: &mut dyn SmtpClientSession, …)`, which has already dropped back to session scope and can't add recipients or resend DATA without restarting the envelope.
- **Suggested fix:** Route DATA rejection through `SmtpClientEnvelope` (the same stage `on_rcpt_ok` uses) instead of falling back to `SmtpClientSession`.

### SMTP-7: AUTH abort indistinguishable from AUTH failure

- **Status:** Open
- **Gumdrop reference:** `smtp/client/handler/ServerAuthAbortHandler.java` — `handleAborted` fires only for a client-initiated `*`
- **Gap:** Hopf's `abort()` re-enters the same `AuthSent` dispatch path as a real failure, so `on_auth_failed` can't tell "we cancelled" from "the server rejected our credentials."
- **Suggested fix:** Track whether the last outbound was `*\r\n` and route the resulting reply to a distinct `on_auth_aborted` callback (or an `aborted: bool` param on `on_auth_failed`).

---

## POP3 client (`crates/hopf-pop3/src/client/`)

### POP3-1: SASL challenge not auto-decoded

- **Status:** Done — fixed as part of the client reply-parser rewrite (semantic-event parser, `client/reply.rs`). `Pop3Event::AuthChallenge` now carries already base64-decoded bytes; `on_auth_challenge`'s signature changed to `challenge: &[u8]`.
- **Gumdrop reference:** `pop3/client/handler/ClientAuthExchange.java` — `handleChallenge(byte[] challenge, …)` receives already-base64-decoded bytes
- **Gap (historical):** `on_auth_challenge(..., challenge: &str)` (`client/handlers.rs`) passed raw base64 text; `respond()` on the same exchange trait auto-encoded, so the pair was asymmetric.

### POP3-2: No backpressure signal during RETR/TOP streaming

- **Status:** Open
- **Gumdrop reference:** `pop3/client/handler/ServerRetrReplyHandler.java`/`ServerTopReplyHandler.java` — `wantsPause()`/`setResumeCallback()`
- **Gap:** `on_message_content(&mut self, data: &[u8])` takes no `Endpoint` and returns nothing, so a driver has no way to pause reads during a large transfer, even though `Endpoint::pause_read`/`resume_read` exist generically.
- **Suggested fix:** Pass `ep: &mut dyn Endpoint` into `on_message_content` (matching most other callbacks) so a driver can call `pause_read`/`resume_read` itself.

### POP3-3: STAT/LIST/UIDL failures kill the connection instead of staying recoverable

- **Status:** Open
- **Gumdrop reference:** `pop3/client/handler/ClientTransactionState.java` — `handleError(transaction, message)` hands back the live state so the session continues
- **Gap:** `endpoint.rs`'s `handle_stat`/`handle_list_all`/`handle_uidl_all` set `ProtoState::Error` and call `ep.close()` on a bare `-ERR`, ending the connection for what should be a recoverable per-command failure.
- **Suggested fix:** Route these errors back through `on_error` with the live `Pop3ClientTransaction` state instead of closing, matching how DELE/RSET/NOOP failures are presumably already handled (verify and mirror).

### POP3-4: Greeting rejection discards the server's message text

- **Status:** Done — fixed as part of the client reply-parser rewrite. `handle_greeting`'s `-ERR` arm now uses the real `Pop3Event::Err { message }` text instead of a hardcoded `"POP3 server rejected"` string.
- **Gumdrop reference:** `pop3/client/handler/ServerGreeting.java` — `handleServiceUnavailable(message)` carries the actual -ERR text
- **Gap (historical):** Hopf's failure path passed a hardcoded string to `on_error` instead of the real greeting text.

### POP3-5: CAPA failure silently treated as success

- **Status:** Open
- **Gumdrop reference:** `pop3/client/handler/ServerCapaReplyHandler.java` — `handleError(auth, message)` signals CAPA explicitly failed
- **Gap:** `handle_capa_auth`/`handle_capa_post_tls` (`client/endpoint.rs`) treat a `-ERR` the same as success (falls back to `{user: true}` capabilities) via the same `on_capa` callback — no error signal, no message text.
- **Suggested fix:** Give CAPA failure its own path (or an `Option<&str>` error param on `on_capa`) instead of silently substituting a default capability set.

### POP3-6: Per-command error classification collapsed

- **Status:** Open — scope confirmed and widened against `POP3ClientProtocolHandler.java`'s actual dispatch methods (not just the handler interfaces)
- **Gumdrop reference:** `dispatchDeleReply`/`dispatchRetrReply`/`dispatchTopReply`/`dispatchListReply`/`dispatchUidlReply` all lowercase the `-ERR` text and substring-match it to pick a callback:
  - DELE: `"already deleted"`/`"already marked"` → `handleAlreadyDeleted`, else → `handleNoSuchMessage`
  - RETR/TOP: `"deleted"` → `handleMessageDeleted`, else → `handleNoSuchMessage`
  - **LIST(n)/UIDL(n) — not previously noted:** `"no such message"`/`"not exist"` → `handleNoSuchMessage`, else → a distinct generic `handleError` (LIST/UIDL each have *both* callbacks, not just one)
- **Gap:** Hopf's `on_no_such_message` is used unconditionally for every one of these failure paths (DELE, RETR, TOP, LIST(n), UIDL(n)) — no text-sniffing, and no separate "generic LIST/UIDL error" callback distinct from "no such message" the way Gumdrop has.
- **Suggested fix:** Still low priority. If done, LIST/UIDL need a second driver callback (`on_list_error`/`on_uidl_error` or similar) in addition to the DELE/RETR/TOP text classification.

### POP3-7: AUTH abort not distinguished from AUTH failure

- **Status:** Open
- **Gumdrop reference:** `ServerAuthAbortHandler.handleAborted(auth)` — `dispatchAuthAbortReply` calls this **unconditionally**, regardless of whether the server's reply to `*` was `+OK` or `-ERR`. It's a distinct third outcome, not routed through `handleAuthSuccess`/`handleAuthFailed` at all.
- **Gap:** Hopf's `Pop3ClientAuthExchange::abort()` just sends `*` and leaves the lexer on `Pop3ReplyShape::Auth`, so the server's reply comes back through the normal `handle_auth` dispatch and lands in `on_authenticated`/`on_auth_failed`/`on_auth_challenge` — indistinguishable from a real exchange step. Same pattern as SMTP-7.
- **Suggested fix:** Add a distinct shape (or a flag on `Auth`) set by `abort()`, and route its reply to a new `on_auth_aborted` callback unconditionally, matching Gumdrop.

### POP3-8: `on_disconnected` carries no closing message

- **Status:** Open
- **Gumdrop reference:** `ServerReplyHandler.handleServiceClosing(String message)` — the *base* interface every one of the 16 `ServerXReplyHandler` interfaces extends, so whichever handler is active when the server closes unexpectedly gets the closing text (or `null`).
- **Gap:** Hopf's `Pop3ClientDriver::on_disconnected(&mut self, ep: &mut dyn Endpoint)` has no message parameter at all — an unexpected close carries no diagnostic text, unlike every other failure path in this driver.
- **Suggested fix:** Thread the last-seen `-ERR`/closing text (if any) through to `on_disconnected`, or add a distinct `on_service_closing(message: Option<&str>)` fired before disconnect when a closing message was actually seen.

---

## IMAP client (`crates/hopf-imap/src/client/`)

### IMAP-1: APPENDUID response code dropped on APPEND completion

- **Status:** Open
- **Gumdrop reference:** `imap/client/handler/ServerAppendReplyHandler.java` — `handleAppendComplete(session, uidValidity, uid)` surfaces the UIDPLUS `APPENDUID` response code
- **Gap:** `on_append_complete(session, ep, status, message)` has no response-code parameter — unlike `on_copy_complete`/`on_move_complete`, which do pass `Option<&ImapCopyUid>`. `endpoint.rs`'s tagged-response handler only special-cases `COPYUID`, not `APPENDUID`, so a successful APPEND's new UID/UIDVALIDITY is unrecoverable by the driver.
- **Suggested fix:** Parse `APPENDUID` the same way `COPYUID` already is, add an `Option<&ImapAppendUid>` (or reuse `ImapCopyUid`'s shape) param to `on_append_complete`.

### IMAP-2: Capabilities from greeting/LOGIN/AUTHENTICATE not propagated

- **Status:** Open
- **Gumdrop reference:** `imap/client/handler/ServerGreeting.java`/`ServerLoginReplyHandler.java` pass `preAuthCapabilities`/post-auth `List<String> capabilities` directly into `handleGreeting`/`handleAuthenticated`
- **Gap:** `on_greeting`/`on_authenticated` take no capabilities parameter. An untagged `CAPABILITY` line arriving alongside the greeting or LOGIN/AUTHENTICATE response is buffered into `capa_buf` but never promoted to `self.caps`, so `capabilities()` can return stale pre-auth data until a separate CAPABILITY command is explicitly issued.
- **Suggested fix:** Promote `capa_buf` into `self.caps` at the same point the greeting/auth-complete event fires, and/or pass the parsed capability list into `on_greeting`/`on_authenticated` directly.
