# Hopf crypto and transport security migration plan

This document is the implementation plan for consolidating Hopf security under
**AWS-LC libcrypto in** `hopf-core`, in-tree reactive TLS and DTLS, a **full Hopf-style QUIC stack in** `hopf-quic` (Gumdrop `org.bluezoo.gumdrop.quic` equivalent — not a `quinn-proto` wrapper), and retiring `**rustls`**, `**quinn-proto**`, and the `**hopf-tls**` crate once parity is proven.

It complements the status tables in
[docs/conformance.html](docs/conformance.html#security-substrate) and
[docs/architecture.html](docs/architecture.html#security-substrate). Those pages
describe *what* is shipped vs planned; this file describes *how* to get there.
Phase 0 touchpoints and seams: `[crypto-migration-inventory.md](crypto-migration-inventory.md)`.

**Status:** Phase 5 (TLS 1.2 ECDHE+GCM, RFC 5246/5288, plus RFC 5077 session-ticket resumption) complete — separate FSM from the TLS 1.3 engine, dispatched via a new `TlsVariant` enum in `TcpConnection`; verified against `rustls` forced to TLS-1.2-only as an independent peer, both directions, including a real ticket-resumption round trip. Client certificate authentication (mTLS) is also now implemented for both the TLS 1.3 and TLS 1.2 engines — see its own writeup below, at the end of the Phase 5 section. Deferred within Phase 5: live mail/FTPS/legacy-server interop. CBC cipher suites are **not** deferred — see [Non-goals](#non-goals): explicitly rejected, permanently, on security grounds. AEAD is sufficient and now fully shipped for both TLS versions plus `hopf-quic`'s own packet protection: AES-GCM, and (as of this pass) `TLS_CHACHA20_POLY1305_SHA256`/RFC 7905's ChaCha20-Poly1305 suites (Phase 2 and Phase 5). Phase 4 (TLS record layer, `TcpConnection`/`hopf-tls` cutover, public WebPKI/native roots) remains complete — see its writeup below for the real interop bugs it caught (several affected `hopf-quic` too, sharing the same key schedule and trust store). Deferred: external OpenSSL/quic-go interop → Phase 2; conformance row flip → Phase 8. Also completed out of phase order: consolidation of the workspace's hand-rolled ASN.1 BER/DER parsing (X.509/PKCS8 DER for TLS, LDAP BER) into one shared `hopf_core::asn1` codec, replacing seven independent duplicated implementations. Phase 6 (DTLS 1.3 and DTLS 1.2) is now complete — see the Phase 6 updates below. Remaining Phase 5 items (live mail/FTPS/legacy-server interop) and Phase 7 (PQC policy centralisation) are next.
**Baseline update (2026-09-09):** [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html) is now the cited baseline for TLS 1.3 (and part of TLS 1.2) — see [Baseline RFCs](#baseline-rfcs-2026-09-09) below for what it changes and the gaps it opens against what's shipped today.
**Phase 6 update (2026-09-09):** DTLS 1.3's engine-level milestone is done — see [Phase 6](#phase-6--dtls) below. `HelloRetryRequest` (RFC 8446 §4.1.4) was built as a Phase 2 prerequisite in the same pass. Loopback-verified only; no DTLS-1.3-capable peer was available anywhere on this machine (checked OpenSSL, GnuTLS, and BoringSSL via `../quiche`) — see Phase 6's own status note for what that means and what's still deferred (real UDP driver wiring, 0-RTT, real interop).
**Phase 6 update, DTLS 1.2 (2026-09-09):** DTLS 1.2 (RFC 6347) is also done — see the [DTLS 1.2](#dtls-12-rfc-6347) subsection under Phase 6. Reuses `tls12::Tls12Engine` plus DTLS 1.3's transport-agnostic `Reassembler`/`RetransmitState`/`ReplayWindow`. Unlike DTLS 1.3, a real peer (OpenSSL 3.6.3) was reachable, and real interop caught 5 bugs — including a transcript-framing rule that's the *opposite* of DTLS 1.3's (RFC 6347 §4.2.6 includes the full DTLS handshake header in the hash; RFC 9147 §5.2 excludes it). Phase 6 is now complete except for the items still explicitly deferred (real UDP driver wiring, 0-RTT, DTLS-1.3 real interop, IP-bound cookies).
**Phase 5 update, Extended Master Secret (2026-09-10):** the top P0 gap from the RFC 9846 baseline update is closed — see the [Extended Master Secret](#phase-5--tls-12) checklist entry. Mandatory (not opportunistic): both `tls12::Tls12Engine` roles now refuse the handshake if the peer doesn't offer/echo RFC 7627's extension, closing the triple-handshake-class attack path completely rather than keeping a legacy fallback alive. DTLS 1.2 picked this up for free (no DTLS-specific changes needed) since it routes through the same shared engine. Verified against the real `rustls`-as-peer TLS 1.2 interop tests and the real OpenSSL 3.6.3 DTLS 1.2 interop tests — both unaffected. Remaining P0 items (RFC 5746 completion, `signature_algorithms_cert`, the other RFC 9846 §1.4 TLS 1.2 deltas, OCSP stapling, KeyUpdate, PQ cert signatures, RFC 9325 profile enforcement) are next.

---



## Goals

1. **One crypto floor** in `hopf-core` (no separate `hopf-crypto` crate) — **facade and wrappers only**; no reimplementation of cryptographic primitives (see [Crypto facade](#a-crypto-facade-do-not-rewrite-primitives)).
2. **Three transport security bindings** on that floor (each implemented as a **reactive engine** — see [Engine design](#engine-design)):
  - **Stream:** TLS 1.2/1.3 record layer + handshake → `TlsEngine` (TCP, STARTTLS; `Endpoint` seam unchanged)
  - **Datagram:** DTLS 1.2/1.3 record layer + handshake → `DtlsEngine` (UDP, DoDTLS, CoAPS)
  - **QUIC:** TLS 1.3 handshake + RFC 9001 key schedule (no TLS record layer)
3. **PQC-first policy** centralised (hybrid `X25519MLKEM768` preferred, classical fallback).
4. **Test every phase** — each phase ships tests that validate its scope before the next phase starts (unit tests, RFC vectors, interop peers, and new integration tests as appropriate).
5. **Retire interim stack:** `rustls`, `quinn-proto`, the `**hopf-tls`** crate, and scattered direct `aws-lc-rs` calls in protocol crates.
6. **Reactor-based security engines** — in-tree TLS, DTLS, and QUIC handshake/record state machines are **reactive** (event in → events out via sinks); see [Engine design](#engine-design).
7. **Crate end state** — TCP TLS/DTLS live in `**hopf-core`**; QUIC transport + RFC 9001 glue live in `**hopf-quic`** as a first-class Hopf protocol crate (see [Crate layout](#crate-layout-end-state)).

The migration is **not complete** until **all existing workspace unit and integration tests** pass on the refactored in-tree stack — the same commands CI uses today (`cargo test --workspace --lib` and each crate's opt-in `--features integration` suites), with `rustls`, `quinn-proto`, and `**hopf-tls`** removed.

## Non-goals

- Replacing AWS-LC with OpenSSL, BoringSSL-as-separate-product, or multiple competing pure-Rust crypto stacks.
- **Reimplementing crypto primitives in Rust** (AES, SHA, RSA, ECDH, ML-KEM, AEAD, etc.) — all primitive operations delegate to **AWS-LC** via `aws-lc-rs` or thin libcrypto FFI. Hopf writes **protocol engines and wire framing**, not ciphers or big-number math.
- Pulling in **Kwik** or any **thread-per-connection** QUIC engine (see [Gumdrop reference](#gumdrop-reference)).
- Servlet/JSP/Java EE APIs.
- Boiling the ocean: SSH, DNSCrypt, CoAP/OSCORE, and GSSAPI are **related follow-ons**, not blockers for the crypto floor itself.
- **Tokio-shaped async**, `**async fn` / `.await`**, or **Java** `Future`**-shaped** security APIs — engines are reactor-reactive, not executor-async (see [Engine design](#engine-design)).
- **Decrypting foreign session-ticket ciphertext** (rustls / OpenSSL / quic-go NST blob formats). Hopf tickets stay hopf-private; external peer interop (Phase 2) exercises wire resume/0-RTT with each stack’s own tickets.
- **CBC cipher suites, for any TLS/DTLS version** — explicitly rejected, not deferred. MAC-then-encrypt CBC has a long, recurring history of practical timing side channels (Lucky Thirteen and its repeated re-discoveries across otherwise-fixed implementations); AEAD is the only mode this codebase will negotiate. AES-GCM and ChaCha20-Poly1305 (both shipped, TLS 1.2, TLS 1.3, and `hopf-quic` packet protection — unlike CBC, ChaCha20-Poly1305 was always a to-do, not a permanent exclusion) cover the space. Any legacy peer that requires CBC to interoperate is out of scope by design, not a gap to close later.

---



## Baseline RFCs (2026-09-09)

**[RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html)** (E. Rescorla, Standards Track, published July 2026) is *The Transport Layer Security (TLS) Protocol Version 1.3* and **obsoletes RFC 8446** — plus **RFC 5246** (TLS 1.2), **RFC 5077** (session tickets), **RFC 6961** (multi-cert OCSP status), **RFC 7627** (Extended Master Secret), and **RFC 8422** (legacy ECDHE curves) — and **updates** RFC 5705 (keying-material exporters) and RFC 6066 (extensions incl. SNI/`status_request`). It's fully backward-compatible with RFC 8446, so existing TLS 1.3 wire behaviour built against 8446 is not broken by this — but **RFC 9846 is now the citation of record** in this plan, and it makes real, non-cosmetic changes for TLS 1.2 in particular. This plan does **not** attempt a full section-by-section renumbering audit of every existing `RFC 8446 §…` citation below (9846 says it "tightens some requirements and clarifies some details" — section numbers may or may not have moved); only the deltas verified below are called out explicitly. Old RFC 8446 citations elsewhere in this file still describe the same shipped behaviour unless a note here says otherwise.

**What's unchanged (still cite the old RFC number as-is):**
- RFC 8448 (*Example Handshake Traces for TLS 1.3*) — test-vectors document, not superseded, still the reference for `crypto/hkdf.rs`'s vector tests.
- RFC 5746 (secure renegotiation signalling) — RFC 9846 explicitly reaffirms "if a server has negotiated TLS 1.3 and receives a ClientHello at any other time, it MUST terminate the connection with `unexpected_message`"; 5746 itself is not touched.
- RFC 9954 (hybrid key exchange framework) and RFC 10024 (the concrete `X25519MLKEM768`/`SecP256r1MLKEM768`/`SecP384r1MLKEM1024` named groups) — post-date and are independent of 9846; now cited in [Phase 7](#phase-7--pqc-policy)'s scope below.

**What changed, confirmed against the RFC text:**
- **§9 "Compliance Requirements"** (9.1 mandatory-to-implement cipher suites, 9.2 mandatory extensions, 9.3 protocol invariants) is the renumbered home of what was RFC 8446 §9.1 — same content, new home document.
- **§1.4 "Updates Affecting TLS 1.2"** adds real new MUSTs for the TLS 1.2 fallback path: a version-downgrade-protection sentinel (§4.2.3), `RSASSA-PSS` signature schemes newly defined for TLS 1.2 (§4.3.3), and **mandatory `supported_versions` and `signature_algorithms_cert` extensions on the TLS 1.2 `ClientHello`** — not just TLS 1.3's.
- **§2.2** replaces RFC 5077 ticket-based resumption with a single unified PSK exchange (the same shape TLS 1.3 already uses) — this is a real mechanism change for TLS 1.2, not a rename.
- **Appendix D** folds in the old RFC 7627 Extended Master Secret content, renamed `extended_master_secret` → `extended_main_secret` (part of a broader "master" → "main" terminology change in the normative text).
- RFC 6961 (multi-cert status request) is now *formally* obsoleted, not just deprecated-in-practice as it already was under 8446 §4.4.2.1.

**Gaps this opens against what's shipped today** — tracked as new checklist items in [Phase 5](#phase-5--tls-12), since they're all TLS-1.2-side: extended_master_secret/RFC 7627 was **never implemented** in `tls12/engine.rs` (grepped — no hits), nor is there a downgrade-protection sentinel, `supported_versions`, or `signature_algorithms_cert` anywhere in the TLS 1.2 engine. `signature_algorithms_cert` is also absent from the **TLS 1.3** engine (only `signature_algorithms` (0x000d) exists, not 0x0032) — worth a look even though 9846 §9.2's TLS 1.3 mandatory-extension list hasn't been independently re-verified against what's shipped. RFC 5077 ticket resumption (Phase 5, already shipped) still works and interops with `rustls`-as-peer today; migrating it to §2.2's unified PSK exchange is new scope, not a fix to something broken.

---



## Interim baseline (done)

Commit `a0553ac` and follow-ups established the **interim** stack:


| Area                 | Today                                                                              |
| -------------------- | ---------------------------------------------------------------------------------- |
| Native crypto        | **AWS-LC** via `aws-lc-rs` / `aws-lc-sys` (BoringSSL lineage)                      |
| TCP TLS / STARTTLS   | `hopf-tls` → **rustls** (aws-lc-rs provider, `prefer-post-quantum`)                |
| QUIC transport       | **quinn-proto** + in-tree mio UDP driver (`hopf-quic`)                             |
| QUIC-TLS             | **rustls** TLS 1.3 configs via `hopf_tls::tls_crypto_provider()`                   |
| HTTP/3               | In-tree in `hopf-http` (feature `h3`)                                              |
| DKIM / DNSSEC verify | Direct `aws-lc-rs` in `hopf-smtp` / `hopf-dns` (Ed448 via `ed448-goldilocks-plus`) |
| UDP datagram I/O     | Cleartext only — **no DTLS**                                                       |


Three integration paths share one provider but **not** one adapter:


| Path               | rustls? | Through `hopf-tls`?                                                                 |
| ------------------ | ------- | ----------------------------------------------------------------------------------- |
| TCP TLS / STARTTLS | Yes     | **Yes** — `TlsAcceptor` / `TlsConnector` / `TlsSession`                             |
| QUIC / HTTP/3      | Yes     | **No** — `hopf-quic` builds configs and hands them to `quinn_proto::crypto::rustls` |
| DTLS (future)      | —       | **No** — datagram record layer + epochs; parallel to `TlsSession`                   |


---



## AWS-LC stack

```
aws-lc-rs  →  aws-lc-sys (FFI)  →  AWS-LC (C: libcrypto [+ libssl])
                                      ↑
                              fork of BoringSSL
```

- `aws-lc-rs` is a **Rust API** (ring-shaped) over **libcrypto**. It is not a separate crypto implementation.
- AWS-LC provides PQC (ML-KEM hybrids), DTLS primitives, and BoringSSL-style **QUIC-TLS hooks**.
- **Target:** `hopf-core::crypto` as the only front door — **sync** primitive API over AWS-LC, using **aws-lc-rs** where sufficient and **direct libcrypto FFI** where not. Hopf-owned **reactive handshake and record-layer engines** live above that floor; **handshake state machines are in-tree** (Phase 0 decision), not libssl or AWS-LC QUIC-TLS API.

---



## Gumdrop reference

Gumdrop split transport security the same way Hopf should:


|              | **agent15 (QUIC handshake)**                           | **JDK / SSLEngine (TCP TLS)**   | **Gumdrop in-tree QUIC**                                    |
| ------------ | ------------------------------------------------------ | ------------------------------- | ----------------------------------------------------------- |
| Scope        | TLS 1.3 **handshake only** (RFC 8446 §4)               | Record layer + TLS 1.2 + 1.3    | RFC 9000 **transport** state machine                        |
| Record layer | **None** — handshake bytes in CRYPTO frames (RFC 9001) | JDK handles records on TCP      | N/A (QUIC packet protection)                                |
| Used for     | QUIC key schedule, ALPN, transport params, 0-RTT       | SMTP/IMAP/HTTPS/STARTTLS on TCP | Streams, loss recovery, migration                           |
| Concurrency  | Driven from Gumdrop selector loops                     | Same                            | **TPC / selector multiplexing** — not thread-per-connection |


**agent15 is not “the Gumdrop TLS stack”.** It is the QUIC-specific handshake engine. Gumdrop did **not** reimplement TCP TLS from scratch — the JVM did that. Gumdrop **did** reimplement QUIC transport in-house.

**Kwik is not used by Gumdrop.** Kwik is thread-per-connection — the opposite of the TPC pattern Hopf and Gumdrop target. That is why Gumdrop wrote its own QUIC implementation; it is why Hopf plans to retire `quinn-proto` (interim, not architecturally aligned).

**Hopf must go further than agent15** because the target is one substrate for TCP + DTLS + QUIC, not JDK for TCP and agent15 for QUIC.

### Gumdrop → Hopf crate mapping (end state)


| Gumdrop                                                                                    | Hopf (after migration)                                                                                                                         |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `org.bluezoo.gumdrop.quic` — in-tree RFC 9000 transport, TPC-driven, agent15 for handshake | `**hopf-quic**` — full QUIC implementation (transport, connection, streams, UDP driver, RFC 9001 crypto glue); **not** a `quinn-proto` wrapper |
| JDK / SSLEngine — TCP TLS                                                                  | `**hopf-core::tls**` — reactive `TlsEngine` + record layer (no `hopf-tls` crate)                                                               |
| agent15 — TLS 1.3 handshake for QUIC                                                       | Shared `**hopf-core::tls/handshake**` (1.3) wired from `**hopf-quic**`                                                                         |
| Transparent DTLS on UDP                                                                    | `**hopf-core::dtls**`                                                                                                                          |
| HTTP/3 codecs                                                                              | `**hopf-http**` (unchanged — consumes `hopf-quic` streams as `Endpoint`s)                                                                      |


Today's `hopf-quic` is mostly **glue around quinn-proto** (~3.8k lines in `driver.rs` alone). The end state replaces quinn's state machine with Hopf-owned code in the same crate, preserving the stream-as-`Endpoint` model and reactive driver shape Gumdrop used.

---



## Crate layout (end state)

No `hopf-crypto` crate. No `**hopf-tls**` crate — it is **removed** after migration (interim rustls adapter only until Phase 8).

### `hopf-core`

```
hopf-core/
  crypto/           ← AWS-LC facade only (aws-lc-rs + thin FFI; no primitive reimplementation)
  tls/              ← TlsEngine + TlsEventSink, record layer, TLS 1.2/1.3 handshakes
  tls/handshake/    ← 1.3 shared with QUIC; 1.2 for mail/legacy TCP
  dtls/             ← DtlsEngine + DtlsEventSink; datagram record + handshake
  security.rs       ← SecurityInfo (already exists)
  connection.rs     ← TcpConnection pumps TlsEngine (replaces hopf-tls / rustls path)
```

TCP TLS and STARTTLS are configured via `**hopf-core**` (acceptor/connector configs, PEM load moved from `hopf-tls`). The umbrella `hopf` crate exposes `hopf::core::tls` (or equivalent) — not `hopf::tls`.

### `hopf-quic`

Full **Gumdrop** `quic` **package** equivalent — a Hopf protocol crate, not a foreign stack wrapper:

```
hopf-quic/
  transport/        ← RFC 9000 state machine (loss recovery, congestion, migration, …)
  crypto/           ← RFC 9001: CRYPTO frames, packet protection, key update (uses hopf-core handshake + crypto)
  driver.rs         ← mio UDP reactor thread; reactive pump (keep, rewrite internals)
  connection/       ← connections, streams, datagrams
  config.rs         ← listen/dial, hardening, ALPN (keep public shape)
  stream.rs         ← QuicStreamEndpoint → hopf_core::Endpoint
```

- **HTTP/3** stays in `**hopf-http`** (feature `h3`) — same split as today (QUIC wire in `hopf-quic`, H3/QPACK in `hopf-http`).
- `**quinn-proto` dependency removed** — nothing in `hopf-quic` delegates transport semantics to quinn.
- Handshake bytes use `**hopf-core**` TLS 1.3 engine (agent15-class), not rustls.



### Protocol crates

`hopf-smtp`, `hopf-dns`, … call `**hopf-core::crypto**` and `**hopf-core::tls**` / `**hopf-quic**` public APIs — not AWS-LC, rustls, or quinn directly.

### Extended partition (future transport families)

Same crypto floor, **separate wire stacks** (not `TlsSession`):

```
hopf-core::crypto
  ├── Stream security:   TLS  → TlsEngine / TlsEventSink
  ├── Datagram security: DTLS → DtlsEngine / DtlsEventSink
  ├── QUIC wire + RFC 9001   → hopf-quic (transport + packet crypto; handshake from hopf-core)
  └── Other transports:  SSH KEX, DNSCrypt, OSCORE, … (own modules, shared primitives)
```

Auth (SCRAM, GSSAPI, …) stays in `**hopf-auth**` on encrypted transport — not part of the record layer.

---



## Engine design

In-tree TLS, DTLS, and QUIC security code is **reactor-based and reactive**. This is a hard design constraint for Phases 2–6, locked in Phase 0.

### Reactive, not async

Hopf security engines follow the same model as the rest of the framework:

- **Not** Tokio-shaped (`async fn`, tasks, wakers).
- **Not** Java `Future`-shaped (complete later, poll for result).
- **Reactive:** the engine advances only when the **reactor** delivers an **external stimulus**; progress is reported by **pushing events** to a wired **handler / sink**.

Everything occurs as a **reaction** to stimuli such as:

- **Network I/O** — TCP segments, UDP datagrams, QUIC packets arriving on a readiness edge
- **Timers** — DTLS retransmit, handshake timeout, QUIC loss-detection deadlines
- **Storage / filesystem completion** — e.g. trust material loaded from disk via `StorageExecutor`
- (Future) **Other reactor sources** — anything else registered on the same thread's event loop

There is no "call a function and block until the handshake finishes" API at the engine boundary.

### Events in, events out

**Inputs** to an engine are stimulus methods with **no meaningful return value** beyond how much wire data was consumed (where applicable):

```text
engine.feed_ciphertext(&mut &[u8])   // or feed_packet for QUIC/DTLS
engine.feed_timer(TimerKind)
engine.feed_verification_result(…)   // resumes a gate (see below)
```

**Outputs** are delivered to a **sink** wired before use (or passed per call — same contract):

```text
trait TlsEventSink {
    fn handshake_complete(&mut self, info: SecurityInfo);
    fn application_data(&mut self, plaintext: &[u8]);
    fn ciphertext_ready(&mut self, tls_records: &[u8]);   // want write
    fn verification_requested(&mut self, req: VerifyRequest);  // optional gate
    fn protocol_error(&mut self, err: TlsProtocolError);
    fn timeout(&mut self, kind: TimerKind);
    fn peer_closed(&mut self, alert: Option<AlertDescription>);
    // … further stages as the protocol requires
}
```

A single sink accepts **many event types** for **different stages** of one job — the same pattern as [rmimeparser](https://crates.io/crates/rmimeparser)'s MIME handler trait (headers, body chunks, multipart boundaries, errors each as distinct callbacks, not one combined return type).

**Network errors, timeouts, and protocol failures** are **distinct event types** on the sink. They are **not** propagated as `Result` return codes from engine methods to the caller. The connection pump reacts to those events like any other (`ProtocolHandler::error`, teardown, retry policy, etc.).

### Why sink-based, not return-value-based

A callback / sink API **does not guarantee** that work is non-blocking — synchronous crypto on the reactor thread is still possible.

A return-value-based (functional) API **guarantees the opposite problem**: the caller must **wait for the result** of the call, which encourages blocking shapes ("handshake returned `Ok`" or "return `Err`") and collapses multi-step progress into one return slot.

We standardise on **sink-based output** so that:

- Multiple outcomes from one stimulus are natural (handshake complete **and** early application data in one read).
- **State-machine gates** are explicit — e.g. *wait for verification result* is a **state**; the engine emits `verification_requested`, idles, and accepts `feed_verification_result` when storage or crypto work completes (wherever that work runs).
- **Where work runs** remains an implementation choice: cheap steps on the reactor; chain building or slow verify on `StorageExecutor` with a completion event back — without changing the engine's external shape.



### Connection pump integration

`TcpConnection`, the QUIC driver, and future UDP/DTLS endpoints remain **thin pumps**:

1. Reactor receives readiness / timer / storage completion.
2. Pump calls the appropriate `engine.feed_*`.
3. Engine pushes events to the sink; sink mutates connection state, queues writes, or invokes `ProtocolHandler`.

Today's return-based `TlsSession` trait in interim `**hopf-tls**` (`process_new_packets` → `TlsProgress`) is replaced by `**hopf-core::tls**` (`TlsEngine` + `TlsEventSink`) and `**hopf-quic**` transport + RFC 9001 crypto (reactive throughout). Phase 0 defines sink taxonomies for each; interim rustls/quinn adapters remain until Phase 8 removes `**hopf-tls**` and `quinn-proto`.

### Crypto facade (`hopf-core::crypto`) — sync primitives, reactive engines

`**aws-lc-rs` being ring-shaped does not conflict with reactive engines.** The shapes apply at **different layers**:

```text
  Reactor stimulus (packet / timer / storage done)
           │
           ▼
  TlsEngine / DtlsEngine (hopf-core) + hopf-quic transport/crypto   ← reactive: feed_* in, sink events out
           │
           │  on each FSM transition, may call ↓
           ▼
  hopf-core::crypto                           ← synchronous primitive API
           │
           ├── aws-lc-rs where it covers the op (DKIM, DNSSEC, AEAD, sign/verify, …)
           └── direct libcrypto FFI where aws-lc-rs is too thin (TLS transcript, some KX/PQC, QUIC hooks)
           │
           ▼
  AWS-LC libcrypto (C)
```

**Reactive** is the **protocol engine** (handshake FSM, record layer, DTLS retransmit, QUIC crypto schedule): *when* to act, *what* to emit, *when* to gate on verification.

**Ring-shaped / functional** is fine for **primitives**: `digest.update`, `aead.seal`, `verify_signature`, `agree_ephemeral` return their result immediately. Even Gumdrop's selector loops call synchronous `MessageDigest` / `Cipher` during event handling. You do not wrap every AES-GCM call in a callback — you call it **inside** a transition, then emit the next **engine** event (`ciphertext_ready`, `handshake_complete`, …).

A **return-value API at the engine boundary** forces the caller to wait for handshake completion. A **return-value API at the primitive boundary** is normal: "here is the MAC" / "verification failed".


| Layer                          | Shape                           | Responsibility                                                                                                                    |
| ------------------------------ | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Engine**                     | Reactive (sink)                 | Wire protocol, state, timers, gates                                                                                               |
| `**hopf-core::crypto**`        | Sync functional                 | Bounded primitive ops; optional **async gate** only at engine level                                                               |
| **Heavy verify / chain build** | Engine gate + `StorageExecutor` | Engine emits `verification_requested`; worker calls **sync** `crypto::verify_chain`; result arrives as `feed_verification_result` |


`aws-lc-rs` **stays in the plan** for all primitive operations it covers. **Direct libcrypto FFI** is added only where aws-lc-rs is too thin — thin **bindings**, not new algorithms. The only documented exception today is **Ed448** for DNSSEC (`ed448-goldilocks-plus`), where AWS-LC lacks the algorithm; that stays a leaf dependency, not a precedent for rewriting mainstream primitives.

Phase 1 inventory should classify each need: **aws-lc-rs sufficient** vs **needs thin FFI wrapper in** `hopf-core::crypto::ffi` — never "implement in Rust".

### Phase 0 deliverable

Before Phase 2 code lands, document and review:

- Engine input methods (stimuli) and sink event taxonomy per transport family
- Gate states: verification pending, handshaking, application data, closed
- Which events `TcpConnection` / QUIC driver sinks handle vs delegate upward
- Test pattern: scripted stimulus sequences asserting **event order** (not return values)

---



## What must be written



### A. Crypto facade (**do not rewrite primitives**)

Hash/HMAC/HKDF, AEAD, ECDH, ML-KEM, RSA, Ed25519, X.509 parse/verify, chain building — **all delegated to AWS-LC**. Hopf does **not** implement these algorithms.

Phase 1 work is **consolidation and wrapping** only:

- `hopf-core::crypto` — synchronous facade ([Crypto facade](#crypto-facade-hopf-corecrypto--sync-primitives-reactive-engines)): call through `aws-lc-rs` or thin libcrypto FFI; no pure-Rust crypto reimplementation.
- Migrate scattered `aws-lc-rs` usage from protocol crates into this facade.
- **Ed448** (DNSSEC only): keep `ed448-goldilocks-plus` behind the facade where AWS-LC has no Ed448 — not a general pattern.

What Hopf **does** write: TLS/DTLS/QUIC **protocol state machines**, **record framing**, **transcript handling**, and **when** to invoke which libcrypto operation — not the operations themselves.

### B. Handshake state machines (**yes — Hopf-owned Rust**)


| Protocol | Work                                                             | Notes                                              |
| -------- | ---------------------------------------------------------------- | -------------------------------------------------- |
| TLS 1.3  | Client + server FSM, extensions, cert verify, ALPN, key schedule | **Shared** for QUIC and TCP 1.3                    |
| TLS 1.2  | Separate FSM + cipher suites                                     | Mail / legacy interop                              |
| DTLS 1.2 | TLS 1.2 crypto + cookie, fragmentation, retransmit               | Gumdrop parity, DoDTLS, CoAPS                      |
| DTLS 1.3 | TLS 1.3 + datagram rules                                         | Can follow 1.2 if 1.2-only is acceptable initially |


This is **agent15-class work**, extended for 1.2, DTLS, and rigorous state tracking (early agent15 lacked strict reprocessing guards — do not repeat that).

### C. Record layers


| Transport | Record layer?                                                 |
| --------- | ------------------------------------------------------------- |
| TCP TLS   | **Yes** — framing, alerts, no renegotiation on 1.3            |
| DTLS      | **Yes** — epochs, sequence numbers, replay window, retransmit |
| QUIC      | **No** — RFC 9001 CRYPTO frames + packet protection keys      |


agent15 skips (C) entirely. Hopf **cannot** skip (C) for TCP or DTLS.

### D. QUIC transport (**yes — full** `hopf-quic`**, drop** `quinn-proto`)

RFC 9000 in `**hopf-quic**` as a first-class Hopf implementation: connections, streams, flow control, loss recovery, congestion, migration, version negotiation, datagrams — reactive, TPC-multiplexed, Gumdrop-shaped.

Today's driver and stream-as-`Endpoint` API are the skeleton; `**quinn_proto::Connection` is replaced** with in-tree state machines. This is the `**org.bluezoo.gumdrop.quic`** role — not a wrapper around an external QUIC library.

### E. QUIC-TLS glue (RFC 9001)

Map handshake secrets → packet protection keys, header protection, key update, 0-RTT rejection policy.

**Decision (Phase 0):** Hopf-owned **TLS 1.3 handshake state machines** in `hopf-core` + libcrypto for primitive ops — the agent15 model extended for TCP and DTLS. **Not** AWS-LC/libssl QUIC-TLS API for handshake bytes. RFC 9001 key schedule and packet protection live in `hopf-quic/crypto`, driven from handshake secrets the core engine exports.

---



## Frozen public seams (implementations swap underneath)

Do not break without an explicit API revision:

- `Endpoint::start_tls` / `start_client_tls`
- `SecurityInfo` / `ProtocolHandler::security_established`
- `QuicListenConfig` / `QuicConnectConfig` / stream-as-`Endpoint` model
- PEM load helpers and trust configuration surfaces (behaviour-preserving)

**Evolving (Phase 0 → 8):** interim `**hopf-tls`** (rustls) and return-based `TlsSession` are removed; TCP TLS is `**hopf-core::tls`**. `**hopf-quic**` public listen/dial/stream API is preserved; internals become in-tree transport.

Future parallel seam: `**DtlsEngine**` on UDP (in `hopf-core::dtls`, same reactor-thread ownership rules as TLS).

---



## Verification

**Per phase:** add or extend tests that prove the phase's deliverables work. A phase is not done until those tests pass. What counts varies by phase — crypto facade migration reuses existing DKIM/DNSSEC unit tests; an isolated handshake engine uses RFC 8446 vectors and external interop; QUIC transport uses `hopf-quic` integration tests and conformance rows.

**Migration complete:** the interim stack (`rustls`, `quinn-proto`) is gone **and** the full existing test matrix passes unchanged at the behaviour level:

```bash
cargo test --workspace --lib
# plus each crate's opt-in integration suites, e.g.:
cargo test -p hopf-quic --features integration
cargo test -p hopf-http --features h3
cargo test -p hopf-smtp --features integration
# … (same set CI documents today)
```

New phase-specific tests are additive; they do not replace the requirement that pre-migration tests still pass on the refactored framework.

---



## Phased plan



### Phase 0 — Inventory and invariants

**Handshake decision (locked):** own the handshake — in-tree reactive TLS 1.3 (and later 1.2 / DTLS) state machines on libcrypto; no AWS-LC QUIC-TLS / libssl handshake path.

**Inventory:** `[crypto-migration-inventory.md](crypto-migration-inventory.md)` — living touchpoint list (rustls, quinn-proto, aws-lc-rs, frozen seams, engine lock, platform matrix). Update that file when touchpoints change; keep this plan for strategy and phases only.

- [x] Handshake decision locked (own the handshake).
- [x] Baseline inventory documented (separate file).
- [x] Confirm frozen seams — checklist in inventory § Frozen seams.
- [x] Lock [Engine design](#engine-design) — trait/sink names and event model in inventory § Engine design lock.
- [x] Platform matrix for `aws-lc-sys` prebuilds — inventory § Platform matrix.



### Phase 1 — `hopf-core::crypto` (facade only)

- [x] Single AWS-LC entry point in core — **wrap, do not reimplement** primitives (`hopf-core/src/crypto/`).
- [x] Trust anchor storage, SPKI/fingerprint helpers (`TrustStore`, `sha256_fingerprint_hex`, `spki_sha256`) — chain building + hostname verify in [`crypto/trust.rs`](crates/hopf-core/src/crypto/trust.rs) + [`crypto/x509.rs`](crates/hopf-core/src/crypto/x509.rs).
- [x] Migrate **DKIM** sign/verify from `hopf-smtp`'s direct `aws_lc_rs` calls.
- [x] Migrate **DNSSEC verify** from `hopf-dns`; Ed448 via goldilocks through `hopf-core::crypto::ed448` only.
- [x] Inventory: every crypto need mapped to aws-lc-rs or thin FFI — see [inventory](crypto-migration-inventory.md) § Direct `aws-lc-rs`.
- [x] **Tests:** DKIM/DNSSEC unit tests pass through the core crypto API (`cargo test -p hopf-smtp --lib`, `cargo test -p hopf-dns --lib --features dnssec`).



### Phase 2 — TLS 1.3 handshake engine (QUIC-first)

- [x] Reactive API scaffold: [`HandshakeEngine`](crates/hopf-core/src/tls/engine.rs), [`TlsEventSink`](crates/hopf-core/src/tls/sink.rs), `feed_handshake_data` / `feed_verification_result`.
- [x] Crypto floor: TLS 1.3 HKDF (`crypto/hkdf.rs`), X25519 (`crypto/kx.rs`), key schedule + RFC 8448 vector tests.
- [x] Handshake message framing + ClientHello builder + ServerHello parser (`tls/handshake/messages.rs`).
- [x] Client/server complete 1-RTT FSM (EncryptedExtensions, Certificate, CertificateVerify, Finished).
- [x] Extensions: QUIC `transport_parameters` (opaque RFC 9000 wire codec + TLS ext 0x0039); hybrid PQC via [`KxPolicy`](crates/hopf-core/src/crypto/kx_policy.rs) + `X25519MLKEM768` (Phase 7 expands central policy).
- [x] Export application traffic secrets in [`QuicSecrets`](crates/hopf-core/src/tls/sink.rs) on `handshake_complete`.
- [x] Verification gate backed by `hopf-core::crypto` trust (chain build + hostname via `TrustStore`; inline when `HandshakeConfig.trust_store` is set, else `verification_requested` gate for StorageExecutor).
- [x] Wire into `hopf-quic` CRYPTO stream (was `quinn-proto` adapter; now in-tree `hopf-quic` transport after Phase 3a); loopback echo (`spike_echo_one_stream_hopf`).
- [x] **Tests:** key schedule RFC 8448 vectors; 1-RTT loopback (classical + hybrid PQC + transport parameters).
- [ ] **External peer interop** (handshake + resume / 0-RTT where applicable): OpenSSL, quic-go, and optionally rustls as *peer* stacks. Each side uses its own ticket ciphertext — hopf NST blobs stay hopf-private (AES-GCM sealed identity); interop is wire PSK/NST/`early_data` behaviour, not decrypting foreign ticket formats. Deferred from Phase 3b; still owned by the handshake/interop gate here.
- [x] **`TLS_CHACHA20_POLY1305_SHA256`** (RFC 8446 §B.4) as an additional negotiated cipher suite alongside `TLS_AES_128_GCM_SHA256` — full `ClientHello`/`ServerHello` suite negotiation (`SUPPORTED_CIPHER_SUITES`, `Tls13Aead`), the TCP record layer's AEAD dispatch (`tls/record.rs`), **and** `hopf-quic`'s own packet/header protection (`transport/packet/protection.rs`'s `PacketKeys`, including RFC 9001 §5.4.4's separate ChaCha20 header-protection construction — QUIC uses the same negotiated `TlsEventSink` callbacks, not a separate suite list, so this had to be threaded through `QuicSecrets`/`TlsBridgeEvents`/`Space` too, not just the TLS layer). Initial/Retry packet protection stay fixed to AES-128-GCM regardless (RFC 9001 §5.2/§5.8 mandate it). **Tests:** engine-level suite-selection + rejection tests, direct AEAD/wire-framing round-trip tests for both the TCP record layer and QUIC packet protection, and real `rustls` interop forcing the suite in both directions for both TLS 1.2 and TLS 1.3.
- [x] **`HelloRetryRequest`** (RFC 8446 §4.1.4) — pulled forward from this phase's original scope (never actually built despite Phase 2 otherwise being marked complete) because DTLS 1.3 (Phase 6) needs it for its cookie-based anti-amplification retry. Cookie extension (0x002c) read/write; HRR detection via the fixed `random` sentinel (`HELLO_RETRY_REQUEST_RANDOM`) on wire-identical `ServerHello`-shaped messages; RFC 8446 §4.4.1's transcript `message_hash` substitution (`Transcript::retry`); server-side triggers HRR (not a hard failure) on a client key-share/group mismatch it can still resolve from `supported_groups`; client regenerates its key share and resends `ClientHello2` (no early data, per §4.1.2). **Tests:** full HRR round trip forcing a hybrid-vs-classical group mismatch between two `HandshakeEngine`s, and a rejected-second-HRR case (RFC 8446 forbids more than one).

*Agent15 equivalent — with proper state machine discipline and AWS-LC underneath.*

### Phase 3 — Full `hopf-quic` transport (drop `quinn-proto`)

#### Phase 3a — Minimal echo cutover (done)

- [x] RFC 9000 state machine **in** `hopf-quic` — Gumdrop-shaped minimal echo subset; reactive mio driver; **no `quinn-proto` dependency** in `hopf-quic`.
- [x] Wire Phase 2 handshake from `hopf-core::tls`; RFC 9001 packet protection in `hopf-quic` transport; driver swapped to in-tree `Connection`/`Endpoint` (`spike_echo_one_stream_hopf` + `QuicListenHardening::permissive()`).

#### Phase 3b — Parity beyond echo

- [x] Retry / address validation (`QuicListenHardening::high_security`); keep stream-as-`Endpoint` public API.
- [x] DATAGRAM (RFC 9221) send/recv + `max_datagram_frame_size` transport option.
- [x] Loss recovery / PTO / congestion (RFC 9002).
- [x] GSO `segment_size` (UDP_SEGMENT batching via `poll_transmit_gso` + pre-AEAD PADDING).
- [x] 0-RTT / early data (opaque hopf tickets + RFC-shaped age / lifetime / anti-replay / ALPN / reject-retry). Ticket ciphertext stays hopf-private; wire PSK/NST/`obfuscated_ticket_age`/early_data accept-reject follow RFC 8446 / 9001.
- [x] Resume **transport-parameter consistency** for 0-RTT (RFC 9000 §7.4.1): remembered limits sealed in tickets v0x02; server rejects early_data when offer shrinks below remembered; client applies remembered limits for 0-RTT flow control.
- [x] Connection-level **0-RTT reject → 1-RTT STREAM retransmit** test (`reject_requeues_0rtt_stream_for_1rtt_retransmit`).
- [x] **Tests:** full `hopf-quic` integration suite (`--features integration`) except `client_config_public_trust*` (deferred to Phase 4 WebPKI).
- [x] **HTTP/3 consumer re-check:** `hopf-http` H3 integration tests against in-tree `hopf-quic` transport (post-`quinn-proto` cutover). Dial-time SNI always applied; PEM client helpers no longer bake `"localhost"`.

Deferred out of Phase 3 (tracked in destination phases, not blockers here):

| Deferred item | Destination |
| --- | --- |
| External OpenSSL / quic-go / rustls peer interop (incl. 0-RTT wire behaviour) | Phase 2 |
| Public WebPKI / native roots + `client_config_public_trust*` | Phase 4 |
| Conformance audit row flip (QUIC / TLS from N/A → Compliant) | Phase 8 |



### Phase 4 — TLS stream record layer + TCP in `hopf-core` (drop `rustls` for 1.3)

- [x] Signature-scheme prerequisite (pulled forward from Phase 7 scope): RSA-PSS + ECDSA P-256/P-384 `CertificateVerify` sign/verify in `hopf-core::tls::handshake::verify`, PKCS#8 key-kind auto-detection, `signature_algorithms` ClientHello extension. Unblocks real-world (non-Ed25519) certificates, including every existing test fixture's `rcgen` default (ECDSA P-256).
- [x] TLS 1.3 record layer — `hopf-core::tls::record::TlsRecordEngine` (RFC 8446 §5 framing + AEAD, wraps `HandshakeEngine` in `HandshakeMode::TcpRecordLayer`), sink-based (`TlsRecordSink`), no return-value `TlsSession` shape.
- [x] `TcpConnection` cut over fully to `TlsRecordEngine` — `TlsSession`/`TlsProgress`/old `TlsAcceptor`/`TlsConnector` (`hopf-core::tls::session`) removed outright, not kept as a parallel path.
- [x] PEM/acceptor/connector helpers moved into `hopf-core::tls::pem` (`acceptor_from_pem`, `connector_from_pem`, `insecure_connector`) plus a new `connector_with_verify_override` hook (`HandshakeConfig::verify_override`) for pluggable trust models that aren't a fixed root set — used to move DANE (`hopf_dns::dane::verify_dane_chain`, rustls-independent) off `hopf_tls::connector`. `hopf-tls` is now a thin re-export shim over `hopf-core::tls::*`, kept only for call-site compatibility until Phase 8 deletes the crate; it no longer depends on `rustls` except as a dev-dependency test peer.
- [x] **Public WebPKI / native roots** — `hopf-core::crypto::trust::public_trust_store()`: native OS roots via `rustls-native-certs` (full DER, added to `TrustStore` as usual), falling back to a vendored `webpki-roots` bundle when native loading yields nothing. `webpki-roots` only provides subject+SPKI components, not full certificates, so `TrustStore` gained a second anchor kind, `ComponentAnchor` (subject_der + spki_der, no full DER) — chain building now walks a unified view of both kinds; only the "peer presented the anchor cert itself" exact-match shortcut is unavailable to component anchors, which doesn't matter for root-CA verification. `hopf_tls::public_trust_connector` and `hopf_quic::client_config_public_trust`/`client_config_public_trust_with` are wired to it and no longer stub `Unsupported`.
- [x] **Tests:** `hopf-tls`'s `--features integration` suite includes real interop against `rustls` as an independent peer (both directions: rustls-as-client vs the new engine, and vice versa via `insecure_connector`), not just Hopf-to-Hopf — this caught and drove the fixes below. `public_trust_connector_validates_a_real_public_certificate` (hopf-tls, TCP against cloudflare.com) and `client_config_public_trust_rejects_a_self_signed_server` (hopf-quic, local) both pass; `client_config_public_trust_validates_a_real_public_doq_resolver` (hopf-quic, UDP against 1.1.1.1:853) is believed correct — identical trust-store/chain-verification code path as the passing TCP test — but unverifiable in this sandbox, which appears to block outbound UDP entirely (confirmed independently with `openssl s_client -quic` against the same host: zero bytes exchanged; local loopback UDP works fine, per the passing companion test). SMTP/IMAP/POP3/FTP STARTTLS/implicit-TLS integration suites pass unchanged (only their TLS test-fixture plumbing needed updating, not their protocol logic). `tls-echo` example still builds. Full workspace `--lib` and `--features integration` suites pass across every crate (two pre-existing, unrelated failures confirmed via `git stash`: `hopf-amqp` integration tests failing on a socket-level OS error, and `hopf-dns`'s `resolver_stub` test binary needing a feature combination not exercised here — neither touches TLS).
- [x] Event-order test for handshake + early app data in one read: `tls::record::client_finished_and_pipelined_app_data_in_one_read_completes_then_delivers_in_order` — a client's Finished plus an immediately-pipelined application write, fed to the server as one combined `feed_ciphertext` call (what a single coalesced TCP `read()` would deliver), must complete the handshake and only then deliver the application data — validates the "Why sink-based, not return-value-based" design rationale directly, not just the general handshake-then-app-data sequence. Written at the `TlsRecordEngine` level, not through a real `TcpConnection` socket: the ordering guarantee (`security_established` called before `deliver_app_in` in `apply_tls_outcome`) is structural in that code, not dependent on socket read timing, so a real-socket version would mostly add nondeterminism (whether two back-to-back writes actually coalesce into one `read()`) without proving anything the record-layer test doesn't already cover precisely.

**Real interop caught five independent, previously-invisible protocol bugs** — each was self-consistent between two `HandshakeEngine` instances (so no amount of Hopf-to-Hopf testing would have found them) but broke against `rustls` as a genuinely independent TLS 1.3 implementation:
1. ALPN extension encoding was missing RFC 7301's outer 2-byte `ProtocolNameList` length (both the writer and the reader agreed on the same wrong format).
2. `EncryptedExtensions` always included an ALPN extension, even when the client offered none (RFC 8446 §4.2: sending an extension the peer didn't offer is a protocol violation) — plus `pick_alpn` was unilaterally picking the server's own preference instead of returning no match.
3. `application_traffic_secret`/`resumption_master_secret` were derived from the transcript hash at the wrong point relative to the client's own `Finished` message.
4. `master_secret`'s `HKDF-Extract` used an empty IKM instead of RFC 8446 §7.1's required `Hash.length` zero bytes — corrupted every post-handshake secret (application traffic, resumption) while leaving handshake-phase secrets untouched, which is why it only surfaced as an app-data decrypt failure after an otherwise-successful handshake.
5. `HandshakeParser` silently popped and discarded buffered handshake messages that arrived after a verification gate (`verification_requested`) stopped mid-drain, instead of leaving them for the later resume — broke any deferred/asynchronous certificate verification (e.g. `insecure_connector`, or a future `StorageExecutor`-backed gate), whether the messages arrived pre-coalesced or across separate `feed_handshake_data` calls.

A sixth surfaced once public WebPKI trust made a *real* CA hierarchy (not a single self-signed test cert) reachable for the first time: `crypto::x509::verify_cert_signature` (X.509 chain-signature verification — a different code path from `CertificateVerify` above) only handled ECDSA-P256-SHA256, RSA-PKCS1-SHA256, and Ed25519. Real root/intermediate CAs routinely sign with ECDSA-P384-SHA384 or RSA-SHA384/512; without those, `public_trust_connector` rejected cloudflare.com's real chain with `SignatureInvalid` even though the handshake itself (and the leaf's own `CertificateVerify`, already broadened for the Phase 4 prerequisite above) was fine. Added `ecdsa-with-SHA384` and `sha384`/`sha512WithRSAEncryption` alongside the existing three.

Also fixed while chasing the above: `ServerHello.legacy_session_id_echo` was always sent empty regardless of what the client's `ClientHello` actually offered (RFC 8446 §4.1.3 requires an exact echo; middlebox-compat clients like `rustls` send a random 32 bytes and reject the mismatch) — and a genuine, independent latent bug in `hopf-ftp`'s server (`FtpControlHandler::connected`) that sent the `220` welcome banner before an implicit-TLS handshake had completed, masked until now by the old `rustls`-backed path's forgiving pre-handshake write queuing (SMTP/IMAP/POP3 already had the correct `!expect_implicit_tls || tls` gate; FTP's server-side control handler didn't).



### Phase 5 — TLS 1.2

*RFC 5246 and RFC 5077 below are the historical citations for what's actually shipped; both are now obsoleted by [RFC 9846](#baseline-rfcs-2026-09-09), which is the citation of record going forward and adds the new gap items below.*

- [x] Full 1.2 ECDHE handshake + GCM record handling (AWS-LC for crypto). CBC is explicitly out of scope, permanently — see [Non-goals](#non-goals).
- [x] Session resumption via RFC 5077 stateless tickets (not RFC 5246 §7.3 session-ID server-side caching — no server-side session state to scale/evict). Renegotiation disabled (out of scope by design, not deferred — TLS 1.2 renegotiation has its own CVE history and this is a legacy-interop-only path).
- [ ] **RFC 9846 §1.4 TLS 1.2 deltas** (new since baseline update, not started): version-downgrade-protection sentinel (§4.2.3), `RSASSA-PSS` signature schemes for TLS 1.2 (§4.3.3), mandatory `supported_versions` and `signature_algorithms_cert` extensions on the TLS 1.2 `ClientHello`. None of these exist in `tls12/engine.rs` today.
- [x] **Extended Master Secret** (RFC 9846 Appendix D, née RFC 7627, renamed `extended_master_secret` → `extended_main_secret` in 9846's prose only — the IANA extension codepoint, `0x0017`, is unchanged) — implemented in `tls12/messages.rs`/`engine.rs` **(2026-09-10)**, closing the P0 checklist gap cleanly (no partial/deferred residue). Policy: **mandatory, not opportunistic** — both roles refuse the handshake outright (`fail`/`protocol_error`) if the peer doesn't offer/echo the extension, matching this codebase's existing strict posture (no CBC ciphers ever, AEAD-only, mandatory chain verification) rather than keeping a downgrade-capable legacy master-secret path alive. `derive_master_secret` branches on the negotiated flag: EMS uses `session_hash` (`Transcript::hash`, already built for `Finished.verify_data`) under the `"extended master secret"` label; the pre-existing `client_random || server_random` seed under `"master secret"` is now dead in practice (both `on_client_hello`/`on_server_hello` refuse before it could be reached) but kept as a real branch on the negotiated value rather than hardcoded, so a caller bug can't silently produce a wrong secret. One real ordering bug found and fixed while implementing: RFC 7627 §3's `session_hash` must cover the transcript through and including `ClientKeyExchange` (but excluding `CertificateVerify`, sent after CKE in the same flight) — the server side already called `derive_master_secret` after hashing CKE, but the client side (`on_server_hello_done`) called it *before* CKE was even built; moved to immediately after `self.emit(&cke, sink)`. No ticket/resumption bookkeeping needed: under the mandatory policy every ticket this server ever mints was already EMS-derived (the handshake fails before one could exist otherwise), so RFC 7627 §5.2/§5.3's session-compatibility rules collapse into the same blanket ClientHello check. Verified via the full `tls12`/`dtls12` test suite (zero regressions, two new mandatory-refusal negative tests), the real `rustls`-as-peer TLS 1.2 interop tests in `hopf-tls` (7 tests, unaffected), and the real OpenSSL 3.6.3 DTLS 1.2 interop tests (both directions, unaffected — DTLS 1.2 needed zero DTLS-specific changes since it hands `Tls12Engine` only `ClientHello2` onward and this lives entirely inside the shared engine/messages code).
- [ ] **Migrate ticket resumption to RFC 9846 §2.2's unified PSK exchange**, replacing the RFC 5077 mechanism above — real protocol change, not a citation fix; today's RFC 5077 implementation keeps working and interops with `rustls` in the meantime.
- [ ] **`signature_algorithms_cert` (extension 0x0032)** — absent from the **TLS 1.3** engine too (only `signature_algorithms`/0x000d exists); check against RFC 9846 §9.2's mandatory-extension list for TLS 1.3, not just the TLS 1.2 delta above.
- [x] **Tests:** real interop against `rustls` forced to TLS-1.2-only, both directions (Hopf server / rustls client and rustls server / Hopf client), plus a real resumption round trip (`rustls`'s own `handshake_kind()` confirms `Full` then `Resumed` against a Hopf ticket-issuing server) — same methodology that found 7 bugs in Phase 4. Deferred: live mail client / FTPS / legacy-server interop (see below).
- [x] **`TLS_ECDHE_ECDSA/RSA_WITH_CHACHA20_POLY1305_SHA256`** (RFC 7905) alongside the existing `AES128/256_GCM_SHA256/384` suites — `SUPPORTED_CIPHER_SUITES`/`cipher_info`/`CipherKind` extended, and the record layer's AEAD dispatch (`tls12/record.rs`) generalized to handle RFC 7905's different nonce construction from GCM's: no explicit per-record nonce on the wire at all (unlike RFC 5288 GCM's 8-byte explicit nonce), the 96-bit nonce is the full 12-byte IV XORed with the sequence number instead (same construction TLS 1.3 already used). **Tests:** direct AEAD/wire-framing round-trip test, and real `rustls` interop forcing the suite in both directions.

`hopf-core::tls::tls12` (new module: `messages.rs`, `engine.rs`, `record.rs`, `ticket.rs`) is a fully separate FSM and cipher-suite set from the TLS 1.3 engine, deliberately not sharing code — TLS 1.2's `Certificate` framing and record layer differ structurally enough that unifying them wasn't worth the coupling. Cipher suites: `ECDHE_ECDSA`/`ECDHE_RSA` × `AES128/256_GCM_SHA256/384` (RFC 5289) — no static-RSA key exchange (preserves forward secrecy), no CBC suites (permanently — see [Non-goals](#non-goals)). Client certificate authentication (mTLS) is supported — see its own writeup below. `TcpConnection` now dispatches through a `TlsVariant` enum (`V13`/`V12`) added to `hopf-core::tls`, since both engines' record-layer sink traits turned out to be identical in shape — no duplicate connection-layer plumbing needed. New PEM helpers: `acceptor_from_pem_tls12`, `connector_from_pem_tls12`, `insecure_connector_tls12`.

Unlike every prior phase, the real `rustls` interop tests for the base handshake (`crates/hopf-tls/src/lib.rs::integration_tests`, `rustls_tls12_client_completes_handshake_against_hopf_tls12_server` and the reverse direction) passed on the first run — no protocol bugs surfaced. The two ASN.1/DER bugs actually found during that stage (RSA `SubjectPublicKeyInfo` extraction reading the wrong byte after `read_tlv` had already stripped the tag; `rcgen::RemoteKeyPair::public_key()` needing the bare `RSAPublicKey` DER rather than a full SPKI) were caught by the RSA-server-cert engine test before interop, not by rustls itself.

Session resumption's own `rustls` interop test *did* catch a real bug on the first run, restoring the pattern: the server's `ServerHello` never echoed RFC 5077 §3.2's (empty) `SessionTicket` extension, so `rustls` — correctly, per spec — didn't know to expect a `NewSessionTicket` message before `ChangeCipherSpec` in the server's final flight, and rejected the extra handshake message as a protocol violation (`InappropriateMessage { expect_types: [ChangeCipherSpec], got_type: Handshake }`). Hopf-vs-Hopf loopback tests never caught this because the client engine unconditionally tolerated an incoming `NewSessionTicket` in that state regardless of whether the server had signaled it — fixed on both ends: `build_server_hello`/`parse_server_hello` now carry the extension bit, and the client now rejects an unadvertised `NewSessionTicket` as a protocol error instead of silently accepting it (`tls12/messages.rs`, `tls12/engine.rs`).

Ticket contents are sealed AES-128-GCM (`tls12/ticket.rs`, deliberately separate from the TLS 1.3 PSK-ticket module — TLS 1.2 seals the actual 48-byte `master_secret` verbatim, since there's no per-resumption PSK derivation like TLS 1.3's `resumption_master_secret`, so a ticket-key or ticket leak exposes every session resumed under it directly with no forward secrecy across resumptions; short lifetimes and real key rotation are the only mitigation, and a rotated key correctly and transparently falls back resumption attempts to a full handshake rather than failing the connection, per its own test). As with TLS 1.3 tickets, the simple `acceptor_from_pem_tls12`/`connector_from_pem_tls12` PEM helpers deliberately leave `ticket_key`/`client_ticket_store` unset (mirroring `pem.rs`'s existing `base_config` precedent for TLS 1.3) — a caller wanting resumption constructs `Tls12Config` directly.

**Explicitly deferred, not started:** live interop tests against an actual mail client, FTPS client, or legacy TLS 1.2 server in the wild (only `rustls`-as-peer interop is done so far). Client certificates (below) are no longer deferred.

**Explicitly rejected, not planned at all (not the same as deferred):** CBC cipher suites, for either TLS version — see [Non-goals](#non-goals) and `tls12/engine.rs`'s module doc. MAC-then-encrypt CBC has a real, recurring timing-side-channel history (Lucky Thirteen and friends); AEAD is judged sufficient — AES-GCM plus, as of this pass, ChaCha20-Poly1305 (above) — with no dedicated CBC pass on the roadmap to eventually pick up.

#### Client certificate authentication (mTLS) — TLS 1.3 and TLS 1.2

- [x] TLS 1.3: `CertificateRequest` (RFC 8446 §4.3.2) build/parse, client `Certificate`/`CertificateVerify` response (or an empty `Certificate` when no client credentials are configured), server-side verification of the client's chain.
- [x] TLS 1.2: `CertificateRequest` (RFC 5246 §7.4.4) build/parse, client `Certificate`/`CertificateVerify` response placed correctly relative to `ClientKeyExchange` (§7.4.6/§7.4.8), server-side verification.
- [x] Policy knob, `ClientAuthPolicy` (`hopf_core::tls::engine`, shared by both engines' configs): `None` (default — no `CertificateRequest` sent, unchanged prior behavior), `Request` (ask, but proceed on an empty/unverified response), `Require` (fail the handshake unless the client presents a certificate that verifies against `client_trust_store`).
- [x] `ServerCredentials` (already just "DER chain + PKCS#8 key") reused as-is for the client's own credentials — no new type needed. `TrustStore::verify_server_chain` reused as-is for the client's chain too, passing `server_name: None` to skip the (server-specific) hostname check.
- [x] Non-breaking PEM/acceptor-connector API: `acceptor_from_pem_with_client_auth`, `connector_from_pem_with_client_cert` (TLS 1.3) and their `_tls12` equivalents, alongside the existing non-mTLS helpers (which default to `ClientAuthPolicy::None` and no client credentials, exactly matching prior behavior — every existing caller is unaffected).
- [x] **Tests:** engine-level (both engines) covering `Require` accepting a trusted cert, `Require` rejecting a missing or untrusted one, `Request` tolerating a missing one, and a tampered `CertificateVerify` signature being rejected — plus real interop against `rustls`, both directions, both TLS versions (`crates/hopf-tls/src/lib.rs::integration_tests`), including a negative test proving a Hopf server's `Require` policy actually rejects a real `rustls` client that presents no certificate.

The TLS 1.2 interop tests passed in both directions on the first run. The TLS 1.3 ones did not, and caught a real bug — the same class of transcript-hash-derivation mistake Phase 4 already found twice: RFC 8446 §7.1's `application_traffic_secret_0` must be derived from the transcript hash *through the peer's own Finished only*, but once a client certificate flows through the same flight, the client's `Certificate`/`CertificateVerify` (sent right after processing the server's `Finished`, before the client's own `Finished`) had already joined the transcript by the time both sides computed that hash — so both the client (deriving its own `application_traffic_secret_0` after appending its cert response) and the server (deriving it inside `on_client_finished`, by which point the client's cert response was already in the transcript) used a hash that silently included the extra messages. Hopf-vs-Hopf engine tests never caught this because they only asserted `handshake_complete` fired, never actually exercised application data under the derived keys; the `rustls` interop tests did, immediately, as a hard `DecryptError` (Hopf client → `rustls` server) and a `close_notify`-less `UnexpectedEof` (`rustls` client → Hopf server). Fixed by capturing that one hash at the correct moment on each side — right after sending/receiving the peer's `Finished`, before any client certificate exchange — and threading it through explicitly instead of reusing whatever the transcript hash happened to be by the time `Finished` processing ran.



### Phase 6 — DTLS

**Status (2026-09-09):** DTLS 1.3 (RFC 9147) **and** DTLS 1.2 (RFC 6347) engine-level milestones both complete. DTLS 1.3 maximally reuses the TLS 1.3 `HandshakeEngine` per its own transport-agnostic design (see [Baseline RFCs](#baseline-rfcs-2026-09-09) for how `HandshakeMode::Dtls` and the `legacy_version`/`legacy_cookie` ClientHello field slot in); DTLS 1.2 reuses both the TLS 1.2 `Tls12Engine` and DTLS 1.3's own transport-agnostic pieces (`Reassembler`, `RetransmitState`, `ReplayWindow`, `DtlsRecordSink`). Started with DTLS 1.3 (shares the most with what's already built — see the `hello_retry_request` item under Phase 2, pulled forward as a prerequisite), then DTLS 1.2. **DTLS 1.3 verification gap, explicitly accepted:** no DTLS-1.3-capable peer was available anywhere on the development machine — checked OpenSSL 3.6.3 (`s_client`/`s_server` cap at DTLSv1.2), GnuTLS 3.8.13 (`VERS-DTLS*` list stops at 1.2), and BoringSSL via `../quiche`'s submodule (pinned to a 2021 FIPS-branch commit whose own source comments say DTLS 1.3 isn't implemented in that revision). Everything in that subsection is proven only Hopf-to-Hopf, in loopback — this codebase's own history (Phases 2/4/5) shows that alone has repeatedly missed real bugs an independent peer caught, so it should be read as *unverified against any other implementation*, not just "less tested." Revisit real interop once a capable peer exists. **DTLS 1.2 had no such gap** — real OpenSSL 3.6.3 interop (`s_client`/`s_server -dtls1_2`) was in scope and caught five real bugs (see its own subsection below), matching the pattern from every prior TLS phase.

- [x] `HandshakeMode::Dtls` on the shared `HandshakeEngine` — `legacy_version` (`0xfefd`), the DTLS-only `legacy_cookie` ClientHello field (self-detected from the wire's own `legacy_version`, no separate mode flag threaded through the parser), `SecurityInfo::protocol` = `"DTLSv1.3"`.
- [x] **RFC 9147 §5.9's `"dtls13 "` HKDF-Expand-Label prefix**, discovered while implementing this phase (corrects an earlier assumption in this doc that DTLS would mirror QUIC's approach of leaving the handshake key schedule untouched and only prefixing its own record-layer derivation — RFC 9147 instead amends RFC 8446 §7.1 itself, so the prefix change applies throughout the *entire* key schedule). `crypto/hkdf.rs` gained `extract_dtls`/`extract_derived_dtls`/`dtls_expand_label`; `handshake/key_schedule.rs`'s ~9 functions gained a `dtls: bool` param threaded from `HandshakeEngine`. **Unverified** — no RFC 9147 equivalent of RFC 8448's known-answer test vectors exists to check this against, and (per the verification gap above) no real peer either; flagged prominently in `hkdf.rs`'s doc comments.
- [x] **DTLS record layer** (`hopf-core::dtls::record`) — RFC 9147 §4's `DTLSCiphertext` unified header (fixed simplest-compliant flags: no Connection ID, 16-bit truncated sequence number, explicit length), §4.2.1's AEAD nonce (IV XOR the reconstructed 64-bit per-epoch sequence number — epoch itself is *not* mixed in, unlike DTLS 1.2), §4.2.2's sequence-number reconstruction (nearest-value-in-window, the same algorithm QUIC uses for packet numbers), §4.2.3's **record sequence-number encryption** (confirmed via the RFC text to be mandatory, not optional, for AES/ChaCha20 suites once records are encrypted — reuses the same `aws_lc_rs::aead::quic` header-protection primitive `hopf-quic` already uses for its own packet protection, just consuming 2 mask bytes instead of QUIC's 5), and §4.2.4/§4.5.1's per-epoch anti-replay (64-entry sliding bitmap). Also `DTLSPlaintext` (epoch 0, cleartext — identical to DTLS 1.2's format) for `ClientHello`/`HelloRetryRequest`/`ServerHello` before any keys exist; self-describing on the wire against `DTLSCiphertext` (their first-byte bit patterns provably never collide — tested).
- [x] **Handshake fragmentation and reassembly** (`hopf-core::dtls::reassembly`) — RFC 9147 §5.2: splits/reassembles at a conservative fixed fragment size (no PMTU discovery), delivers complete messages to `HandshakeEngine` strictly in `message_seq` order (buffering both out-of-order fragments of one message and out-of-order complete messages), translating between DTLS's 12-byte fragment header and the TLS 4-byte header the engine's transcript hash expects (RFC 9147 §5.2 mandates the transcript uses the TLS-shaped form).
- [x] **Flight-based retransmission** (`hopf-core::dtls::retransmit`) — blind timeout-and-resend (RFC 6347 §4.2.4.1-style backoff: 1s doubling to a 60s cap, 6 attempts before giving up), buffering the last-sent flight's raw wire bytes verbatim. No duplicate-received-flight-triggers-immediate-resend behaviour (a real DTLS optimization) — purely timer-driven, which RFC 9147 permits without ACK support.
- [x] **`DtlsRecordEngine` + `DtlsRecordSink`** (`hopf-core::dtls::engine`) — ties the above to `HandshakeEngine`, mirroring `TlsRecordEngine`'s shape (`start`, `feed_datagram`, `send_application_data`, `feed_verification_result`, `send_close_notify`), plus DTLS-only `feed_timer` and the sink's new `arm_retransmit_timer` (the first engine in this crate where the record layer itself needs a timer armed — TCP has none, QUIC's timer wheel lives inside `hopf-quic`).
- [x] **Tests:** full loopback handshake + ALPN/protocol-name checks, application data round trip, close-notify, tampered-record rejection, and the DTLS-specific case with no TCP/QUIC analogue — a dropped flight, retransmit timer firing, and the resend actually completing the handshake. Plus focused unit tests per module (record AEAD/replay/reconstruction, fragmentation/reassembly ordering, retransmit backoff) — 26 new tests, all passing, zero new compiler warnings.
- [ ] **Explicitly deferred** (not started): real UDP driver/listener wiring for DoDTLS/CoAPS consumers (`hopf-quic`'s mio `Poll`/registration/read-loop scaffolding is shape-reusable; its connection-ID-based demultiplexing isn't — DTLS demuxes by 4-tuple pre-handshake instead); the ACK handshake message (RFC 9147 §7); record sequence-number-confidentiality refinements beyond the fixed flag choice already shipped, and Connection IDs (RFC 9147 §4.2.3/§9); 0-RTT for DTLS (would reuse the existing TLS 1.3 ticket/PSK machinery, the same pattern `hopf-quic` used for QUIC 0-RTT); real interop against a DTLS-1.3-capable peer, once one exists.

#### DTLS 1.2 (RFC 6347)

**Status (2026-09-09):** Complete, including real OpenSSL interop. Reuses `tls::tls12::Tls12Engine` unchanged in FSM terms (same approach as DTLS 1.3 wrapping `HandshakeEngine`) plus `hopf-core::dtls`'s transport-agnostic `Reassembler`/`RetransmitState`/`ReplayWindow`/`DtlsRecordSink` verbatim (elevated to `pub(crate)` for cross-module reuse — the same precedent `tls12/record.rs` already set re-exporting `tls`'s `TlsRecordSink`). Confirmed via RFC 6347 to be structurally *simpler* than DTLS 1.3: one header shape for plaintext/ciphertext (no unified-header split, no record sequence-number encryption, no sequence-number reconstruction — the full epoch+sequence_number is always sent in cleartext), and the RFC 5246 PRF/key-block is unmodified (only the Finished MAC's version parameter changes to `{254,253}` — no DTLS-1.2 analog of DTLS 1.3's `"dtls13 "` HKDF-prefix surprise).

- [x] **`tls12` transport-mode awareness** — `Tls12Config.dtls: bool` drives `legacy_version` (`0xfefd` vs `0x0303`) and `SecurityInfo.protocol` (`"DTLSv1.2"`); `ClientHelloParams`/`ParsedClientHello` gained a `cookie` field (RFC 6347 §4.2.1, written/parsed only in DTLS mode); new `build_hello_verify_request`/`parse_hello_verify_request` for handshake type 3. **No FSM changes** — `Tls12Engine` still treats whatever `ClientHello` it's handed as the only one, since RFC 6347 §4.2.1 excludes `ClientHello1`/`HelloVerifyRequest` from the transcript entirely (the opposite mechanism from DTLS 1.3's `message_hash` substitution).
- [x] **`hopf-core::dtls12` module** — `record.rs`: the single `DTLSPlaintext`/`DTLSCiphertext` header (type+version+epoch+seq+length, all cleartext), reusing `tls12/record.rs`'s AES-GCM/ChaCha20-Poly1305 sealing with one change (AAD's sequence-number input is `epoch || sequence_number` per RFC 6347 §4.1.2.1, not TLS's pure 64-bit counter) plus per-epoch `ReplayWindow` reuse. `engine.rs`: `Dtls12RecordEngine` wraps `Tls12Engine` in DTLS mode, owning the `ClientHello1` → `HelloVerifyRequest` → `ClientHello2` cookie round trip entirely outside the wrapped engine (discarding-and-recreating the `Tls12Engine` instance across the retry, so it only ever sees the real `ClientHello2`).
- [x] **Cookie policy**: `HMAC-SHA256(cookie_secret, ClientHello.random)`, truncated to 16 bytes — real cryptographic binding to *this* handshake attempt, but **not** bound to a network address (that needs the peer address the deferred production UDP driver wiring would thread through — same gap DTLS 1.3 already flagged for its own cookie extension). `Dtls12Config.require_cookie` defaults to **off**, since forcing the extra round trip for protection that isn't address-bound yet has a real cost and no real benefit.
- [x] **Real OpenSSL interop** (`hopf-core::dtls12::interop_tests`, `--features integration`) — a new subprocess+real-UDP-socket harness (this workspace's existing `rustls` interop is in-process; OpenSSL's DTLS tools are external binaries with no in-process channel available), driving `openssl s_client -dtls1_2` / `openssl s_server -dtls1_2` against `Dtls12RecordEngine` in both directions. **Found and fixed 5 real bugs**, continuing this project's established pattern (Phase 4: 5 bugs; Phase 5: 1 more) of real interop catching what Hopf-to-Hopf loopback testing structurally cannot:
  1. **GCM explicit-nonce wire/crypto mismatch** — `write_record` wrote the wire's explicit-nonce field as bare `seq` while the actual AEAD nonce used `epoch||seq`, internally inconsistent (loopback didn't catch it because both sides derived the same wrong value symmetrically).
  2. **Read side wrongly assumed the peer's explicit nonce equals `epoch||seq`** — confirmed via real OpenSSL traffic that the explicit-nonce field is sender-chosen and independent of the header's epoch/sequence fields (RFC 5288 §3: the receiver must use whatever the sender put on the wire). Fixed to read the wire's own 8 explicit-nonce bytes for the AEAD nonce, matching `tls::tls12::record.rs`'s already-proven approach — the AAD's sequence-number input (`epoch||seq`) was unaffected and correct.
  3. **Transcript hash framing was backwards from DTLS 1.3's rule** — wrongly assumed (by analogy, unverified) that DTLS 1.2 excludes `message_seq`/`fragment_offset`/`fragment_length` from the Finished hash like DTLS 1.3 does. RFC 6347 §4.2.6 says the opposite: the full 12-byte DTLS handshake header **is** hashed (with `fragment_offset=0`/`fragment_length=total`, "as if sent as a single fragment"). Required adding `Tls12Engine::hash_message()` with independent per-direction `dtls_tx_seq`/`dtls_rx_seq` counters to the *shared* engine (gated behind `!self.config.dtls` for the existing TCP TLS 1.2 path, confirmed byte-identical — all 37 pre-existing TCP TLS 1.2 tests passed unchanged). Loopback tests couldn't catch this either: both sides of a loopback pair apply the same wrong framing symmetrically and it cancels out.
  4. **`message_seq` counters wrongly reset to 0 after a `HelloVerifyRequest` cookie retry** — RFC 6347 §4.2.2's own worked example shows `ClientHello2`'s `message_seq` continues from `ClientHello1` (i.e. `1`, not reset to `0`) despite the engine being discarded and recreated for the retry. Fixed via a new `Tls12Config.dtls_initial_seq: (u16, u16)`, set to `(1, 1)` when constructing the post-cookie engine instance.
  5. **Test-harness-only**: `openssl s_server` exits almost immediately on stdin EOF (confirmed by direct reproduction), and the client-interop test's `Dtls12Config` was missing a real `trust_store`, silently stalling the async certificate-verification gate forever. Both fixed in the test harness itself, not product code.
- [x] **Tests:** 14 loopback/unit tests (cookie on/off, application data, close-notify, tamper rejection, dropped-flight retransmit, ticket resumption over DTLS framing) plus 6 record-layer unit tests, plus the 2 real OpenSSL interop tests above — all passing, zero new compiler warnings (confirmed against the workspace's pre-existing warning baseline).
- [ ] **Explicitly deferred**: real IP-address-bound cookie validation (needs the same production UDP driver wiring DTLS 1.3 already deferred); GnuTLS interop (OpenSSL was the minimum bar and is done; not attempted this pass).



### Phase 7 — PQC policy

- [ ] Centralise group preference (hybrid ML-KEM first) in one config object for 1.3 / DTLS 1.3 / QUIC, per [RFC 9954](https://datatracker.ietf.org/doc/rfc9954/)'s concatenation-based hybrid design, offering [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html)'s three registered groups — `X25519MLKEM768` preferred, `SecP256r1MLKEM768`/`SecP384r1MLKEM1024` as classical-curve alternatives — with a pure-classical fallback.
- [ ] Replaces rustls `prefer-post-quantum` knob.
- [ ] **Tests:** handshake tests assert negotiated group order across TCP, QUIC, and DTLS paths.



### Phase 8 — Remove interim crates and dependencies

- [ ] **Remove crate** `hopf-tls`; drop `rustls`, `quinn-proto`, redundant PEM/trust helpers from workspace.
- [ ] Update umbrella `hopf` crate, `scripts/publish-crates.sh`, and docs (TLS from `hopf-core`; QUIC fully in-tree in `hopf-quic`).
- [ ] Keep `aws-lc-sys` (or direct FFI) as **the** native crypto dependency.
- [ ] Update conformance audit rows from **N/A (rustls / quinn)** to **Compliant (in-tree)** — includes QUIC transport / 0-RTT / TLS handshake rows deferred from Phase 3b.
- [ ] **Tests:** full workspace unit + integration matrix passes (see [Verification](#verification)) — this is the migration completion gate.



### Phase 9 — GSSAPI / Kerberos SASL (auth, not transport)

*After core crypto + TLS/QUIC path is stable.*

- [ ] Optional `gssapi` feature on `hopf-auth` (like `pam`): links `libgssapi_krb5` / SSPI — **not** subsumed by AWS-LC.
- [ ] RFC 4752 SASL client/server; KDC/keytab work on `StorageExecutor` (Gumdrop pattern).
- [ ] Wire through SMTP/IMAP/LDAP/AMQP; RFC 1961 for `hopf-socks`.
- [ ] **Tests:** MIT Kerberos or containerised KDC in CI; SASL GSSAPI round-trips on SMTP/IMAP.



### Future — parallel transport families (same crypto floor)


| Protocol             | Depends on                           | Notes                                                  |
| -------------------- | ------------------------------------ | ------------------------------------------------------ |
| **DNSCrypt**         | `hopf-core::crypto`                  | UDP object encryption; not DTLS-interoperable          |
| **SSH / SFTP / SCP** | `hopf-core::crypto` + new `hopf-ssh` | SSH KEX + channels; host-key trust model               |
| **CoAP / CoAPS**     | DTLS (Phase 6) or OSCORE             | CoAPS = DTLS; OSCORE = separate message-security stack |
| **ARC (mail)**       | `hopf-core::crypto`                  | DKIM-style signing on `Authentication-Results`         |


---



## Direct answer: do we write TLS handshaking?

**Yes — but not one monolith:**


| Use case    | Handshake                                | Record layer  |
| ----------- | ---------------------------------------- | ------------- |
| **QUIC**    | **Yes** (TLS 1.3 only) — *agent15 scope* | No (RFC 9001) |
| **TCP TLS** | **Yes** (1.3 + **1.2**)                  | **Yes**       |
| **DTLS**    | **Yes** (1.2 minimum; 1.3 optional)      | **Yes**       |


Gumdrop split the problem: **JDK did TCP; agent15 did QUIC handshake only; Gumdrop's own code did QUIC transport.** Hopf unifies on **AWS-LC for all primitives** but **implements protocol state machines and wire layers in-tree**.

### Engineering size (rough order)

1. `**hopf-quic` transport** (replacing quinn) — most lines; Gumdrop `quic` package equivalent.
2. **TLS 1.2 + record layers in** `hopf-core` (replacing rustls / `hopf-tls`) — broad interop.
3. **TLS 1.3 handshake** — hard but bounded; shared between QUIC and TCP 1.3.
4. **DTLS** — incremental once 1.2/1.3 patterns exist.

---



## First milestone (when implementation starts)

**Phase 1 + Phase 2 + minimal Phase 3 slice:**

- `hopf-core::crypto` facade live.
- TLS 1.3 handshake in core exports QUIC secrets to `**hopf-quic**`.
- One loopback HTTP/3 request over **in-tree** `hopf-quic` **transport** (no `quinn-proto`).

That proves the Gumdrop-shaped split (`hopf-quic` = transport, core = handshake + crypto floor) before removing `**hopf-tls**` and touching SMTP STARTTLS at scale.

---



## Risks and mitigations


| Risk                                    | Mitigation                                                                                                                        |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Conformance debt**                    | Update [conformance.html](docs/conformance.html) rows per phase; phase tests plus full workspace regression before Phase 8 closes |
| **Handshake reprocessing / epoch bugs** | Strict FSM; learn from early agent15 and datagram edge cases; test event order, not return values                                 |
| **MSRV / native build matrix**          | Document platform support; pin `aws-lc-sys` prebuild policy                                                                       |
| **Scope creep**                         | QUIC + TLS 1.3 + TCP 1.3 first; 1.2 and DTLS 1.2 follow for mail/IoT parity                                                       |
| **Second native stack for GSSAPI**      | Optional feature; auth partition only; after transport stack is stable                                                            |


---



## References

- [RFC 9846 — TLS 1.3, current baseline (obsoletes 8446, 5246, 5077, 6961, 7627, 8422)](https://www.rfc-editor.org/rfc/rfc9846.html) — see [Baseline RFCs](#baseline-rfcs-2026-09-09)
- [RFC 9954 — Hybrid Key Exchange in TLS 1.3](https://datatracker.ietf.org/doc/rfc9954/)
- [RFC 10024 — PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3](https://www.rfc-editor.org/rfc/rfc10024.html)
- [Architecture → Security substrate](docs/architecture.html#security-substrate)
- [Conformance → Security substrate](docs/conformance.html#security-substrate)
- [Phase 0 inventory](crypto-migration-inventory.md)
- [TLS roadmap (interim rustls)](docs/tls.html#roadmap)
- [QUIC implementation status (interim quinn-proto)](docs/quic-h3.html#implementation-status)
- [Gumdrop](https://github.com/cpkb-bluezoo/gumdrop) — behavioural reference (`../gumdrop`)

