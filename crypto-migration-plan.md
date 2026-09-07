# Hopf crypto and transport security migration plan

This document is the implementation plan for consolidating Hopf security under
**AWS-LC libcrypto in** `hopf-core`, in-tree reactive TLS and DTLS, a **full Hopf-style QUIC stack in** `hopf-quic` (Gumdrop `org.bluezoo.gumdrop.quic` equivalent — not a `quinn-proto` wrapper), and retiring `**rustls`**, `**quinn-proto**`, and the `**hopf-tls**` crate once parity is proven.

It complements the status tables in
[docs/conformance.html](docs/conformance.html#security-substrate) and
[docs/architecture.html](docs/architecture.html#security-substrate). Those pages
describe *what* is shipped vs planned; this file describes *how* to get there.
Phase 0 touchpoints and seams: `[crypto-migration-inventory.md](crypto-migration-inventory.md)`.

**Status:** Phase 3 in progress — in-tree RFC 9000 transport drives `hopf-quic` (quinn-proto removed from the crate); loopback echo (`spike_echo_one_stream_hopf` + `QuicListenHardening::permissive()`) is green. Retry/hardening/GSO/0-RTT and broader integration remain open.

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
- [x] Wire into `hopf-quic` CRYPTO stream via `quinn-proto::crypto::Session` adapter (`hopf-quic/src/crypto/`); loopback echo (`spike_echo_one_stream_hopf`). OpenSSL/quic-go interop still open.
- [x] **Tests:** key schedule RFC 8448 vectors; 1-RTT loopback (classical + hybrid PQC + transport parameters).

*Agent15 equivalent — with proper state machine discipline and AWS-LC underneath.*

### Phase 3 — Full `hopf-quic` transport (drop `quinn-proto`)

- [x] RFC 9000 state machine **in** `hopf-quic` — Gumdrop-shaped minimal echo subset; reactive mio driver; **no `quinn-proto` dependency** in `hopf-quic`.
- [x] Wire Phase 2 handshake from `hopf-core::tls`; RFC 9001 packet protection in `hopf-quic` transport; driver swapped to in-tree `Connection`/`Endpoint` (`spike_echo_one_stream_hopf`).
- [ ] Finish Retry hardening, GSO, 0-RTT, loss recovery / congestion beyond the echo milestone; keep stream-as-`Endpoint` public API.
- [ ] **Tests:** full `hopf-quic` integration suite (`--features integration`), H3 tests, conformance QUIC rows.



### Phase 4 — TLS stream record layer + TCP in `hopf-core` (drop `rustls` for 1.3)

- [ ] TLS 1.3 record layer on `TcpConnection` via `**hopf-core::tls**` (`TlsEngine` + sink pump).
- [ ] Move PEM/acceptor/connector helpers from `**hopf-tls**` into core; implicit TLS + STARTTLS unchanged at protocol crate level.
- [ ] **Tests:** `tls-echo`, SMTP/IMAP/POP3/FTP STARTTLS integration tests; event-order tests for handshake + early app data in one read.



### Phase 5 — TLS 1.2

- [ ] Full 1.2 handshake + CBC/GCM record handling (AWS-LC for crypto).
- [ ] Session resumption; renegotiation disabled.
- [ ] **Tests:** mail client interop, FTPS, legacy TLS 1.2 servers.



### Phase 6 — DTLS

- [ ] `**DtlsEngine` + `DtlsEventSink**` on UDP (parallel reactive shape to TLS).
- [ ] DTLS 1.2 record layer + handshake (priority for Gumdrop / DoDTLS / CoAPS); timer-driven retransmit as `feed_timer` stimuli.
- [ ] Framework-transparent DTLS on UDP listeners (Gumdrop parity).
- [ ] **Tests:** DNS over DTLS resolver path; timer/retransmit event sequences; later CoAP.



### Phase 7 — PQC policy

- [ ] Centralise group preference (hybrid ML-KEM first) in one config object for 1.3 / DTLS 1.3 / QUIC.
- [ ] Replaces rustls `prefer-post-quantum` knob.
- [ ] **Tests:** handshake tests assert negotiated group order across TCP, QUIC, and DTLS paths.



### Phase 8 — Remove interim crates and dependencies

- [ ] **Remove crate** `hopf-tls`; drop `rustls`, `quinn-proto`, redundant PEM/trust helpers from workspace.
- [ ] Update umbrella `hopf` crate, `scripts/publish-crates.sh`, and docs (TLS from `hopf-core`; QUIC fully in-tree in `hopf-quic`).
- [ ] Keep `aws-lc-sys` (or direct FFI) as **the** native crypto dependency.
- [ ] Update conformance audit rows from **N/A (rustls / quinn)** to **Compliant (in-tree)**.
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

- [Architecture → Security substrate](docs/architecture.html#security-substrate)
- [Conformance → Security substrate](docs/conformance.html#security-substrate)
- [Phase 0 inventory](crypto-migration-inventory.md)
- [TLS roadmap (interim rustls)](docs/tls.html#roadmap)
- [QUIC implementation status (interim quinn-proto)](docs/quic-h3.html#implementation-status)
- [Gumdrop](https://github.com/cpkb-bluezoo/gumdrop) — behavioural reference (`../gumdrop`)

