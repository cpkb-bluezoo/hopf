# Hopf — Project Plan

This document records architectural and product decisions made while planning a
native successor to [Gumdrop](https://github.com/cpkb-bluezoo/gumdrop) (sibling
repo `../gumdrop`). It is written so another agent or contributor can continue
without re-deriving the discussion.

Status: **active greenfield**. Published architecture reference:
[docs/architecture.html](docs/architecture.html). Design locks from GitHub issues
[#1](https://github.com/cpkb-bluezoo/hopf/issues/1)–[#8](https://github.com/cpkb-bluezoo/hopf/issues/8)
are summarised below.

---

## Purpose

Hopf is a **natively compiled, asynchronous, non-blocking, event-driven
multi-protocol networking framework** in Rust.

It is **not** a server-only product. The default topology is a **graph of
endpoints** on one Runtime: **listen and dial are equal** binding birth paths
([#1](https://github.com/cpkb-bluezoo/hopf/issues/1)). Peer / P2P
compositions (N listeners + M dialers) are normal, not a third stack. Clients
routinely host multiple protocols in one process (at minimum **DNS under dial**).

It carries forward Gumdrop’s core idea: a small, coherent I/O and security
substrate on which many Internet application protocols (HTTP, mail, MQTT, DNS,
FTP, SOCKS, WebDAV, etc.) share the same transport model — TLS/QUIC where
appropriate, transport-level backpressure, shared worker pools independent of
connection count, and plain buffer semantics rather than a proprietary buffer
world (Gumdrop’s contrast with Netty’s `ByteBuf`).

### Why leave Java

Gumdrop proved the architecture in Java NIO (selector loops + separate servlet /
worker pools). The strategic concern is ecosystem direction:

- Project Loom makes it easy to scale **blocking** `Socket` /
  `InputStream`/`OutputStream` code without adopting streaming /
  non-blocking design.
- Major Java APIs in this space (Servlets, JavaMail, etc.) did not evolve toward
  that design.
- High-performance multi-protocol frameworks that demand real async discipline
  remain niche in Java; native languages are a better long-term home for this
  work.
- Native TLS/QUIC in-process (no JNI bridges to a separate QUIC engine).

Hopf is **not** a line-by-line port of Gumdrop’s Java types. It is a
re-implementation of the **techniques, protocol work, and architectural
contracts**, with Rust ownership and a thread-per-core execution model.

Gumdrop remains the reference implementation and the source of protocol
behaviour, state machines, and design patterns to port deliberately.

---

## Execution model: thread-per-core

**Decision: thread-per-core (TPC) on mio readiness loops.**

Rationale (aligned with Gumdrop):

- Each connection is owned by one reactor thread for its lifetime (affinity).
- I/O, TLS, and protocol byte handling stay on that thread (cf. Gumdrop
  `SelectorLoop`).
- Application / blocking / storage work runs on a **separate worker /
  storage pool** (cf. Gumdrop worker pool + `StorageExecutor`).
- Cross-core coordination is **explicit** (message passing), not implicit task
  migration.

**Rejected as the primary substrate:**

| Option                                        | Why not (for this project)                                                                                    |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Work-stealing async runtimes (e.g. Tokio mt)  | Connection state migrates; fights near-zero-deps and TPC fidelity                                             |
| Glommio / Monoio / Compio as the product base | Useful ideas (quotas, completion I/O, shard channels), but adopting them means owning *their* stack and deps  |
| C as implementation language                  | Viable for an ABI later; poor default for a full multi-protocol framework (memory safety tax on every parser) |

**Optional future:** io_uring completion paths for Linux (sockets and/or files)
behind the same endpoint/handler traits — an evolution, not day-one
requirement. Study Glommio for quotas / shard messaging *ideas*; do not take
the crate as foundation.

**Hybrid note:** A Gumdrop-shaped `Listener` / `Connector` / `Endpoint` /
`ProtocolHandler` API should not hard-wire a third-party async runtime. TPC +
mio readiness loops are the execution strategy; traits should allow a later
uring backend. Multiplatform is desirable.

---

## I/O substrate: mio (readiness)

**Decision: build on [mio](https://github.com/tokio-rs/mio) (epoll / kqueue /
similar readiness), with an in-tree executor / timer / registration model
analogous to Gumdrop’s** `SelectorLoop`**.**

(The mio crate is hosted under the `tokio-rs` GitHub org; Hopf uses **mio
only**, not the Tokio runtime.)

This preserves:

- Readiness mental model (interest ops, fill buffer, parse, write queue,
  backpressure).
- Portable development (including macOS) without requiring io_uring.
- Near-zero dependency surface for the reactor.

**Do not** pull Hyper, Axum, Tower, or an async app runtime.

Implement from scratch (as in Gumdrop): accept loops, per-core reactors,
timers, cross-thread registration/task queues, buffer pools, backpressure,
**listen and dial** binding APIs.

### Files and storage

mio covers **sockets** (and similar fds), not Gumdrop’s
`AsynchronousFileChannel` story. Mail, FTP, WebDAV, and large body paths need
an explicit **storage executor**: blocking or off-loop file I/O, never on the
reactor thread. Zero-copy (`sendfile` / related) may use thin `libc` wrappers
later. This is first-class architecture, not an afterthought.

### DNS as dial substrate

([#4](https://github.com/cpkb-bluezoo/hopf/issues/4)) Name resolution is
**Runtime substrate**, not only a late “DNS product” tranche:

- Per-reactor `DnsResolver` (sockets, pending queries, timers on that core).
- Process-shared config + TTL cache.
- Dial-by-name resolves on the **target reactor**; callbacks run there, then
  dial TCP/QUIC.
- Staging: SocketAddr-only → thin UDP A/AAAA → parity (TCP truncation, DoH/DoQ, …).
- **No** blocking `getaddrinfo` on reactor threads; storage-pool blocking
  resolve is transitional demos only if mentioned at all.

---

## Concrete dependencies

### Allowed (hard)

| Dependency | Role |
| ---------- | ---- |
| **mio** | Readiness-based networking (TPC reactors) |
| **rustls** | TLS for TCP **and** QUIC (single TLS story) |
| **quinn-proto** | QUIC **transport** state machine; mio/TPC glue in-tree ([#7](https://github.com/cpkb-bluezoo/hopf/issues/7)) |

Expect transitive crypto from rustls (e.g. ring / aws-lc-rs, webpki). That is
accepted as part of rustls, not a license to add general web frameworks.

Thin `libc` (or equivalent) usage is acceptable for CPU affinity,
`sendfile`, and similar syscalls.

**Rejected as QUIC engines:** stacks that pull an async app runtime or a second
crypto library. HTTP/3 codecs are **in-tree** (cpkb-bluezoo incremental push
style), layered on quinn-proto + mio.

### Strongly allowed (sibling parsers — required when features ship)

Workspace path deps (see root `Cargo.toml`):


| Crate | Role |
| ----- | ---- |
| **[tractrix](https://crates.io/crates/tractrix)** | Incremental push **XML** (Gonzalez lineage) — WebDAV wire XML **and** composition scripts ([#8](https://github.com/cpkb-bluezoo/hopf/issues/8)) |
| **[rjsonparser](../rjsonparser)** | Incremental push JSON — protocol payloads / telemetry / wherever JSON appears |
| **[rmimeparser](../rmimeparser)** | Incremental push MIME / RFC 5322 — mail and related |
| **[rprotobuf](../rprotobuf)** | Incremental push protobuf — OTLP / telemetry |

Do **not** add TOML/YAML/serde codecs for composition “because ecosystem” —
XML via tractrix is the locked declarative format once a loader exists.

### Strongly allowed (still “near zero”)

| Area | Approach |
| ---- | -------- |
| **Non-TLS crypto** | Reuse ring (via rustls) and/or a small RustCrypto set for digests, HMAC, PBKDF, AES-GCM, signatures (DKIM, DNSSEC, Digest auth, session crypto). Do **not** hand-roll RSA/ECDSA/Ed25519/AES-GCM. |
| **Trust / roots** | Explicit PEM/DER config; `rustls-native-certs` or `webpki-roots` (or document PEM-only and ship a bundle policy). |
| **Compression** | zlib binding or `miniz_oxide` / similar if WebSocket permessage-deflate or HTTP content-codings are required. |

### Implement in-tree (non-dependencies)

- TPC reactor, timers, buffer pools, backpressure, dynamic bindings, Connector
- Protocol codecs and state machines (HTTP/1–2; **HTTP/3 in-tree** on quinn-proto)
- Auth **TrustPolicy** / **IdentityMaterial** / SASL wire helpers ([#2](https://github.com/cpkb-bluezoo/hopf/issues/2))
- Quotas, rate limits, telemetry wiring
- Grammar-driven incremental push codecs on shared `ByteStreamLexer` ([#3](https://github.com/cpkb-bluezoo/hopf/issues/3))
- Composition **builder API** (canonical); XML loader desugars into it ([#8](https://github.com/cpkb-bluezoo/hopf/issues/8))

### Explicit non-dependencies

- **Async app runtimes** (Tokio and equivalents), **Hyper**, **Axum**, **Tower**,
  **serde** stacks as architecture
- Full **`quinn`** crate (use **quinn-proto** + in-tree mio glue only)
- Separate QUIC crypto stacks alongside rustls
- **Glommio**, **Monoio**, **Compio** as required runtime
- Servlet / JSP / JNDI / Java EE APIs; reflective XML **DI** (Guice/Spring/`class=`)
- TOML/YAML as primary composition formats
- Heavy Kerberos/GSSAPI unless a concrete need appears (would be FFI)
- Dependency injection frameworks, ORM, object serialisation such as serde

---

## Layering locks (from issues)

### Transport vs HTTP Stream ([#5](https://github.com/cpkb-bluezoo/hopf/issues/5))

| Layer | Concepts |
| ----- | -------- |
| **A — Transport (`hopf-core` / `-quic`)** | `Endpoint` (byte stream); TCP endpoint; UDP endpoint (datagrams — not faked as a stream); QUIC stream endpoint; multiplexed QUIC connection (`open_stream` / accept) |
| **B — HTTP Stream (`hopf-http`)** | One request/response exchange; `HttpStream` + server / client handlers (`ServerHandler` / `ServerWriter`, `ClientHandler` / `ClientWriter`) — **version- and transport-agnostic** |

H1 **adapts** a TCP `Endpoint` into serialized Streams (`H1Endpoint`); H2 multiplexes Streams on one TCP `Endpoint`; H3 maps each request to a QUIC stream `Endpoint`. Bind vs dial only affects how the transport Endpoint was born; role (server / client) is a separate axis. Terminology: HTTP Stream ≠ H2 stream id ≠ QUIC stream endpoint.

### Dynamic bindings ([#6](https://github.com/cpkb-bluezoo/hopf/issues/6))

**All bindings are dynamic.** Listen and dial are added/removed through Runtime
APIs while the process is alive. Configuration is a **script** over those APIs
(Rust `main` / builder, later XML). `Service` orchestrates lifecycle; it does
**not** own an immutable listener list as source of truth. Current
`tcp_listeners()` one-shot register is transitional.

### Composition root ([#8](https://github.com/cpkb-bluezoo/hopf/issues/8))

```text
main → Runtime::start → CompositionScript
         → TrustPolicy / IdentityMaterial / TLS / DNS
         → add bindings (listen/dial)
         → handler factories (closed registry)
       → wait / shutdown
```

- **Canonical:** Rust builder / composition API.
- **Declarative:** XML via **tractrix** (same codec as WebDAV) → same builder
  calls; closed registry of `proto` / handler / trust names — **no** reflective DI.
- TOML/YAML rejected as primary composition formats.

### Auth ([#2](https://github.com/cpkb-bluezoo/hopf/issues/2))

Prefer **TrustPolicy** + **IdentityMaterial** over Realm-as-root naming. Attach
to **both** listen and dial. SASL client/server are **wire roles**, independent
of listen/dial. mTLS / EXTERNAL: mutual present + verify.

### Codec style ([#3](https://github.com/cpkb-bluezoo/hopf/issues/3))

**Grammar-driven incremental codecs:** protocol-specific token alphabets on
shared `ByteStreamLexer`; update parse FSM as each production completes; CRLF
is one production, not the only event boundary. Early **parse** state ≠ early
**app** callbacks. HTTP `LINE`-only scanner is **transitional**.

---

## Goals

1. **TPC multi-protocol networking framework** with equal listen/dial, shared
   TLS/QUIC config, TrustPolicy, quotas, and transport-level flow control.
2. **Plain buffers** (`&[u8]` / pooled owned buffers).
3. **Near-zero dependencies** beyond mio, rustls, quinn-proto, and the sibling
   parsers (tractrix / rjsonparser / rmimeparser / rprotobuf) when features need them.
4. **Port Gumdrop protocol IP deliberately** — behaviour and state machines,
   not Java APIs. Differentiating protocols (mail, MQTT, DNS, SOCKS, WebDAV,
   etc.) as product identity; HTTP reimplemented in-tree (not Hyper).
5. **Separate I/O cores from worker/storage pools** — never block reactors on
   disk, DNS, or app logic.
6. **Panic isolation** at connection/handler boundaries.
7. **Allocation discipline** — buffer pools / careful hot-path allocation.
8. **Single TLS story** — rustls for TCP TLS and QUIC; document STARTTLS vs
   always-secure QUIC at the composition façade.

---

## Non-goals

- Preserving Servlet, JSP, or JavaMail APIs; reflective XML DI.
- Bit-identical Gumdrop Java package layouts or JNI.
- Supporting every platform equally on day one for every advanced feature.
- Work-stealing schedulers as the default concurrency story.

---

## Name and theme

**Name: Hopf**

**Math:** [Hopf circles](https://en.wikipedia.org/wiki/Hopf_circles)
— two circles produced by a plane cutting a torus at a special angle.

**Lineage with sibling projects:**

| Project | Everyday / name hook | Mathematical spine |
| ------- | -------------------- | ------------------ |
| **Gumdrop** | Gumdrop candy | Torus (logo: torus + gumdrop) |
| **Gonzalez** / **tractrix** | Proper name / curve | Mexican-hat wavelet; XML parser port |
| **Hopf** | Proper name (Yvon Hopf) | Circles on the torus — torus family sequel |

---

## Relationship to Gumdrop

| | Gumdrop | Hopf |
| - | ------- | ---------- |
| Language | Java 17+ | Rust |
| I/O | `Selector` / NIO | mio readiness (+ optional uring later) |
| TLS / QUIC | JSSE (+ external QUIC via JNI) | **rustls** + **quinn-proto** (one crypto story) |
| Concurrency | SelectorLoop affinity + workers | TPC + workers/storage (same diagram) |
| Bindings | Static + dynamic listeners | **All dynamic**; config is a script |
| Product noun | Server / Service-centric | **Networking** — listen, dial, peers |
| Protocols | In-tree | Port / reimplement in-tree (server **and** client roles) |
| Servlet container | Yes | Non-goal |
| XML config | Reflective DI (`class=`) | Document via tractrix → builder; no DI |
| Deps philosophy | Minimal | Same, stricter about app frameworks |

Use `../gumdrop` as behavioural reference (especially `SelectorLoop`,
`Endpoint` / handlers, `StorageExecutor`, protocol packages under
`org.bluezoo.gumdrop.*`).

