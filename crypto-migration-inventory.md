# Crypto migration — Phase 0 inventory

Companion to [`crypto-migration-plan.md`](crypto-migration-plan.md). This document is the **living touchpoint inventory** for Phase 0 (and updated as migration proceeds). The plan keeps strategy and phases; **this file lists every dependency and call site** to retire or consolidate.

**Generated:** 2026-09-07 (Phase 0 baseline). Re-scan with:

```bash
rg -l 'rustls|quinn_proto|aws_lc_rs' --glob '*.rs' --glob 'Cargo.toml'
rg 'hopf_tls::' --glob '*.rs'
```

---

## Phase 0 status

| Item | Status |
|------|--------|
| Handshake owned in-tree (no libssl / QUIC-TLS API) | **Locked** — see plan Phase 0 |
| Touchpoint inventory (this document) | **Baseline complete** |
| Frozen public seams confirmed | **Yes** — see [Frozen seams](#frozen-seams) |
| Engine design locked (trait names + event model) | **Yes** — see [Engine design lock](#engine-design-lock) |
| `aws-lc-sys` platform matrix | **Documented** — see [Platform matrix](#platform-matrix) |

---

## Locked decisions (Phase 0)

1. **Own the handshake** — reactive TLS 1.3/1.2/DTLS state machines in `hopf-core`; RFC 9001 key schedule in `hopf-quic/crypto`; libcrypto for primitives only.
2. **No primitive reimplementation** — `hopf-core::crypto` wraps AWS-LC (`aws-lc-rs` + thin FFI); Ed448 via `ed448-goldilocks-plus` only.
3. **Reactive engines** — `feed_*` stimuli + event sinks; not Tokio/`Future`-shaped async.
4. **Crate end state** — remove `hopf-tls`; `hopf-quic` = full in-tree QUIC (Gumdrop `org.bluezoo.gumdrop.quic` role).

---

## Workspace dependencies (root `Cargo.toml`)

| Dependency | Role today | Retire phase |
|------------|------------|--------------|
| `rustls` 0.23 (`aws-lc-rs`, `prefer-post-quantum`, `tls12`) | TCP TLS + QUIC-TLS configs | Phase 4 (TCP 1.3), Phase 8 (QUIC path) |
| `rustls-pemfile` | PEM load in `hopf-tls`, `hopf-quic` | Phase 4 / 8 → `hopf-core` |
| `rustls-native-certs` | OS trust store in `hopf-tls` | Phase 4 → `hopf-core::crypto` |
| `webpki-roots` | Vendored fallback roots in `hopf-tls` | Phase 4 → `hopf-core::crypto` |
| `quinn-proto` 0.11 (`rustls-aws-lc-rs`) | QUIC transport in `hopf-quic` | Phase 3 |
| `aws-lc-rs` / `aws-lc-sys` (`prebuilt-nasm`) | Primitives + rustls provider | **Keep** (facade in Phase 1) |
| `rcgen` (`aws_lc_rs`) | Test/demo cert generation | Keep for tests; may move behind dev-deps |
| `ed448-goldilocks-plus` | DNSSEC Ed448 verify (`hopf-dns`) | Keep behind facade (Phase 1) |
| `tinyvec` pin | Transitive quinn-proto workaround | Drops with quinn-proto |

---

## Crate dependency graph (interim)

```text
hopf-core ──tls traits──► hopf-tls ──► rustls ──► aws-lc-rs
                │
hopf-quic ──────┼──► hopf-tls (tls_crypto_provider, PEM helpers)
                ├──► quinn-proto ──► rustls (QUIC crypto)
                └──► rustls, rustls-pemfile (config.rs)

hopf-dns ──dot/doh──► hopf-tls
         ──doq──────► hopf-quic
         ──dnssec───► aws-lc-rs, ed448-goldilocks-plus
         ──dane─────► rustls (feature)

hopf-smtp ──► hopf-tls, aws-lc-rs (DKIM)
hopf-http ──h3──► hopf-quic
```

---

## `rustls` touchpoints

### Primary: `hopf-tls` (crate to remove — Phase 8)

| Location | Use | Migrate to |
|----------|-----|------------|
| `crates/hopf-tls/src/lib.rs` | Full rustls adapter: `ServerConnection` / `ClientConnection`, config builders, PEM, trust stores, mTLS, SNI, `RustlsAcceptor`/`RustlsConnector` implementing `hopf-core` traits | `hopf-core::tls` (Phase 4–5); crate removed Phase 8 |

**Public API surface** (all callers must move to `hopf-core::tls`):

- `tls_crypto_provider()` — also used by **`hopf-quic`**
- `acceptor_from_pem`, `acceptor`, `acceptor_with_*`, `server_config_*`
- `connector`, `connector_from_pem`, `public_trust_connector`, `insecure_connector`, `connector_with_identity`, `connector_for_certified_pem`
- `client_config_*`, `public_root_cert_store()`

Unit tests in `hopf-tls/src/lib.rs` (~30 tests): mTLS, SNI, ALPN, insecure connector — become core TLS regression suite.

### Primary: `hopf-quic` (Phase 3 transport + Phase 8 rustls removal)

| File | Use |
|------|-----|
| `config.rs` | Builds `rustls::ServerConfig` / `ClientConfig`; wraps in `quinn_proto::crypto::rustls::{QuicServerConfig, QuicClientConfig}`; calls `hopf_tls::tls_crypto_provider()` |
| `driver.rs` | `quinn_proto::crypto::rustls::HandshakeData` downcast for `SecurityInfo` |
| `config.rs` (tests) | `rcgen` self-signed certs |

### `hopf-dns`

| File | Use | Migrate |
|------|-----|---------|
| `dane.rs` | `rustls` types for DANE TLSA → custom verifier / `RootCertStore` | Phase 4 trust layer in core |
| `client/mod.rs` | `hopf_tls::public_trust_connector`, `insecure_connector` (DoT) | `hopf-core::tls` |
| `client/ddr.rs` | `hopf_tls::public_trust_connector` | core |
| `tests/resolver_stub.rs` | `hopf_tls` + `rcgen` for DoT/DoH integration | core |

### Protocol crates (via `hopf-tls` only)

| Crate | Files | Notes |
|-------|-------|-------|
| `hopf-smtp` | `integration.rs`, `server/relay/handler.rs` | acceptor, connector, insecure_connector |
| `hopf-imap` | `integration.rs` | acceptor + direct `rustls` in one SOCKS-style TLS test client |
| `hopf-pop3` | `integration.rs` | acceptor, connector |
| `hopf-ftp` | `integration.rs` | acceptor, connector, `rcgen` |
| `hopf-socks` | `integration.rs` | acceptor; direct `rustls::StreamOwned` in TLS-fronted proxy test |
| `hopf-amqp` | `integration.rs` | `connector_from_pem` (AMQPS) |
| `hopf-http` | `server/facade.rs` (doc), client negotiates TLS via configs | indirect |

### Direct `rustls` in integration tests (no `hopf-tls`)

| File | Use |
|------|-----|
| `crates/hopf-imap/src/integration.rs` | Manual `ClientConfig` + roots for test client |
| `crates/hopf-socks/src/integration.rs` | Manual `ClientConnection` + `StreamOwned` for TLS-wrapped SOCKS test |

### Examples

| Example | TLS / QUIC |
|---------|------------|
| `examples/tls-echo` | `hopf_tls::acceptor_from_pem`, `rcgen` |
| `examples/http-hello` | `hopf_tls`, `rcgen` |
| `examples/http3-hello` | `hopf-quic` + `rcgen` |
| `examples/smtp-ldap` | `hopf_tls::connector_from_pem` |
| `examples/http-get` | optional QUIC/H3 paths |

### Crates with `rustls` in `Cargo.toml` but no direct `use rustls` in lib

| Crate | Note |
|-------|------|
| `hopf-imap`, `hopf-ftp`, `hopf-pop3`, `hopf-socks` | Dev/integration only |

---

## `quinn-proto` touchpoints

All in **`hopf-quic`** (Phase 3 replaces internals; public API preserved).

| File | quinn-proto use |
|------|-----------------|
| `driver.rs` | **Main integration:** `Endpoint`, `Connection`, `Incoming`, `Event`, `ConnectionHandle`, `SendStream`, `RecvStream`, datagrams, timers, migration, Retry — largest file (~3.8k LOC) |
| `config.rs` | `TransportConfig`, `VarInt`, `ServerConfig`, `ClientConfig`, rustls QUIC crypto wrappers |
| `stream.rs` | `ConnectionHandle`, `StreamId` |
| `error.rs` | `ConnectionError`, `SendDatagramError`, `VarInt` |
| `udp.rs` | `EcnCodepoint`, `Transmit` |
| `hooks.rs` | `Connection::poll_timeout` (doc) |
| `path.rs` | `Transmit` (doc) |
| `lib.rs` | Crate docs |

### Downstream `hopf-quic` consumers (unchanged at API boundary)

| Crate / area | Use |
|--------------|-----|
| `hopf-http` (`h3`) | `listen_h3`, `connect_h3`, H3 endpoints, `set_stream_priority(quinn_priority())` in `priority.rs` |
| `hopf-dns` (`doq`) | `client/doq.rs`, `server/doq.rs` |
| `hopf-masque` | H3 client paths |
| `hopf` umbrella | `quic` feature |
| `examples/http3-hello`, `http-get` | demos |

---

## Direct `aws-lc-rs` touchpoints (Phase 1 → `hopf-core::crypto`)

**Phase 1 status:** protocol crates below now call `hopf-core::crypto` instead of `aws-lc-rs` directly. Remaining direct use is inside `hopf-core::crypto` and interim TLS/QUIC (`hopf-tls`, `hopf-quic`, `rustls`).

| Crate | File | Operations | Status |
|-------|------|------------|--------|
| `hopf-smtp` | `auth/dkim/*` | SHA-256, RSA/Ed25519 sign/verify | **Migrated** → `hopf_core::crypto` |
| `hopf-dns` | `dnssec/crypto.rs` | RSA/ECDSA/Ed25519/Ed448 verify, DS/NSEC3 hashes | **Migrated** → `hopf_core::crypto` |
| `hopf-tls` | `lib.rs` | Cert SHA-256 fingerprint | **Migrated** → `hopf_core::crypto::cert` |
| `hopf-core` | `crypto/*` | All primitive ops (facade) | **Live** |
| `hopf-dns` | `dane.rs` | rustls provider only | Interim — Phase 4+ |

### Indirect aws-lc-rs (via rustls / rcgen)

| Path | Note |
|------|------|
| `rustls` with `aws-lc-rs` feature | All TLS/QUIC handshake crypto today |
| `quinn-proto` with `rustls-aws-lc-rs` | QUIC record protection today |
| `rcgen` with `aws_lc_rs` | Test certificate generation |

---

## `hopf-core` TLS seams (frozen — implementations swap)

| Seam | Location | Interim impl | Target impl |
|------|----------|--------------|-------------|
| `TlsSession` | `hopf-core/src/tls.rs` | `hopf-tls` rustls sessions | `hopf-core::tls` `TlsEngine` pump |
| `TlsAcceptor` / `TlsConnector` | `hopf-core/src/tls.rs` | `hopf-tls` | `hopf-core::tls` |
| `SharedTlsAcceptor` / `SharedTlsConnector` | type aliases | PEM configs from `hopf-tls` | core |
| TCP TLS pump | `hopf-core/src/connection.rs` | `read_tls`, `process_new_packets`, `read_plaintext`, … | `TlsEngine::feed_*` + sink |
| Listener TLS config | `hopf-core/src/listener.rs` | `with_tls`, `with_starttls_acceptor` | same API, core acceptors |
| Connector TLS config | `hopf-core/src/connector.rs` | `with_tls(connector, server_name)` | same API, core connectors |
| `Endpoint::start_tls` | `hopf-core/src/endpoint.rs`, `connection.rs` | STARTTLS via acceptor | unchanged behaviour |
| `Endpoint::start_client_tls` | same | client connector | unchanged |
| `SecurityInfo` | `hopf-core/src/security.rs` | from rustls after handshake | from in-tree engine |
| `ProtocolHandler::security_established` | protocol crates | ALPN / mTLS gating | unchanged contract |

---

## Frozen seams (behaviour-preserving)

These **must not break** without an explicit API revision (confirmed Phase 0):

- [x] `Endpoint::start_tls` / `start_client_tls`
- [x] `SecurityInfo` / `ProtocolHandler::security_established`
- [x] `QuicListenConfig` / `QuicConnectConfig` / `QuicStreamEndpoint` as `Endpoint`
- [x] PEM / trust configuration **behaviour** (paths may move from `hopf-tls` to core)
- [x] Protocol crate TLS usage patterns (implicit TLS, STARTTLS, DoT, AMQPS)

**Evolving (documented):** `TlsSession` return-based trait → `TlsEngine` + `TlsEventSink`; crate `hopf-tls` removed.

---

## Engine design lock (Phase 0)

Names and model locked for Phase 2+ implementation. Full prose in [plan → Engine design](crypto-migration-plan.md#engine-design).

### Transport engines (reactive)

| Engine | Crate | Sink | Stimuli |
|--------|-------|------|---------|
| `TlsEngine` | `hopf-core::tls` | `TlsEventSink` | `feed_ciphertext`, `feed_timer`, `feed_verification_result`, … |
| `DtlsEngine` | `hopf-core::dtls` | `DtlsEventSink` | + datagram / epoch timers |
| QUIC transport | `hopf-quic::transport` | connection/stream sink (TBD in Phase 3 design note) | UDP packets, timers |
| QUIC crypto (RFC 9001) | `hopf-quic::crypto` | crypto sink / secret export to transport | CRYPTO frames via handshake engine |

### Sink event categories (minimum)

- Progress: `handshake_complete(SecurityInfo)`, `application_data`, `ciphertext_ready`
- Gates: `verification_requested(VerifyRequest)` → `feed_verification_result`
- Failure: `protocol_error`, `timeout`, `peer_closed` — **not** `Result` from `feed_*`
- QUIC-specific: `connection_migrated`, stream events (Phase 3 taxonomy)

### Interim adapters (until Phase 8)

| Adapter | Role |
|---------|------|
| `hopf-tls` rustls `TlsSession` | Translates rustls pump → eventual sink events for TCP |
| `hopf-quic` + quinn-proto | Entire QUIC stack interim; driver unchanged at boundary |

---

## Platform matrix (`aws-lc-sys`)

Hopf workspace pins `aws-lc-rs` with `prebuilt-nasm` (see root `Cargo.toml`). **MSRV: Rust 1.85.**

| Platform | Expected support | Notes |
|----------|------------------|-------|
| Linux x86_64 | Yes | Primary CI/dev |
| Linux aarch64 | Yes | aws-lc prebuilds |
| macOS x86_64 | Yes | Primary dev |
| macOS aarch64 (Apple Silicon) | Yes | Primary dev |
| Windows x86_64 | Yes | aws-lc prebuilds |
| FreeBSD / other | Best-effort | May need source build; document when tested |

**Operational notes:**

- `prebuilt-nasm` avoids requiring NASM on common targets; source builds need CMake + NASM.
- FIPS and non-default AWS-LC build modes are **out of scope** unless explicitly chosen later.
- Document any platform that fails `cargo test --workspace --lib` in CI as unsupported until fixed.

---

## Phase mapping (retirement checklist)

| Touchpoint group | Phase | Status |
|------------------|-------|--------|
| Inventory + engine lock + platform doc | **0** | Done |
| `hopf-core::crypto` facade; migrate DKIM/DNSSEC | **1** | Done |
| TLS 1.3 handshake engine (QUIC-first) | **2** | |
| `hopf-quic` in-tree RFC 9000; drop `quinn-proto` | **3** | |
| TCP TLS 1.3 record layer; move PEM/trust from `hopf-tls` | **4** | |
| TLS 1.2 | **5** | |
| DTLS | **6** | |
| Central PQC policy | **7** | |
| Remove `hopf-tls`, `rustls`, `quinn-proto`; full test matrix | **8** | |

---

## Maintenance

When adding or removing a touchpoint during migration:

1. Update the relevant table in this file.
2. Note the phase in the **Phase mapping** section.
3. Do not duplicate strategy text here — link to [`crypto-migration-plan.md`](crypto-migration-plan.md).
