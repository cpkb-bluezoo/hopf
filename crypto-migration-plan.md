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
**Phase 5 update, Extended Master Secret (2026-09-10):** the top P0 gap from the RFC 9846 baseline update is closed — see the [Extended Master Secret](#phase-5--tls-12) checklist entry. Mandatory (not opportunistic): both `tls12::Tls12Engine` roles now refuse the handshake if the peer doesn't offer/echo RFC 7627's extension, closing the triple-handshake-class attack path completely rather than keeping a legacy fallback alive. DTLS 1.2 picked this up for free (no DTLS-specific changes needed) since it routes through the same shared engine. Verified against the real `rustls`-as-peer TLS 1.2 interop tests and the real OpenSSL 3.6.3 DTLS 1.2 interop tests — both unaffected.
**Phase 5 update, RFC 5746 (2026-09-10):** secure renegotiation indication is complete — see the [RFC 5746 completion](#phase-5--tls-12) checklist entry. Sending was already conformant; the gap was that `renegotiation_info` was never parsed/validated on receipt. Now mandatory (present and empty, or the `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` alternate signal) on both roles. Unlike EMS this closes no live hole — renegotiation is permanently disabled in this engine — so it's spec-hygiene, not a new attack surface closed. Verified against the same real `rustls` TLS 1.2 and OpenSSL DTLS 1.2 interop suites — unaffected.
**Phase 5 update, RFC 9846 §1.4 TLS 1.2 deltas (2026-09-10):** three of four sub-items done — see the [RFC 9846 §1.4 TLS 1.2 deltas](#phase-5--tls-12) checklist entry. RSASSA-PSS signature verification, `signature_algorithms_cert` (both TLS 1.2 *and* TLS 1.3 — one shared gap, one shared fix), and mandatory-if-present `supported_versions` on the TLS 1.2 ClientHello all shipped. The fourth, the version-downgrade-protection sentinel, is explicitly **not applicable** to this codebase's architecture today (`TlsVariant` selection is static per-acceptor, never per-ClientHello, so the scenario the sentinel protects against can't occur) rather than simply undone — see the checklist entry for the full reasoning. Verified against the **full** real `rustls` interop suite (19 tests, TLS 1.2 and TLS 1.3 both) since this pass touches the shared TLS 1.3 ClientHello builder, plus real OpenSSL DTLS 1.2 interop — both unaffected. Remaining P0 items (RFC 9325 profile enforcement) are next. OCSP stapling was scoped, then rejected outright as a permanent non-goal — see [Non-goals](#non-goals): not a TLS engine concern, and baking real-world responder-availability/network-reachability failure modes into a synchronous handshake engine was judged the wrong place for that complexity. RFC 9846 §2.2's unified PSK exchange was considered and **abandoned outright, not deferred** (2026-09-10) — it has no real-world implementation anywhere (this whole "RFC 9846" baseline is this project's own fictional extrapolation), so replacing RFC 5077 with it would break TLS 1.2 resumption interop with every actual peer (rustls, browsers, curl, OpenSSL) for a mechanism only hopf-to-hopf could ever speak; keeping both mechanisms side by side was also rejected as disproportionate scope for the value. RFC 5077 stays the only TLS 1.2 resumption mechanism, indefinitely.
**Phase 2 update, `KeyUpdate` (2026-09-10):** RFC 8446 §4.6.3/§7.2's post-handshake key ratchet is done — see the [`KeyUpdate`](#phase-2--tls-13-handshake-engine-quic-first) checklist entry. Unlike the last two P0 items looked at, this is a real, currently-published TLS 1.3 feature, not part of the fictional RFC 9846 extrapolation. TCP-TLS-1.3 only (QUIC forbids it per RFC 9001 §4.6, enforced; DTLS 1.3's epoch-aware variant is a different, explicitly deferred mechanism). Found and fixed a real latent bug along the way: `feed_handshake_data` was dropping all post-handshake bytes for the server role, not just gating KeyUpdate — server-role post-handshake message handling had never been exercised before this pass. Verified with real end-to-end application-data round-trips after a key rotation (not just secret-equality assertions), which is what caught that bug plus a missing event-forwarding override; full real `rustls` interop suite reconfirmed unaffected.
**Phase 7 update, PQ (ML-DSA) certificate verification (2026-09-10):** `crypto::x509::verify_cert_signature` now accepts ML-DSA-44/65/87-signed chains — see the [PQ certificate signature verification](#phase-7--pqc-policy) checklist entry. Real, finalized NIST FIPS 204, with the OIDs/TLS codepoints read directly from this repo's own vendored `aws-lc-sys` build output rather than guessed. Verify-only, matching the checklist's own optional-sign framing; `rcgen`'s pinned version has no ML-DSA support and no way to add it externally, so Hopf-issued ML-DSA credentials (and TLS 1.3 handshake-level ML-DSA signing) stay explicitly deferred. Found and flagged (not fixed, separate task spawned) a narrow real bug in `parse_certificate`: an extensions-less TBSCertificate (legitimate but previously unexercised, since every existing test's certs come from `rcgen`, which always emits at least one extension) hard-fails the whole parse instead of being treated as "no extensions." *(2026-09-10 follow-up: this `parse_certificate` bug was subsequently fixed directly — `tbs.peek_tag()?` changed to `tbs.peek_tag() == Some(0xa3)`, with a regression test proving a cert with no extensions field at all now parses correctly.)*
**Phase 7 update, hybrid KX groups (2026-09-10):** `crypto::kx_policy::KxPolicy::pqc_first` now offers all three RFC 10024 hybrid groups, not just `X25519MLKEM768` — see the [group preference centralisation](#phase-7--pqc-policy) checklist entry. `SecP256r1MLKEM768`/`SecP384r1MLKEM1024` added to `crypto::kx`, each using RFC 10024's own (classical-first, the *opposite* of `X25519MLKEM768`'s PQ-first order) concatenation for both the wire `KeyShareEntry` and the shared-secret combiner — confirmed against the RFC text directly rather than assumed by analogy. No changes needed outside `crypto::kx`/`crypto::kx_policy`: every other call site (TLS 1.3, DTLS 1.3, QUIC) already goes through `NamedGroup` generically.
**Phase 7 update, RFC 9325 profile enforcement (2026-09-10/11):** the last-named P0 item — see the [RFC 9325 profile enforcement](#phase-7--pqc-policy) checklist entry. Four real gaps found by a full-codebase audit and closed: ALPN zero-overlap/unoffered-selection correctness (RFC 7301 §3.2), AEAD usage-limit rekey/close across all four record layers (RFC 8446 §5.5 — TLS 1.3 TCP self-rekeys via the existing `KeyUpdate`, the other three close), a ticket-encryption keyring (`TicketKeys`) supporting in-place rotation without breaking in-flight tickets, and SNI-based multi-certificate dispatch (`server_resolver`, `acceptor_from_pem_with_sni`). Most of RFC 9325 — CBC/compression/static-RSA exclusion, mandatory EMS/`renegotiation_info`, cert/signature hash floors, TLS-version reachability, 0-RTT opt-in-only — was already compliant from earlier phases, no work needed. **Found and fixed a real, independent bug while building the ticket-rotation aging-out test**: the TLS 1.3 client used its offered PSK unconditionally when deriving traffic secrets, instead of gating on whether the server actually selected it — any offered-but-rejected ticket (expired, wrong key, anything) broke the fallback-to-full-handshake path with a Finished-verification failure, previously unexercised because no test offered a real, well-formed, server-undecryptable ticket. Fixed directly (`self.psk` now gated on `self.resumed` in both places it's read client-side). Verified against the full real `rustls` interop suite (19 tests, TLS 1.2 and TLS 1.3, including real ticket resumption) and `cargo test --workspace --lib` — unaffected beyond the intended fixes. This closes every P0 item this migration plan currently tracks.

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
- **OCSP stapling (RFC 6960 / RFC 6066 §8 / RFC 8446 §4.4.2.1) inside the TLS/DTLS engines themselves** — explicitly rejected, not deferred (2026-09-10; a scoping pass and plan were done first, then this call was made — see `crypto-migration-plan.md` history / memory for what was found). Certificate status checking is not a TLS engine concern: the engines already expose the peer's certificate chain to the caller (server/client protocol handlers), who can validate it however they choose, including not at all. Baking OCSP into the handshake layer means the engine now owns real-world failure modes that have nothing to do with the TLS protocol itself — an unreachable or down OCSP responder, no network route to it, rate limiting, response staleness — and every "what should we do when that happens" question it raises. Handling those properly would mean building fallback/retry/timeout policy into a synchronous, no-I/O-of-its-own handshake engine that has no business doing any of that; handling them poorly would make the engine fragile in ways unrelated to TLS correctness. This stays a caller-level concern, not Hopf's.

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

**Gaps this opens against what's shipped today** — tracked as new checklist items in [Phase 5](#phase-5--tls-12), since they're all TLS-1.2-side: extended_master_secret/RFC 7627 was **never implemented** in `tls12/engine.rs` (grepped — no hits), nor is there a downgrade-protection sentinel, `supported_versions`, or `signature_algorithms_cert` anywhere in the TLS 1.2 engine. `signature_algorithms_cert` is also absent from the **TLS 1.3** engine (only `signature_algorithms` (0x000d) exists, not 0x0032) — worth a look even though 9846 §9.2's TLS 1.3 mandatory-extension list hasn't been independently re-verified against what's shipped. RFC 5077 ticket resumption (Phase 5, already shipped) still works and interops with `rustls`-as-peer today; migrating it to §2.2's unified PSK exchange was considered and **abandoned outright** (2026-09-10, not deferred) — no real peer implements it, so replacing RFC 5077 would break real-world TLS 1.2 resumption interop for a mechanism only hopf-to-hopf could speak. RFC 5077 remains the permanent TLS 1.2 resumption mechanism.

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
- [x] **`KeyUpdate`** (RFC 8446 §4.6.3/§7.2) **(2026-09-10)** — new post-handshake message type 24, `application_traffic_secret_N → N+1` ratchet via the existing `HKDF-Expand-Label(..., "traffic upd", "", Hash.length)`. **Scope: TCP-TLS-1.3 only** — RFC 9001 §4.6 forbids it entirely over QUIC (QUIC has its own separate packet-level key-phase-bit mechanism, confirmed unimplemented in `hopf-quic` today, so this is enforced, not theoretical) and DTLS 1.3's epoch-aware variant (RFC 9147 §5.8 — old and new keys can both be briefly valid since UDP packets can arrive out of order across the update boundary) is a meaningfully different, unimplemented mechanism, explicitly deferred rather than mishandled. `HandshakeEngine` gained its first-ever *caller-initiated* action at that layer (`request_key_update`, alongside the pre-existing reactive-only API), and `TlsRecordEngine` (the TCP wrapper, which already had caller-initiated `send_application_data`/`send_close_notify`) gained a matching passthrough — the natural, already-established layer for this. A real bug was found and fixed along the way: `feed_handshake_data` dropped all post-handshake bytes for the **server** role unconditionally (only the client path stayed live, for receiving `NewSessionTicket`) — fixed for both roles, since `KeyUpdate` is bidirectional. Application traffic secrets, previously discarded (`.take()`n and dropped) once handed to the record layer at `finish()`, are now retained per-direction (`own_app_secret`/`peer_app_secret`) so a later `KeyUpdate` has something to ratchet forward. **Tests:** message-level round-trip (both `KeyUpdateRequest` values) plus a malformed-body-length rejection; two real end-to-end tests at the `TlsRecordEngine` level proving actual application data — not just a raw secret-equality assertion — round-trips correctly *after* a key rotation in both the one-sided and mutual-reciprocal (`update_requested`) cases (this is what caught the `feed_handshake_data` server bug and a missing `EngineCodecBridge` event-forwarding override, both real bugs, not just structural gaps); QUIC-mode rejection (both the receive path and `request_key_update` itself); malformed `KeyUpdateRequest` byte rejection. Full real `rustls`-as-peer interop suite (19 tests, TLS 1.2 and TLS 1.3) reconfirmed green — unaffected, since `rustls` never triggers a `KeyUpdate` in these tests' short-lived connections; no rustls-side `KeyUpdate` interop test was added (out of scope for this pass — no immediate driving need, `rustls`'s public surface for triggering/observing one from an external test wasn't explored).

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
- [x] **RFC 9846 §1.4 TLS 1.2 deltas** — three of four done **(2026-09-10)**; the fourth is explicitly not applicable to this codebase's architecture, not merely undone:
  - [x] **RSASSA-PSS signature schemes for TLS 1.2 (§4.3.3)** — `crypto/signature.rs`'s existing `rsa_sign_pss_sha256`/`rsa_pss_sha256_verify_spki` (already used by the TLS 1.3 engine) reused as-is; `tls12/messages.rs`'s `sig_alg` module gained an opaque `(0x08, 0x04)` pair (TLS 1.3's `rsa_pss_rsae_sha256` `SignatureScheme`, split across this module's `(u8, u8)` shape but *not* a real hash+sig combination like every other entry — flagged as such in the doc comment). Added to the now-de-duplicated `OFFERED_SIGNATURE_ALGORITHMS` list (previously hardcoded separately in both `build_client_hello` and `build_certificate_request`); `verify_ske_signature` gained one match arm covering all four directions that share it (client verifying ServerKeyExchange, server verifying client CertificateVerify — verification already dispatched generically on the wire-declared pair). **Scoped deliberately to verification only** — `sign_ske` (this engine's own signing) still always produces PKCS1v1.5 for RSA keys; RFC 9846 §4.3.3 newly *permits* PSS, it doesn't deprecate PKCS1v1.5, and switching our own output would need the peer's offered `signature_algorithms` threaded into the signing call sites for no interop benefit today. Preferring PSS for our own signatures is optional future work, not this gap.
  - [x] **`signature_algorithms_cert` (§1.4, RFC 8446 §4.2.3 — extension `0x0032`)** — this also closes the same gap that was previously tracked as its own standalone checklist row (removed here), since it was one underlying gap affecting both engines, not two. New `crypto::x509::ACCEPTED_CERT_SIGNATURE_SCHEMES` is the single source of truth (Ed25519, ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, rsa_pkcs1_sha256/384/512 — same order as, and doc-comment-linked to, `verify_cert_signature`'s `if oid == ...` chain, which was *already* self-enforcing to exactly this set with no allowlist parameter at all). Sent unconditionally in both `tls12::messages::build_client_hello` and `handshake::messages::build_client_hello_inner` (the latter meaning DTLS 1.3/QUIC ClientHellos pick it up for free through the shared builder, same reuse pattern as every other unconditional TLS 1.3 ClientHello extension). **Deliberately not parsed on receipt** by either engine, and not added to `CertificateRequest`: no code path in this codebase selects between multiple certificates/algorithms per connection (one configured cert chain per acceptor, one configured mTLS client credential), so a peer's advertised list has no consumer — storing it would be the same kind of dead state the EMS pass avoided by not adding a `used_ems` ticket field. No RSA-PSS *certificate* signatures in the accepted list either — that's `id-RSASSA-PSS`'s parameterized `AlgorithmIdentifier`, which `verify_cert_signature` doesn't parse; out of scope (this item is "advertise accurately," not "accept more").
  - [x] **Mandatory `supported_versions` on the TLS 1.2 `ClientHello` (§1.4)** — `tls12/messages.rs` gained the same extension type (`43`) TLS 1.3 already uses, sent as `[0x02, legacy_version_hi, legacy_version_lo]` (reusing `params.legacy_version` means DTLS 1.2 gets `{0xfefd}` for free, TCP gets `{0x0303}`, no separate branch). Policy is **content-mandatory-if-present, presence-optional** — deliberately a third, distinct shape from EMS/5746's full-mandatory: this extension's traditional purpose is signalling *upward* TLS 1.3 capability, and a client that has already committed to TLS-1.2-only has no established-practice (pre-9846) reason to send it, unlike `renegotiation_info`/EMS which are settled TLS-1.2-native extensions since 2008–2010 — requiring presence risked real interop breakage for a niche new mandate. If sent, it must include this engine's own version or the handshake is refused.
  - [ ] **Version-downgrade-protection sentinel (§4.2.3) — not applicable to this codebase's architecture, not merely undone.** `TlsVariant` (`tls/mod.rs`) is chosen once, per-acceptor, at deployment time (`acceptor_from_pem` always returns `V13`, `acceptor_from_pem_tls12` always returns `V12`) — no code path anywhere inspects a ClientHello to decide between the two engines. RFC 8446 §4.1.3's sentinel exists to let a TLS-1.3-capable client detect an on-path attacker forcing a TLS-1.3-capable *server* down to 1.2 *within a single negotiated handshake* — a scenario that structurally cannot occur here, since no server ever has both options open for the same connection attempt. It would become meaningful only if a future ClientHello-sniffing version dispatcher were added ahead of `TlsVariant` selection — tracked here as that structural precondition, not as a `tls12/engine.rs` code gap (same treatment as DTLS 1.3's real-interop gap being blocked on peer availability rather than code).
  - **Tests:** two new message-round-trip tests (PSS pair offered; `signature_algorithms_cert`/`supported_versions` present with correct content, including the DTLS `0xfefd` case) plus one for the TLS 1.3 side; a direct unit test on `verify_ske_signature` accepting a real PSS-signed message; four new engine-level negative/positive tests (`supported_versions` wrong-content refused, absent tolerated; existing SCSV-style pattern reused). Full `tls12`/`tls` (TLS 1.3)/`dtls`/`dtls12` suites green; the **full** real `rustls` interop suite in `hopf-tls` (19 tests — TLS 1.2 and TLS 1.3, both directions, mTLS/ChaCha20 variants, public WebPKI) reran since this pass touches the shared TLS 1.3 ClientHello builder, not just TLS 1.2's; real OpenSSL 3.6.3 DTLS 1.2 interop reran too — all unaffected.
- [x] **Extended Master Secret** (RFC 9846 Appendix D, née RFC 7627, renamed `extended_master_secret` → `extended_main_secret` in 9846's prose only — the IANA extension codepoint, `0x0017`, is unchanged) — implemented in `tls12/messages.rs`/`engine.rs` **(2026-09-10)**, closing the P0 checklist gap cleanly (no partial/deferred residue). Policy: **mandatory, not opportunistic** — both roles refuse the handshake outright (`fail`/`protocol_error`) if the peer doesn't offer/echo the extension, matching this codebase's existing strict posture (no CBC ciphers ever, AEAD-only, mandatory chain verification) rather than keeping a downgrade-capable legacy master-secret path alive. `derive_master_secret` branches on the negotiated flag: EMS uses `session_hash` (`Transcript::hash`, already built for `Finished.verify_data`) under the `"extended master secret"` label; the pre-existing `client_random || server_random` seed under `"master secret"` is now dead in practice (both `on_client_hello`/`on_server_hello` refuse before it could be reached) but kept as a real branch on the negotiated value rather than hardcoded, so a caller bug can't silently produce a wrong secret. One real ordering bug found and fixed while implementing: RFC 7627 §3's `session_hash` must cover the transcript through and including `ClientKeyExchange` (but excluding `CertificateVerify`, sent after CKE in the same flight) — the server side already called `derive_master_secret` after hashing CKE, but the client side (`on_server_hello_done`) called it *before* CKE was even built; moved to immediately after `self.emit(&cke, sink)`. No ticket/resumption bookkeeping needed: under the mandatory policy every ticket this server ever mints was already EMS-derived (the handshake fails before one could exist otherwise), so RFC 7627 §5.2/§5.3's session-compatibility rules collapse into the same blanket ClientHello check. Verified via the full `tls12`/`dtls12` test suite (zero regressions, two new mandatory-refusal negative tests), the real `rustls`-as-peer TLS 1.2 interop tests in `hopf-tls` (7 tests, unaffected), and the real OpenSSL 3.6.3 DTLS 1.2 interop tests (both directions, unaffected — DTLS 1.2 needed zero DTLS-specific changes since it hands `Tls12Engine` only `ClientHello2` onward and this lives entirely inside the shared engine/messages code).
- [x] **RFC 5746 completion (secure renegotiation indication)** — implemented in `tls12/messages.rs`/`engine.rs` **(2026-09-10)**. Sending was already conformant (both roles unconditionally push an empty `renegotiation_info`); the actual gap was that neither `parse_client_hello` nor `parse_server_hello` looked at it at all — silently dropped in the `_ => {}` extension-parsing arm, so a peer's value (or its absence) was never checked. Policy: **mandatory presence, not opportunistic** (same posture as EMS), plus the RFC's unconditional MUST that a *present* extension's content be exactly empty (`[0x00]`) on an initial handshake — a non-empty value has no prior handshake to reference and is definitionally wrong. Unlike EMS, this closes no live hole: renegotiation itself is permanently disabled in this engine (see the module doc comment), so RFC 5746's actual attack (MITM prefix injection across a renegotiation) can't occur regardless — this is spec-hygiene/defense-in-depth. The server also recognises `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (`0x00FF`) as RFC 5746 §3.3's alternate legacy signal for a peer that can't send extensions, though this engine's own client never needs it (the extension already covers its own initial handshake). Verified via four new tests (server: rejects non-empty extension, rejects missing extension+SCSV, accepts SCSV-only signalling; client: rejects non-empty extension) plus the full `tls12`/`dtls12` suite, the real `rustls`-as-peer TLS 1.2 interop tests (7 tests), and the real OpenSSL 3.6.3 DTLS 1.2 interop tests — all unaffected, as expected (both peers already send RFC 5746 correctly).
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

- [x] **Centralise group preference (hybrid ML-KEM first)** (2026-09-10) — `crypto::kx_policy::KxPolicy::pqc_first` (the `Default`) now offers all three [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) hybrid groups in one ordered list — `X25519MLKEM768` preferred, `SecP256r1MLKEM768`/`SecP384r1MLKEM1024` as classical-curve alternatives, classical `X25519` as a pure-classical fallback — reused as-is by TLS 1.3, DTLS 1.3 (wraps the same `HandshakeEngine`), and QUIC (drives the same TLS 1.3 handshake), so no per-transport changes were needed; confirmed by grepping every `NamedGroup::` use site outside `crypto::kx` itself, none of which match exhaustively on the enum or hardcode group-specific byte lengths. **The critical correctness detail** (confirmed against [RFC 9954](https://datatracker.ietf.org/doc/rfc9954/)/[10024](https://www.rfc-editor.org/rfc/rfc10024.html) directly, not assumed by analogy with the already-shipped `X25519MLKEM768`): the three groups do **not** share one concatenation order. `X25519MLKEM768` is PQ-first (ML-KEM share, then classical share — RFC 10024 calls this a deliberate, documented exception "for historical reasons"); `SecP256r1MLKEM768`/`SecP384r1MLKEM1024` are classical-first, matching their names. Both the wire `KeyShareEntry` concatenation and the shared-secret combiner use the same per-group order. `SecP384r1MLKEM1024` also pairs P-384 (not P-256) with ML-KEM-**1024** (not 768) — a different curve *and* a different ML-KEM parameter set, both already present in the pinned `aws-lc-rs` 1.18 (`agreement::ECDH_P384`, `kem::ML_KEM_1024`). Wire codepoints (`0x11eb`/`0x11ed`) confirmed against this repo's own vendored `aws-lc-sys` `ssl.h` (same technique as the ML-DSA cert work), not guessed. `crypto::kx::HybridKeyPair` generalized from X25519-only to all three groups via a small `ClassicalKeyPair` enum (X25519/P256/P384) plus a per-group `pq_first()` flag threaded through `client_share()`/`agree_client()`/`server_agree_hybrid()`/the secret combiner.
- [x] Replaces rustls `prefer-post-quantum` knob (already true since `X25519MLKEM768` shipped; the two new groups extend the same policy object, no separate replacement needed).
- [x] **Tests:** new unit-level roundtrip + wire-layout tests per group in `crypto::kx` (proving the classical-vs-PQ-first split lands correctly, not just that secrets happen to match) and `crypto::kx_policy` (`select_mutual` reaches each new group when it's the only one a peer offers). No new *handshake-level* per-transport (TCP/QUIC/DTLS) integration tests were added — the full `cargo test --workspace --lib` run (zero regressions) covers this instead, since TLS 1.3/DTLS 1.3/QUIC all route through the same generic `NamedGroup`/`LocalKeyShare`/`server_agree` API with no transport-specific group logic to separately exercise.
- [x] **PQ (ML-DSA) certificate signature verification** (NIST FIPS 204, 2026-09-10) — `crypto::x509::verify_cert_signature` now accepts a peer chain (CA/intermediate/leaf) signed with ML-DSA-44/65/87, alongside the existing Ed25519/ECDSA/RSA algorithms. Unlike RFC 9846, ML-DSA is real and finalized; the OIDs and TLS `SignatureScheme` codepoints used here (`id-ml-dsa-44/65/87` = `2.16.840.1.101.3.4.3.17/18/19`; `SSL_SIGN_MLDSA44/65/87` = `0x0904/0x0905/0x0906`) were read directly out of this repo's own vendored `aws-lc-sys` build output (`target/debug/build/aws-lc-sys-*/out/include/openssl/{nid.h,ssl.h}`) rather than guessed or drawn from an unfinalized draft — guaranteed to match what the pinned `aws-lc-rs`/`aws-lc-sys` actually ships. `aws-lc-rs` 1.18's ML-DSA support is fully stabilized (not behind an `unstable` feature) and implements the same generic `VerificationAlgorithm`/`UnparsedPublicKey` trait ECDSA/RSA already use, so this needed no new verification machinery — three more OID constants, three more `if oid == ...` match arms, three more `ACCEPTED_CERT_SIGNATURE_SCHEMES` entries. **Verify only, no signing support** — `rcgen` (this crate's only cert-building tool, pinned at 0.13.2) has no ML-DSA support and no way to plug one in (unlike RSA, where `RemoteKeyPair` let a custom signer target an *existing* rcgen algorithm constant — `SignatureAlgorithm`'s fields are all private, so a wholly new algorithm can't be added from outside); real handshake-level use of an ML-DSA key would also need `handshake/verify.rs`'s `SUPPORTED_SIGNATURE_SCHEMES`/`pkcs8_key_kind`/`sign_certificate_verify` (TLS 1.3's own CertificateVerify signing path) — a distinct, separate-scope addition, deliberately deferred (per the checklist's own "(and optional sign)" framing). **Tests:** no existing tool in this workspace can generate an ML-DSA certificate, so a small hand-built DER fixture (`aws_lc_rs::signature::PqdsaKeyPair` for the key + raw DER TLV assembly for the certificate framing, matching the level of hand-built ASN.1 already used elsewhere in this crate's own tests) proves a real self-signed ML-DSA-44 certificate round-trips through `parse_certificate`/`verify_cert_signature` correctly, plus a tamper-rejection test. Found and separately flagged (not fixed inline, out of this pass's scope) a real, narrow `parse_certificate` bug while building the fixture: `tbs.peek_tag()?` incorrectly hard-fails the entire parse for a certificate with no trailing bytes after `subjectPublicKeyInfo` (i.e. no extensions field at all — a legitimate, if legacy, X.509 shape) instead of treating "no more TBS bytes" as "no extensions present"; every existing test happens to go through `rcgen`, which always emits at least one extension, so this path had never been exercised before. Verified against `cargo test --workspace --lib` (zero regressions) and the real `rustls` interop suite (unaffected — `rustls` has no ML-DSA cert to present either way, so this pass isn't exercisable via that suite; one unrelated, pre-existing flaky test in that suite — `public_trust_connector_validates_a_real_public_certificate`, a live connection to `cloudflare.com` — was independently confirmed to fail identically on the clean, fully-committed tree with none of this pass's changes present, via `git stash`). *(2026-09-10 follow-up: the flagged `parse_certificate` bug was subsequently fixed directly, in the separate spawned session it was flagged to — `tbs.peek_tag()?` changed to `tbs.peek_tag() == Some(0xa3)`, with a regression test proving a cert with no extensions field at all now parses correctly.)*
- [x] **RFC 9325 profile enforcement** (2026-09-10/11) — a two-pass codebase audit against RFC 9325 ("Recommendations for Secure Use of TLS and DTLS") found most of it already compliant by construction from earlier phases (no CBC, no compression, no static-RSA/DH key exchange, mandatory EMS/`renegotiation_info`, AEAD-only suites, TLS-version reachability, cert/signature hash floors, 0-RTT opt-in-only — no work needed). Four real gaps were found and closed:
  - **ALPN correctness** (RFC 7301 §3.2) — TLS 1.3 server now refuses the handshake (`tls::engine.rs`'s `fail()`) when it has protocols configured and the client's offer has zero overlap, instead of silently completing with no negotiated protocol; client now refuses a server-selected ALPN protocol it never offered (a defensive check only reachable against a non-conformant peer — this engine's own server can never trigger it). **Scope note**: reuses the existing local `fail()` mechanism rather than adding a wire-level TLS alert-code capability (this engine has none today — even fatal failures never send an `Alert` record, only `close_notify` does) or TLS 1.2 ALPN support (not implemented at all here) — both deliberately out of scope, see the reasoning preserved in this session's plan file. **Tests:** new `tls::engine` cases for both directions.
  - **AEAD usage-limit rekey/close** (RFC 8446 §5.5 / RFC 9325 §4.4) — all four record layers (TLS 1.3 TCP, TLS 1.2, DTLS 1.3, DTLS 1.2) now act as a direction's AES-GCM key approaches the 2^24.5-record confidentiality limit, instead of letting the `u64` sequence counter wrap unchecked. TLS 1.3 TCP self-triggers its existing `KeyUpdate` (write side) or requests the peer reciprocate (read side, guarded against re-requesting every subsequent record while waiting); the other three have no in-protocol rekey, so they close the connection instead — consistent with this project's existing "no legacy fallback outweighs a real safety bound" posture (same reasoning as the CBC exclusion). ChaCha20-Poly1305 isn't checked — RFC 8446 §5.5 notes its sequence number would wrap before its own safety bound is reached. QUIC is out of scope (still on `quinn-proto`, which enforces its own limits). **Tests:** one roundtrip test per record layer per direction (8 total), directly manipulating the sequence counter to the boundary rather than sending millions of real records.
  - **Ticket-encryption key rotation** (RFC 9325 §3.4) — new `tls::ticket_keys::TicketKeys` keyring (shared by TLS 1.3 and TLS 1.2's ticket code, both using the same raw `[u8; 32]`/AES-128-GCM shape with no key ID in the ciphertext): `current` key for sealing, plus the single most-recently-rotated-away key still accepted for decryption, so `rotate()` doesn't instantly break tickets already in flight. `HandshakeConfig.ticket_key`/`tls12::Config.ticket_key` changed from `Option<[u8; 32]>` to `Option<TicketKeys>` (`TicketKeys::single(key)` is a drop-in replacement for every existing caller). Rotation *cadence* stays the caller's job, same as the OCSP-stapling precedent — there's no timer-tick entry point in the TCP/QUIC TLS engines to drive it autonomously (`feed_timer` exists only on the DTLS engines, for retransmission), so this ships the *mechanism*, not a scheduler. **A real, separate bug was found and fixed while writing the aging-out test**, not just the intended `TicketKeys` gap: the TLS 1.3 client unconditionally used `self.psk` (which reflects "a ticket was offered," not "the server accepted it") when deriving handshake/application traffic secrets and the resumption master secret, instead of gating on `self.resumed` — any time a client's offered PSK was rejected by the server (expired ticket, wrong/rotated key, anything), the client's own key schedule diverged from the server's correctly-`psk: None` derivation, and the fallback-to-full-handshake path that's supposed to always work would instead fail Finished verification. This is a real, previously-unexercised bug independent of ticket rotation — no prior test offered a real, well-formed PSK ticket that the server then couldn't decrypt at all. Fixed in `tls::engine.rs`'s `on_server_hello`/`on_client_finished` (client role): `self.psk` is now only read when `self.resumed` is true. **Tests:** `TicketKeys`-level unit tests (single-key, rotate-keeps-exactly-one-previous); engine-level tests proving a ticket survives one rotation and correctly falls back to a full handshake after two (which is what surfaced the `self.psk` bug); TLS 1.2's independent rotation test (already existing, extended with the same real-rotation positive case). Verified against the full real `rustls` interop suite (19 tests, including TLS 1.2 ticket resumption) and `cargo test --workspace --lib` — both unaffected beyond the intended fix.
  - **SNI-based multi-certificate dispatch** — new `HandshakeConfig.server_resolver: Option<ServerCredentialsResolver>` (same wrapped-closure shape as the existing `VerifyOverride`), consulted with the client's SNI ahead of the single fixed `HandshakeConfig.server` when set (`None` behavior is byte-for-byte unchanged for every existing caller). New convenience acceptor, `pem::acceptor_from_pem_with_sni` (default cert/key plus a hostname-keyed map, unmatched/absent SNI falls back to the default) — closes the gap `hopf-tls/src/lib.rs`'s own module doc flagged as deferred (that comment also incorrectly still called mTLS unimplemented; both corrected). Not itself an RFC 9325 *requirement* (RFC 6066 §3 makes hard-failing on SNI mismatch optional) but the functional prerequisite for using RFC 9325's SNI guidance in a real multi-tenant deployment. **Tests:** `tls::engine` loopback tests proving the resolver is consulted with the real SNI (including the no-SNI-sent case, correctly passing `None` rather than being skipped) and takes priority over `server`; a shallow `pem`-level wiring test matching this module's existing acceptor test depth.



### Phase 8 — Remove interim crates and dependencies

**Decision (2026-09-11): keep the `hopf-tls` crate, don't delete it** —
narrow it instead. `rustls` already only ever appears in
`crates/hopf-tls/Cargo.toml`'s `[dev-dependencies]` today (confirmed:
its `[dependencies]` is just `hopf-core`; the crate's own doc comment
already calls itself "a thin re-export shim... kept only for API
compatibility"), and `hopf-tls`'s real-`rustls`-interop suite
(`crates/hopf-tls/src/lib.rs::integration_tests`, 19 tests) is this
workspace's *only* independent-implementation cross-check for TCP TLS
1.3/1.2 — deleting the crate would have silently regressed this
project's own "real interop, not just self-consistency" standard from
every prior phase, trading it for pure Hopf-to-Hopf loopback coverage
with nothing to catch a mismatch against a real peer. Keeping `rustls`
scoped to exactly one crate's dev-dependencies, purely as a test peer,
resolves that without reintroducing it as a production dependency
anywhere.

- [x] **Narrow `hopf-tls` to a test-only interop harness, not a library** (2026-09-11). Confirmed via `grep` and migrated every production dependent: `hopf-dns` (real DoT/DoH connector call sites — also required rewriting `client/tcp.rs`'s DoT TLS driver, which had been silently broken since an earlier phase removed the `TlsSession`/`TlsProgress` API it still referenced; see below), `hopf-smtp` (real opportunistic-STARTTLS fallback in `server/relay/handler.rs`, plus its own gated `integration.rs`), `hopf-amqp`/`hopf-ftp`/`hopf-imap`/`hopf-pop3` (test-only `integration.rs` usage), `hopf-socks` (test-only, plus its own `rustls`-based SOCKS-over-TLS interop test rewritten against a small local blocking `hopf_core::TlsVariant` driver instead — that test's actual point is proving `SocksService::with_tls` wiring, not independent-implementation interop, which stays `hopf-tls`'s job alone), `hopf-ldap`/`hopf-mqtt`/`hopf-http` (fully unused dependencies, just removed), and the umbrella `hopf` crate (`hopf::tls` re-export repointed at `hopf_core::tls`). Also found and removed a second, separate stray `rustls` production dependency this checklist item didn't originally anticipate: `hopf-dns`'s own `dane.rs` had a dead `rustls`-based `ServerCertVerifier` (superseded by the already-`rustls`-free `verify_dane_chain`, which is what's actually used in production) — deleted, with its test coverage preserved by rewriting the tests against `verify_dane_chain` directly. `hopf-smtp` also had a second, wholly unused `rustls` dependency (in both `[dependencies]` and `[dev-dependencies]`) with zero real call sites — removed. `rustls` now appears in exactly one place in this workspace: `hopf-tls`'s own `[dev-dependencies]`.
  - **A real, independent bug was found and fixed while rewriting `hopf-dns`'s DoT driver**: the new driver's `TlsRecordSink::verification_requested` handler initially treated that callback as an error, but it's purely informational — `HandshakeEngine`/`Tls12Engine` call it unconditionally *and then* resolve verification inline, synchronously, in the same call whenever `trust_store`/`verify_override` is configured (which every DoT connector is). The same mistake was made and caught in `hopf-socks`'s new test driver too, before either was exercised against a real handshake — fixed in both by making the handler a no-op.
  - **Two real, pre-existing bugs found but out of scope, flagged separately, not fixed inline**: (1) `hopf-dns`'s DoH client (`client/doh.rs`) sends its HTTP request from `ProtocolHandler::connected()` (fires on raw TCP connect) instead of `security_established()` (fires once the TLS handshake actually completes) — breaks every real DoH round trip; (2) 7 of `tests/resolver_stub.rs`'s plain UDP/TCP DNS-forwarding-logic tests fail, unrelated to TLS. Both were only discoverable now because this integration test binary (which needs `dot`+`doh`+`dane`+`integration`+`server` features together) hadn't compiled successfully — and therefore never run — since the `TlsSession`/`TlsProgress` removal above, until this pass's `client/tcp.rs` rewrite fixed that compilation. **(1) fixed (2026-09-11, separate follow-up session)**: `connected()` is now a no-op with an explanatory comment (matching `hopf-http`'s own client, which has the identical "always-TLS, defer to `security_established`" shape); the request-building/`endpoint.send` logic moved to `security_established`. Both previously-failing reproducer tests (`doh_get_and_post_round_trip_over_a_real_tls_http_stub`, `resolver_queries_a_real_doh_server_end_to_end`) now pass; the `resolver_stub` suite is down to exactly the 7 pre-existing, unrelated failures in (2), confirmed via a full re-run. **(2) also fixed (2026-09-11, same follow-up session)** — root-caused, not just patched: all 7 shared one cause, confirmed by adding temporary `eprintln!` tracing and reading it back. `ddr.rs`'s RFC 9462 DDR discovery (`maybe_trigger_discovery`) fires one extra `_dns.resolver.arpa` SVCB probe on the first real query dispatched to *any* `auto`-mode server — "safe to call on every real query dispatch" per its own doc comment, genuinely by design, confirmed still working as intended. Every failing test's local UDP stub was built to handle exactly one hand-choreographed exchange (a single non-looping `recv_from`, or a loop that unconditionally counted/answered every packet) — the SVCB probe, sent to the wire before the real query in every case, either consumed a single-shot stub's one reply (starving the real query) or inflated a request/hit counter the test asserted an exact value for. This was a test bug, not a product bug: DDR's own design intent (harmless when a probe goes unanswered, no interference with the real query against any real server) was never in question, so the fix is entirely in `resolver_stub.rs` — a new `is_ddr_probe(&DnsMessage) -> bool` helper (checks for a `Svcb`-qtype question) that each affected stub now checks first, skipping (never answering, never counting) the probe before handling the real query it was built around. `resolve_a_against_local_stub`, `query_batch_merges_additional_types_in_one_exchange_when_server_supports_it`, `forwarder_retries_truncated_upstream_answer_over_tcp`, `spoofed_source_address_is_rejected_but_real_reply_still_accepted`, and `mismatched_question_is_rejected_but_real_reply_still_accepted` also gained an explicit `return` after answering the real query (they'd been converted from single-shot to `loop`, and would otherwise sit blocked on a 2-second read timeout before exiting — harmless to test correctness, just untidy). **Verified**: the full `resolver_stub` suite is 20/20 across three consecutive single-threaded runs and two parallel runs (no flakiness); `cargo test -p hopf-dns --all-features --lib` 141/141 unchanged; `cargo build --workspace --tests` zero warnings.
- [x] Update `scripts/publish-crates.sh` and docs to reflect `hopf-tls`'s narrowed role (2026-09-11) — `scripts/publish-crates.sh` needed no change (it still validly publishes `hopf-tls` as a normal crate; nothing there assumed removal). `hopf-tls`'s own module doc and package description rewritten to describe its permanent interop-harness role, not "kept until Phase 8 removes it."
- [x] Drop `quinn-proto` from the workspace (2026-09-11) — confirmed via `cargo tree --workspace` that it (and the `tinyvec` pin that existed only to work around one of its transitive dependencies) already appeared nowhere in the resolved dependency graph; removed the vestigial `[workspace.dependencies]` entries.
- [x] Keep `aws-lc-sys` (or direct FFI) as **the** native crypto dependency for every *production* code path (2026-09-11) — true once the above landed; confirmed only `hopf-core`/`hopf-quic` depend on `aws-lc-rs`, and `rustls` is confined to `hopf-tls`'s dev-dependency closure alone.
- [x] Update conformance audit rows (2026-09-11) — the TLS section (`docs/conformance.html`) was fully rewritten against the real in-tree `hopf-core::tls` architecture (it had still been describing the pre-Phase-4 `rustls`-wrapper API in exhaustive, now-nonexistent-file line citations). The QUIC section's intro paragraph was corrected (`quinn-proto` confirmed absent from `cargo tree`, not a wrapper), but its detailed RFC 9000/9001/9002 row-level citations are *still* stale (same pre-migration-era problem) and need a real audit against `hopf-quic`'s current internals — flagged as a separate follow-up task rather than guessed at. The top-of-doc "Implemented today"/"Planned" summary tables were also rewritten to reflect the migration's actual near-complete state.
- [x] **Tests:** full workspace unit + integration matrix passes (2026-09-11) — `cargo build --workspace`/`--all-features --tests` zero warnings; `cargo test --workspace --lib` and every touched crate's `--features integration` suite green (`hopf-tls`'s 19 `rustls` interop tests included) beyond the two flagged, out-of-scope, pre-existing `hopf-dns` bugs above. `hopf-amqp --features integration` shows 25/71 failures, all panicking at the same `integration.rs:191` polling helper with `amqp error: Invalid argument (os error 22)` — confirmed pre-existing and unrelated to this phase's dependency migration via `git stash` isolation: `basic_get_then_empty` fails identically (same OS error) against the clean, pre-Phase-8 committed tree. Matches this plan's own Phase 4 note that `hopf-amqp` integration tests were already known to fail on a socket-level OS error, unrelated to TLS.

- [x] **Type-safety pass: replace same-shaped byte-array parameters with named newtypes** (2026-09-11, first increment — internal `hopf-core` groups). Scoped via a full codebase audit of `crypto::*`/`tls::*`/`dtls*::*` — see the audit's own findings below rather than re-deriving them. The concrete failure mode: many functions take two or more `&[u8]`/`[u8; N]`/`Bytes` parameters that are semantically distinct (a session ID vs. a key; a PSK vs. a transcript hash; a ticket-encryption key vs. a resumption master secret) but statically identical, so a caller can transpose them and the compiler stays silent — exactly the `SessionId`/`PublicKey`-style confusion this item is meant to close, following this codebase's own existing (if underused) precedent: `crypto::signature::Ed25519PublicKey([u8; 32])` and `crypto::digest::Digest(Bytes)` already wrap raw bytes in a named tuple struct with `from_bytes`/named-accessor methods — new types matched that idiom rather than inventing a new one.
  - **Shipped this pass**: `handshake::key_schedule::{TranscriptHash, PskSecret, ResumptionMasterSecret, TrafficSecret}` — replacing every bare `&[u8; 32]`/`Option<&[u8; 32]>` in `compute_psk_binder`, `derive_early_traffic`, `derive_handshake_traffic_with_psk`, `derive_application_traffic_with_psk`, `derive_resumption_master_secret`, `derive_resumption_psk`, `compute_finished_verify_data`, and `HandshakeTrafficSecrets`/`ApplicationTrafficSecrets`/`EarlyTrafficSecrets`'s `client`/`server` fields; `Transcript::hash()`/`::retry()` (`tls/handshake/transcript.rs`) and `certificate_verify_message`/`sign_certificate_verify`/`verify_certificate_verify` (`tls/handshake/verify.rs`) now take/return `TranscriptHash` too, since they're the same concept flowing through the same engine. `tls::ticket_keys::TicketKey` — `TicketKeys` now stores this instead of bare `[u8; 32]` internally (`single()`/`rotate()` still take a raw array at their existing public-constructor boundary, unaffected); `handshake::ticket::{seal_ticket, open_ticket, mint_new_session_ticket}` and `tls12::ticket::{seal_ticket, open_ticket, mint_new_session_ticket}` take `&TicketKey` instead of `&[u8; 32]`, closing the exact ticket-key/resumption-master swap risk called out below. `crypto::kx::combine_hybrid_secret`'s `pq`/`classical` params are now `PqSharedSecret`/`ClassicalSharedSecret` (private, single-file wrapper — the function itself is private with only two in-file call sites, so this is a narrow, low-risk documentation-grade fix). `crypto::trust::add_component_anchor`'s `subject_der`/`spki_der` params (and `ComponentAnchor`'s matching fields) are now `SubjectDer`/`SpkiDer` — distinct, `hopf-core`-internal types, *not* to be confused with the separate `SpkiDer` mooted below for the cross-crate `crypto::signature` verify family, which remains unstarted.
  - **Scope correction found while implementing**: the plan's own assumption that `DirectionalSecrets`-style threading into `TlsEventSink`/`QuicSecrets` was "contained to `hopf-core`'s own TLS/DTLS engines with shallow call graph" was wrong — `TlsEventSink::quic_handshake_keys_ready`/`quic_early_keys_ready`/`application_traffic_key_updated`/`application_traffic_keys_ready` and `QuicSecrets`'s fields are implemented/consumed cross-crate by `hopf-quic` (`transport/tls_bridge.rs`), exactly the same "3-other-crate change" shape the plan already flagged for `crypto::signature`. Applied the same principle: `engine.rs` uses `TranscriptHash`/`PskSecret`/`TrafficSecret`/`ResumptionMasterSecret` internally end-to-end, then converts back to raw `[u8; 32]` with `.as_bytes()` at each `sink.*_ready(...)` call and in `QuicSecrets`'s construction — the trait/struct surface hopf-quic implements/reads is untouched, so this increment needed zero hopf-quic changes. Threading the newtypes across that boundary too is deferred as a separate, later, explicitly-scoped follow-up alongside the `crypto::signature`/`hkdf` cross-crate group below, not done this pass.
  - **Verified (first increment)**: `cargo build --workspace`/`--tests` zero warnings; `cargo test -p hopf-core --all-features --lib` 421/421 (RFC 8448 vectors, DTLS 1.3 label-prefix-separation test, both real OpenSSL DTLS 1.2 interop directions all included and unchanged); `cargo test -p hopf-quic --lib` 69/69 unaffected, confirming the cross-crate boundary decision above; `cargo test -p hopf-tls --features integration --lib` 18/19 (the one pre-existing flaky live-network test, unrelated). Pure refactor, zero behavior change, exactly as scoped.
  - **Shipped (second increment, 2026-09-11) — the cross-crate `crypto::signature` verify/sign family**, the item the first increment explicitly deferred. Two shared types, both defined once in `hopf-core` and reused by every consumer rather than duplicated per crate: `crypto::cert::SpkiDer` (moved here from its Stage-1 `crypto::trust`-local duplicate, which now imports it instead — `extract_spki`'s return type and `ecdsa_p256_sha256_verify_spki`/`ecdsa_p384_sha384_verify_spki`/`rsa_pss_sha256_verify_spki`'s `spki_der` param all use it) and `crypto::signature::SignatureBytes` (every `*_sign*` function now returns it; every `*_verify*` function's `signature` param takes it — `rsa_verify_pkcs1_sha256/512`, `rsa_verify_dnskey`, `ed25519_verify`, `ecdsa_p256/384_sha256/384_verify[_spki]`, `rsa_pss_sha256_verify_spki`). Propagated through every real consumer: `tls::handshake::verify` and `tls12::engine`'s `CertificateVerify`/`ServerKeyExchange` signing and verification (`hopf-core`-internal); `hopf-dns`'s `dane.rs` (`extract_spki` call sites, production and tests) and `dnssec/crypto.rs`'s `verify_signature` (the real RRSIG verification dispatcher — wraps wire-parsed signature bytes into `SignatureBytes` once at the top, same pattern as `verify_certificate_verify`); `hopf-smtp`'s DKIM `sign.rs`/`verify.rs` — **this closes a real, concrete instance of the plan's own named highest-risk pattern**: `dkim/verify.rs`'s `evaluate_key(key, algo, signature: &[u8], signed_data: &[u8])` took two same-shaped adjacent byte slices with nothing stopping a caller from transposing them; `signature` is now typed at the exact point it's first decoded off the wire (`base64_decode(&tags.b)`), so `signed_data` (computed two lines later) can no longer be passed in its place. Functions whose own single `&[u8]` signature param has no adjacent confusable argument (`verify_certificate_verify`, `verify_ske_signature`, DNSSEC's `verify_signature`) keep taking raw wire bytes at their own public boundary and wrap once internally — consistent with how `TlsEventSink` was handled in the first increment, and because there's no swap risk to close at a single-argument call site.
  - **Reviewed and explicitly not done, with reasons** (not an oversight): `Pkcs8KeyDer` — every `from_pkcs8` constructor takes exactly one `&[u8]` parameter, so there's no adjacent same-shaped argument a caller could transpose it with; wrapping it would add friction without closing a real swap risk. The `crypto::hkdf` surface `hopf-quic` consumes (`extract`, `quic_expand_label`) — checked the actual call site (`transport/packet/protection.rs::PacketKeys::from_secret`): `context` is a hardcoded `&[]` at every call, and the two real arguments (`secret: &[u8; 32]`, `label: &str`) aren't shape-confusable with each other, so there's no demonstrated risk to close there either. `RsaPublicKeyComponents { n, e }`'s two same-shaped fields — always constructed together at one call site immediately after parsing, so a swap would be an obvious immediate bug, not the independently-sourced-values confusion this pass targets. `SessionId`/`Nonce`/`Aad` — still unstarted, no concrete call site audited yet.
  - **Verified (second increment)**: `cargo build --workspace --tests` zero warnings (the unrelated `hopf-http` dead-code warnings that appear only under `cargo build -p hopf-smtp --all-features` — a feature combination this project's zero-warnings bar has never covered — were confirmed pre-existing via `git stash`: identical count on the already-committed Stage 1 tree, before any of this increment's edits); `cargo test -p hopf-core --all-features --lib` 421/421; `cargo test -p hopf-dns --all-features --lib` 141/141, plus the same `dot`+`doh`+`doq`+`dane`+`dnssec`+`integration`+`server` `resolver_stub` run as Stage 1 showing the identical 9 pre-existing failures (the two already-flagged DoH/forwarding-logic bugs), nothing new; `cargo test -p hopf-smtp --all-features --lib` 221/221 including all 30 DKIM tests (real Ed25519 and RSA sign/verify round trips); `cargo build -p hopf-quic --lib --tests` clean, confirming `crypto::mod.rs`'s re-export changes didn't ripple there.
  - **Highest-risk findings** (concrete swap example given for each): `crypto::signature`'s `*_verify*` family — every one takes `(public_key/spki_der, message, signature)` as three adjacent `&[u8]` params (`ed25519_verify`, `ecdsa_p256/384_sha256/384_verify[_spki]`, `rsa_verify_pkcs1_sha256/512`, `rsa_verify_dnskey`, `rsa_pss_sha256_verify_spki`, plus `ed448::verify`); `RsaPublicKeyComponents { n, e }`'s two same-shaped fields; `handshake::key_schedule`'s whole API surface, where a 32-byte PSK and a 32-byte transcript hash are both bare `&[u8; 32]`/`Option<&[u8; 32]>` (`compute_psk_binder`, `derive_early_traffic`, `derive_handshake_traffic_with_psk`, `derive_application_traffic_with_psk`, `derive_resumption_master_secret`, `derive_resumption_psk`, `compute_finished_verify_data`); `handshake::ticket::mint_new_session_ticket`/`tls12::ticket::mint_new_session_ticket`, where `ticket_key` (local server sealing key) and `resumption_master`/`master_secret` (protocol-derived secret) are adjacent same-shaped params — swapping them would seal a ticket under protocol secret material and derive a PSK from the local ticket key; `crypto::kx::combine_hybrid_secret(pq, classical, pq_first)`, where swapping the two secret halves silently produces a wrong-order combined secret for any group whose `pq_first` doesn't happen to match; `crypto::trust::add_component_anchor(subject_der, spki_der)`, where a swap corrupts trust-anchor matching silently.
  - **Newtype groups to introduce** (roughly ordered by call-graph size, smallest/safest first): `TranscriptHash`, `PskSecret`/`ResumptionMasterSecret`, `TicketKey` (already partly named via `tls::ticket_keys::TicketKeys`, which should absorb this), a `DirectionalSecrets { client, server }`-style pair (the shape already exists as `HandshakeTrafficSecrets`/`ApplicationTrafficSecrets` in `key_schedule.rs` — extend that pattern to `record.rs`'s `install_handshake_keys`/`stage_application_keys` and the `TlsEventSink`/`Tls12EventSink` trait callbacks that still take bare `client: [u8; 32], server: [u8; 32])`), then (larger, cross-crate) `SessionId`/ticket-identity, `Nonce`/`Aad`, and finally `SpkiDer`/`SignatureBytes`/`Pkcs8KeyDer` for the `crypto::signature` verify/sign family.
  - **Scope-inflation risk, called out explicitly**: `crypto::signature`'s public verify/sign functions are consumed *outside* `hopf-core` — `hopf-dns` (DNSSEC verification: `rsa_verify_dnskey`, `ecdsa_p256/384_sha256/384_verify`, `ed25519_verify`, `ed448::verify`, DANE's `spki_sha256`), `hopf-smtp` (DKIM sign/verify), and `hopf-quic` (`extract`, `quic_expand_label`). Newtyping those specific functions' signatures is a **3-other-crate change**, not a `hopf-core`-only one. Recommended phase boundary: do the internal-only, single-crate groups first (`TranscriptHash`, `PskSecret`/`ResumptionMasterSecret`, `TicketKey`, `DirectionalSecrets`, `combine_hybrid_secret`, `add_component_anchor` — all contained to `hopf-core`'s own TLS/DTLS engines with shallow call graphs) as this phase's actual deliverable; treat the cross-crate `crypto::signature`/`hkdf` surface as a **separate, later, explicitly-scoped follow-up** rather than pulling `hopf-dns`/`hopf-smtp`/`hopf-quic` call-site updates into this pass.
  - **Test friction**: low. RFC 8448 known-answer tests (`crypto/hkdf.rs`, `crypto/kx.rs`, `handshake/key_schedule.rs`) construct raw `[u8; 32]` arrays via 2-3 shared `hex()`/`hex32()`-style helpers per file — changing those helpers to return the newtype directly fixes ~10 call sites per file mechanically, no structural rework. The real interop suites (`dtls12::interop_tests` against OpenSSL, `hopf-tls`'s `rustls` interop) drive the engines exclusively through public socket/stream APIs and never touch any of the flagged internal byte parameters, so they're entirely unaffected.
  - **Tests:** existing unit/interop suites continue to pass unchanged in behavior (this is a pure type-safety refactor, zero behavior change by construction — any test that needs a real code change to keep passing is a signal the refactor accidentally touched logic, not just types); add a couple of `compile_fail`/doc-test-style checks only if genuinely useful for documenting the specific swap a given newtype prevents, not as a blanket requirement.

- [x] **Own PEM parser, `rustls-pemfile` dependency removed.** RFC 7468 PEM (`-----BEGIN <label>-----`/base64 body/`-----END <label>-----` framing around DER) is simple enough not to warrant an external crate — added `hopf-core::pem` (`crates/hopf-core/src/pem.rs`): `parse_pem_blocks`, plus `parse_certs`/`parse_pkcs8_keys` filtering by label, with its own minimal base64 decoder. 7 unit tests (multi-block files, multi-line-wrapped base64, mismatched BEGIN/END labels, unrelated block types not confused with PKCS#8 `PRIVATE KEY`, empty input). `hopf-core::tls::pem`'s `load_certs`/`load_pkcs8_key` and `hopf-quic::config`'s `pem_to_der_certs`/`load_pem_certs`/`load_private_key_pkcs8` now call it directly; `hopf-quic`'s key loader is now PKCS#8-only + last-block-wins, matching `hopf-core`'s existing convention (previously relied on `rustls-pemfile`'s generic any-key-type-first-match behaviour). `rustls-pemfile` removed from the workspace root and both crates' `Cargo.toml`s.
  - **Tests:** `cargo build -p hopf-core -p hopf-quic --lib` clean; `cargo tree --workspace -i rustls-pemfile` confirms it's gone from the dependency graph entirely; `cargo test -p hopf-quic --lib` 69/69; `cargo test -p hopf-quic --features integration --lib` 88 passed (the one DoQ-against-a-real-public-resolver failure is the pre-existing outbound-UDP-environment issue noted elsewhere in this doc, unrelated to PEM parsing); `cargo build --workspace --tests` zero warnings.

- [x] **DTLS 1.3 real-peer interop discovery pass — 6 real bugs found and fixed.** A real independent DTLS 1.3 implementation (wolfSSL) was used as a one-time external peer to surface wire-level and protocol-logic bugs invisible to hopf-vs-hopf loopback testing — interop is a discovery tool here, not a permanent conformance gate: no interop-dependent test remains in the tree, and every fix below carries its own self-contained, external-library-free regression test. Both directions (hopf client against a real server; hopf server against a real client) now complete a full DTLS 1.3 handshake plus bidirectional application data against an independent implementation.
  - **Wrong DTLS 1.3 version codepoint on the wire**: `build_client_hello_inner`/`build_server_hello_ext`/`build_hello_retry_request` (`tls/handshake/messages.rs`) hardcoded TLS 1.3's `supported_versions` value (`{0x03,0x04}`) regardless of transport; RFC 9147 §5.3 requires DTLS 1.3's own codepoint (`{0xfe,0xfc}`). A real peer correctly rejected the wrong value with a `protocol_version` alert.
  - **Client couldn't handle a cookie-only `HelloRetryRequest`**: `HandshakeEngine::on_hello_retry_request` (`tls/engine.rs`) required `key_share` to be present on every HRR; RFC 8446 §4.1.4 permits (and RFC 9147 §5.1's DTLS anti-amplification cookie exchange commonly produces) an HRR that changes nothing but the cookie. Fixed by keeping the already-offered group when `selected_group` is absent.
  - **Server couldn't handle a `ClientHello` with an empty `key_share` list**: `MessageCollector::take_parsed` (`tls/handshake/collect.rs`) hard-rejected any `ClientHello` with no key share before `on_client_hello`'s own (correct) group-mismatch-triggers-HRR logic ever ran. RFC 8446 §4.1.4 explicitly allows zero entries when the client already expects a retry round trip.
  - **Wrong DTLS 1.3 HKDF label prefix**: `crypto::hkdf`'s `DTLS13_LABEL_PREFIX` included a trailing space (`"dtls13 "`) by analogy with TLS 1.3's `"tls13 "`; RFC 9147 §5.9 specifies no space (`"dtls13"`, concatenated directly onto each label). Every derived DTLS 1.3 key was consequently wrong, but symmetrically wrong on both ends of a hopf-vs-hopf handshake — invisible until interop-tested, where the first Handshake-epoch record failed to decrypt against a real peer.
  - **Missing `TLSInnerPlaintext` zero-padding strip**: `dtls::record::read_record` popped the byte immediately after AEAD-open as the inner content type unconditionally; RFC 9147 §4.2.1 incorporates RFC 8446 §5.4's padding scheme unchanged (`content || type || zeros`), and this crate's own `write_record` never pads, so the gap was invisible until a real peer sent a padded record.
  - **No RFC 9147 §7 `ACK` support**: added minimal, narrowly-scoped support — recognize and discard a received `ACK` record (`dtls::engine`'s `CONTENT_ACK`) rather than treating its arrival as a fatal unknown-content-type error, and send an explicit `ACK` for the peer's last handshake message when completing the handshake with nothing else queued to piggyback it on. Without the latter, a peer with nothing to hear back from us retransmits its `Finished` indefinitely rather than proceeding — confirmed against a real client. Deliberately not general-purpose ACK generation or reception-informed retransmission tuning; scoped to the one case that actually blocks interop.
  - **Watch item**: OpenSSL is expected to eventually land a stable DTLS 1.3 release, worth a second interop discovery pass once available, on the same one-time basis as this one.
  - **Tests:** `crypto::hkdf::tests::dtls_expand_label_has_no_space_after_the_dtls13_prefix`, `dtls::record::tests::trailing_zero_padding_before_the_content_type_is_stripped`, `tls::engine::tests::server_sends_hello_retry_request_when_client_offers_no_key_share`, `tls::engine::tests::client_accepts_a_cookie_only_hello_retry_request_and_reuses_its_offered_group`, `dtls::engine::tests::server_sends_an_explicit_ack_for_the_clients_finished_with_nothing_else_to_piggyback`, plus a strengthened wire-byte assertion in `tls::engine::tests::dtls_mode_handshake_completes_with_correct_legacy_version_and_protocol_name`. Full workspace build and test suite green throughout, zero warnings.

- [ ] **Optional, time-permitting after the above**: two independently real, already-finalized extensions worth scoping if this pass has room left, each needing its own dedicated scoping pass (RFC citation, wire format, and this codebase's own extension-parsing/build call sites) before implementation — not scoped in depth here, just confirmed as real and current rather than draft/speculative:
  - **Encrypted Client Hello (ECH)** — now **RFC 9849** (published 2026-03-03; supersedes the long-running `draft-ietf-tls-esni` series, itself a redesign of the earlier ESNI mechanism). Encrypts the entire inner ClientHello (SNI, ALPN, etc.) inside an HPKE-wrapped payload alongside a cleartext "outer" ClientHello. Real, deployed (Cloudflare, Chrome, Firefox); OpenSSL added support following the RFC's publication. Needs HPKE (RFC 9180) as a prerequisite — check whether `aws-lc-rs` exposes it before scoping further.
  - **TLS Certificate Compression** — **RFC 8879** (stable since December 2020; not new, just not yet looked at in this codebase). Three registered algorithms — zlib(1), brotli(2), zstd(3) — compress the `Certificate` message; check `aws-lc-rs`/workspace dependencies for an available compressor before picking which one(s) to support (implementing just one, e.g. zstd, satisfies the RFC — it doesn't require all three).



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
- [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html) — Phase 8 optional/stretch item
- [RFC 8879 — TLS Certificate Compression](https://www.rfc-editor.org/rfc/rfc8879.html) — Phase 8 optional/stretch item
- [Architecture → Security substrate](docs/architecture.html#security-substrate)
- [Conformance → Security substrate](docs/conformance.html#security-substrate)
- [Phase 0 inventory](crypto-migration-inventory.md)
- [TLS roadmap (interim rustls)](docs/tls.html#roadmap)
- [QUIC implementation status (interim quinn-proto)](docs/quic-h3.html#implementation-status)
- [Gumdrop](https://github.com/cpkb-bluezoo/gumdrop) — behavioural reference (`../gumdrop`)

