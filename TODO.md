# TODO

## Divergence tracking against gumdrop

hopf is kept in step with its sister project
[gumdrop](https://github.com/cpkb-bluezoo/gumdrop). Each review compares
the gumdrop commits since the previous baseline with hopf and either
ports the change or files an issue for it.

| Reviewed on | gumdrop baseline (compared up to) | gumdrop range reviewed | hopf state |
|---|---|---|---|
| 2026-10-19 | `0a7f22fbe9c9ae0208fafbea69770c8bd445539d` (main, 2026-10-19; after v3.1.0) | `v3.0.0` (`976ef1ac`) .. `0a7f22fb` | main after `ef10edf` |

Next review: `git -C ../gumdrop log --oneline 0a7f22fbe9c9ae0208fafbea69770c8bd445539d..HEAD`
lists what has not yet been compared.

### 2026-10-19 review summary

Ported in this review (uncommitted at the time of writing; see the git
history after `ef10edf`):

- TLS: psk_key_exchange_modes offered in every ClientHello; QUIC NewSessionTicket advertises 0xffffffff early data; `accept_offered_key_share` for QUIC servers (gumdrop 649dac70, aae9f3ce, 8c6e3aac).
- QUIC: HANDSHAKE_DONE retransmitted on loss; 0-RTT resent as 0-RTT after Retry; 4 MiB UDP socket buffers; app-limited congestion window; PTO probes repeat the oldest unacknowledged data; settled server Initial SCID and connection ID transport parameter checks (gumdrop ec3c0b04, 67121886, fd0e2d4e, 101379ec in part, d6058dd1, 1a95d523).
- QPACK: Required Insert Count is 1 + largest referenced index (gumdrop aae9f3ce).
- HTTP/3: a response body held for the non-incremental priority slot is no longer dropped on close (gumdrop aae9f3ce).
- gRPC: zero-length frames complete; protocol errors answered with grpc-status; no on_grpc_status after on_error; gzip/deflate (br opt-in) message compression on server and client (gumdrop 2fafc735, e2d84741, b4bec7b5).

Already present in hopf before the review: sent-data records freed on ACK; record_size_limit 16385 accepted; transport parameters reported before a HelloRetryRequest; all early data in the first flight; Extended CONNECT WebSocket over h2/h3; ordered telemetry exporter writes; ContentEncoding size-limit distinction.

Not applicable to hopf: ACK-frequency IMMEDIATE_ACK tuning (extension not implemented), retired-stream priority (priorities are a no-op), compatible version negotiation ordering (server does not switch versions), JCA CryptoServices plumbing, servlet security constraints, interop harness tweaks.

Tracked as issues (large features and hopf bugs found during the comparison):

| Area | Issues |
|---|---|
| QUIC congestion/recovery | #482 CUBIC + HyStart++, #483 pacing, #484 receive windows (never raised), #485 connection-level send flow control, #486 stream state release, #493 ACK ranges and ack_delay_exponent |
| QUIC connection management | #487 unknown frames drop packets (critical), #488 spare connection IDs, #489 path validation / migration / preferred_address, #490 key discard and HANDSHAKE_DONE ack, #491 anti-amplification (critical), #492 RESET_STREAM / STOP_SENDING |
| TLS | #494 FIPS mode (needs approval for the aws-lc-rs `fips` feature), #495 server psk_key_exchange_modes parsing |
| gRPC | #496 server streaming, #497 client streaming and on_complete, #498 metadata and deadlines, #499 grpcio interop tests |
| HTTP | #500 abort callback after end of request, #501 h2 client RST_STREAM silent, #502 deferred upgrade dropped on h2/h3, #506 access log records and CLF/ELFF sink |
| Telemetry | #503 deterministic flush, #504 LogRecord with level axis and per-sink routing, #505 console sink and eprintln! routing, #507 qlog event surface, #508 qlog JSON-SEQ sink and QLOGDIR, #509 quic-interop-runner endpoint, key log and CI |
