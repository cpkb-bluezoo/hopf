# hopf-mqtt

MQTT **broker and async client** for [Hopf](https://cpkb-bluezoo.github.io/hopf/)
(Gumdrop `mqtt` port).

Status: complete for the current implementation plan tranche (codec, broker
core, v5 core, async client, MQTT-over-WebSocket bridge, examples). See
[PLAN.md](../../PLAN.md) for how this fits into the wider Hopf project.

## Target capabilities

- **MQTT 3.1.1** full semantics, plus a **useful v5 core**: wire properties,
  reason codes, Receive Maximum / outbound flow control, subscription
  options (No Local, Retain As Published, Retain Handling), Session Expiry
  Interval.
- QoS 0/1/2, retained messages, wills, topic wildcards, session takeover.
- Multi-reactor fan-out: publishes cross reactors via
  [`hopf_core::ConnHandle`](../hopf-core/src/handle.rs), never touching a
  peer `Endpoint` from another thread directly.
- Staged Connect / Publish / Subscribe handler SPI (Gumdrop shape).
  CONNECT defaults to **deny** until `MqttConfig::with_credentials` or
  `allow_anonymous()`; enhanced AUTH uses
  [`hopf_auth::CredentialStore`](../hopf-auth/src/store.rs).
- Async, non-blocking client on the `hopf-core` `Runtime` / `ProtocolHandler`
  SPI, with DNS resolution via `hopf-dns`.
- Optional MQTT-over-WebSocket bridge (`websocket` feature) sharing broker
  state with the TCP listener (timers via `ConnHandle::schedule_timer`).
- Offline QoS ≥ 1 queues (`MqttMessageStore`, default in-memory; optional
  file-backed) and in-process QoS retransmission while connected.

Still limited: QoS retry / inflight state does not survive broker process
restarts (even with a file-backed offline store).

See [docs/mqtt.html](https://cpkb-bluezoo.github.io/hopf/mqtt.html).

## Examples

```
cargo run -p mqtt -- 127.0.0.1:1883
cargo run -p mqtt-pub -- 127.0.0.1 1883 demo/topic "hello from hopf"
```

`examples/mqtt` is a broker on plain TCP; `examples/mqtt-pub` is an async
client that subscribes to a topic, publishes once, and prints anything it
receives (including its own echo).
