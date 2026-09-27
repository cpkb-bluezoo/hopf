# hopf-amqp1

AMQP **1.0 async client** for [Hopf](https://cpkb-bluezoo.github.io/hopf/) —
targets brokers with native AMQP 1.0 support (RabbitMQ 4's native AMQP 1.0
listener, ActiveMQ Artemis `amqp://`). Client-only — no broker.

AMQP 1.0 (ISO/IEC 19464) shares only the four-byte `AMQP` magic with the
[`hopf-amqp`](https://docs.rs/hopf-amqp) crate's AMQP 0-9-1 (RabbitMQ classic
protocol); framing, the type system, and the connection/session/link model
are unrelated.

## Capabilities

- SASL `PLAIN` (when credentials are configured) or `ANONYMOUS`, auto-negotiated
- Connection `open`, sessions (`begin`/`end`), sender/receiver links (`attach`/`detach`)
- Session-level flow control (incoming/outgoing window) and link credit
- Sending messages (`header`, `properties`, `application-properties`, `data`
  body), automatically split across multiple `transfer` frames for large messages
- Receiving messages, streamed to the application as `transfer` frames arrive
  rather than buffered whole
- Delivery settlement: accept / reject / release / modify, and outcome
  notifications for messages this client sent
- AMQPS via implicit TLS on dial
- DNS via `hopf-dns`

## Examples

```
cargo test -p hopf-amqp1 --lib client::tests
```

See [`client` module docs](https://docs.rs/hopf-amqp1) for a full quick-start
example (connect, begin a session, attach a sender, send a message).

## Integration tests

```
cargo test -p hopf-amqp1 --features integration
```

Requires a broker with native AMQP 1.0 support; defaults to `127.0.0.1:5672`
/ `guest`/`guest` (RabbitMQ 4 node addressing, `/queues/<name>`), overridable
with `HOPF_AMQP1_HOST`, `HOPF_AMQP1_PORT`, `HOPF_AMQP1_USER`,
`HOPF_AMQP1_PASS`, and `HOPF_AMQP1_ADDRESS_STYLE=artemis` for a plain
queue-name address instead. `HOPF_AMQP1_TLS_PORT` / `HOPF_AMQP1_TLS_CA`
configure the amqps (implicit TLS) test; it's skipped if no CA cert is found.

## Known limitations

- No automatic reconnection (unlike `hopf-amqp`'s `AmqpRecoveringClient`) —
  a future addition if needed.
- This client doesn't yet send heartbeats to satisfy a peer's advertised
  `idle-time-out`, nor does it enforce one against the peer; it advertises
  no requirement of its own. Fine for short-lived or steadily-busy
  connections; a long-idle connection against a broker with a strict idle
  timeout could be dropped.
- `delivery-annotations`, `message-annotations`, and `footer` message
  sections are received (raw maps) but not yet offered on the send side.
