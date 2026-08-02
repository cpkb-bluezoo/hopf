# hopf-amqp

AMQP **0-9-1 async client** for [Hopf](https://cpkb-bluezoo.github.io/hopf/)
(RabbitMQ wire protocol). Client-only — no broker.

## Capabilities

- Connection handshake (`PLAIN` / `AMQPLAIN`), tune negotiation, heartbeats
- Multi-channel open/close
- Exchange / queue declare, bind, unbind, purge, delete
- `basic.publish` with streamed content frames (`frame_max` splitting)
- Publisher confirms (`confirm.select`) and `basic.return`
- `basic.consume` push deliveries (start / data / complete), ack / nack / reject / qos
- AMQPS via implicit TLS on dial
- DNS via `hopf-dns`

Message bodies are opaque bytes; `content-type` / `content-encoding` and other
basic properties are carried as AMQP content-header metadata.

See [docs/amqp.html](https://cpkb-bluezoo.github.io/hopf/amqp.html).

## Examples

```
cargo run -p amqp-pub -- 127.0.0.1 5672 demo.queue "hello from hopf"
cargo run -p amqp-consume -- 127.0.0.1 5672 demo.queue
```

## Integration tests

```
cargo test -p hopf-amqp --features integration
```

Requires a RabbitMQ (or compatible) broker; defaults to `127.0.0.1:5672` /
`guest`/`guest`, overridable with `HOPF_AMQP_HOST`, `HOPF_AMQP_PORT`,
`HOPF_AMQP_USER`, `HOPF_AMQP_PASS`.
