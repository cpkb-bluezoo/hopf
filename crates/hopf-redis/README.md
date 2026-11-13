# hopf-redis

Async **Redis and Valkey client** for [Hopf](https://cpkb-bluezoo.github.io/hopf/),
speaking RESP2 and RESP3.

- **One pipelined connection, bound to a reactor.** Commands may be issued from
  any thread, go out at once without waiting for earlier replies, and each reply
  is a callback on the reactor, exactly once, in the order commands were issued.
- **Handshake:** `HELLO 3` (with `AUTH` and `SETNAME`), falling back to RESP2
  with `AUTH` for a server that predates `HELLO`; `SELECT`. Commands issued
  meanwhile wait, so none runs unauthenticated.
- **DNS and TLS:** host names through `hopf-dns`; TLS through a `hopf-core`
  connector (trust anchors, mutual TLS, pins).
- **Typed helpers** for strings, keys, hashes, lists, sets, sorted sets and
  scripts, `SET` options, `transaction` as one atomic write, and a generic
  `command` for anything else.
- **Failure you can reason about:** a command sent when the connection is lost
  fails with `ConnectionLost` and is never re-sent; a timed-out command's late
  reply is discarded in its place; after a failed connect, commands fail fast for
  a growing time.
- **Publish/subscribe:** `RedisSubscriber` is a dedicated connection that
  reconnects by itself and subscribes again to everything (channels, patterns,
  shard channels), notices a dead connection with a keepalive, and delivers
  messages, acknowledgements and unknown push kinds to a handler. A command
  connection takes a push handler for RESP3 pushes such as key invalidations.
- **A push RESP parser** (`hopf_redis::resp`) that holds none of the stream,
  reads every RESP2 and RESP3 type in any split, and checks every size a server
  announces against configurable limits before reserving memory.

```rust
use hopf_core::{Runtime, RuntimeConfig};
use hopf_redis::{RedisClient, RedisConfig};

let rt = Runtime::start(RuntimeConfig::default()).unwrap();
let redis = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", 6379));
redis.set("greeting", "hello", |r| assert!(r.is_ok()));
redis.get("greeting", |r| println!("{r:?}"));
```

Tested against Redis 7.4 and Valkey 8.1 as well as a scripted server; see
[docs/redis.html](../../docs/redis.html).
