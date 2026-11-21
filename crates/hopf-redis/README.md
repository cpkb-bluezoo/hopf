# hopf-redis

Async **Redis and Valkey client** for [Hopf](https://cpkb-bluezoo.github.io/hopf/),
speaking RESP2 and RESP3.

- **One pipelined connection, bound to a reactor.** Commands may be issued from
  any thread, go out at once without waiting for earlier replies, and each reply
  is told to a callback or a sink on the reactor, exactly once, in the order
  commands were issued.
- **Streaming only.** The crate offers no call that returns, or passes to a
  callback, a value whose size depends on what the server holds. A string or a
  collection (`GET`, `LRANGE`, `EVAL`, a pub/sub message) is told to a sink as
  chunks in constant memory, with flow control; an identifier (a key, a hash
  field, a channel) is delivered whole up to `max_field` (64 KiB); a scalar (a
  count, `OK`, nil) is a value. Memory per connection is set by configuration,
  never by data, and a test (`tests/api_audit.rs`) checks that every public
  signature keeps to it. Someone who wants a small value whole accumulates it in
  their own sink, where the limit is visible in their code.
- **Handshake:** `HELLO 3` (with `AUTH` and `SETNAME`), falling back to RESP2
  with `AUTH` for a server that predates `HELLO`; `SELECT`. Commands issued
  meanwhile wait, so none runs unauthenticated.
- **DNS and TLS:** host names through `hopf-dns`; TLS through a `hopf-core`
  connector (trust anchors, mutual TLS, pins).
- **Helpers** for strings, keys, hashes, lists, sets, sorted sets and scripts.
  Those whose reply is a single value (`incr`, `del`, `expire`, `publish`,
  `set` with its options, ...) take a callback; those whose reply is a string or
  a collection (`get`, `mget`, `lrange`, `hgetall`, `eval`, ...) take a sink.
  `transaction` is one atomic write whose `EXEC` reply streams to a sink, and
  `command` and `send` carry any single-value command.
- **Failure you can reason about:** a command sent when the connection is lost
  fails with `ConnectionLost` and is never re-sent; a timed-out command's late
  reply is discarded in its place; after a failed connect, commands fail fast for
  a growing time.
- **Publish/subscribe:** `RedisSubscriber` is a dedicated connection that
  reconnects by itself and subscribes again to everything (channels, patterns,
  shard channels), notices a dead connection with a keepalive, and streams each
  message to a handler: the channel whole (bounded by `max_field`), the body in
  chunks of any size, with `Flow::Skip` to drop one message and `Flow::Pause`
  (then `resume()`) to hold the connection. A message that cannot be delivered
  is dropped alone and reported. A command connection takes a push sink for RESP3
  pushes, `InvalidationSink` being the ready one for key invalidations.
- **Cluster:** `RedisCluster` learns the layout from `CLUSTER SHARDS` (or
  `CLUSTER SLOTS`), sends each command to the master of its key's slot, follows
  `MOVED` and `ASK`, refreshes the layout when nodes fail or slots move, and
  fails multi-slot commands with `CROSSSLOT` without touching the network.
  `wait_replicas` and `wait_aof` run `WAIT` and `WAITAOF` on the connection
  that carried the write they confirm. Works with Redis Cluster and Valkey
  Cluster.
- **An event-driven push RESP parser** (`hopf_redis::resp`) that holds none of
  the stream and has no limit on a string's or an aggregate's size, because it
  holds neither. It tells a sink what it reads, with a string's payload as
  chunks borrowed from the connection's ring, so nothing it parses is copied or
  collected; a sink can pause it, or discard the rest of a reply in constant
  memory. A reply nobody waits for, such as a timed-out command's, is discarded
  as it arrives, up to `max_skip`.
- **Streaming through a cluster.** `RedisCluster::send_streaming` and the same
  helpers as a client follow `MOVED`, `ASK` and retries without the sink hearing
  of an attempt that was redirected: only the start of a reply is held back, to
  see if it is an error. After the first event that is not, the command is
  committed to its node and nothing more is held.
- **Streaming values out.** `Command::arg_stream` takes an argument pulled from a
  source a block at a time, so a value of any size is never held whole; the
  source is opened afresh for each attempt, so redirections and reconnections
  work, and one that cannot be repeated fails with `NotRepeatable` rather than
  sending a short value. A command larger than the outbound buffer is written in
  blocks too.
- **Streaming replies.** `send_streaming` and the shape sinks (`BulkSink`,
  `ElementsSink`, `KeysSink`, `FieldsSink`) deliver a value of any size as
  chunks in constant memory, with `Pause` and `StreamHandle::resume` for
  backpressure and `Skip` and `StreamHandle::cancel` to give up. The timeout of
  such a command is for silence, not for the whole reply. A connection costs
  its ring, one line and one identifier: connections x (ring + `max_line` +
  `max_field`), whatever the data.

```rust
use hopf_core::{Runtime, RuntimeConfig};
use hopf_redis::{RedisClient, RedisConfig};

let rt = Runtime::start(RuntimeConfig::default()).unwrap();
let redis = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", 6379));
redis.set("greeting", "hello", |r| assert!(r.is_ok()));   // a single value: a callback
redis.incr("visits", |r| println!("{r:?}"));
// redis.get("greeting", sink) takes a BulkHandler, which is told the value in chunks.
```

Tested against Redis 7.4 and Valkey 8.1 (single node and cluster) as well as
scripted servers; see
[docs/redis.html](../../docs/redis.html). `cargo bench -p hopf-redis --bench
client` measures allocations and CPU per command, on one node and through a
cluster, with the results and how to read them in
[benches/README.md](benches/README.md).
