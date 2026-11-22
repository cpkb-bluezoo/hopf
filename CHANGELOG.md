# Changelog

All notable changes to hopf are recorded here. The workspace crates are
versioned together. Changes before 0.7.0 are in the git history and tags.

## Unreleased

### Added

- **hopf-mailbox: `MemoryFactory`**, a mailbox store held in memory (messages,
  flags, UIDs, append and any `SearchCriteria`; no files, no sockets), for
  tests of code that serves or reads mailboxes where unit tests may not touch
  the file system. The NNTP server's protocol tests run over it.
- **hopf-nntp client: streaming posts, attachments and a choice of SASL
  mechanism** (#544). `NntpSession::post_stream` takes an `NntpPoster` that is
  asked for the article a piece at a time, the next only when the connection
  has taken the last, with dot-stuffing and the terminator added; a poster that
  fails closes the connection and the post hears the error. `post` is now that
  over a slice, so there is one way an article is sent.
  `post_with_attachments` follows the text with `NntpAttachment`s (a path,
  bytes, a `Read` or an `AttachmentSource`) as uuencoded blocks, each read and
  encoded on a thread of its own and written a piece at a time, and
  `article_with_attachments` / `body_with_attachments` tell an
  `NntpArticleHandler` the text of an article and, apart from it, each file as
  it arrives. Posting a 128 MiB article or attachment to the server, and reading
  it back, takes the same heap as a small one. `NntpClient::sasl_mechanisms`
  names the mechanisms to try (and when the server offers none the connection
  fails instead of sending a password another way), `bearer_token` uses
  OAUTHBEARER or XOAUTH2, and `sasl_external` uses the TLS client certificate.
  `tests/roundtrip.rs` runs the client against the server for each mechanism,
  and for posts with attachments that come back the same.
- **hopf-nntp: a news reader server** (#543). `NntpService` serves the
  mailboxes of a `MailboxStore` as newsgroups (a mailbox is a group, a UID is
  an article number), or any other source of articles through a
  `ReaderHandler`. Reader mode: `CAPABILITIES`, `MODE READER`, `DATE`, `HELP`,
  `QUIT`, `GROUP`, `LISTGROUP`, `LAST`, `NEXT`, `ARTICLE`, `HEAD`, `BODY`,
  `STAT`, `LIST ACTIVE`/`NEWSGROUPS`/`OVERVIEW.FMT`, `NEWGROUPS`, `OVER` and
  `HDR` (with `XOVER`/`XHDR`), `POST`, `STARTTLS` and `AUTHINFO` (`USER`/`PASS`
  and `SASL`), with wildmats. Commands may be pipelined. Everything that
  touches the news runs on the storage pool and writes its answer into a
  bounded pipe that the connection empties as it drains, so a slow client
  slows the read of the store and a client that stops reading is closed after
  `write_stall_timeout`; articles are dot-stuffed by a state machine that holds
  no line. A 192 MiB article peaks at about 127 KiB of heap. A posted article
  reaches a `PostSink` dot-unstuffed in pieces of at most 64 KiB, one write at
  a time; the stock sink keeps only the header block to find the groups, adds a
  `Message-ID` and a `Date` if they are missing, and aborts every append if the
  post fails or the client goes away. Passwords are refused (`483`) on a
  connection that is not encrypted unless `allow_cleartext_auth` is set,
  `require_authentication` answers news commands with `480` until the client
  has authenticated, `STARTTLS` discards bytes sent ahead of the handshake and
  resets the session, and a connection whose credentials are refused
  `max_auth_failures` times is closed. `NntpService::with_telemetry` exports
  `nntp.server.*` metrics (`hopf_otel::NntpServerMetrics`, new) and a trace for
  each connection.
- **hopf-core testing:** the test `Peer` lets a handler start TLS and records
  the request (`Peer::tls_started`); the handshake is completed with
  `Peer::secure`.

- **hopf-redis (new crate):** an async Redis and Valkey client (#527), behind
  the `redis` feature of `hopf`. `RedisClient::connect(&reactor, RedisConfig)`
  is one pipelined connection bound to a reactor: commands from any thread, each
  reply told to a callback or a sink on the reactor, exactly once and in issue
  order. It negotiates
  RESP3 (`HELLO 3`) and falls back to RESP2, authenticates (password, or ACL
  user and password), selects a database, resolves host names through
  `hopf-dns` and speaks TLS through a `hopf-core` connector. Helpers cover
  strings, keys, hashes, lists, sets, sorted sets and scripts (those with a
  single-value reply take a callback, those with a string or a collection take a
  sink; see below), `SetOptions` covers `SET`, `transaction` writes
  `MULTI`..`EXEC` as one batch, and `command` and `send` carry any single-value
  command. A command in flight when the connection is lost fails with
  `ConnectionLost` and is not sent again; a timed-out command's late reply is
  discarded in its place; after a failed connect commands fail fast for a
  growing time. `hopf_redis::resp` has the command encoder and `RespParser`, an
  event-driven push parser that holds none of the stream (limits on depth, line
  length and bytes discarded only).
  `RedisSubscriber` is a connection for publish/subscribe (channels, patterns
  and shard channels) that reconnects by itself, subscribes again to everything,
  watches the connection with a keepalive and tells a `SubscriberHandler` of
  each message, as a header (the channel, and the pattern, whole and bounded by
  `max_field`) then the body in chunks, however large, which the handler may
  skip or pause on; a message that cannot be delivered is dropped alone and
  reported with `on_dropped`. `RedisClient::publish` and `spublish` publish.
  The RESP3 pushes a command connection gets (key invalidations, for one) go to
  a sink of the application's own, `set_push_sink`, as the events of a reply,
  with `InvalidationSink` ready for `CLIENT TRACKING`; a cluster makes one for
  each node, `set_push_sinks`. A command connection refuses `SUBSCRIBE` and its
  relatives.
  `RedisCluster` is the cluster client: it learns the layout from `CLUSTER
  SHARDS` (or `CLUSTER SLOTS`), keeps one connection per master, sends each
  command to the master of the slot its key hashes to (CRC16 with hash tags,
  with a table of where each command's keys are), fails commands with keys in
  several slots with `CROSSSLOT` before they reach the network, follows `MOVED`
  and `ASK` (with `ASKING` written in the same batch), refreshes the layout when
  a node cannot be reached or a slot moves (one fetch at a time, rate-limited),
  and never sends again a command that was already sent when its connection was
  lost. Transactions run on the owner of their slot, `command_for_key` routes a
  command by an explicit key, and `ClusterConfig::node_config` gives every node
  connection its password, TLS and timeouts. Tested against Redis 7.4 and
  Valkey 8.1, including slot migration and master failover.
- **hopf-redis: streaming only** (#541). The crate offers no call that returns,
  or passes to a callback, a value whose size depends on what the server holds;
  this is the framework's rule that nothing buffers a message or a stream, and a
  scalability matter, not a tuning one. A string or a collection (`GET`, `MGET`,
  `LRANGE`, `HGETALL`, `EVAL`, the `EXEC` reply of `transaction`, a pub/sub
  message) is told to a sink as chunks that borrow from the connection's buffer,
  in constant memory, with `Flow::Pause` and `StreamHandle::resume` for flow
  control in both directions and `Flow::Skip` and `StreamHandle::cancel` to give
  up on a reply (the rest is discarded in constant memory, the connection stays
  usable). Shape sinks (`BulkSink`, `ElementsSink`, `KeysSink`, `FieldsSink`)
  cover the common replies. An identifier (a key, a hash field, a channel) is
  delivered whole up to `max_field` (64 KiB); a scalar is a value. A command's
  arguments stream out too (`Command::arg_stream`, with the source opened afresh
  for each attempt), and a command larger than the outbound buffer is written in
  blocks instead of failing the connection. Streamed commands go through a
  cluster, following `MOVED`, `ASK` and retries without the sink hearing of a
  redirected attempt. Timeouts for a stream are for silence, and a consumer that
  has paused is not mistaken for a dead connection. `Value`, the whole-reply
  callbacks and the limits that existed to size a buffer are gone; a connection
  costs its ring, one line and one identifier, whatever the data. A reply nobody
  waits for is discarded in constant memory (it used to be built in full and then
  dropped). Measured with a counting allocator: 256 MiB through a client, out of
  a client, through a cluster and to a subscriber raises the peak heap by a few
  kilobytes at most. `tests/api_audit.rs` fails if a public signature
  reintroduces an unbounded type. `hopf-core` gained a `pause_read` fix so a
  paused connection is held by TCP and loses nothing.
- **hopf-core:** limits on a listener's open connections, and an idle timeout
  that is enforced (#542). `TcpListenerConfig::max_connections` and
  `max_connections_per_address` bound how many connections a listener has open
  in total and from one peer address (an IPv4 peer on a dual-stack socket counts
  as its IPv4 address); a connection over either is accepted and closed at once,
  as the peer lists and the rate limit do, and the telemetry hook is told. The
  place is held by the connection and given back when it is dropped, however it
  ended. Composition XML takes `max-connections` and
  `max-connections-per-address`. `idle_timeout`, accepted and stored but ignored
  until now on listeners and dials alike, now closes a connection with nothing
  received or sent for the whole timeout (`ErrorKind::TimedOut` to the handler's
  `error`, then `disconnected`); it is checked once per timeout, so a busy
  connection costs no timer per byte. `docs/runtime-options.html` documents both,
  including that a handler waiting on a slow answer looks idle.
- **hopf-dns:** a limit on the queries outstanding on one TCP or DoT connection
  (#539). A client could pipeline queries faster than a callback-shaped handler
  answered them, each tying up handler state, upstream capacity and memory with
  nothing to stop it. `DnsService::set_max_in_flight` (default 128, `None` for no
  limit) now stops a connection being read while it has that many outstanding, and
  reads it again when an answer completes, so TCP's own flow control holds the
  client back and nothing is refused or dropped; queries start in the order they
  were sent, and answers may still come back in any order (RFC 7766 §6.2.1.1). A
  callback let go of without an answer frees its place. `DnsServerMetrics` gains
  `backpressure_events` and `in_flight_peak`, and `DnsServerTelemetry` gains
  `in_flight` and `backpressure` (with default no-op bodies), exported by
  `hopf-otel` as `dns.server.in_flight` and `dns.server.backpressure`.
  `listen_dns_tcp_with` and `listen_dns_dot_with` give a DNS listener the
  `TcpListenerConfig` settings (peer lists, accept rate limit, buffer caps, PROXY
  protocol, idle timeout, connection limits).
- **hopf-redis: cluster publish/subscribe** (#538). `RedisClusterSubscriber`
  keeps one `RedisSubscriber` per node that needs one, on the layout a
  `RedisCluster` keeps, and reconciles them whenever the layout changes. A
  classic channel or pattern is subscribed on one master, and moves to another
  (subscribing everything again) when that node's connection is lost or it leaves
  the cluster. A shard channel is subscribed on the master that owns its slot and
  follows the slot: on a `MOVED` reply, on the `sunsubscribe` a server pushes
  when it loses the slot, and on a new layout; the new owner has acknowledged
  before the old is released. Keyspace and keyevent patterns
  (`subscribe_keyspace`) are subscribed on every master, following masters as they
  join and leave. Each node's connection has a handler made for it, so one
  connection's messages never interleave with another's. The documentation says
  what is guaranteed (no duplicates from the arrangement, subscribe before
  unsubscribe, nothing dropped silently) and what is not (at-most-once, as Redis).
  Tested against scripted nodes and a real Redis cluster, including a slot
  migrated away and back, and a failover.
- **hopf-redis:** `WAIT` and `WAITAOF` bound to the connection of the write
  (#532). `RedisCluster::wait_replicas(slot_key, n, timeout_ms, cb)` and
  `wait_aof(...)` send the command behind the last command submitted for the
  slot, on the connection that carried it (or to the slot's master when nothing
  is in flight); a write that is redirected takes its `WAIT` with it and the
  first node's answer is discarded; a lost connection fails the callback and
  the `WAIT` is never sent again. The client's deadline is its command timeout
  plus `timeout_ms` (none for 0). `RedisClient::wait_replicas` and `wait_aof`
  are the same calls on one server, and fail at once inside `MULTI`.
  `RedisCluster::command_for_key` routes any command by a key; `WAIT` through
  `command` or `send` with no key is refused rather than sent to any master.
  `CLUSTERDOWN` and `TRYAGAIN` for an ordinary command are now retried against
  a fresh layout, as many times as it has redirections left, so a failover is
  not seen by callers; and a command whose slot the layout just fetched leaves
  unserved waits for the next layout instead of failing. `max_pending` no
  longer counts the commands the connection sends for its own handshake.
- **hopf-core:** readiness and graceful shutdown (#530).
  `Runtime::is_ready()`, `is_draining()`, `bind_failures()` and
  `open_connections()`; `Runtime::start_drain()` stops accepting and tells every
  open connection's handler through the new `ProtocolHandler::drain` (default:
  do nothing); `Runtime::shutdown_graceful()` (and `_within(timeout)`, and
  `drain(timeout)` for a shared runtime) waits for open connections up to
  `RuntimeConfig::drain_timeout` (new, default 30 s), returning as soon as none
  is left, then closes the rest by force. `Composition::shutdown_graceful()`
  does the same. `TelemetryHook` gains `on_runtime_state`, `on_bind_failure` and
  `on_drain_complete`, which a `hopf-otel` pipeline exports as
  `hopf.runtime.ready`, `.draining`, `.bind_failures`,
  `.drain.forced_connections` and `.drain.duration`. No protocol crate says
  goodbye on `drain` yet, so until each adopts it a drain waits for connections
  to end by themselves or for the drain period; `AlpnHttpEndpoint` forwards the
  call to its inner handler. `RuntimeConfig` has a new field, so a struct
  literal without `..Default::default()` needs one.
- **hopf-otel / hopf-dns:** DNS metrics over OTLP/JSONL (#529).
  `TelemetryPipeline::dns_metrics()` and `dns_upstream_metrics()` return
  instrument sets (`DnsServerMetrics`, `DnsUpstreamMetrics`) named
  `dns.server.*` (queries, responses with `dns.response.code`, query duration,
  cache hits, upstream queries, stale and aggressive-NSEC answers, errors,
  cookies, RFC 10029 expansion) and `dns.upstream.*` (queries, answers,
  latency, timeouts, failures, retries, connects, reconnects, pool size and
  in-flight), with a `dns.transport` attribute. Attach them with
  `DnsService::set_telemetry`, `UpstreamClient::set_telemetry` and
  `DnsResolver::set_upstream_telemetry`. `hopf-dns` defines the
  `DnsServerTelemetry` and `DnsUpstreamTelemetry` traits (module `telemetry`)
  and `hopf-otel` implements them, so `hopf-dns` gains no exporter dependency;
  `hopf-otel` now depends on `hopf-dns`. The snapshot counters of
  `DnsService::metrics()` are unchanged. `DnsTransport::as_str()` is new.
  `ExportHandle::try_send_metric` is documented as the way for an application
  to add meters of its own.
- **hopf-core:** `ServerTlsBuilder` (#528), a public server TLS configuration
  that combines what the fixed acceptor helpers each offer one of: client
  authentication (`client_auth`), a credentials resolver consulted on every
  handshake (`server_resolver`), ALPN and the TCP version policy, and client
  trust that is consulted on every handshake too, so it can change without a
  restart. Client trust is a fixed `client_trust_store`, a `client_trust`
  callback returning the current `TrustStore`, or a `client_verify`
  `ClientVerifyOverride` that decides from the client's chain. `build()` gives
  a `SharedTlsAcceptor`; `apply_to(&mut HandshakeConfig)` sets the same
  configuration on any handshake config. It refuses contradictory settings
  (no credentials, client authentication with nothing to trust, trust with no
  client authentication). Both the TLS 1.3 and TLS 1.2 engines honour it.
- **hopf-quic:** `server_config_from_tls_builder` (and `_with`) builds a
  `QuicServerConfig` from a `ServerTlsBuilder`, so a QUIC listener (DoQ,
  HTTP/3) has the same credentials, resolver and client-trust behaviour as a
  TCP one.
- **hopf-dns:** `UpstreamClient` (#526), a callback-shaped client for one
  encrypted upstream resolver, over DoT (feature `dot`) or DoQ (feature
  `doq`). `query(message, callback)` returns at once and the callback runs
  once on the client's reactor, never inline, with the answer or an
  `UpstreamError`. DoT queries are pipelined on a pooled connection and
  matched by message ID, so answers may arrive out of order; the connection
  is opened by the first query, closed after `idle_timeout`, and reopened by
  the next. A query waiting on a lost connection is sent again on a fresh one
  (`retries`), a per-query timeout fails it once, and a late answer is
  discarded. `UpstreamTls::builder` sets the trust anchors, a client
  certificate for mutual TLS and SPKI pins. `UpstreamClient::metrics()` gives
  queries, answers, timeouts, retries, reconnects, pool size, in flight and
  latency. `DnsResolver::add_server_upstream` takes a client you built, and
  `dot_upstream_metrics` reports the ones the resolver opened.
- **hopf-core:** `ClientTlsBuilder`, the client counterpart of
  `ServerTlsBuilder`: trust anchors or the public WebPKI, a client
  certificate, a verifier of your own, ALPN and the TCP version policy, in one
  builder. `ReactorHandle::connect` dials on a given reactor, so a client's
  connections live on the reactor that owns it.
- **hopf-dns:** `DnsService` answers RFC 10029 multiple-QTYPE queries
  (#531). `DnsService::set_max_multi_qtypes(n)` allows up to `n` extra types
  per query; the default, `0`, leaves the mechanism off. A query that names
  extra types in an `MQTYPE-Query` option has each one asked of the handler
  as an ordinary single-question query with the same `QueryContext`, and the
  answers are merged into one response whose `MQTYPE-Response` option lists
  the types it covers. A type the handler declines or fails, or that is beyond
  the cap, is left for the client to ask separately. Handlers need no change,
  and one that answers late works as usual. New counters
  `DnsServerMetrics::{mqtype_queries, mqtype_subqueries}`.
- **hopf-core:** in-memory counterparts of the PEM builders, for identities
  generated at run time: `acceptor_from_pem_bytes`, `acceptor_from_pem_tls12_bytes`,
  `acceptor_from_credentials_tls12`, `acceptor_from_credentials_with_sni`,
  `connector_from_pem_bytes`, `connector_from_pem_bytes_with_tcp_version_policy`
  and `connector_from_pem_tls12_bytes`. The path-based builders read the file
  and use these.
- **hopf-mqtt:** a client connection with a non-zero keep-alive no longer
  closes when its first PINGREQ falls due. It had the same fault as
  hopf-amqp: the keep-alive timer used `Endpoint::fail`, which force-closes a
  real connection. PINGREQs are now sent directly from the timer, and the
  keep-alive timers are cancelled when the connection drops. A broker that
  does not answer with PINGRESP still times the connection out.
- **hopf-core `testing`:** `Peer::connect_timed`, `Peer::elapsed` and
  `Peer::advance`. A handler that is waiting only for a timer it set no
  longer makes a test wait for the time to pass: the peer's clock skips ahead.

### Fixed

- **hopf-nntp client:** a `283` reply to `AUTHINFO SASL` (success, with data for
  the client, which SCRAM sends as the server's signature) was treated as a
  failed login. It is now accepted, and the data is checked.
- **hopf-imap:** the body structure follows rmimeparser 0.7, whose
  `MimeHandler::content_id` takes the local part and the domain.

- **hopf-dns:** `DnsResolver::add_server_dot` (and an auto-selected DoT
  upstream) no longer runs each query on its own thread against a blocking
  connection that serves one query at a time. DoT queries now go through
  `UpstreamClient`: pipelined, non-blocking, and with the `MQTYPE-Query`
  option and the EDNS OPT record attached like the other transports. A
  forwarder over DoT is no longer held up by one slow upstream answer.
- **hopf-dns:** a response that carries both a DNS Cookie and another EDNS
  option now has one OPT record, not two (RFC 6891 section 6.1.1).
- **hopf-amqp:** a client connection with heartbeats enabled no longer closes
  when its first heartbeat falls due. The send timer used `Endpoint::fail` to
  signal the handler, which on a real connection also force-closes it, so
  every connection dropped after one heartbeat interval. Heartbeats are now
  sent directly from the timer, and the handshake and heartbeat timers are
  cancelled when the connection drops. A broker that stops sending still
  times the connection out.
- **hopf-core `testing`:** `Endpoint::fail` on the test endpoint now behaves as
  on a real connection: it records the error, closes the endpoint and reports
  the error to the handler, instead of doing nothing.
- **hopf-core:** a connection closed because its outbound buffer overflowed
  (or a TLS send failed) now reports the error to the protocol handler
  before `disconnected`, instead of closing silently. A connection closed
  from inside `connected` is likewise now closed properly, so its handler
  hears `disconnected`; before, it was left registered and never notified.
- **hopf-http:** an HTTP/1 client request that is still sending its body when
  the connection closes now fails with an error, instead of its handler
  never being called.

- **hopf-http:** the HTTP/1 client now runs a body writer's `on_body_writable`
  callback when the connection has drained what was written, not when the
  staging buffer is merely handed to the connection. A writer that carries on
  at every callback no longer outruns a slow peer and overflows the 4 MiB
  outbound buffer, which closed the connection.
- **hopf-core:** `Endpoint::on_write_ready` now also runs when it is registered
  with nothing buffered; before, no write event was requested for an empty
  buffer, so the callback never ran.

### Breaking changes

- **hopf-dns:** `DnsQueryHandler` is callback-shaped (#525). `handle_query` and
  `handle_non_query_opcode` take a `DnsQueryCallback` and return nothing. The
  callback is completed exactly once, with `respond`, `respond_sequence`,
  `decline` or `error`, before the method returns or later from any thread, so
  a handler that waits on a client (a Redis round trip, an upstream query) no
  longer holds the listener. The answer is delivered on the connection's own
  reactor; cookie handling, TSIG signing and UDP truncation happen when it is
  ready. Stream transports write each answer as it completes, so several
  queries on one connection may be answered out of order (RFC 7766
  section 6.2.1.1). A callback dropped without being completed is logged and
  answered `SERVFAIL`. `HandlerOutcome` is no longer public.
  - **Migration:** a handler that returns its answer straight away implements
    the new `SyncDnsQueryHandler::resolve(&self, &DnsMessage, &QueryContext)
    -> Option<DnsMessage>` (`None` declines) with no other change, and is
    adapted automatically. `FnHandler` and `EmptyHandler` already are. A
    handler that has to wait implements `DnsQueryHandler` directly.
  - `MetricsSink` no longer has a lifetime and is `Clone`, so a handler can
    keep it for a later answer. `QueryContext::metrics` has that type.
  - `DnsService::process_on`, `process_query_sync` and `process_wire` now wait
    for the answer and are for tests and callers off the reactor. The
    listeners use the new non-blocking `DnsService::dispatch_wire`.
- **hopf-dns:** `QueryContext` carries the whole connection (#524), and is
  owned. It has no lifetime, is `Clone` and `#[non_exhaustive]`, and is read
  through accessors (`peer()`, `local()`, `transport()`, `tsig_key()`,
  `security()`, `sni()`, `peer_certificate_chain()`, `metrics()`) instead of
  public fields; `QueryContext<'_>` in a handler signature becomes
  `QueryContext`. A handler that answers later keeps a clone and reads the
  client's mTLS identity from its own callback. `FnHandler::on_opcode` is
  unchanged; `on_query_ctx` and `on_opcode_ctx` add closures that take the
  context.
  - **New:** `ConnectionInfo { peer, local, security }` and
    `DnsService::{dispatch_wire_with, process_wire_with, process_on_with}`.
    `dispatch_wire`, `process_wire` and `process_on` are thin wrappers that
    know only the peer. The TCP, DoT and DoQ listeners fill in the local
    address and the connection's shared `SecurityInfo` (client certificate
    chain and SNI); the UDP listener fills in its bound address.
- **hopf-dns:** `ForwarderHandler` no longer blocks the listener thread while
  it waits for its upstream. The upstream timeout and the RFC 8767 client
  response timer run on the resolver's reactor, and the answer is delivered
  when the upstream replies or the timer fires, whichever is first.

### Changed

- **hopf-core: application data written together shares TLS records** (#545).
  On a TLS connection (1.2 and 1.3), `Endpoint::send` no longer seals a record
  per call: what a handler writes in one event is held, up to a record's worth
  at a time, and sealed together just before the socket is written to, which is
  at the end of the event, so nothing waits and latency is unchanged. A write
  as large as a record is sealed as it is, without a copy; a close seals what
  is held before the `close_notify`; and the held bytes count against
  `max_net_out`. Writing 200,000 small (20-byte) pieces in one callback was
  200,000 records and 8.4 MB (TLS 1.3) on the wire; it is 245 records and 4.0
  MB (the data itself), and took 12 ms instead of 204 ms. The peer decrypts,
  and an observer sees, the record boundaries of the connection and no longer
  the boundaries of the application's writes.
- **hopf-webdav (behaviour change):** RFC 3744 privileges are now enforced
  whenever a `role_policy` is set; before, they were only reported (#512).
  A method runs only if the authenticated user holds the privileges RFC 3744
  appendix B requires for it, and is otherwise refused with `403` and the
  `DAV:need-privileges` precondition. A deployment that set `role_policy` only
  to report privileges must give its users the `webdav:*` roles they need, and
  authenticate them; a request with no authenticated user holds no
  privileges. Privileges are roles, held on every resource: per-resource ACLs
  and the `ACL` method are still not supported.
- Unit tests (`cargo test --lib`) do no socket or file I/O and do not wait
  for the clock. Those that do are behind each crate's `integration` feature.
  `scripts/check-hermetic-tests.sh` runs the unit tests with no network and a
  read-only filesystem, and CI runs it. `hopf-mailbox`, `hopf-ldap` and
  `hopf-otel` have gained an `integration` feature for this.

## 0.7.0 - 2026-11-01

### Breaking changes

- **hopf-core:** `ProtocolHandler::receive` takes the connection's inbound
  ring, `&mut LoopBuf`, instead of a slice cursor. The ring is fixed in size
  for the life of the connection: consume whole tokens only, and the rest is
  presented again with the next bytes. `receive_slice` is removed. Handlers
  that still want a contiguous cursor can read the ring through
  `hopf_core::with_slice`. `forward_slice` remains for code (a test, say) that
  holds a cursor.
- **hopf-auth:** HTTP Digest offers SHA-256 and uses it by default; MD5 is
  used only when asked for. DIGEST-MD5 is removed.
- **hopf-pop3:** APOP and `CredentialStore::plaintext_password` are removed.
- **hopf-mqtt:** the client driver trait has a new required method,
  `on_publish_failed`, called when the broker refuses a QoS 1 or QoS 2 publish
  (MQTT 5.0 reason codes of 0x80 and above).
- **hopf-webdav:** the Multi-Status parser reads a document as it arrives.
  Events are delivered by each `feed`, only an unfinished token is kept, and a
  parse error is reported by the `feed` that reaches it. A response with
  several hrefs now reports each: the first goes to `start_response` and the
  others to the new `MultiStatusHandler::additional_href`.
- **hopf-grpc:** `ProtoModelSerializer::start_field` returns a `Result`, and
  `end_field` takes the writer and the ring and returns a `Result`. They used
  to write nothing.
- **hopf-smtp:** `DsnAction` has a new variant, `Delayed`.
- **New public fields** on configuration structs, which matter only to code
  that builds them with a struct literal and no `..Default::default()`:
  `FtpConfig::login_limits` and `HttpClientTimeouts::attempt_delay`.

### Behaviour changes to be aware of

- **SMTP relay:** a message is accepted (250) once it is in the relay's
  on-disk queue, and delivered from there. A temporary failure from the next
  hop (a 4xx reply, or no reply at all) is retried with backoff until the
  maximum queue lifetime (five days by default), then bounced. A permanent
  failure (5xx) is bounced at once. Both are decided per recipient. Before,
  a message that nothing could take got a 450 and the sender's client did the
  retrying. Without `RelayOptions::with_queue_dir` the queue is in a private
  temporary directory and does not survive a restart.
- **FTP:** failed logins are limited by default: a connection is closed after
  3, each failure is answered a second late, and a source address with 10
  failures in ten minutes is refused for ten minutes. Use
  `LoginLimits::unlimited()` for the old behaviour.
- **IMAP, POP3 and FTP:** implicit TLS configured without a TLS acceptor no
  longer serves cleartext on the TLS port. `start()` fails with
  `InvalidInput`, and a listener composed by hand refuses every connection.
  `FtpService::start` also fails with `NotFound` if the root is not a
  directory.
- **POP3:** `transaction_timeout` is enforced by a timer. Before, it was
  checked only when the next command arrived, so an idle session was never
  ended.
- **HTTP client:** a name that resolves to several addresses is connected to
  as RFC 8305 describes (see below), and a failure to connect or resolve now
  reaches the application. On the `ClientHandler` path it arrives as
  `request_failed`; before, it was only logged.

### Added

- **hopf-smtp:**
  - A durable relay queue (`RelayQueue`, configured by `RelayOptions`) with
    per-recipient retry, bounce and delay notices. A recipient still queued
    after a configurable interval (four hours by default) makes the relay send
    one `Action: delayed` notice (RFC 3464), as RFC 3461 asks for by default.
  - `SmtpSend::on_recipients` reports each recipient's outcome. A recipient
    refused at `RCPT TO` is no longer lost behind a plain `Delivered` when
    another recipient is accepted.
- **Every server service:** `stop()` on `ImapService`, `Pop3Service`,
  `FtpService` and `MqttService` stops accepting connections. Open sessions
  carry on. Without it nothing could release the `Runtime`, so it could not be
  shut down cleanly.
- **hopf-ftp:** `LoginLimits`, set with `FtpConfig::with_login_limits`.
- **hopf-http:**
  - Connecting to the addresses of a name as RFC 8305 (Happy Eyeballs
    version 2) describes: the families alternate, the next address is tried
    after `HttpClientTimeouts::attempt_delay` (250 ms by default) or at once
    when the previous fails, and the first connection to be established wins.
    The application's handler is made only for that connection. HTTP/3 dials
    are unchanged.
- **hopf-grpc:**
  - The proto3 JSON mapping of `Timestamp` (RFC 3339), `Duration`
    (`1.5s`), `FieldMask` (camelCase paths) and the wrapper types (the bare
    value), in both directions.
  - `Struct`, `Value`, `ListValue` and `NullValue` as built-in types, mapped to
    and from arbitrary JSON, nested at most 100 deep. `Any` is still an
    ordinary message.
  - Repeated fields, repeated messages and maps in the JSON serializer.
  - `GrpcResponseMessage::start_field` and `end_field`, so a handler can write
    nested messages, repeated fields and map entries, with the same calls for
    `application/grpc` and `application/grpc+json`.
- **hopf-core `testing`:** `Peer` can run a handler on binary input and
  output, fail a connection, make a connection secure, and fire the timers a
  handler scheduled while it is pumped.

### Changed

- Parsers and codecs read the connection's ring as the bytes arrive and keep
  only an unfinished token, rather than collecting input first: HTTP/1,
  HTTP/2, HTTP/3, QUIC streams, the TLS record engines, IMAP, POP3, FTP, SMTP,
  MQTT and NNTP. IMAP command arguments are read by a progressive grammar
  machine per verb, and the IMAP client builds its structured payloads token by
  token.
- Depends on the crates.io releases of `loopbuf`, `rjsonparser`, `rprotobuf`,
  `rmimeparser` and `tractrix`.

### Fixed

- **hopf-imap:** `BODY.PEEK` fetches are answered with `BODY[...]`; pipelined
  commands run in order and each `APPEND` has its own spool; a missing
  destination is answered `[TRYCREATE]` and a failed `SELECT` keeps the
  session; the first SASL message is prompted for and the acknowledgement of
  the last is awaited; `AUTHENTICATE` sends its initial response only when the
  server advertises `SASL-IR`; every capability in a `CAPABILITY` response code
  is read; a non-synchronizing literal sent after a refused command is
  skipped.
- **hopf-mailbox:** a Maildir mailbox keeps the session's own changes when it
  is refreshed; address searches match display names.
- **hopf-smtp:**
  - A pipelined session whose sender or every recipient was refused with a
    4xx no longer reports the 503/554 that follows as the outcome.
  - No failure notice is sent for a message that is being deferred.
  - A hang-up is reported to the sender instead of dropping its callbacks.
  - A message that went over the limit is read to the end before it is
    refused.
  - 235 waits for the client's empty line after the final SASL data.
  - SPF dual CIDR lengths are read as RFC 7208 writes them.
  - DMARC falls back to the organizational domain when there is no record at
    the name.
- **hopf-http:**
  - A client-supplied authenticated-user header is dropped at the request
    boundary on every transport, and after Bearer authentication.
  - Relative, query-only and dot-segment redirect `Location` values are
    resolved as RFC 3986 says.
  - A request is counted as in flight before it is sent, so an upgrade is not
    missed.
- **hopf-webdav:** the privileges contained in a role's privilege are
  reported, such as `bind` under `write`; Multi-Status structure is recognised
  only in the `DAV:` namespace.
- **hopf-mqtt:** DISCONNECT is sent on MQTT 3.1.1 so the broker does not
  publish the Will; 3.1.1 sessions with CleanSession 0 are kept across
  disconnects.
- **hopf-ftp:**
  - The authorization hook is asked before listing, sizing or stat-ing a path.
  - `PASV` and `EPSV` try each port of a configured range, where they tried
    one random port and answered 425 if it was taken.
  - A root that has gone away costs the connection a 421. Before, it panicked
    on the accept thread and stopped every listener of the runtime from
    accepting.
- **hopf-grpc:** type names are resolved after the whole `.proto` file is
  read; packed repeated fields and map entries are decoded from protobuf wire
  data; a long value after a key in a JSON response no longer repeats the key
  when the response buffer has to grow.
- **hopf-socks:** the first outcome of a CONNECT or UDP ASSOCIATE is kept.
- **hopf-otel:** a non-default port is included in the OTLP `Host` header.
- **hopf-mdns:** an empty TXT record is never published.

### Known issues

- **hopf-webdav:** ACL privileges (RFC 3744) are computed and reported, but
  no method checks them before it runs. Enforcement is planned for 0.7.1
  (#512).
- Some timing-dependent tests are flaky on slow machines and have been
  disabled or are to be reworked.
