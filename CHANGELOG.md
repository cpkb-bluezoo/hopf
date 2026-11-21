# Changelog

All notable changes to hopf are recorded here. The workspace crates are
versioned together. Changes before 0.7.0 are in the git history and tags.

## Unreleased

### Added

- **hopf-redis (new crate):** an async Redis and Valkey client (#527), behind
  the `redis` feature of `hopf`. `RedisClient::connect(&reactor, RedisConfig)`
  is one pipelined connection bound to a reactor: commands from any thread, each
  reply a callback on the reactor, exactly once and in issue order. It negotiates
  RESP3 (`HELLO 3`) and falls back to RESP2, authenticates (password, or ACL
  user and password), selects a database, resolves host names through
  `hopf-dns` and speaks TLS through a `hopf-core` connector. Typed helpers cover
  strings, keys, hashes, lists, sets, sorted sets and scripts, `SetOptions`
  covers `SET`, `transaction` writes `MULTI`..`EXEC` as one batch, and `command`
  and `send` carry anything else. A command in flight when the connection is
  lost fails with `ConnectionLost` and is not sent again; a timed-out command's
  late reply is discarded in its place; after a failed connect commands fail
  fast for a growing time. `hopf_redis::resp` has the `Value` type, the command
  encoder and `RespParser`, an incremental parser with limits on bulk size,
  aggregate size, depth, line length and total reply size.
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
