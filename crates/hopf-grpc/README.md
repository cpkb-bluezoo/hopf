# hopf-grpc

Unary and streaming gRPC over Hopf HTTP Streams: length-prefixed framing, runtime
`.proto` model (`ProtoFile`), schema-aware push events via `rprotobuf`, and
`ServerHandler` / client bindings.

Same architecture as Gumdrop’s `org.bluezoo.gumdrop.grpc` package - no generated
stubs, no message DOM at the application boundary.

Messages may be compressed per the gRPC HTTP/2 protocol (`grpc-encoding` /
`grpc-accept-encoding`): `gzip` and `deflate` are decoded by default and `br`
when enabled with `encodings(..)`. The server compresses responses the client
accepts (`compress_responses`, `compression_threshold`) and
`GrpcClient::compression` compresses requests. A message that expands beyond
the maximum message size is `RESOURCE_EXHAUSTED`, a corrupt one `INTERNAL`,
and a request in an encoding the server does not offer is `UNIMPLEMENTED`.

A client names the server it calls with `GrpcClient::authority` (sent as
`:authority`; servers built on gRPC core refuse a call without one).

## Interoperability tests

`tests/grpcio_interop.rs` runs every kind of RPC, metadata (including `-bin`),
deadlines, gzip and deflate and empty messages in both directions against
grpcio, Python's gRPC implementation: Hopf's client against a grpcio server,
and a grpcio client against a Hopf server. The Python side is built from
`tests/grpcio` and run in a container, so podman or docker is needed at test
time (set `HOPF_CONTAINER_RUNTIME` to choose one); without either the tests
say so and pass without running. They are not part of the default CI job:

```bash
cargo test -p hopf-grpc --features integration --test grpcio_interop
```
