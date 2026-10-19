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
