# hopf-grpc

Unary gRPC over Hopf HTTP Streams: length-prefixed framing, runtime
`.proto` model (`ProtoFile`), schema-aware push events via `rprotobuf`, and
`ServerHandler` / client bindings.

Same architecture as Gumdrop’s `org.bluezoo.gumdrop.grpc` package — no generated
stubs, no message DOM at the application boundary.
