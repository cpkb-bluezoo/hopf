# hopf-otel

OpenTelemetry for Hopf:

- **Connection logs** — `TelemetryPipeline::hook` implements `TelemetryHook`
- **HTTP request traces & metrics** — `InstrumentedServerFactory` at the
  Stream handler (Gumdrop-style; not TCP accept)
- **Exporters** — OTLP/HTTP (`/v1/logs`, `/v1/traces`, `/v1/metrics`) and JSONL

Hot-path methods only enqueue. Encoding and I/O run on a dedicated export worker.

```rust
use std::sync::Arc;
use hopf_otel::{InstrumentedServerFactory, OtelConfig, TelemetryPipeline};

let pipeline = TelemetryPipeline::start(
    OtelConfig::new("echo")
        .with_otlp_endpoint("http://127.0.0.1:4318"),
)?;

let factory = Arc::new(InstrumentedServerFactory::new(app_factory, &pipeline));
// attach factory to your HTTP endpoint; attach pipeline.hook() to Runtime
```

Outbound propagation:

```rust
use hopf_otel::with_traceparent;

let tp = response.traceparent();
let mut req = with_traceparent(client_writer, tp);
req.headers(outbound);
```

See [docs/telemetry.html](../../docs/telemetry.html).
