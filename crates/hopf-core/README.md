# hopf-core

Thread-per-core (TPC) readiness reactor, `Endpoint` / `ProtocolHandler` /
`Service` / `Listener` / `Connector` traits, buffer pools, timers, and
`StorageExecutor` for blocking filesystem work. Bind
(`Runtime::add_tcp_listener`) and dial (`Runtime::connect`) are peer birth
paths for TCP Endpoints.

## Quick start

```rust
use hopf_core::{Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};

struct Echo;
impl ProtocolHandler for Echo {
    fn connected(&mut self, _: &mut dyn Endpoint) {}
    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        endpoint.send(data);
        *data = &[];
    }
    fn disconnected(&mut self, _: &mut dyn Endpoint) {}
    fn error(&mut self, _: &mut dyn Endpoint, _: &std::io::Error) {}
}

fn main() -> std::io::Result<()> {
    let rt = Runtime::start(RuntimeConfig::default())?;
    rt.add_tcp_listener(TcpListenerConfig::new(
        "127.0.0.1:8080".parse().unwrap(),
        || Box::new(Echo),
    ))?;
    // Blocking FS: rt.storage().submit(endpoint, || std::fs::read(...), |result| { ... });
    Ok(())
}
```

See workspace [PLAN.md](../../PLAN.md) and [TRANCHES.md](../../TRANCHES.md).
Run `cargo run -p echo` for a live echo server.
