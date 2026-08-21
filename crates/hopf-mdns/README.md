# hopf-mdns

Multicast DNS (RFC 6762) and DNS-SD (RFC 6763) for Hopf (Gumdrop-parity,
with a push-based service API instead of Gumdrop's central-registry pull —
Hopf has no server-wide listener registry to walk).

## Features

| Feature | Enables |
|---------|---------|
| (default) | Responder (probe/announce/goodbye), querier + cache, DNS-SD advertise/browse |
| `integration` | Real loopback-multicast round-trip tests (`tests/`) |

## Not in scope (v1)

IPv6 mDNS (`ff02::fb`) — matches Gumdrop's own stated limitation.

## Quick start

```rust,no_run
use std::sync::Arc;
use hopf_core::Runtime;
use hopf_mdns::{MdnsService, ServiceRegistration};

let rt = Arc::new(Runtime::start(Default::default())?);
let mdns = MdnsService::start(&rt, "my-host")?;

mdns.register_service(ServiceRegistration {
    service_type: "_http._tcp".into(),
    instance_name: "My Web Server".into(),
    port: 8080,
    txt: vec![("path".into(), "/".into())],
});
# Ok::<(), std::io::Error>(())
```
