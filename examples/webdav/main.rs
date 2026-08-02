// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV file server example.
//!
//! ```text
//! cargo run -p webdav -- /tmp/webdav-root
//! cargo run -p webdav -- 127.0.0.1:8080 /path/to/files
//! WEBDAV_WRITE=1 cargo run -p webdav -- /tmp/webdav-root
//! ```
//!
//! Write is **off** by default. This demo uses
//! [`WebDavConfig::allow_unauthenticated_access`] for a cleartext loopback
//! server; production deployments should wrap the factory in
//! `hopf_http::BasicAuthFactory` / Digest / Bearer (or mTLS) instead of
//! relying on that flag alone.

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hopf_core::{
    storage::{StorageConfig, StorageExecutor},
    Runtime, RuntimeConfig, TcpListenerConfig,
};
use hopf_http::{CleartextHttpEndpoint, HttpLimits, ServerHandlerFactory};
use hopf_webdav::{DeadPropMode, WebDavConfig, WebDavFactory};

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let mut addr: Option<SocketAddr> = None;
    let mut root = env::var("WEBDAV_ROOT")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    while let Some(a) = args.next() {
        if let Ok(sa) = a.parse::<SocketAddr>() {
            addr = Some(sa);
        } else {
            root = PathBuf::from(a);
        }
    }

    let addr = addr.unwrap_or_else(|| "127.0.0.1:8080".parse().unwrap());
    let allow_write = env::var("WEBDAV_WRITE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let storage = Arc::new(StorageExecutor::new(StorageConfig::default()));
    let config = WebDavConfig {
        root_path: root.clone(),
        allow_write,
        webdav_enabled: true,
        welcome_file: "index.html".to_string(),
        dead_property_storage: DeadPropMode::Auto,
        allow_unauthenticated_access: true,
        ..Default::default()
    };
    let factory: Arc<dyn ServerHandlerFactory> =
        Arc::new(WebDavFactory::new(config, Arc::clone(&storage))?);
    let limits = HttpLimits::default();

    let rt = Runtime::start(RuntimeConfig::default())?;
    let factory2 = Arc::clone(&factory);
    let (bound, _) = rt.add_tcp_listener(TcpListenerConfig::new(addr, move || {
        Box::new(CleartextHttpEndpoint::new(Arc::clone(&factory2), limits))
            as Box<dyn hopf_core::ProtocolHandler>
    }))?;

    eprintln!(
        "webdav serving {} on http://{bound} (write={allow_write}, unauthenticated demo)",
        root.display()
    );
    eprintln!("press Enter to stop");

    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    rt.shutdown();
    Ok(())
}
