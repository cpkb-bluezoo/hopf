// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP server authenticated via LDAP search-then-bind (`LdapCredentialStore`).
//!
//! ```text
//! cargo run -p smtp-ldap -- 127.0.0.1:2525 ldap.example.com dc=example,dc=com
//!
//! Optional env:
//!   LDAP_BIND_DN / LDAP_BIND_PASSWORD  — service bind
//!   LDAP_USER_FILTER                   — default (uid={0})
//!   LDAP_PORT                          — default 389
//!   LDAP_CA_PEM                        — if set, dial LDAPS with this CA + SNI=host
//! ```
//!
//! Note: SASL/`password_match` for this store must run off the reactor
//! (storage/worker pool). Hopf mail AUTH call sites that use LDAP should
//! not invoke the store on a reactor thread.

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_ldap::{LdapCredentialStore, LdapStoreConfig, DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT};
use hopf_smtp::{SmtpConfig, SmtpService};

fn main() -> io::Result<()> {
    let listen: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2525".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let ldap_host = env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1".into());
    let base_dn = env::args()
        .nth(3)
        .unwrap_or_else(|| "dc=example,dc=com".into());
    let hostname = env::args()
        .nth(4)
        .unwrap_or_else(|| "localhost".into());

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);

    let mut store_cfg = LdapStoreConfig::new(&ldap_host, &base_dn, Arc::clone(&rt))
        .with_timeout(Duration::from_secs(15));

    if let Ok(port) = env::var("LDAP_PORT") {
        store_cfg = store_cfg.with_port(
            port.parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        );
    }

    if let (Ok(dn), Ok(pw)) = (env::var("LDAP_BIND_DN"), env::var("LDAP_BIND_PASSWORD")) {
        store_cfg = store_cfg.with_bind(dn, pw);
    }
    if let Ok(filter) = env::var("LDAP_USER_FILTER") {
        store_cfg = store_cfg.with_user_filter(filter);
    }

    if let Ok(ca) = env::var("LDAP_CA_PEM") {
        let connector = hopf_tls::connector_from_pem(Path::new(&ca), &[])?;
        let port = store_cfg.port;
        if port == DEFAULT_LDAP_PORT {
            store_cfg = store_cfg.with_port(DEFAULT_LDAPS_PORT);
        }
        let _ = port;
        store_cfg = store_cfg.with_ldaps(connector, ldap_host.clone());
    }

    let store = Arc::new(LdapCredentialStore::new(store_cfg));
    let config = SmtpConfig::new(listen, hostname.clone())
        .with_store(store)
        .auth_required(true);
    let service = SmtpService::new(config);
    let bound = service.start(Arc::clone(&rt))?;

    eprintln!(
        "smtp-ldap on smtp://{bound}/  hostname={hostname}  ldap={ldap_host} base={base_dn}"
    );
    eprintln!("AUTH: PLAIN/LOGIN via LdapCredentialStore (off-reactor password_match)");
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    drop(rt);
    Ok(())
}
