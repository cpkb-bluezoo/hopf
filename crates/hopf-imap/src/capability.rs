// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP CAPABILITY string construction.

use crate::ImapConfig;

/// Build the space-separated capability list advertised to clients.
///
/// Only extensions that are implemented and enabled in [`ImapConfig`] are
/// included. Pre-auth capabilities differ from post-auth.
pub fn build_capabilities(config: &ImapConfig, authenticated: bool, tls: bool) -> String {
    let mut caps = vec!["IMAP4rev2".to_string()];

    if !authenticated && !tls && config.tls_acceptor.is_some() && !config.implicit_tls {
        caps.push("STARTTLS".to_string());
    }

    if !authenticated {
        caps.push("AUTH=PLAIN".to_string());
        if !tls && config.tls_acceptor.is_some() && !config.implicit_tls {
            caps.push("LOGINDISABLED".to_string());
        }
    }

    if authenticated {
        if config.enable_idle {
            caps.push("IDLE".to_string());
        }
        if config.enable_namespace {
            caps.push("NAMESPACE".to_string());
        }
        if config.enable_quota {
            caps.push("QUOTA".to_string());
        }
        if config.enable_move {
            caps.push("MOVE".to_string());
        }
        if config.enable_condstore {
            caps.push("CONDSTORE".to_string());
        }
        if config.enable_qresync {
            caps.push("QRESYNC".to_string());
        }
    }

    // Always advertised when implemented (independent of auth).
    caps.push("UNSELECT".to_string());
    caps.push("UIDPLUS".to_string());
    caps.push("CHILDREN".to_string());
    caps.push("LIST-EXTENDED".to_string());
    caps.push("LIST-STATUS".to_string());
    caps.push("LITERAL-".to_string());
    caps.push("ID".to_string());
    if config.enable_enable {
        caps.push("ENABLE".to_string());
    }

    caps.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_auth::PasswordStore;
    use hopf_mailbox::MaildirFactory;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn test_config(enable_idle: bool) -> ImapConfig {
        let dir = tempdir().unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut cfg = ImapConfig::new(
            addr,
            "localhost",
            Arc::new(PasswordStore::new()),
            Arc::new(MaildirFactory::new(dir.path())),
        );
        cfg.enable_idle = enable_idle;
        cfg.enable_quota = false;
        cfg.enable_move = false;
        cfg.enable_namespace = false;
        cfg.enable_condstore = false;
        cfg.enable_qresync = false;
        cfg
    }

    #[test]
    fn capability_truthfulness_pre_auth() {
        let cfg = test_config(true);
        let caps = build_capabilities(&cfg, false, false);
        assert!(caps.contains("IMAP4rev2"));
        assert!(caps.contains("UIDPLUS"));
        assert!(caps.contains("UNSELECT"));
        assert!(caps.contains("LIST-EXTENDED"));
        assert!(caps.contains("ID"));
        assert!(!caps.contains(" IDLE"));
        assert!(!caps.contains("MOVE"));
        assert!(!caps.contains("NAMESPACE"));
        assert!(!caps.contains("QUOTA"));
        assert!(!caps.contains("CONDSTORE"));
    }

    #[test]
    fn capability_truthfulness_authenticated() {
        let cfg = test_config(true);
        let caps = build_capabilities(&cfg, true, true);
        assert!(caps.contains("IDLE"));
        assert!(caps.contains("ENABLE"));
        assert!(!caps.contains("STARTTLS"));
        assert!(!caps.contains("LOGINDISABLED"));
    }

    #[test]
    fn disabled_idle_not_advertised() {
        let cfg = test_config(false);
        let caps = build_capabilities(&cfg, true, true);
        assert!(!caps.split_whitespace().any(|c| c == "IDLE"));
    }
}
