// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! APOP challenge helpers and SASL mechanism filtering.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hopf_auth::crypto::{ct_eq_hex, md5_hex};
use hopf_auth::{CredentialStore, SaslMechanism};

/// Build an APOP timestamp `<pid.millis@hostname>`.
pub fn apop_timestamp(hostname: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("<{pid}.{millis}@{hostname}>")
}

/// Verify an APOP digest: `MD5(timestamp || password)` as lowercase hex.
pub fn verify_apop(
    store: &dyn CredentialStore,
    username: &str,
    timestamp: &str,
    digest_hex: &str,
) -> bool {
    let Some(password) = store.plaintext_password(username) else {
        // Fall back: only works if store keeps plaintext; otherwise reject.
        return false;
    };
    let mut data = Vec::with_capacity(timestamp.len() + password.len());
    data.extend_from_slice(timestamp.as_bytes());
    data.extend_from_slice(password.as_bytes());
    let expected = md5_hex(&data);
    ct_eq_hex(digest_hex, &expected)
}

/// Mechanisms advertised for CAPA / AUTH, filtered by TLS state.
pub fn advertised_mechanisms(
    store: &Arc<dyn CredentialStore>,
    tls: bool,
) -> Vec<SaslMechanism> {
    store
        .supported_mechanisms()
        .into_iter()
        .filter(|m| tls || !m.requires_tls())
        .collect()
}

/// Format CAPA `SASL …` line (without trailing CRLF), or `None` if empty.
pub fn capa_sasl_line(mechs: &[SaslMechanism]) -> Option<String> {
    if mechs.is_empty() {
        return None;
    }
    let mut s = String::from("SASL");
    for m in mechs {
        s.push(' ');
        s.push_str(m.name());
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_auth::{
        CertificateIdentity, Cb, CredentialStore, PasswordStore, ScramCredentials, TokenValidation,
    };

    /// APOP needs a recoverable secret; `PasswordStore` deliberately does not
    /// retain plaintext. This stub is only for the APOP unit test.
    struct PlaintextStub {
        user: String,
        pass: String,
    }

    impl CredentialStore for PlaintextStub {
        fn password_match(&self, username: &str, password: &str) -> bool {
            username == self.user && password == self.pass
        }
        fn plaintext_password(&self, username: &str) -> Option<String> {
            (username == self.user).then(|| self.pass.clone())
        }
        fn digest_ha1(&self, _: &str, _: &str) -> Option<String> {
            None
        }
        fn scram_credentials(&self, _: &str) -> Option<ScramCredentials> {
            None
        }
        fn validate_bearer(&self, _: &str, cb: Cb<Option<TokenValidation>>) {
            cb(None);
        }
        fn authenticate_certificate(&self, _: &str) -> Option<CertificateIdentity> {
            None
        }
    }

    #[test]
    fn apop_roundtrip() {
        let store = PlaintextStub {
            user: "alice".into(),
            pass: "secret".into(),
        };
        let ts = "<1.2@localhost>";
        let mut data = Vec::new();
        data.extend_from_slice(ts.as_bytes());
        data.extend_from_slice(b"secret");
        let digest = md5_hex(&data);
        assert!(verify_apop(&store, "alice", ts, &digest));
        assert!(!verify_apop(&store, "alice", ts, "deadbeef"));
    }

    #[test]
    fn password_store_does_not_support_apop() {
        let store = PasswordStore::new().with_user("alice", "secret");
        assert!(!verify_apop(&store, "alice", "<1.2@localhost>", "anything"));
    }
}
