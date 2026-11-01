// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL mechanism filtering for CAPA / AUTH.

use std::sync::Arc;

use hopf_auth::{CredentialStore, SaslMechanism};

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

    #[test]
    fn the_capa_sasl_line_lists_the_mechanisms_in_order() {
        assert_eq!(capa_sasl_line(&[]), None);
        assert_eq!(
            capa_sasl_line(&[SaslMechanism::ScramSha256, SaslMechanism::Plain]).as_deref(),
            Some("SASL SCRAM-SHA-256 PLAIN")
        );
    }
}
