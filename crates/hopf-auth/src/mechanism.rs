// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL mechanism names (Gumdrop `SASLMechanism`, excluding GSSAPI).

/// Supported SASL mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaslMechanism {
    /// RFC 4616 — requires TLS in production.
    Plain,
    /// Legacy two-step Base64 username/password (`draft-murchison-sasl-login`).
    Login,
    /// RFC 2195.
    CramMd5,
    /// RFC 2831 (deprecated by RFC 6331; kept for parity).
    DigestMd5,
    /// RFC 5802 / RFC 7677.
    ScramSha256,
    /// RFC 7628.
    OauthBearer,
    /// RFC 4422 Appendix A — TLS client certificate.
    External,
}

impl SaslMechanism {
    /// Wire name (e.g. `SCRAM-SHA-256`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
            Self::CramMd5 => "CRAM-MD5",
            Self::DigestMd5 => "DIGEST-MD5",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::OauthBearer => "OAUTHBEARER",
            Self::External => "EXTERNAL",
        }
    }

    /// Parse wire name (case-insensitive). GSSAPI returns `None`.
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "PLAIN" => Some(Self::Plain),
            "LOGIN" => Some(Self::Login),
            "CRAM-MD5" => Some(Self::CramMd5),
            "DIGEST-MD5" => Some(Self::DigestMd5),
            "SCRAM-SHA-256" => Some(Self::ScramSha256),
            "OAUTHBEARER" => Some(Self::OauthBearer),
            "EXTERNAL" => Some(Self::External),
            _ => None,
        }
    }

    /// Whether the mechanism is a challenge/response exchange (not cleartext password).
    pub fn is_challenge_response(self) -> bool {
        matches!(
            self,
            Self::CramMd5 | Self::DigestMd5 | Self::ScramSha256
        )
    }

    /// Whether Gumdrop marks the mechanism as requiring TLS.
    pub fn requires_tls(self) -> bool {
        matches!(
            self,
            Self::Plain | Self::Login | Self::OauthBearer | Self::External
        )
    }

    /// All mechanisms shipped in this crate (no GSSAPI).
    pub fn all() -> &'static [SaslMechanism] {
        &[
            Self::Plain,
            Self::Login,
            Self::CramMd5,
            Self::DigestMd5,
            Self::ScramSha256,
            Self::OauthBearer,
            Self::External,
        ]
    }
}

impl std::fmt::Display for SaslMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
