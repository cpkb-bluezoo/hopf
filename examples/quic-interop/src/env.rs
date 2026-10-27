// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! quic-interop-runner environment contract.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct InteropEnv {
    pub role: String,
    pub test_case: String,
    pub requests: Vec<String>,
    pub www: PathBuf,
    pub downloads: PathBuf,
    pub certs: PathBuf,
    pub port: u16,
}

impl InteropEnv {
    pub fn from_env() -> Self {
        let requests = std::env::var("REQUESTS")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        Self {
            role: std::env::var("ROLE").unwrap_or_default(),
            test_case: std::env::var("TESTCASE").unwrap_or_default(),
            requests,
            www: PathBuf::from(env_or("INTEROP_WWW", "/www")),
            downloads: PathBuf::from(env_or("INTEROP_DOWNLOADS", "/downloads")),
            certs: PathBuf::from(env_or("INTEROP_CERTS", "/certs")),
            port: env_or("INTEROP_PORT", "443").parse().unwrap_or(443),
        }
    }

    pub fn cert_file(&self) -> PathBuf {
        self.certs.join("cert.pem")
    }

    pub fn key_file(&self) -> PathBuf {
        self.certs.join("priv.key")
    }

    pub fn ca_file(&self) -> PathBuf {
        self.certs.join("ca.pem")
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}

pub fn enable_key_log() {
    if let Ok(Some(log)) = hopf_core::tls::KeyLogFile::from_environment() {
        eprintln!(
            "writing TLS secrets to {}",
            std::env::var(hopf_core::tls::SSLKEYLOGFILE_ENV).unwrap_or_default()
        );
        hopf_core::tls::set_default_key_log(Some(log));
    }
}

/// Keep the export worker alive for the process lifetime.
pub fn enable_qlog_pipeline() -> Option<hopf_otel::TelemetryPipeline> {
    if std::env::var("QLOGDIR")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        return None;
    }
    eprintln!(
        "writing qlog to {}",
        std::env::var("QLOGDIR").unwrap_or_default()
    );
    let pipe = hopf_otel::TelemetryPipeline::start(
        hopf_otel::OtelConfig::new("quic-interop").with_default_stderr_if_empty(),
    )
    .ok()?;
    Some(pipe)
}
