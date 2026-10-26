// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NSS key log format for TLS 1.3 secrets (Wireshark and QUIC interop).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Receives derived TLS secrets in NSS key log format (`label client_random secret`, hex).
pub trait KeyLog: Send + Sync {
    /// Record one secret. `client_random` is the ClientHello random (32 bytes).
    fn log(&self, label: &str, client_random: &[u8; 32], secret: &[u8]);
}

/// NSS labels for TLS 1.3.
pub mod labels {
    /// 0-RTT client traffic secret.
    pub const CLIENT_EARLY_TRAFFIC_SECRET: &str = "CLIENT_EARLY_TRAFFIC_SECRET";
    /// Client handshake traffic secret.
    pub const CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    /// Server handshake traffic secret.
    pub const SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    /// Exporter master secret.
    pub const EXPORTER_SECRET: &str = "EXPORTER_SECRET";

    /// Application traffic secret label for the client at `generation` (0 at handshake completion).
    pub fn client_traffic_secret(generation: u32) -> String {
        format!("CLIENT_TRAFFIC_SECRET_{generation}")
    }

    /// Application traffic secret label for the server at `generation`.
    pub fn server_traffic_secret(generation: u32) -> String {
        format!("SERVER_TRAFFIC_SECRET_{generation}")
    }
}

/// Environment variable read by [`KeyLogFile::from_environment`].
pub const SSLKEYLOGFILE_ENV: &str = "SSLKEYLOGFILE";

static DEFAULT_KEY_LOG: OnceLock<Mutex<Option<Arc<dyn KeyLog>>>> = OnceLock::new();

fn default_slot() -> &'static Mutex<Option<Arc<dyn KeyLog>>> {
    DEFAULT_KEY_LOG.get_or_init(|| Mutex::new(None))
}

/// Process-wide default key log ([`HandshakeConfig::key_log`] falls back to this).
pub fn set_default_key_log(key_log: Option<Arc<dyn KeyLog>>) {
    *default_slot().lock().unwrap_or_else(|e| e.into_inner()) = key_log;
}

/// Current process-wide default, if any.
pub fn default_key_log() -> Option<Arc<dyn KeyLog>> {
    default_slot().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Append NSS key log lines to a file, flushed after each line.
#[derive(Debug)]
pub struct KeyLogFile {
    // Never read programmatically -- kept only so `#[derive(Debug)]` shows
    // which file a `KeyLogFile` points at.
    #[allow(dead_code)]
    path: PathBuf,
    writer: Mutex<File>,
}

impl KeyLogFile {
    /// Open `path` for append (create if missing).
    pub fn open(path: impl AsRef<Path>) -> io::Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Arc::new(Self {
            path,
            writer: Mutex::new(file),
        }))
    }

    /// Open `SSLKEYLOGFILE` when set.
    pub fn from_environment() -> io::Result<Option<Arc<Self>>> {
        match std::env::var(SSLKEYLOGFILE_ENV) {
            Ok(path) if !path.is_empty() => Ok(Some(Self::open(path)?)),
            _ => Ok(None),
        }
    }
}

impl KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8; 32], secret: &[u8]) {
        let mut line = String::with_capacity(label.len() + 2 * (32 + secret.len()) + 3);
        line.push_str(label);
        line.push(' ');
        append_hex(&mut line, client_random);
        line.push(' ');
        append_hex(&mut line, secret);
        line.push('\n');
        if let Ok(mut w) = self.writer.lock() {
            if w.write_all(line.as_bytes()).is_ok() {
                let _ = w.flush();
            }
        }
    }
}

fn append_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn file_key_log_appends_nss_lines() {
        let dir = std::env::temp_dir().join(format!("hopf-keylog-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("keys.log");
        let log = KeyLogFile::open(&path).unwrap();
        let random = [0x11u8; 32];
        let secret = [0x22u8; 32];
        log.log(labels::CLIENT_HANDSHAKE_TRAFFIC_SECRET, &random, &secret);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("CLIENT_HANDSHAKE_TRAFFIC_SECRET "));
        assert!(text.contains("1111111111111111"));
        let _ = fs::remove_dir_all(dir);
    }
}
