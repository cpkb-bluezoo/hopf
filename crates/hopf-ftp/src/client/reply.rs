// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP control-channel reply type and address-parsing helpers.

use std::net::{Ipv4Addr, SocketAddr};

use super::error::{FtpError, FtpResult};

// ---------------------------------------------------------------------------
// Reply type
// ---------------------------------------------------------------------------

/// One FTP reply (possibly multiline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpReply {
    /// Three-digit reply code.
    pub code: u16,
    /// Text lines (all continuation bodies plus the terminating line text).
    pub lines: Vec<String>,
}

impl FtpReply {
    /// Primary text: first line, or all lines joined with newlines.
    pub fn text(&self) -> String {
        if self.lines.len() == 1 {
            self.lines[0].clone()
        } else {
            self.lines.join("\n")
        }
    }
}

// ---------------------------------------------------------------------------
// Address-parsing helpers (kept for async client and external users)
// ---------------------------------------------------------------------------

/// Parse a `227` PASV reply text into a [`SocketAddr`].
///
/// Expects the canonical form `(h1,h2,h3,h4,p1,p2)` anywhere in `text`.
pub fn parse_pasv_addr(text: &str) -> FtpResult<SocketAddr> {
    let start = text
        .find('(')
        .ok_or_else(|| FtpError::Parse(format!("PASV: no '(' in {text:?}")))?
        + 1;
    let end = text[start..]
        .find(')')
        .ok_or_else(|| FtpError::Parse(format!("PASV: no ')' in {text:?}")))?
        + start;
    let parts: Vec<&str> = text[start..end].split(',').collect();
    if parts.len() != 6 {
        return Err(FtpError::Parse(format!("PASV: expected 6 fields, got {}", parts.len())));
    }
    let mut nums = [0u16; 6];
    for (i, p) in parts.iter().enumerate() {
        nums[i] = p
            .trim()
            .parse()
            .map_err(|_| FtpError::Parse(format!("PASV: bad number {:?}", p)))?;
    }
    let ip = Ipv4Addr::new(nums[0] as u8, nums[1] as u8, nums[2] as u8, nums[3] as u8);
    let port = nums[4] * 256 + nums[5];
    Ok(SocketAddr::from((ip, port)))
}

/// Parse a `229` EPSV reply text into the data port number.
///
/// Expects `(|||port|)` or `(|af|addr|port|)` anywhere in `text`.
pub fn parse_epsv_port(text: &str) -> FtpResult<u16> {
    let start = text
        .find('(')
        .ok_or_else(|| FtpError::Parse(format!("EPSV: no '(' in {text:?}")))?
        + 1;
    let end = text[start..]
        .find(')')
        .ok_or_else(|| FtpError::Parse(format!("EPSV: no ')' in {text:?}")))?
        + start;
    let inner = &text[start..end];
    // Format: `|||port|` or `|af|addr|port|`
    let parts: Vec<&str> = inner.split('|').collect();
    let port_str = parts
        .iter()
        .rev()
        .find(|p| !p.is_empty())
        .copied()
        .ok_or_else(|| FtpError::Parse(format!("EPSV: no port in {text:?}")))?;
    port_str
        .parse()
        .map_err(|_| FtpError::Parse(format!("EPSV: bad port {port_str:?}")))
}

/// Parse a `257` PWD reply and extract the quoted path.
///
/// Returns `None` when no double-quoted string is found.
pub fn parse_pwd_path(text: &str) -> Option<String> {
    let start = text.find('"')?;
    let end = text[start + 1..].find('"')? + start + 1;
    Some(text[start + 1..end].replace("\"\"", "\""))
}
