// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Control-channel reply parsing.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};

use super::error::{FtpError, FtpResult};

/// One FTP reply (possibly multiline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpReply {
    /// Three-digit reply code.
    pub code: u16,
    /// Lines of text (final line and any continuation bodies without the code prefix).
    pub lines: Vec<String>,
}

impl FtpReply {
    /// Primary text: first line, or joined lines.
    pub fn text(&self) -> String {
        if self.lines.len() == 1 {
            self.lines[0].clone()
        } else {
            self.lines.join("\n")
        }
    }
}

/// Read one complete reply from `r`.
pub fn read_reply(r: &mut dyn ReadWrite) -> FtpResult<FtpReply> {
    let first = read_line(r)?;
    if first.len() < 3 {
        return Err(FtpError::Parse(format!("short reply: {first:?}")));
    }
    let code: u16 = first[..3]
        .parse()
        .map_err(|_| FtpError::Parse(format!("bad code: {first}")))?;
    let sep = first.as_bytes().get(3).copied().unwrap_or(b' ');
    let mut lines = Vec::new();
    if sep == b'-' {
        let rest = first.get(4..).unwrap_or("").trim_end_matches(['\r', '\n']);
        if !rest.is_empty() {
            lines.push(rest.to_string());
        }
        loop {
            let line = read_line(r)?;
            if line.len() >= 4
                && line.as_bytes()[3] == b' '
                && line.as_bytes()[..3]
                    .iter()
                    .all(|b| b.is_ascii_digit())
                && line[..3].parse::<u16>().ok() == Some(code)
            {
                let rest = line.get(4..).unwrap_or("").trim_end_matches(['\r', '\n']);
                lines.push(rest.to_string());
                break;
            }
            lines.push(line.trim_end_matches(['\r', '\n']).to_string());
        }
    } else {
        let rest = first.get(4..).unwrap_or("").trim_end_matches(['\r', '\n']);
        lines.push(rest.to_string());
    }
    Ok(FtpReply { code, lines })
}

/// Object that is both [`Read`] and [`Write`] (control / data streams).
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn read_line(r: &mut dyn Read) -> FtpResult<String> {
    let mut buf = Vec::with_capacity(128);
    let mut b = [0u8; 1];
    loop {
        r.read_exact(&mut b)?;
        buf.push(b[0]);
        if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' && buf[buf.len() - 1] == b'\n' {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(FtpError::Parse("reply line too long".into()));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Parse `227` host/port from reply text.
pub fn parse_pasv_addr(text: &str) -> FtpResult<SocketAddr> {
    let start = text
        .find('(')
        .ok_or_else(|| FtpError::Parse(format!("PASV: {text}")))?
        + 1;
    let end = text[start..]
        .find(')')
        .ok_or_else(|| FtpError::Parse(format!("PASV: {text}")))?
        + start;
    let parts: Vec<&str> = text[start..end].split(',').collect();
    if parts.len() != 6 {
        return Err(FtpError::Parse(format!("PASV fields: {text}")));
    }
    let mut nums = [0u16; 6];
    for (i, p) in parts.iter().enumerate() {
        nums[i] = p
            .trim()
            .parse()
            .map_err(|_| FtpError::Parse(format!("PASV number: {p}")))?;
    }
    let ip = Ipv4Addr::new(
        nums[0] as u8,
        nums[1] as u8,
        nums[2] as u8,
        nums[3] as u8,
    );
    let port = nums[4] * 256 + nums[5];
    Ok(SocketAddr::from((ip, port)))
}

/// Parse `229` port from reply text (`|||port|`).
pub fn parse_epsv_port(text: &str) -> FtpResult<u16> {
    let start = text
        .find('(')
        .ok_or_else(|| FtpError::Parse(format!("EPSV: {text}")))?
        + 1;
    let end = text[start..]
        .find(')')
        .ok_or_else(|| FtpError::Parse(format!("EPSV: {text}")))?
        + start;
    let inner = &text[start..end];
    // |||port| or |2|::1|port|
    let parts: Vec<&str> = inner.split('|').collect();
    // "", "", "", "port", ""  OR  "", "2", "addr", "port", ""
    let port_str = parts
        .iter()
        .rev()
        .find(|p| !p.is_empty())
        .copied()
        .ok_or_else(|| FtpError::Parse(format!("EPSV: {text}")))?;
    port_str
        .parse()
        .map_err(|_| FtpError::Parse(format!("EPSV port: {port_str}")))
}
