// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP reply parsing (multiline `code-` / `code `).

use std::io::Read;

use super::error::{SmtpError, SmtpResult};
use super::stream::SmtpStream;

/// One SMTP reply (possibly multiline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    /// Three-digit reply code.
    pub code: u16,
    /// Lines of text without the code prefix.
    pub lines: Vec<String>,
}

impl SmtpReply {
    /// Primary text: joined lines.
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }
}

/// Read one complete reply.
pub fn read_reply(stream: &mut SmtpStream) -> SmtpResult<SmtpReply> {
    let first = read_line(stream)?;
    if first.len() < 3 {
        return Err(SmtpError::Parse(format!("short reply: {first:?}")));
    }
    let code: u16 = first[..3]
        .parse()
        .map_err(|_| SmtpError::Parse(format!("bad code: {first}")))?;
    let sep = first.as_bytes().get(3).copied().unwrap_or(b' ');
    let mut lines = Vec::new();
    if sep == b'-' {
        let rest = first.get(4..).unwrap_or("").trim_end_matches(['\r', '\n']);
        if !rest.is_empty() {
            lines.push(rest.to_string());
        }
        loop {
            let line = read_line(stream)?;
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
    Ok(SmtpReply { code, lines })
}

fn read_line(r: &mut SmtpStream) -> SmtpResult<String> {
    let mut buf = Vec::with_capacity(128);
    let mut b = [0u8; 1];
    loop {
        r.read_exact(&mut b)?;
        buf.push(b[0]);
        if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' && buf[buf.len() - 1] == b'\n' {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(SmtpError::Parse("reply line too long".into()));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
