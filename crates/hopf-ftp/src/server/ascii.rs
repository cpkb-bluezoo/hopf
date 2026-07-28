// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TYPE A newline normalisation.

/// Convert lone LF / CR to CRLF for ASCII mode transfers.
pub fn normalize_ascii_newlines(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 16);
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'\r' => {
                if i + 1 < input.len() && input[i + 1] == b'\n' {
                    out.extend_from_slice(b"\r\n");
                    i += 2;
                } else {
                    out.extend_from_slice(b"\r\n");
                    i += 1;
                }
            }
            b'\n' => {
                out.extend_from_slice(b"\r\n");
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}
