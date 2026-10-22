// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Hand-built JSON for qlog event `data` objects.

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Mutable JSON object builder.
pub struct QlogJson {
    sb: String,
}

impl QlogJson {
    /// Start a JSON object.
    pub fn object() -> Self {
        Self { sb: String::from('{') }
    }

    fn separate(&mut self) {
        let last = self.sb.as_bytes().last().copied().unwrap_or(b'{');
        if last != b'{' && last != b'[' && last != b':' {
            self.sb.push(',');
        }
    }

    fn key(&mut self, key: &str) {
        self.separate();
        Self::append_string(&mut self.sb, key);
        self.sb.push(':');
    }

    /// Append a quoted JSON string to `out`.
    pub fn append_string(out: &mut String, value: &str) {
        out.push('"');
        for c in value.chars() {
            match c {
                '"' | '\\' => {
                    out.push('\\');
                    out.push(c);
                }
                c if c < '\u{0020}' => {
                    out.push_str(&format!("\\u00{}{}", HEX[(c as u32 >> 4) as usize], HEX[(c as u32 & 15) as usize]));
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }

    /// String field.
    pub fn put(mut self, key: &str, value: &str) -> Self {
        self.key(key);
        Self::append_string(&mut self.sb, value);
        self
    }

    /// Integer field.
    pub fn put_u64(mut self, key: &str, value: u64) -> Self {
        self.key(key);
        self.sb.push_str(&value.to_string());
        self
    }

    /// Boolean field.
    pub fn put_bool(mut self, key: &str, value: bool) -> Self {
        self.key(key);
        self.sb.push_str(if value { "true" } else { "false" });
        self
    }

    /// Duration in microseconds as qlog milliseconds.
    pub fn put_millis_from_micros(mut self, key: &str, micros: i64) -> Self {
        self.key(key);
        self.sb.push_str(&micros_to_millis_json(micros));
        self
    }

    /// Lowercase hex bytes.
    pub fn put_hex(mut self, key: &str, value: &[u8]) -> Self {
        self.key(key);
        self.sb.push('"');
        for b in value {
            self.sb.push(HEX[(b >> 4) as usize] as char);
            self.sb.push(HEX[(b & 15) as usize] as char);
        }
        self.sb.push('"');
        self
    }

    /// Embed pre-built JSON.
    pub fn put_raw(mut self, key: &str, json: &str) -> Self {
        self.key(key);
        self.sb.push_str(json);
        self
    }

    /// Open nested object.
    pub fn begin_object(mut self, key: &str) -> Self {
        self.key(key);
        self.sb.push('{');
        self
    }

    /// Close nested object.
    pub fn end_object(mut self) -> Self {
        self.sb.push('}');
        self
    }

    /// Open array.
    pub fn begin_array(mut self, key: &str) -> Self {
        self.key(key);
        self.sb.push('[');
        self
    }

    /// Close array.
    pub fn end_array(mut self) -> Self {
        self.sb.push(']');
        self
    }

    /// Array element (JSON text).
    pub fn item_raw(mut self, json: &str) -> Self {
        self.separate();
        self.sb.push_str(json);
        self
    }

    /// Finish object.
    pub fn build(mut self) -> String {
        self.sb.push('}');
        self.sb
    }

    /// Lowercase hex.
    pub fn hex(value: &[u8]) -> String {
        let mut out = String::with_capacity(value.len() * 2);
        for b in value {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
        out
    }
}

fn micros_to_millis_json(micros: i64) -> String {
    let negative = micros < 0;
    let abs = micros.unsigned_abs();
    let fraction = abs % 1000;
    let millis = abs / 1000;
    let mut sb = String::with_capacity(24);
    if negative {
        sb.push('-');
    }
    sb.push_str(&millis.to_string());
    sb.push('.');
    if fraction < 100 {
        sb.push('0');
    }
    if fraction < 10 {
        sb.push('0');
    }
    sb.push_str(&fraction.to_string());
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn millis_from_micros() {
        assert_eq!(micros_to_millis_json(1_500), "1.500");
        assert_eq!(micros_to_millis_json(100_000), "100.000");
    }
}
