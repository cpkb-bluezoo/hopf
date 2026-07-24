// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 7873 DNS cookies (EDNS option 10).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::wire::DnsResourceRecord;

/// EDNS option code for COOKIE.
pub const EDNS_OPTION_COOKIE: u16 = 10;
/// Client cookie length.
pub const CLIENT_COOKIE_LENGTH: usize = 8;

/// Cookie manager (client + optional server secret).
pub struct DnsCookie {
    client_cookie: [u8; CLIENT_COOKIE_LENGTH],
    server_cookies: Mutex<HashMap<String, Vec<u8>>>,
    server_secret: [u8; 16],
}

impl Default for DnsCookie {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCookie {
    /// Fresh random client cookie + server secret.
    pub fn new() -> Self {
        let mut client_cookie = [0u8; CLIENT_COOKIE_LENGTH];
        let mut server_secret = [0u8; 16];
        fill_random(&mut client_cookie);
        fill_random(&mut server_secret);
        Self {
            client_cookie,
            server_cookies: Mutex::new(HashMap::new()),
            server_secret,
        }
    }

    /// Current client cookie.
    pub fn client_cookie(&self) -> [u8; CLIENT_COOKIE_LENGTH] {
        self.client_cookie
    }

    /// Regenerate client cookie.
    pub fn regenerate_client_cookie(&mut self) {
        fill_random(&mut self.client_cookie);
    }

    /// Option data for outbound query to `server_key` (e.g. "8.8.8.8:53").
    pub fn build_option_data(&self, server_key: &str) -> Vec<u8> {
        let mut data = self.client_cookie.to_vec();
        if let Some(sc) = self.server_cookies.lock().unwrap().get(server_key) {
            data.extend_from_slice(sc);
        }
        data
    }

    /// Encode as EDNS option bytes (code + length + data) for OPT RDATA.
    pub fn encode_edns_option(&self, server_key: &str) -> Vec<u8> {
        let data = self.build_option_data(server_key);
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        out
    }

    /// Remember server cookie from OPT RDATA options blob.
    pub fn store_from_opt_rdata(&self, server_key: &str, opt_rdata: &[u8]) {
        let mut i = 0;
        while i + 4 <= opt_rdata.len() {
            let code = u16::from_be_bytes([opt_rdata[i], opt_rdata[i + 1]]);
            let len = u16::from_be_bytes([opt_rdata[i + 2], opt_rdata[i + 3]]) as usize;
            i += 4;
            if i + len > opt_rdata.len() {
                break;
            }
            if code == EDNS_OPTION_COOKIE && len >= CLIENT_COOKIE_LENGTH {
                let rest = &opt_rdata[i + CLIENT_COOKIE_LENGTH..i + len];
                if rest.len() >= 8 && rest.len() <= 32 {
                    self.server_cookies
                        .lock()
                        .unwrap()
                        .insert(server_key.to_string(), rest.to_vec());
                }
            }
            i += len;
        }
    }

    /// Store cookies seen in a response message's OPT.
    pub fn store_from_message(&self, server_key: &str, additionals: &[DnsResourceRecord]) {
        for rr in additionals {
            if rr.rtype == Some(crate::wire::DnsType::Opt) {
                self.store_from_opt_rdata(server_key, &rr.rdata);
            }
        }
    }

    /// Server cookie for address verification (simple HMAC-like XOR mix).
    pub fn generate_server_cookie(&self, client_cookie: &[u8], client_ip: &[u8]) -> [u8; 8] {
        let mut out = [0u8; 8];
        for i in 0..8 {
            out[i] = self.server_secret[i]
                ^ self.server_secret[i + 8]
                ^ client_cookie.get(i).copied().unwrap_or(0)
                ^ client_ip.get(i % client_ip.len().max(1)).copied().unwrap_or(0);
        }
        out
    }
}

fn fill_random(buf: &mut [u8]) {
    // Prefer getrandom via std if available; fall back to time-based mix.
    #[cfg(unix)]
    {
        use std::fs::File;
        use std::io::Read;
        if let Ok(mut f) = File::open("/dev/urandom") {
            let _ = f.read_exact(buf);
            return;
        }
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((t >> ((i % 8) * 8)) as u8).wrapping_add(i as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_roundtrip_and_server_cookie() {
        let mut jar = DnsCookie::new();
        let opt = jar.encode_edns_option("1.1.1.1:53");
        assert_eq!(&opt[0..2], &EDNS_OPTION_COOKIE.to_be_bytes());
        let len = u16::from_be_bytes([opt[2], opt[3]]) as usize;
        assert_eq!(len, CLIENT_COOKIE_LENGTH);
        assert_eq!(&opt[4..], &jar.client_cookie());

        // Server returns client cookie + 8-byte server cookie.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());
        let mut data = jar.client_cookie().to_vec();
        data.extend_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2]);
        rdata.extend_from_slice(&(data.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&data);
        jar.store_from_opt_rdata("1.1.1.1:53", &rdata);
        let built = jar.build_option_data("1.1.1.1:53");
        assert_eq!(built.len(), CLIENT_COOKIE_LENGTH + 8);

        jar.regenerate_client_cookie();
        let sc = jar.generate_server_cookie(&jar.client_cookie(), &[127, 0, 0, 1]);
        assert_eq!(sc.len(), 8);
    }
}

