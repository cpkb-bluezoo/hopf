// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 7873 DNS cookies (EDNS option 10).

use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::wire::DnsResourceRecord;

type HmacSha256 = Hmac<Sha256>;

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

    /// Server cookie for address verification (RFC 7873 §5.2): HMAC-SHA256
    /// over the client cookie and client IP, keyed by the server secret,
    /// truncated to 8 octets.
    pub fn generate_server_cookie(&self, client_cookie: &[u8], client_ip: &[u8]) -> [u8; 8] {
        let mut mac = HmacSha256::new_from_slice(&self.server_secret)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(client_cookie);
        mac.update(client_ip);
        let full = mac.finalize().into_bytes();
        let mut out = [0u8; 8];
        out.copy_from_slice(&full[..8]);
        out
    }

    /// Whether `server_cookie` is exactly what we'd issue this
    /// client/address combination right now.
    pub fn validate_server_cookie(&self, client_cookie: &[u8], client_ip: &[u8], server_cookie: &[u8]) -> bool {
        server_cookie.len() == 8 && server_cookie == self.generate_server_cookie(client_cookie, client_ip)
    }

    /// Server-side response COOKIE option (RFC 7873 §5.2): echoes the
    /// client's own cookie plus a freshly issued server cookie. The server
    /// always returns a *valid* server cookie regardless of whether one
    /// was presented, or whether it validated — that's the mechanism by
    /// which a client establishes/refreshes its cookie relationship.
    pub fn encode_response_edns_option(&self, client_cookie: &[u8], client_ip: &[u8]) -> Vec<u8> {
        let mut data = client_cookie.to_vec();
        data.extend_from_slice(&self.generate_server_cookie(client_cookie, client_ip));
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        out
    }
}

/// Parse an inbound query's COOKIE option from its OPT additional record,
/// if any: the mandatory 8-byte client cookie, and an optional 8-32 byte
/// server cookie if the client is presenting one it was previously issued
/// (RFC 7873 §4).
pub fn parse_client_cookie(additionals: &[DnsResourceRecord]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    for rr in additionals {
        if rr.rtype != Some(crate::wire::DnsType::Opt) {
            continue;
        }
        let opt_rdata = &rr.rdata;
        let mut i = 0;
        while i + 4 <= opt_rdata.len() {
            let code = u16::from_be_bytes([opt_rdata[i], opt_rdata[i + 1]]);
            let len = u16::from_be_bytes([opt_rdata[i + 2], opt_rdata[i + 3]]) as usize;
            i += 4;
            if i + len > opt_rdata.len() {
                break;
            }
            if code == EDNS_OPTION_COOKIE && len >= CLIENT_COOKIE_LENGTH {
                let client = opt_rdata[i..i + CLIENT_COOKIE_LENGTH].to_vec();
                let server = if len > CLIENT_COOKIE_LENGTH {
                    let sc = &opt_rdata[i + CLIENT_COOKIE_LENGTH..i + len];
                    (sc.len() >= 8 && sc.len() <= 32).then(|| sc.to_vec())
                } else {
                    None
                };
                return Some((client, server));
            }
            i += len;
        }
    }
    None
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

    #[test]
    fn server_cookie_is_deterministic_and_input_sensitive() {
        let jar = DnsCookie::new();
        let cc = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let ip_a = [127, 0, 0, 1];
        let ip_b = [127, 0, 0, 2];

        let a1 = jar.generate_server_cookie(&cc, &ip_a);
        let a2 = jar.generate_server_cookie(&cc, &ip_a);
        assert_eq!(a1, a2, "same inputs must produce the same cookie");

        let b = jar.generate_server_cookie(&cc, &ip_b);
        assert_ne!(a1, b, "a different client IP must change the cookie");

        let other_cc = [9u8, 9, 9, 9, 9, 9, 9, 9];
        let c = jar.generate_server_cookie(&other_cc, &ip_a);
        assert_ne!(a1, c, "a different client cookie must change the cookie");

        // Not a plain concatenation/reorderable mix: swapping bytes between
        // the two inputs (same combined bytes, different split) must not
        // produce the same cookie the way a naive XOR mix would.
        let swapped_cc = [1u8, 2, 3, 4, 5, 6, 7, 127];
        let swapped_ip = [8u8, 0, 0, 1];
        let d = jar.generate_server_cookie(&swapped_cc, &swapped_ip);
        assert_ne!(a1, d);
    }

    #[test]
    fn server_cookie_differs_across_independently_keyed_jars() {
        let cc = [0u8; 8];
        let ip = [10u8, 0, 0, 1];

        let jar1 = DnsCookie::new();
        let jar2 = DnsCookie::new();
        // Two independently random secrets must (overwhelmingly) produce
        // different server cookies for identical client cookie/IP input.
        assert_ne!(
            jar1.generate_server_cookie(&cc, &ip),
            jar2.generate_server_cookie(&cc, &ip),
            "distinct server secrets must not collide"
        );
    }

    #[test]
    fn validate_server_cookie_accepts_genuine_and_rejects_tampered() {
        let jar = DnsCookie::new();
        let cc = [5u8; 8];
        let ip = [192, 0, 2, 1];
        let sc = jar.generate_server_cookie(&cc, &ip);
        assert!(jar.validate_server_cookie(&cc, &ip, &sc));

        let mut tampered = sc;
        tampered[0] ^= 0xFF;
        assert!(!jar.validate_server_cookie(&cc, &ip, &tampered));

        // A cookie valid for one IP must not validate for another.
        assert!(!jar.validate_server_cookie(&cc, &[192, 0, 2, 2], &sc));
    }

    #[test]
    fn parse_client_cookie_extracts_client_and_optional_server_parts() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());
        let client = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let server = [9u8, 10, 11, 12, 13, 14, 15, 16];
        let mut data = client.to_vec();
        data.extend_from_slice(&server);
        rdata.extend_from_slice(&(data.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&data);
        let opt = DnsResourceRecord::opt(1232, false, &rdata);

        let (got_client, got_server) = parse_client_cookie(&[opt]).expect("cookie option present");
        assert_eq!(got_client, client);
        assert_eq!(got_server, Some(server.to_vec()));
    }

    #[test]
    fn parse_client_cookie_handles_client_only_and_absent_option() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());
        let client = [1u8, 2, 3, 4, 5, 6, 7, 8];
        rdata.extend_from_slice(&(client.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&client);
        let opt = DnsResourceRecord::opt(1232, false, &rdata);
        let (got_client, got_server) = parse_client_cookie(&[opt]).expect("cookie option present");
        assert_eq!(got_client, client);
        assert_eq!(got_server, None);

        let no_opt = DnsResourceRecord::opt(1232, false, &[]);
        assert_eq!(parse_client_cookie(&[no_opt]), None);
        assert_eq!(parse_client_cookie(&[]), None);
    }

    #[test]
    fn server_response_option_round_trips_and_validates() {
        let jar = DnsCookie::new();
        let client = [7u8; 8];
        let ip = [203, 0, 113, 5];
        let opt_bytes = jar.encode_response_edns_option(&client, &ip);

        assert_eq!(&opt_bytes[0..2], &EDNS_OPTION_COOKIE.to_be_bytes());
        let len = u16::from_be_bytes([opt_bytes[2], opt_bytes[3]]) as usize;
        assert_eq!(len, CLIENT_COOKIE_LENGTH + 8);
        let data = &opt_bytes[4..4 + len];
        assert_eq!(&data[..8], &client);
        assert!(jar.validate_server_cookie(&client, &ip, &data[8..]));
    }
}

