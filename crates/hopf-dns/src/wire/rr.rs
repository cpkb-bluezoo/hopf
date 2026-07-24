// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::net::{Ipv4Addr, Ipv6Addr};

use super::class::DnsClass;
use super::error::DnsFormatError;
use super::name::{decode_name, encode_name};
use super::r#type::DnsType;

/// DNSSEC OK bit in OPT TTL (RFC 4035 §3.2.1) — bit 15 of lower 16 bits.
pub const EDNS_FLAG_DO: u32 = 0x8000;
/// Default EDNS UDP payload size advertised in OPT CLASS field.
pub const OPT_UDP_PAYLOAD: u16 = 4096;

/// DNS resource record (RFC 1035 §3.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    /// Owner name.
    pub name: String,
    /// Parsed type if known.
    pub rtype: Option<DnsType>,
    /// Raw TYPE.
    pub raw_type: u16,
    /// Parsed class if known.
    pub rclass: Option<DnsClass>,
    /// Raw CLASS (OPT: UDP payload size).
    pub raw_class: u16,
    /// TTL (OPT: extended RCODE/version/flags).
    pub ttl: u32,
    /// RDATA octets.
    pub rdata: Vec<u8>,
}

impl DnsResourceRecord {
    /// Construct with known type/class.
    pub fn new(
        name: impl Into<String>,
        rtype: DnsType,
        rclass: DnsClass,
        ttl: u32,
        rdata: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            raw_type: rtype.value(),
            rtype: Some(rtype),
            raw_class: rclass.value(),
            rclass: Some(rclass),
            ttl,
            rdata,
        }
    }

    /// Opaque / unknown type preservation (RFC 3597).
    pub fn opaque(
        name: impl Into<String>,
        raw_type: u16,
        raw_class: u16,
        ttl: u32,
        rdata: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            rtype: DnsType::from_value(raw_type),
            raw_type,
            rclass: DnsClass::from_value(raw_class),
            raw_class,
            ttl,
            rdata,
        }
    }

    /// A record.
    pub fn a(name: impl Into<String>, ttl: u32, addr: Ipv4Addr) -> Self {
        Self::new(name, DnsType::A, DnsClass::In, ttl, addr.octets().to_vec())
    }

    /// AAAA record.
    pub fn aaaa(name: impl Into<String>, ttl: u32, addr: Ipv6Addr) -> Self {
        Self::new(name, DnsType::Aaaa, DnsClass::In, ttl, addr.octets().to_vec())
    }

    /// CNAME.
    pub fn cname(name: impl Into<String>, ttl: u32, canonical: &str) -> Result<Self, DnsFormatError> {
        Ok(Self::new(
            name,
            DnsType::Cname,
            DnsClass::In,
            ttl,
            encode_name(canonical)?,
        ))
    }

    /// PTR.
    pub fn ptr(name: impl Into<String>, ttl: u32, target: &str) -> Result<Self, DnsFormatError> {
        Ok(Self::new(
            name,
            DnsType::Ptr,
            DnsClass::In,
            ttl,
            encode_name(target)?,
        ))
    }

    /// NS.
    pub fn ns(name: impl Into<String>, ttl: u32, ns: &str) -> Result<Self, DnsFormatError> {
        Ok(Self::new(
            name,
            DnsType::Ns,
            DnsClass::In,
            ttl,
            encode_name(ns)?,
        ))
    }

    /// MX.
    pub fn mx(
        name: impl Into<String>,
        ttl: u32,
        preference: u16,
        exchange: &str,
    ) -> Result<Self, DnsFormatError> {
        let mut rdata = Vec::with_capacity(2 + exchange.len() + 2);
        rdata.extend_from_slice(&preference.to_be_bytes());
        rdata.extend_from_slice(&encode_name(exchange)?);
        Ok(Self::new(name, DnsType::Mx, DnsClass::In, ttl, rdata))
    }

    /// TXT (single character-string).
    pub fn txt(name: impl Into<String>, ttl: u32, text: &str) -> Result<Self, DnsFormatError> {
        let bytes = text.as_bytes();
        if bytes.len() > 255 {
            return Err(DnsFormatError::new("TXT string longer than 255"));
        }
        let mut rdata = Vec::with_capacity(1 + bytes.len());
        rdata.push(bytes.len() as u8);
        rdata.extend_from_slice(bytes);
        Ok(Self::new(name, DnsType::Txt, DnsClass::In, ttl, rdata))
    }

    /// SRV.
    pub fn srv(
        name: impl Into<String>,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
    ) -> Result<Self, DnsFormatError> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&weight.to_be_bytes());
        rdata.extend_from_slice(&port.to_be_bytes());
        rdata.extend_from_slice(&encode_name(target)?);
        Ok(Self::new(name, DnsType::Srv, DnsClass::In, ttl, rdata))
    }

    /// OPT / EDNS0 pseudo-RR (name empty, CLASS = UDP size, TTL = flags).
    pub fn opt(udp_payload: u16, do_bit: bool, options: &[u8]) -> Self {
        let mut ttl = 0u32;
        if do_bit {
            ttl |= EDNS_FLAG_DO;
        }
        Self {
            name: String::new(),
            rtype: Some(DnsType::Opt),
            raw_type: DnsType::Opt.value(),
            rclass: None,
            raw_class: udp_payload,
            ttl,
            rdata: options.to_vec(),
        }
    }

    /// EDNS DO bit set?
    pub fn edns_do(&self) -> bool {
        self.rtype == Some(DnsType::Opt) && (self.ttl & EDNS_FLAG_DO) != 0
    }

    /// Parse A RDATA.
    pub fn as_a(&self) -> Option<Ipv4Addr> {
        if self.rtype != Some(DnsType::A) || self.rdata.len() != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            self.rdata[0],
            self.rdata[1],
            self.rdata[2],
            self.rdata[3],
        ))
    }

    /// Parse AAAA RDATA.
    pub fn as_aaaa(&self) -> Option<Ipv6Addr> {
        if self.rtype != Some(DnsType::Aaaa) || self.rdata.len() != 16 {
            return None;
        }
        let mut o = [0u8; 16];
        o.copy_from_slice(&self.rdata);
        Some(Ipv6Addr::from(o))
    }

    /// Domain name in RDATA (CNAME/NS/PTR).
    pub fn as_domain_name(&self) -> Option<String> {
        let mut c = 0;
        decode_name(&self.rdata, &mut c).ok()
    }

    /// MX preference + exchange.
    pub fn as_mx(&self) -> Option<(u16, String)> {
        if self.rtype != Some(DnsType::Mx) || self.rdata.len() < 3 {
            return None;
        }
        let pref = u16::from_be_bytes([self.rdata[0], self.rdata[1]]);
        let mut c = 2;
        let ex = decode_name(&self.rdata, &mut c).ok()?;
        Some((pref, ex))
    }

    /// Concatenate TXT character-strings.
    pub fn as_txt(&self) -> Option<String> {
        if self.rtype != Some(DnsType::Txt) {
            return None;
        }
        let mut out = String::new();
        let mut i = 0;
        while i < self.rdata.len() {
            let len = self.rdata[i] as usize;
            i += 1;
            if i + len > self.rdata.len() {
                return None;
            }
            out.push_str(&String::from_utf8_lossy(&self.rdata[i..i + len]));
            i += len;
        }
        Some(out)
    }

    /// Clone with adjusted TTL.
    pub fn with_ttl(&self, ttl: u32) -> Self {
        let mut c = self.clone();
        c.ttl = ttl;
        c
    }

    // -- RRSIG (RFC 4034 §3.1) --

    fn require_rrsig(&self) -> Option<()> {
        if self.rtype == Some(DnsType::Rrsig) {
            Some(())
        } else {
            None
        }
    }

    /// Type covered by this RRSIG.
    pub fn rrsig_type_covered(&self) -> Option<u16> {
        self.require_rrsig()?;
        if self.rdata.len() < 18 {
            return None;
        }
        Some(u16::from_be_bytes([self.rdata[0], self.rdata[1]]))
    }

    /// Algorithm number.
    pub fn rrsig_algorithm(&self) -> Option<u8> {
        self.require_rrsig()?;
        Some(*self.rdata.get(2)?)
    }

    /// Original TTL of the covered RRset.
    pub fn rrsig_original_ttl(&self) -> Option<u32> {
        self.require_rrsig()?;
        if self.rdata.len() < 18 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.rdata[4],
            self.rdata[5],
            self.rdata[6],
            self.rdata[7],
        ]))
    }

    /// Signature expiration (Unix seconds).
    pub fn rrsig_expiration(&self) -> Option<u32> {
        self.require_rrsig()?;
        if self.rdata.len() < 18 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.rdata[8],
            self.rdata[9],
            self.rdata[10],
            self.rdata[11],
        ]))
    }

    /// Signature inception (Unix seconds).
    pub fn rrsig_inception(&self) -> Option<u32> {
        self.require_rrsig()?;
        if self.rdata.len() < 18 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.rdata[12],
            self.rdata[13],
            self.rdata[14],
            self.rdata[15],
        ]))
    }

    /// Key tag.
    pub fn rrsig_key_tag(&self) -> Option<u16> {
        self.require_rrsig()?;
        if self.rdata.len() < 18 {
            return None;
        }
        Some(u16::from_be_bytes([self.rdata[16], self.rdata[17]]))
    }

    /// Signer name.
    pub fn rrsig_signer_name(&self) -> Option<String> {
        self.require_rrsig()?;
        let mut c = 18;
        decode_name(&self.rdata, &mut c).ok()
    }

    /// Signature bytes (after signer name).
    pub fn rrsig_signature(&self) -> Option<&[u8]> {
        self.require_rrsig()?;
        let mut c = 18;
        decode_name(&self.rdata, &mut c).ok()?;
        Some(&self.rdata[c..])
    }

    /// RRSIG RDATA through end of signer name (signed-data prefix).
    pub fn rrsig_header_bytes(&self) -> Option<&[u8]> {
        self.require_rrsig()?;
        let mut c = 18;
        decode_name(&self.rdata, &mut c).ok()?;
        Some(&self.rdata[..c])
    }

    // -- DNSKEY (RFC 4034 §2.1) --

    fn require_dnskey(&self) -> Option<()> {
        if self.rtype == Some(DnsType::Dnskey) {
            Some(())
        } else {
            None
        }
    }

    /// DNSKEY flags.
    pub fn dnskey_flags(&self) -> Option<u16> {
        self.require_dnskey()?;
        if self.rdata.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([self.rdata[0], self.rdata[1]]))
    }

    /// DNSKEY algorithm.
    pub fn dnskey_algorithm(&self) -> Option<u8> {
        self.require_dnskey()?;
        Some(*self.rdata.get(3)?)
    }

    /// Public key material (after flags/protocol/algorithm).
    pub fn dnskey_public_key(&self) -> Option<&[u8]> {
        self.require_dnskey()?;
        if self.rdata.len() < 4 {
            return None;
        }
        Some(&self.rdata[4..])
    }

    /// SEP (KSK) flag set?
    pub fn dnskey_is_sep(&self) -> bool {
        self.dnskey_flags()
            .map(|f| f & 0x0001 != 0)
            .unwrap_or(false)
    }

    /// Key tag (RFC 4034 Appendix B).
    pub fn dnskey_key_tag(&self) -> Option<u16> {
        self.require_dnskey()?;
        let mut ac: u32 = 0;
        for (i, &b) in self.rdata.iter().enumerate() {
            if i & 1 == 0 {
                ac += u32::from(b) << 8;
            } else {
                ac += u32::from(b);
            }
        }
        ac += (ac >> 16) & 0xffff;
        Some((ac & 0xffff) as u16)
    }

    /// Build a DNSKEY RR.
    pub fn dnskey(
        name: impl Into<String>,
        ttl: u32,
        flags: u16,
        algorithm: u8,
        public_key: &[u8],
    ) -> Self {
        let mut rdata = Vec::with_capacity(4 + public_key.len());
        rdata.extend_from_slice(&flags.to_be_bytes());
        rdata.push(3); // protocol
        rdata.push(algorithm);
        rdata.extend_from_slice(public_key);
        Self::new(name, DnsType::Dnskey, DnsClass::In, ttl, rdata)
    }

    // -- DS (RFC 4034 §5.1) --

    fn require_ds(&self) -> Option<()> {
        if self.rtype == Some(DnsType::Ds) {
            Some(())
        } else {
            None
        }
    }

    /// DS key tag.
    pub fn ds_key_tag(&self) -> Option<u16> {
        self.require_ds()?;
        if self.rdata.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([self.rdata[0], self.rdata[1]]))
    }

    /// DS algorithm.
    pub fn ds_algorithm(&self) -> Option<u8> {
        self.require_ds()?;
        Some(*self.rdata.get(2)?)
    }

    /// DS digest type.
    pub fn ds_digest_type(&self) -> Option<u8> {
        self.require_ds()?;
        Some(*self.rdata.get(3)?)
    }

    /// DS digest bytes.
    pub fn ds_digest(&self) -> Option<&[u8]> {
        self.require_ds()?;
        if self.rdata.len() < 4 {
            return None;
        }
        Some(&self.rdata[4..])
    }

    /// Build a DS RR.
    pub fn ds(
        name: impl Into<String>,
        ttl: u32,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: &[u8],
    ) -> Self {
        let mut rdata = Vec::with_capacity(4 + digest.len());
        rdata.extend_from_slice(&key_tag.to_be_bytes());
        rdata.push(algorithm);
        rdata.push(digest_type);
        rdata.extend_from_slice(digest);
        Self::new(name, DnsType::Ds, DnsClass::In, ttl, rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn common_rr_constructors_and_accessors() {
        let a = DnsResourceRecord::a("ex.test.", 60, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(a.as_a(), Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(a.with_ttl(10).ttl, 10);

        let aaaa = DnsResourceRecord::aaaa("ex.test.", 60, Ipv6Addr::LOCALHOST);
        assert_eq!(aaaa.as_aaaa(), Some(Ipv6Addr::LOCALHOST));

        let cname = DnsResourceRecord::cname("www.ex.test.", 60, "ex.test.").unwrap();
        let cn = cname.as_domain_name().unwrap();
        assert!(
            cn.eq_ignore_ascii_case("ex.test.") || cn.eq_ignore_ascii_case("ex.test"),
            "got {cn:?}"
        );

        let mx = DnsResourceRecord::mx("ex.test.", 60, 10, "mail.ex.test.").unwrap();
        let (pref, ex) = mx.as_mx().unwrap();
        assert_eq!(pref, 10);
        assert!(
            ex.eq_ignore_ascii_case("mail.ex.test.") || ex.eq_ignore_ascii_case("mail.ex.test"),
            "got {ex:?}"
        );

        let txt = DnsResourceRecord::txt("ex.test.", 60, "hello").unwrap();
        assert_eq!(txt.as_txt().as_deref(), Some("hello"));

        let srv =
            DnsResourceRecord::srv("_http._tcp.ex.test.", 60, 0, 5, 80, "ex.test.").unwrap();
        assert_eq!(srv.rtype, Some(DnsType::Srv));
        assert!(DnsResourceRecord::txt("x.", 1, &"x".repeat(256)).is_err());
    }

    #[test]
    fn opt_do_bit_and_dnskey_ds() {
        let opt = DnsResourceRecord::opt(1232, true, &[]);
        assert!(opt.edns_do());
        let opt2 = DnsResourceRecord::opt(1232, false, &[1, 2]);
        assert!(!opt2.edns_do());

        let key = DnsResourceRecord::dnskey("ex.test.", 60, 0x0001, 8, &[1, 2, 3, 4]);
        assert_eq!(key.dnskey_flags(), Some(0x0001));
        assert_eq!(key.dnskey_algorithm(), Some(8));
        assert_eq!(key.dnskey_public_key(), Some(&[1, 2, 3, 4][..]));
        assert!(key.dnskey_is_sep());
        assert!(key.dnskey_key_tag().is_some());

        let ds = DnsResourceRecord::ds("ex.test.", 60, 1234, 8, 2, &[9, 9, 9]);
        assert_eq!(ds.ds_key_tag(), Some(1234));
        assert_eq!(ds.ds_algorithm(), Some(8));
        assert_eq!(ds.ds_digest_type(), Some(2));
        assert_eq!(ds.ds_digest(), Some(&[9, 9, 9][..]));

        let short = DnsResourceRecord::opaque("x.", DnsType::A.value(), 1, 0, vec![1]);
        assert!(short.as_a().is_none());
    }
}

