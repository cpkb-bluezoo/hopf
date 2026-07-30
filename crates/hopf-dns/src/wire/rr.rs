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
/// EDNS Padding option code (RFC 7830).
pub const EDNS_OPTION_PADDING: u16 = 12;

/// Build an RFC 7830 Padding option (code + length + `padding_len`
/// zero-valued octets) ready to append into an OPT record's options — the
/// caller composes this with whatever other options (e.g. COOKIE) belong
/// in the same record. Padding matters most on encrypted transports (DoT/
/// DoQ/DoH), where an attacker can otherwise infer queries from packet
/// sizes alone even though the payload itself is opaque.
pub fn encode_edns_padding(padding_len: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + padding_len as usize);
    out.extend_from_slice(&EDNS_OPTION_PADDING.to_be_bytes());
    out.extend_from_slice(&padding_len.to_be_bytes());
    out.resize(out.len() + padding_len as usize, 0u8);
    out
}

/// Decoded SOA RDATA (RFC 1035 §3.3.13) — a named struct rather than a
/// tuple since seven positional fields (several same-typed `u32`s) would
/// be too easy to transpose by accident at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaData {
    /// Primary master name server.
    pub mname: String,
    /// Mailbox of the responsible person.
    pub rname: String,
    /// Zone serial number.
    pub serial: u32,
    /// Refresh interval, seconds.
    pub refresh: u32,
    /// Retry interval, seconds.
    pub retry: u32,
    /// Expire time, seconds.
    pub expire: u32,
    /// Negative-caching TTL (RFC 2308 §4).
    pub minimum: u32,
}

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

    /// SOA.
    #[allow(clippy::too_many_arguments)]
    pub fn soa(
        name: impl Into<String>,
        ttl: u32,
        mname: &str,
        rname: &str,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Result<Self, DnsFormatError> {
        let mut rdata = encode_name(mname)?;
        rdata.extend_from_slice(&encode_name(rname)?);
        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&refresh.to_be_bytes());
        rdata.extend_from_slice(&retry.to_be_bytes());
        rdata.extend_from_slice(&expire.to_be_bytes());
        rdata.extend_from_slice(&minimum.to_be_bytes());
        Ok(Self::new(name, DnsType::Soa, DnsClass::In, ttl, rdata))
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

    /// Length of the RFC 7830 Padding option, if this OPT record's options
    /// carry one.
    pub fn edns_padding_length(&self) -> Option<u16> {
        if self.rtype != Some(DnsType::Opt) {
            return None;
        }
        let mut i = 0;
        while i + 4 <= self.rdata.len() {
            let code = u16::from_be_bytes([self.rdata[i], self.rdata[i + 1]]);
            let len = u16::from_be_bytes([self.rdata[i + 2], self.rdata[i + 3]]) as usize;
            i += 4;
            if i + len > self.rdata.len() {
                return None;
            }
            if code == EDNS_OPTION_PADDING {
                return Some(len as u16);
            }
            i += len;
        }
        None
    }

    /// Extended RCODE octet (RFC 6891 §6.1.3) — the upper 8 bits of the
    /// 12-bit extended RCODE. Combine with the DNS header's own 4-bit
    /// RCODE via [`Self::edns_full_rcode`] to get the actual code (e.g.
    /// BADVERS/BADSIG = 16, which can't be represented in the header's
    /// RCODE field alone).
    pub fn edns_extended_rcode(&self) -> Option<u8> {
        (self.rtype == Some(DnsType::Opt)).then_some((self.ttl >> 24) as u8)
    }

    /// EDNS VERSION octet (RFC 6891 §6.1.3) — 0 is the only version
    /// defined to date.
    pub fn edns_version(&self) -> Option<u8> {
        (self.rtype == Some(DnsType::Opt)).then_some(((self.ttl >> 16) & 0xFF) as u8)
    }

    /// Full 12-bit extended RCODE (RFC 6891 §6.1.3): this record's
    /// extended-RCODE octet as the high 8 bits, combined with the DNS
    /// header's own 4-bit RCODE (e.g. from [`super::DnsMessage::rcode`])
    /// as the low 4 bits.
    pub fn edns_full_rcode(&self, header_rcode: u8) -> Option<u16> {
        self.edns_extended_rcode()
            .map(|ext| (u16::from(ext) << 4) | u16::from(header_rcode & 0x0F))
    }

    /// Set a non-default EDNS extended-RCODE and/or VERSION octet (both 0
    /// on a plain [`Self::opt`]) — e.g. to signal BADVERS or a full
    /// extended RCODE above 15 such as BADCOOKIE (23).
    pub fn with_edns_rcode_version(mut self, extended_rcode: u8, version: u8) -> Self {
        self.ttl =
            (self.ttl & 0x0000_FFFF) | (u32::from(extended_rcode) << 24) | (u32::from(version) << 16);
        self
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

    /// Full SOA RDATA (RFC 1035 §3.3.13).
    pub fn as_soa(&self) -> Option<SoaData> {
        if self.rtype != Some(DnsType::Soa) {
            return None;
        }
        let mut c = 0;
        let mname = decode_name(&self.rdata, &mut c).ok()?;
        let rname = decode_name(&self.rdata, &mut c).ok()?;
        if c + 20 > self.rdata.len() {
            return None;
        }
        let field = |off: usize| {
            u32::from_be_bytes([
                self.rdata[c + off],
                self.rdata[c + off + 1],
                self.rdata[c + off + 2],
                self.rdata[c + off + 3],
            ])
        };
        Some(SoaData {
            mname,
            rname,
            serial: field(0),
            refresh: field(4),
            retry: field(8),
            expire: field(12),
            minimum: field(16),
        })
    }

    /// SRV priority, weight, port, and target (RFC 2782).
    pub fn as_srv(&self) -> Option<(u16, u16, u16, String)> {
        if self.rtype != Some(DnsType::Srv) || self.rdata.len() < 7 {
            return None;
        }
        let priority = u16::from_be_bytes([self.rdata[0], self.rdata[1]]);
        let weight = u16::from_be_bytes([self.rdata[2], self.rdata[3]]);
        let port = u16::from_be_bytes([self.rdata[4], self.rdata[5]]);
        let mut c = 6;
        let target = decode_name(&self.rdata, &mut c).ok()?;
        Some((priority, weight, port, target))
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

    // -- NSEC (RFC 4034 §4.1) --

    fn require_nsec(&self) -> Option<()> {
        if self.rtype == Some(DnsType::Nsec) {
            Some(())
        } else {
            None
        }
    }

    /// Next owner name in canonical zone order.
    pub fn nsec_next_domain(&self) -> Option<String> {
        self.require_nsec()?;
        let mut c = 0;
        decode_name(&self.rdata, &mut c).ok()
    }

    /// RR type values present at this owner name.
    pub fn nsec_types(&self) -> Option<Vec<u16>> {
        self.require_nsec()?;
        let mut c = 0;
        decode_name(&self.rdata, &mut c).ok()?;
        super::bitmap::decode_type_bitmap(&self.rdata[c..])
    }

    /// Build an NSEC RR.
    pub fn nsec(
        name: impl Into<String>,
        ttl: u32,
        next_domain: &str,
        types: Vec<u16>,
    ) -> Result<Self, DnsFormatError> {
        let mut rdata = encode_name(next_domain)?;
        rdata.extend_from_slice(&super::bitmap::encode_type_bitmap(types));
        Ok(Self::new(name, DnsType::Nsec, DnsClass::In, ttl, rdata))
    }

    // -- NSEC3 (RFC 5155 §3) --

    fn require_nsec3(&self) -> Option<()> {
        if self.rtype == Some(DnsType::Nsec3) {
            Some(())
        } else {
            None
        }
    }

    /// Hash algorithm (1 = SHA-1, the only one defined to date).
    pub fn nsec3_hash_algorithm(&self) -> Option<u8> {
        self.require_nsec3()?;
        self.rdata.first().copied()
    }

    /// Flags octet (bit 0 = Opt-Out, RFC 5155 §3.1.2.1).
    pub fn nsec3_flags(&self) -> Option<u8> {
        self.require_nsec3()?;
        self.rdata.get(1).copied()
    }

    /// Additional hash iterations (RFC 5155 §3.1.3).
    pub fn nsec3_iterations(&self) -> Option<u16> {
        self.require_nsec3()?;
        if self.rdata.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([self.rdata[2], self.rdata[3]]))
    }

    /// Salt bytes.
    pub fn nsec3_salt(&self) -> Option<&[u8]> {
        self.require_nsec3()?;
        let salt_len = *self.rdata.get(4)? as usize;
        let start = 5;
        if start + salt_len > self.rdata.len() {
            return None;
        }
        Some(&self.rdata[start..start + salt_len])
    }

    /// Next hashed owner name (raw hash bytes, not base32hex-encoded).
    pub fn nsec3_next_hashed_owner(&self) -> Option<&[u8]> {
        self.require_nsec3()?;
        let salt_len = *self.rdata.get(4)? as usize;
        let hash_len_idx = 5 + salt_len;
        let hash_len = *self.rdata.get(hash_len_idx)? as usize;
        let start = hash_len_idx + 1;
        if start + hash_len > self.rdata.len() {
            return None;
        }
        Some(&self.rdata[start..start + hash_len])
    }

    /// RR type values present at the name this hash covers.
    pub fn nsec3_types(&self) -> Option<Vec<u16>> {
        self.require_nsec3()?;
        let salt_len = *self.rdata.get(4)? as usize;
        let hash_len_idx = 5 + salt_len;
        let hash_len = *self.rdata.get(hash_len_idx)? as usize;
        let start = hash_len_idx + 1 + hash_len;
        if start > self.rdata.len() {
            return None;
        }
        super::bitmap::decode_type_bitmap(&self.rdata[start..])
    }

    /// Build an NSEC3 RR. `name` (the base32hex hash label + zone) is the
    /// caller's responsibility — see [`super::base32hex`].
    #[allow(clippy::too_many_arguments)]
    pub fn nsec3(
        name: impl Into<String>,
        ttl: u32,
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: &[u8],
        next_hashed_owner: &[u8],
        types: Vec<u16>,
    ) -> Self {
        let mut rdata = Vec::new();
        rdata.push(hash_algorithm);
        rdata.push(flags);
        rdata.extend_from_slice(&iterations.to_be_bytes());
        rdata.push(salt.len() as u8);
        rdata.extend_from_slice(salt);
        rdata.push(next_hashed_owner.len() as u8);
        rdata.extend_from_slice(next_hashed_owner);
        rdata.extend_from_slice(&super::bitmap::encode_type_bitmap(types));
        Self::new(name, DnsType::Nsec3, DnsClass::In, ttl, rdata)
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
    fn soa_round_trips_through_as_soa() {
        let soa = DnsResourceRecord::soa(
            "ex.test.", 3600, "ns1.ex.test.", "hostmaster.ex.test.", 2026072701, 3600, 900, 604800, 300,
        )
        .unwrap();
        let decoded = soa.as_soa().unwrap();
        assert!(decoded.mname.eq_ignore_ascii_case("ns1.ex.test") || decoded.mname.eq_ignore_ascii_case("ns1.ex.test."));
        assert!(
            decoded.rname.eq_ignore_ascii_case("hostmaster.ex.test")
                || decoded.rname.eq_ignore_ascii_case("hostmaster.ex.test.")
        );
        assert_eq!(decoded.serial, 2026072701);
        assert_eq!(decoded.refresh, 3600);
        assert_eq!(decoded.retry, 900);
        assert_eq!(decoded.expire, 604800);
        assert_eq!(decoded.minimum, 300);

        // Non-SOA records must not decode.
        let a = DnsResourceRecord::a("ex.test.", 60, Ipv4Addr::new(1, 2, 3, 4));
        assert!(a.as_soa().is_none());
    }

    #[test]
    fn srv_round_trips_through_as_srv() {
        let srv = DnsResourceRecord::srv("_http._tcp.ex.test.", 60, 10, 20, 8080, "target.ex.test.").unwrap();
        let (priority, weight, port, target) = srv.as_srv().unwrap();
        assert_eq!(priority, 10);
        assert_eq!(weight, 20);
        assert_eq!(port, 8080);
        assert!(
            target.eq_ignore_ascii_case("target.ex.test") || target.eq_ignore_ascii_case("target.ex.test."),
            "got {target:?}"
        );

        let a = DnsResourceRecord::a("ex.test.", 60, Ipv4Addr::new(1, 2, 3, 4));
        assert!(a.as_srv().is_none());
    }

    #[test]
    fn edns_padding_round_trips_and_coexists_with_other_options() {
        let padding = encode_edns_padding(16);
        assert_eq!(padding.len(), 4 + 16);
        let opt = DnsResourceRecord::opt(1232, false, &padding);
        assert_eq!(opt.edns_padding_length(), Some(16));

        // Padding appended after another option (e.g. COOKIE) must still
        // be found.
        let mut combined = vec![0u8, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]; // fake COOKIE option, 8-byte client cookie
        combined.extend_from_slice(&encode_edns_padding(4));
        let opt2 = DnsResourceRecord::opt(1232, false, &combined);
        assert_eq!(opt2.edns_padding_length(), Some(4));

        let no_padding = DnsResourceRecord::opt(1232, false, &[]);
        assert_eq!(no_padding.edns_padding_length(), None);
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

    #[test]
    fn edns_extended_rcode_and_version_default_to_zero() {
        let opt = DnsResourceRecord::opt(1232, true, &[]);
        assert_eq!(opt.edns_extended_rcode(), Some(0));
        assert_eq!(opt.edns_version(), Some(0));
        assert_eq!(opt.edns_full_rcode(3 /* NXDOMAIN */), Some(3));
        // DO bit and the rcode/version octets live in disjoint parts of
        // TTL and must not disturb each other.
        assert!(opt.edns_do());
    }

    #[test]
    fn edns_extended_rcode_and_version_round_trip() {
        let opt = DnsResourceRecord::opt(1232, true, &[]).with_edns_rcode_version(1, 0);
        // BADVERS (16) = extended octet 1 << 4 | header rcode 0.
        assert_eq!(opt.edns_extended_rcode(), Some(1));
        assert_eq!(opt.edns_version(), Some(0));
        assert_eq!(opt.edns_full_rcode(0), Some(crate::wire::RCODE_BADVERS));
        assert!(opt.edns_do(), "setting rcode/version must not clear DO");

        // A full 12-bit extended code above 15, e.g. BADCOOKIE = 23 = (1 << 4) | 7.
        let opt2 = DnsResourceRecord::opt(1232, false, &[]).with_edns_rcode_version(1, 0);
        assert_eq!(opt2.edns_full_rcode(7), Some(23));
        assert!(!opt2.edns_do());

        // A nonzero EDNS VERSION (e.g. an unsupported future version).
        let opt3 = DnsResourceRecord::opt(1232, false, &[]).with_edns_rcode_version(0, 9);
        assert_eq!(opt3.edns_version(), Some(9));
        assert_eq!(opt3.edns_extended_rcode(), Some(0));
    }

    #[test]
    fn edns_accessors_are_none_for_non_opt_records() {
        let a = DnsResourceRecord::a("ex.test", 60, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(a.edns_extended_rcode(), None);
        assert_eq!(a.edns_version(), None);
        assert_eq!(a.edns_full_rcode(0), None);
    }

    #[test]
    fn nsec_roundtrip() {
        let types = vec![DnsType::A.value(), DnsType::Rrsig.value(), DnsType::Nsec.value()];
        let nsec = DnsResourceRecord::nsec("a.ex.test", 3600, "b.ex.test", types.clone()).unwrap();
        assert_eq!(nsec.nsec_next_domain().as_deref(), Some("b.ex.test"));
        let mut decoded = nsec.nsec_types().unwrap();
        decoded.sort_unstable();
        let mut expected = types;
        expected.sort_unstable();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn nsec3_roundtrip() {
        let salt = [0xAB, 0xCD];
        let next_hash = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        let types = vec![DnsType::A.value(), DnsType::Rrsig.value()];
        let nsec3 = DnsResourceRecord::nsec3("q04.ex.test", 3600, 1, 1, 10, &salt, &next_hash, types.clone());
        assert_eq!(nsec3.nsec3_hash_algorithm(), Some(1));
        assert_eq!(nsec3.nsec3_flags(), Some(1));
        assert_eq!(nsec3.nsec3_iterations(), Some(10));
        assert_eq!(nsec3.nsec3_salt(), Some(&salt[..]));
        assert_eq!(nsec3.nsec3_next_hashed_owner(), Some(&next_hash[..]));
        let mut decoded = nsec3.nsec3_types().unwrap();
        decoded.sort_unstable();
        let mut expected = types;
        expected.sort_unstable();
        assert_eq!(decoded, expected);
    }
}

