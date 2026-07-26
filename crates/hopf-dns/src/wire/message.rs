// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::collections::HashMap;

use super::error::DnsFormatError;
use super::name::{decode_name, write_name_compressed};
use super::question::DnsQuestion;
use super::rr::DnsResourceRecord;
use super::r#type::DnsType;

/// Header size in octets.
pub const HEADER_SIZE: usize = 12;

/// Query/Response flag.
pub const FLAG_QR: u16 = 0x8000;
/// Authoritative Answer.
pub const FLAG_AA: u16 = 0x0400;
/// Truncation.
pub const FLAG_TC: u16 = 0x0200;
/// Recursion Desired.
pub const FLAG_RD: u16 = 0x0100;
/// Recursion Available.
pub const FLAG_RA: u16 = 0x0080;
/// Authenticated Data.
pub const FLAG_AD: u16 = 0x0020;
/// Checking Disabled.
pub const FLAG_CD: u16 = 0x0010;

/// Standard query opcode.
pub const OPCODE_QUERY: u16 = 0;

/// No error.
pub const RCODE_NOERROR: u16 = 0;
/// Format error.
pub const RCODE_FORMERR: u16 = 1;
/// Server failure.
pub const RCODE_SERVFAIL: u16 = 2;
/// Non-existent domain.
pub const RCODE_NXDOMAIN: u16 = 3;
/// Not implemented.
pub const RCODE_NOTIMP: u16 = 4;
/// Refused.
pub const RCODE_REFUSED: u16 = 5;

const Z_BITS_MASK: u16 = 0x0040;

/// Parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    /// Transaction ID.
    pub id: u16,
    /// Header flags.
    pub flags: u16,
    /// Questions.
    pub questions: Vec<DnsQuestion>,
    /// Answers.
    pub answers: Vec<DnsResourceRecord>,
    /// Authority.
    pub authorities: Vec<DnsResourceRecord>,
    /// Additional.
    pub additionals: Vec<DnsResourceRecord>,
}

impl DnsMessage {
    /// Construct a message.
    pub fn new(
        id: u16,
        flags: u16,
        questions: Vec<DnsQuestion>,
        answers: Vec<DnsResourceRecord>,
        authorities: Vec<DnsResourceRecord>,
        additionals: Vec<DnsResourceRecord>,
    ) -> Self {
        Self {
            id,
            flags: flags & !Z_BITS_MASK,
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    /// Standard recursive query.
    pub fn query(id: u16, question: DnsQuestion, recursion_desired: bool) -> Self {
        let mut flags = 0u16;
        if recursion_desired {
            flags |= FLAG_RD;
        }
        Self::new(id, flags, vec![question], Vec::new(), Vec::new(), Vec::new())
    }

    /// Response shell copying questions.
    pub fn response_template(&self, rcode: u16) -> Self {
        let mut flags = FLAG_QR | (self.flags & FLAG_RD) | (rcode & 0x0F);
        flags |= FLAG_RA;
        Self::new(
            self.id,
            flags,
            self.questions.clone(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    /// QR bit set.
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }
    /// QR bit clear.
    pub fn is_query(&self) -> bool {
        !self.is_response()
    }
    /// OPCODE field.
    pub fn opcode(&self) -> u16 {
        (self.flags >> 11) & 0x0F
    }
    /// TC bit.
    pub fn is_truncated(&self) -> bool {
        self.flags & FLAG_TC != 0
    }
    /// RD bit.
    pub fn is_recursion_desired(&self) -> bool {
        self.flags & FLAG_RD != 0
    }
    /// RCODE field.
    pub fn rcode(&self) -> u16 {
        self.flags & 0x0F
    }
    /// EDNS DO in OPT additional.
    pub fn has_do(&self) -> bool {
        self.additionals.iter().any(|rr| rr.edns_do())
    }

    /// The UDP payload size this message's sender advertises it can
    /// receive (RFC 6891 §6.2.3, OPT record's CLASS field) — or the RFC
    /// 1035 §2.3.4 legacy limit of 512 octets if it sent no OPT record at
    /// all. Used to decide whether *replying* to this message over UDP
    /// needs truncation (RFC 1035 §4.1.1 / RFC 2181 §9).
    pub fn requested_udp_payload_size(&self) -> u16 {
        self.additionals
            .iter()
            .find(|rr| rr.rtype == Some(DnsType::Opt))
            .map(|rr| rr.raw_class)
            .unwrap_or(512)
    }

    /// Parse wire bytes.
    pub fn parse(data: &[u8]) -> Result<Self, DnsFormatError> {
        if data.len() < HEADER_SIZE {
            return Err(DnsFormatError::new("message too short"));
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]) & !Z_BITS_MASK;
        let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
        let an = u16::from_be_bytes([data[6], data[7]]) as usize;
        let ns = u16::from_be_bytes([data[8], data[9]]) as usize;
        let ar = u16::from_be_bytes([data[10], data[11]]) as usize;
        let mut cursor = HEADER_SIZE;
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd {
            questions.push(parse_question(data, &mut cursor)?);
        }
        let mut answers = Vec::with_capacity(an);
        for _ in 0..an {
            answers.push(parse_rr(data, &mut cursor)?);
        }
        let mut authorities = Vec::with_capacity(ns);
        for _ in 0..ns {
            authorities.push(parse_rr(data, &mut cursor)?);
        }
        let mut additionals = Vec::with_capacity(ar);
        for _ in 0..ar {
            additionals.push(parse_rr(data, &mut cursor)?);
        }
        Ok(Self::new(
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        ))
    }

    /// Serialize with name compression.
    pub fn serialize(&self) -> Result<Vec<u8>, DnsFormatError> {
        let mut out = Vec::new();
        let mut table = HashMap::new();
        write_u16(&mut out, self.id);
        write_u16(&mut out, self.flags & !Z_BITS_MASK);
        write_u16(&mut out, self.questions.len() as u16);
        write_u16(&mut out, self.answers.len() as u16);
        write_u16(&mut out, self.authorities.len() as u16);
        write_u16(&mut out, self.additionals.len() as u16);
        for q in &self.questions {
            write_question(&mut out, q, &mut table)?;
        }
        for rr in &self.answers {
            write_rr(&mut out, rr, &mut table)?;
        }
        for rr in &self.authorities {
            write_rr(&mut out, rr, &mut table)?;
        }
        for rr in &self.additionals {
            write_rr(&mut out, rr, &mut table)?;
        }
        Ok(out)
    }
}

fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn parse_question(data: &[u8], cursor: &mut usize) -> Result<DnsQuestion, DnsFormatError> {
    let name = decode_name(data, cursor)?;
    if *cursor + 4 > data.len() {
        return Err(DnsFormatError::new("truncated question"));
    }
    let type_v = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]);
    *cursor += 2;
    let class_v = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]);
    *cursor += 2;
    // RFC 3597: an unrecognized QTYPE/QCLASS is preserved raw, the same
    // way RR type/class already is — not a reason to fail the whole message.
    Ok(DnsQuestion::opaque(name, type_v, class_v))
}

fn parse_rr(data: &[u8], cursor: &mut usize) -> Result<DnsResourceRecord, DnsFormatError> {
    let name = decode_name(data, cursor)?;
    if *cursor + 10 > data.len() {
        return Err(DnsFormatError::new("truncated resource record"));
    }
    let type_v = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]);
    *cursor += 2;
    let class_v = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]);
    *cursor += 2;
    let ttl = u32::from_be_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
    ]);
    *cursor += 4;
    let rdlen = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]) as usize;
    *cursor += 2;
    if *cursor + rdlen > data.len() {
        return Err(DnsFormatError::new("truncated rdata"));
    }
    let rdata = data[*cursor..*cursor + rdlen].to_vec();
    *cursor += rdlen;
    Ok(DnsResourceRecord::opaque(name, type_v, class_v, ttl, rdata))
}

fn write_question(
    out: &mut Vec<u8>,
    q: &DnsQuestion,
    table: &mut HashMap<String, u16>,
) -> Result<(), DnsFormatError> {
    write_name_compressed(out, &q.name, table)?;
    write_u16(out, q.raw_qtype);
    write_u16(out, q.raw_qclass);
    Ok(())
}

fn write_rr(
    out: &mut Vec<u8>,
    rr: &DnsResourceRecord,
    table: &mut HashMap<String, u16>,
) -> Result<(), DnsFormatError> {
    write_name_compressed(out, &rr.name, table)?;
    write_u16(out, rr.raw_type);
    write_u16(out, rr.raw_class);
    write_u32(out, rr.ttl);
    if rr.rdata.len() > u16::MAX as usize {
        return Err(DnsFormatError::new("rdata too long"));
    }
    write_u16(out, rr.rdata.len() as u16);
    out.extend_from_slice(&rr.rdata);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn query_roundtrip() {
        let q = DnsQuestion::in_class("example.com", DnsType::A);
        let msg = DnsMessage::query(0x1234, q, true);
        let bytes = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert!(parsed.is_recursion_desired());
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.questions[0].qtype, Some(DnsType::A));
    }

    #[test]
    fn answer_with_a() {
        let q = DnsQuestion::in_class("example.com", DnsType::A);
        let mut msg = DnsMessage::query(1, q, true);
        msg.flags |= FLAG_QR | FLAG_RA;
        msg.answers
            .push(DnsResourceRecord::a("example.com", 300, Ipv4Addr::new(93, 184, 216, 34)));
        let bytes = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&bytes).unwrap();
        assert_eq!(
            parsed.answers[0].as_a(),
            Some(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    /// RFC 3597: an unrecognized QTYPE/QCLASS must not fail parsing the
    /// whole message — the raw value round-trips even though `qtype`/
    /// `qclass` can't resolve to a known enum variant.
    #[test]
    fn unknown_qtype_and_qclass_round_trip_without_failing_the_message() {
        let q = DnsQuestion::opaque("weird.example", 65280, 65281);
        assert_eq!(q.qtype, None);
        assert_eq!(q.qclass, None);
        let msg = DnsMessage::query(9, q, true);
        let bytes = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&bytes).expect("unknown QTYPE/QCLASS must still parse");
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "weird.example");
        assert_eq!(parsed.questions[0].qtype, None);
        assert_eq!(parsed.questions[0].raw_qtype, 65280);
        assert_eq!(parsed.questions[0].qclass, None);
        assert_eq!(parsed.questions[0].raw_qclass, 65281);
    }
}
