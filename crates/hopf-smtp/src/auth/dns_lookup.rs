// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Small DNS-lookup seam shared by SPF/DKIM/DMARC so they can be unit-tested
//! against a fake resolver instead of a live [`hopf_dns::DnsResolver`].

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hopf_dns::wire::RCODE_NXDOMAIN;
use hopf_dns::DnsResolver;

/// Outcome of a single DNS query, distinguishing "no such name" (NXDOMAIN)
/// from "name exists but no records of this type" (NODATA) — both matter for
/// SPF's void-lookup accounting (RFC 7208 §4.6.4) and DKIM/DMARC PermError
/// classification.
pub enum Lookup<T> {
    /// One or more matching records.
    Answers(Vec<T>),
    /// NXDOMAIN.
    NxDomain,
    /// NOERROR with no matching records.
    NoData,
    /// Timeout, SERVFAIL, or other transient failure.
    TempError,
}

impl<T> Lookup<T> {
    /// `true` for [`Self::NxDomain`] or [`Self::NoData`] — a "void" lookup.
    pub fn is_void(&self) -> bool {
        matches!(self, Lookup::NxDomain | Lookup::NoData)
    }
}

type Cb<T> = Box<dyn FnOnce(Lookup<T>) + Send>;

/// DNS operations needed by SPF/DKIM/DMARC (production: [`DnsResolver`]; tests: a fake).
pub trait DnsLookup: Send + Sync {
    /// TXT record character-strings, one `String` per TXT record.
    fn query_txt(&self, name: &str, cb: Cb<String>);
    /// A records.
    fn query_a(&self, name: &str, cb: Cb<Ipv4Addr>);
    /// AAAA records.
    fn query_aaaa(&self, name: &str, cb: Cb<Ipv6Addr>);
    /// MX records as `(preference, exchange)`, unsorted.
    fn query_mx(&self, name: &str, cb: Cb<(u16, String)>);
    /// PTR records (domain names).
    fn query_ptr(&self, name: &str, cb: Cb<String>);
}

fn classify<T>(
    result: std::io::Result<hopf_dns::wire::DnsMessage>,
    extract: impl Fn(&hopf_dns::wire::DnsResourceRecord) -> Option<T>,
) -> Lookup<T> {
    match result {
        Err(_) => Lookup::TempError,
        Ok(msg) => {
            if msg.rcode() == RCODE_NXDOMAIN {
                return Lookup::NxDomain;
            }
            if msg.rcode() != hopf_dns::wire::RCODE_NOERROR {
                return Lookup::TempError;
            }
            let answers: Vec<T> = msg.answers.iter().filter_map(extract).collect();
            if answers.is_empty() {
                Lookup::NoData
            } else {
                Lookup::Answers(answers)
            }
        }
    }
}

impl DnsLookup for DnsResolver {
    fn query_txt(&self, name: &str, cb: Cb<String>) {
        self.query_txt(name, Box::new(move |r| cb(classify(r, |rr| rr.as_txt()))));
    }

    fn query_a(&self, name: &str, cb: Cb<Ipv4Addr>) {
        self.query_a(name, Box::new(move |r| cb(classify(r, |rr| rr.as_a()))));
    }

    fn query_aaaa(&self, name: &str, cb: Cb<Ipv6Addr>) {
        self.query_aaaa(name, Box::new(move |r| cb(classify(r, |rr| rr.as_aaaa()))));
    }

    fn query_mx(&self, name: &str, cb: Cb<(u16, String)>) {
        self.query_mx(name, Box::new(move |r| cb(classify(r, |rr| rr.as_mx()))));
    }

    fn query_ptr(&self, name: &str, cb: Cb<String>) {
        self.query_ptr(
            name,
            Box::new(move |r| cb(classify(r, |rr| rr.as_domain_name()))),
        );
    }
}

impl DnsLookup for Arc<DnsResolver> {
    fn query_txt(&self, name: &str, cb: Cb<String>) {
        <DnsResolver as DnsLookup>::query_txt(self, name, cb);
    }
    fn query_a(&self, name: &str, cb: Cb<Ipv4Addr>) {
        <DnsResolver as DnsLookup>::query_a(self, name, cb);
    }
    fn query_aaaa(&self, name: &str, cb: Cb<Ipv6Addr>) {
        <DnsResolver as DnsLookup>::query_aaaa(self, name, cb);
    }
    fn query_mx(&self, name: &str, cb: Cb<(u16, String)>) {
        <DnsResolver as DnsLookup>::query_mx(self, name, cb);
    }
    fn query_ptr(&self, name: &str, cb: Cb<String>) {
        <DnsResolver as DnsLookup>::query_ptr(self, name, cb);
    }
}
