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

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_dns::wire::{
        DnsClass, DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, RCODE_NOERROR, RCODE_REFUSED,
        RCODE_SERVFAIL,
    };
    use std::io;

    fn reply(rcode: u16, answers: Vec<DnsResourceRecord>) -> io::Result<DnsMessage> {
        Ok(DnsMessage::new(1, FLAG_QR | rcode, Vec::new(), answers, Vec::new(), Vec::new()))
    }

    fn a(ip: [u8; 4]) -> DnsResourceRecord {
        DnsResourceRecord::a("x.example", 60, Ipv4Addr::from(ip))
    }

    fn kind<T>(l: &Lookup<T>) -> &'static str {
        match l {
            Lookup::Answers(_) => "answers",
            Lookup::NxDomain => "nxdomain",
            Lookup::NoData => "nodata",
            Lookup::TempError => "temperror",
        }
    }

    #[test]
    fn a_failed_query_is_a_temporary_error() {
        let l = classify::<Ipv4Addr>(Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")), |rr| rr.as_a());
        assert_eq!(kind(&l), "temperror");
    }

    #[test]
    fn nxdomain_is_a_void_lookup_of_its_own_kind() {
        let l = classify(reply(hopf_dns::wire::RCODE_NXDOMAIN, Vec::new()), |rr| rr.as_a());
        assert_eq!(kind(&l), "nxdomain");
        assert!(l.is_void());
    }

    #[test]
    fn servfail_and_refused_are_temporary_errors() {
        for rcode in [RCODE_SERVFAIL, RCODE_REFUSED] {
            let l = classify(reply(rcode, Vec::new()), |rr| rr.as_a());
            assert_eq!(kind(&l), "temperror", "rcode {rcode}");
            assert!(!l.is_void());
        }
    }

    #[test]
    fn a_reply_with_nothing_of_the_type_asked_for_is_nodata() {
        let l = classify(reply(RCODE_NOERROR, Vec::new()), |rr| rr.as_a());
        assert_eq!(kind(&l), "nodata");
        assert!(l.is_void());
        // An answer of another type (a CNAME, say) is not an answer.
        let other = DnsResourceRecord::new("x.example", DnsType::Cname, DnsClass::In, 60, vec![0]);
        assert_eq!(kind(&classify(reply(RCODE_NOERROR, vec![other]), |rr| rr.as_a())), "nodata");
    }

    #[test]
    fn answers_of_the_right_type_are_extracted_and_the_rest_ignored() {
        let cname = DnsResourceRecord::new("x.example", DnsType::Cname, DnsClass::In, 60, vec![0]);
        match classify(reply(RCODE_NOERROR, vec![cname, a([192, 0, 2, 1]), a([192, 0, 2, 2])]), |rr| rr.as_a()) {
            Lookup::Answers(v) => assert_eq!(v, [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]),
            other => panic!("{}", kind(&other)),
        }
    }

    #[test]
    fn a_txt_record_in_several_strings_reads_as_one() {
        // RFC 7208 section 3.3: the strings of one record are joined with nothing between.
        let rr = DnsResourceRecord::new("x.example", DnsType::Txt, DnsClass::In, 60, {
            let mut r = vec![9];
            r.extend_from_slice(b"v=spf1 ip");
            r.push(11);
            r.extend_from_slice(b"4:192.0.2.1");
            r
        });
        match classify(reply(RCODE_NOERROR, vec![rr]), |rr| rr.as_txt()) {
            Lookup::Answers(v) => assert_eq!(v, ["v=spf1 ip4:192.0.2.1"]),
            other => panic!("{}", kind(&other)),
        }
    }

    // The real resolver, against a stub name server ---------------------------

    use hopf_core::{Runtime, RuntimeConfig};
    use std::sync::mpsc;
    use std::time::Duration;

    /// A UDP name server for a few fixed names.
    fn stub() -> std::net::SocketAddr {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let Ok(q) = DnsMessage::parse(&buf[..n]) else { continue };
                let Some(question) = q.questions.first() else { continue };
                let name = question.name.to_ascii_lowercase();
                let mut resp = q.response_template(match name.as_str() {
                    "nx.example" => hopf_dns::wire::RCODE_NXDOMAIN,
                    "fail.example" => RCODE_SERVFAIL,
                    _ => RCODE_NOERROR,
                });
                if name == "host.example" {
                    match question.qtype {
                        Some(DnsType::A) => resp.answers.push(DnsResourceRecord::a(&name, 60, Ipv4Addr::new(192, 0, 2, 7))),
                        Some(DnsType::Aaaa) => resp.answers.push(DnsResourceRecord::aaaa(&name, 60, "2001:db8::7".parse().unwrap())),
                        Some(DnsType::Mx) => resp.answers.push(DnsResourceRecord::mx(&name, 60, 10, "mail.host.example").unwrap()),
                        Some(DnsType::Txt) => resp.answers.push(DnsResourceRecord::txt(&name, 60, "v=spf1 -all").unwrap()),
                        Some(DnsType::Ptr) => resp.answers.push(DnsResourceRecord::ptr(&name, 60, "ptr.host.example").unwrap()),
                        _ => {}
                    }
                }
                let _ = sock.send_to(&resp.serialize().unwrap(), peer);
            }
        });
        addr
    }

    fn resolver() -> (Arc<DnsResolver>, Arc<Runtime>) {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
        dns.add_server(stub());
        dns.set_timeout(Duration::from_secs(2));
        dns.open().unwrap();
        (dns, rt)
    }

    fn ask<T: Send + 'static>(f: impl FnOnce(Cb<T>)) -> Lookup<T> {
        let (tx, rx) = mpsc::channel();
        f(Box::new(move |l| {
            let _ = tx.send(l);
        }));
        rx.recv_timeout(Duration::from_secs(5)).expect("an answer")
    }

    #[test]
    fn the_resolver_answers_each_kind_of_question() {
        let (dns, _rt) = resolver();
        let dns: Arc<dyn DnsLookup> = dns;
        match ask(|cb| dns.query_a("host.example", cb)) {
            Lookup::Answers(v) => assert_eq!(v, [Ipv4Addr::new(192, 0, 2, 7)]),
            other => panic!("A: {}", kind(&other)),
        }
        match ask(|cb| dns.query_aaaa("host.example", cb)) {
            Lookup::Answers(v) => assert_eq!(v, ["2001:db8::7".parse::<Ipv6Addr>().unwrap()]),
            other => panic!("AAAA: {}", kind(&other)),
        }
        match ask(|cb| dns.query_mx("host.example", cb)) {
            Lookup::Answers(v) => assert_eq!(v, [(10, "mail.host.example".to_string())]),
            other => panic!("MX: {}", kind(&other)),
        }
        match ask(|cb| dns.query_txt("host.example", cb)) {
            Lookup::Answers(v) => assert_eq!(v, ["v=spf1 -all"]),
            other => panic!("TXT: {}", kind(&other)),
        }
        match ask(|cb| dns.query_ptr("host.example", cb)) {
            Lookup::Answers(v) => assert_eq!(v, ["ptr.host.example"]),
            other => panic!("PTR: {}", kind(&other)),
        }
    }

    #[test]
    fn the_resolver_tells_nothing_there_from_no_such_name_from_a_failure() {
        let (dns, _rt) = resolver();
        let dns: Arc<dyn DnsLookup> = dns;
        assert_eq!(kind(&ask(|cb| dns.query_a("nx.example", cb))), "nxdomain");
        assert_eq!(kind(&ask(|cb| dns.query_txt("fail.example", cb))), "temperror");
        // The name exists but has no MX.
        assert_eq!(kind(&ask(|cb| dns.query_mx("other.example", cb))), "nodata");
    }

    #[test]
    fn an_spf_check_runs_against_the_real_resolver() {
        let (dns, _rt) = resolver();
        let (tx, rx) = mpsc::channel();
        crate::auth::spf::check_host(
            dns,
            "192.0.2.1".parse().unwrap(),
            "host.example",
            "user@host.example",
            "host.example",
            "me.example",
            Box::new(move |o| {
                let _ = tx.send(o);
            }),
        );
        let out = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(out.result, crate::auth::spf::SpfResult::Fail, "the stub's record is `v=spf1 -all`");
    }
}
