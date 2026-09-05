// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Compute a TLSA record (RFC 6698) from an existing certificate file —
//! offline, no DNS involved — so an operator deploying hopf as an inbound
//! MX has something concrete to publish for DANE (RFC 7672) ingress
//! authentication. See issues #352/#354.
//!
//! ```text
//! cargo run -p tlsa-record -- --cert mx.example.com.pem --name _25._tcp.mx.example.com
//! ```
//!
//! Defaults to usage=dane-ee (3), selector=spki (1), matching-type=sha256
//! (1) — RFC 7672's recommended combination for SMTP MX certificates: it
//! survives certificate renewal as long as the key pair is reused, and
//! (being DANE-EE) needs no separate CA trust.

use std::env;
use std::fs;
use std::io::BufReader;
use std::process::ExitCode;

use hopf_dns::dane::compute_association_data;
use hopf_dns::{TlsaMatchingType, TlsaSelector, TlsaUsage};

struct Args {
    cert_path: String,
    name: String,
    usage: TlsaUsage,
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
    ttl: u32,
}

fn print_usage() {
    eprintln!(
        "usage: tlsa-record --cert <path> --name <owner-name> \
         [--usage <name>] [--selector <name>] [--matching-type <name>] [--ttl <secs>]\n\
         \n\
         \x20 --cert <path>           PEM or DER certificate file (the leaf/server certificate)\n\
         \x20 --name <owner-name>     TLSA owner name, e.g. _25._tcp.mx.example.com\n\
         \x20 --usage <name>          pkix-ta|pkix-ee|dane-ta|dane-ee, or 0-3 (default: dane-ee)\n\
         \x20 --selector <name>       cert|spki, or 0-1 (default: spki)\n\
         \x20 --matching-type <name>  exact|sha256|sha384, or 0-2 (default: sha256)\n\
         \x20 --ttl <secs>            record TTL (default: 3600)"
    );
}

fn parse_usage(s: &str) -> Option<TlsaUsage> {
    Some(match s.to_ascii_lowercase().as_str() {
        "0" | "pkix-ta" => TlsaUsage::PkixTa,
        "1" | "pkix-ee" => TlsaUsage::PkixEe,
        "2" | "dane-ta" => TlsaUsage::DaneTa,
        "3" | "dane-ee" => TlsaUsage::DaneEe,
        _ => return None,
    })
}

fn parse_selector(s: &str) -> Option<TlsaSelector> {
    Some(match s.to_ascii_lowercase().as_str() {
        "0" | "cert" | "full-cert" | "full-certificate" => TlsaSelector::FullCertificate,
        "1" | "spki" => TlsaSelector::SubjectPublicKeyInfo,
        _ => return None,
    })
}

fn parse_matching_type(s: &str) -> Option<TlsaMatchingType> {
    Some(match s.to_ascii_lowercase().as_str() {
        "0" | "exact" => TlsaMatchingType::Exact,
        "1" | "sha256" => TlsaMatchingType::Sha256,
        "2" | "sha384" => TlsaMatchingType::Sha384,
        _ => return None,
    })
}

fn parse_args() -> Result<Args, String> {
    let mut cert_path = None;
    let mut name = None;
    let mut usage = TlsaUsage::DaneEe;
    let mut selector = TlsaSelector::SubjectPublicKeyInfo;
    let mut matching_type = TlsaMatchingType::Sha256;
    let mut ttl = 3600u32;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} requires a value"));
        match arg.as_str() {
            "--cert" => cert_path = Some(value()?),
            "--name" => name = Some(value()?),
            "--usage" => {
                let v = value()?;
                usage = parse_usage(&v).ok_or_else(|| format!("invalid --usage {v:?}"))?;
            }
            "--selector" => {
                let v = value()?;
                selector = parse_selector(&v).ok_or_else(|| format!("invalid --selector {v:?}"))?;
            }
            "--matching-type" => {
                let v = value()?;
                matching_type =
                    parse_matching_type(&v).ok_or_else(|| format!("invalid --matching-type {v:?}"))?;
            }
            "--ttl" => {
                let v = value()?;
                ttl = v.parse().map_err(|_| format!("invalid --ttl {v:?}"))?;
            }
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unrecognized argument {other:?}")),
        }
    }

    Ok(Args {
        cert_path: cert_path.ok_or("--cert is required")?,
        name: name.ok_or("--name is required")?,
        usage,
        selector,
        matching_type,
        ttl,
    })
}

/// Read `path` as either PEM (taking the first certificate) or raw DER.
fn load_cert_der(path: &str) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    if bytes.starts_with(b"-----BEGIN") {
        let mut reader = BufReader::new(bytes.as_slice());
        let mut certs = rustls_pemfile::certs(&mut reader);
        let first = certs
            .next()
            .ok_or_else(|| format!("{path}: no certificate found in PEM file"))?
            .map_err(|e| format!("{path}: malformed PEM: {e}"))?;
        Ok(first.as_ref().to_vec())
    } else {
        Ok(bytes)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Compute the TLSA record and format it as a ready-to-publish zone-file
/// line. Separated from `main` so it's directly testable without spawning
/// the built binary or capturing stdout.
fn build_record_line(args: &Args) -> Result<String, String> {
    let cert_der = load_cert_der(&args.cert_path)?;
    let association_data =
        compute_association_data(args.selector, args.matching_type, &cert_der).ok_or_else(|| {
            format!(
                "could not compute association data for selector={:?} matching-type={:?} \
                 (a SubjectPublicKeyInfo selector needs a parseable X.509 certificate)",
                args.selector, args.matching_type
            )
        })?;
    Ok(format!(
        "{}. {} IN TLSA {} {} {} {}",
        args.name.trim_end_matches('.'),
        args.ttl,
        args.usage.to_u8(),
        args.selector.to_u8(),
        args.matching_type.to_u8(),
        hex_encode(&association_data)
    ))
}

fn run() -> Result<(), String> {
    let args = parse_args().inspect_err(|_| print_usage())?;
    println!("{}", build_record_line(&args)?);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_usage_accepts_numeric_and_named_forms() {
        assert_eq!(parse_usage("0"), Some(TlsaUsage::PkixTa));
        assert_eq!(parse_usage("pkix-ta"), Some(TlsaUsage::PkixTa));
        assert_eq!(parse_usage("PKIX-TA"), Some(TlsaUsage::PkixTa));
        assert_eq!(parse_usage("1"), Some(TlsaUsage::PkixEe));
        assert_eq!(parse_usage("pkix-ee"), Some(TlsaUsage::PkixEe));
        assert_eq!(parse_usage("2"), Some(TlsaUsage::DaneTa));
        assert_eq!(parse_usage("dane-ta"), Some(TlsaUsage::DaneTa));
        assert_eq!(parse_usage("3"), Some(TlsaUsage::DaneEe));
        assert_eq!(parse_usage("dane-ee"), Some(TlsaUsage::DaneEe));
        assert_eq!(parse_usage("garbage"), None);
        assert_eq!(parse_usage("4"), None);
    }

    #[test]
    fn parse_selector_accepts_numeric_and_named_forms() {
        assert_eq!(parse_selector("0"), Some(TlsaSelector::FullCertificate));
        assert_eq!(parse_selector("cert"), Some(TlsaSelector::FullCertificate));
        assert_eq!(parse_selector("full-certificate"), Some(TlsaSelector::FullCertificate));
        assert_eq!(parse_selector("1"), Some(TlsaSelector::SubjectPublicKeyInfo));
        assert_eq!(parse_selector("spki"), Some(TlsaSelector::SubjectPublicKeyInfo));
        assert_eq!(parse_selector("SPKI"), Some(TlsaSelector::SubjectPublicKeyInfo));
        assert_eq!(parse_selector("garbage"), None);
    }

    #[test]
    fn parse_matching_type_accepts_numeric_and_named_forms() {
        assert_eq!(parse_matching_type("0"), Some(TlsaMatchingType::Exact));
        assert_eq!(parse_matching_type("exact"), Some(TlsaMatchingType::Exact));
        assert_eq!(parse_matching_type("1"), Some(TlsaMatchingType::Sha256));
        assert_eq!(parse_matching_type("sha256"), Some(TlsaMatchingType::Sha256));
        assert_eq!(parse_matching_type("2"), Some(TlsaMatchingType::Sha384));
        assert_eq!(parse_matching_type("sha384"), Some(TlsaMatchingType::Sha384));
        assert_eq!(parse_matching_type("garbage"), None);
    }

    /// A fresh, collision-free path — `cargo test` runs tests in parallel
    /// within the same process, so a pid/timestamp-derived name alone can
    /// collide between two tests calling this at nearly the same instant.
    fn write_temp_cert(bytes: &[u8], ext: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tlsa-record-test-{}-{n}.{ext}",
            std::process::id(),
        ));
        fs::write(&path, bytes).unwrap();
        path
    }

    fn test_cert_pem_and_der() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["mx.example.com".to_string()]).unwrap();
        let pem = cert.cert.pem().into_bytes();
        let der = cert.cert.der().as_ref().to_vec();
        (pem, der)
    }

    #[test]
    fn load_cert_der_reads_pem_and_der_identically() {
        let (pem, der) = test_cert_pem_and_der();
        let pem_path = write_temp_cert(&pem, "pem");
        let der_path = write_temp_cert(&der, "der");

        let from_pem = load_cert_der(pem_path.to_str().unwrap()).unwrap();
        let from_der = load_cert_der(der_path.to_str().unwrap()).unwrap();
        assert_eq!(from_pem, der, "PEM-loaded bytes must equal the raw DER");
        assert_eq!(from_pem, from_der);

        let _ = fs::remove_file(pem_path);
        let _ = fs::remove_file(der_path);
    }

    #[test]
    fn load_cert_der_reports_a_clear_error_for_a_missing_file() {
        let err = load_cert_der("/nonexistent/path/does-not-exist.pem").unwrap_err();
        assert!(err.contains("does-not-exist.pem"), "{err}");
    }

    #[test]
    fn build_record_line_full_cert_exact_matches_the_raw_der_hex() {
        let (pem, der) = test_cert_pem_and_der();
        let pem_path = write_temp_cert(&pem, "pem");

        let args = Args {
            cert_path: pem_path.to_str().unwrap().to_string(),
            name: "_25._tcp.mx.example.com".to_string(),
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::FullCertificate,
            matching_type: TlsaMatchingType::Exact,
            ttl: 3600,
        };
        let line = build_record_line(&args).unwrap();
        let expected_hex = hex_encode(&der);
        assert_eq!(
            line,
            format!("_25._tcp.mx.example.com. 3600 IN TLSA 3 0 0 {expected_hex}")
        );

        let _ = fs::remove_file(pem_path);
    }

    #[test]
    fn build_record_line_defaults_match_rfc_7672s_recommended_combination() {
        let (pem, _der) = test_cert_pem_and_der();
        let pem_path = write_temp_cert(&pem, "pem");

        let args = Args {
            cert_path: pem_path.to_str().unwrap().to_string(),
            name: "_25._tcp.mx.example.com.".to_string(), // trailing dot must be normalized, not doubled
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching_type: TlsaMatchingType::Sha256,
            ttl: 3600,
        };
        let line = build_record_line(&args).unwrap();
        assert!(line.starts_with("_25._tcp.mx.example.com. 3600 IN TLSA 3 1 1 "), "{line}");
        assert!(!line.contains(".. "), "trailing dot must not be doubled: {line}");
        // 32-byte SHA-256 digest -> 64 lowercase hex chars.
        let hex = line.rsplit(' ').next().unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        let _ = fs::remove_file(pem_path);
    }
}
