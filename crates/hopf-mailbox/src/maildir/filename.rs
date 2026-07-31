// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Maildir filename encoding (`:2,` flags).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::flag::Flag;

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Parse / build Maildir filenames.
#[derive(Clone, Debug)]
pub struct MaildirFilename {
    /// Identity without `:2,...`
    pub base: String,
    /// System flags from info.
    pub flags: BTreeSet<Flag>,
    /// Keyword letters `a`–`z`.
    pub keyword_letters: BTreeSet<char>,
}

impl MaildirFilename {
    /// Split base / info.
    pub fn parse(name: &str) -> Self {
        if let Some((base, info)) = name.split_once(":2,") {
            let mut flags = BTreeSet::new();
            let mut keyword_letters = BTreeSet::new();
            for c in info.chars() {
                if let Some(f) = Flag::from_maildir_letter(c) {
                    flags.insert(f);
                } else if c.is_ascii_lowercase() {
                    keyword_letters.insert(c);
                }
            }
            Self {
                base: base.to_string(),
                flags,
                keyword_letters,
            }
        } else {
            Self {
                base: name.to_string(),
                flags: BTreeSet::new(),
                keyword_letters: BTreeSet::new(),
            }
        }
    }

    /// Full filename with `:2,` info.
    pub fn to_string_name(&self) -> String {
        let mut letters: Vec<char> = self
            .flags
            .iter()
            .filter_map(|f| f.maildir_letter())
            .collect();
        letters.sort_unstable();
        let mut kw: Vec<char> = self.keyword_letters.iter().copied().collect();
        kw.sort_unstable();
        letters.extend(kw);
        format!("{}:2,{}", self.base, letters.iter().collect::<String>())
    }

    /// Generate a unique base name with optional size.
    ///
    /// Includes the local hostname (sanitized — see [`sanitized_hostname`])
    /// alongside the timestamp/pid/counter, matching the classic Maildir
    /// unique-name convention: `time.delivery-id.hostname`. Without it,
    /// two hosts delivering into the same maildir over NFS at the same
    /// millisecond with colliding pids could produce the same filename;
    /// the hostname is what makes the name globally, not just
    /// single-host, unique.
    pub fn generate(size: Option<u64>) -> String {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let host = sanitized_hostname();
        match size {
            Some(s) => format!("{ms}.{pid}.{n}.{host},S={s}"),
            None => format!("{ms}.{pid}.{n}.{host}"),
        }
    }
}

/// Local hostname, with `/` and `:` escaped as `\057`/`\072` (the classic
/// Maildir convention) since both are structurally significant in a
/// maildir filename — `/` is a path separator, `:` introduces the
/// `:2,<flags>` suffix.
fn sanitized_hostname() -> String {
    sanitize_hostname_component(&raw_hostname())
}

fn sanitize_hostname_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '/' => out.push_str("\\057"),
            ':' => out.push_str("\\072"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(unix)]
fn raw_hostname() -> String {
    // POSIX gethostname(2); libc is already a dependency (used for flock
    // in the mbox backend).
    let mut buf = vec![0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return "localhost".to_string();
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

#[cfg(not(unix))]
fn raw_hostname() -> String {
    "localhost".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_name_includes_a_nonempty_hostname_component() {
        let name = MaildirFilename::generate(None);
        let parts: Vec<&str> = name.split('.').collect();
        // time . pid . counter . hostname (hostname may itself contain
        // dots, e.g. "host.example.com", so require at least 4 parts and
        // a non-empty tail rather than an exact count).
        assert!(parts.len() >= 4, "expected time.pid.counter.host, got: {name}");
        assert!(!parts.last().unwrap().is_empty());
        assert_eq!(parts.join("."), name);
    }

    #[test]
    fn generated_name_with_size_appends_the_size_suffix_after_the_hostname() {
        let name = MaildirFilename::generate(Some(1234));
        assert!(name.ends_with(",S=1234"), "got: {name}");
        let without_suffix = name.strip_suffix(",S=1234").unwrap();
        assert!(!without_suffix.contains(','));
    }

    #[test]
    fn successive_generated_names_are_unique() {
        let a = MaildirFilename::generate(None);
        let b = MaildirFilename::generate(None);
        assert_ne!(a, b);
    }

    #[test]
    fn generated_base_round_trips_through_parse() {
        let base = MaildirFilename::generate(None);
        let full = format!("{base}:2,S");
        let parsed = MaildirFilename::parse(&full);
        assert_eq!(parsed.base, base);
        assert!(parsed.flags.contains(&Flag::Seen));
    }

    #[test]
    fn sanitize_hostname_component_escapes_slash_and_colon() {
        assert_eq!(sanitize_hostname_component("host/name"), "host\\057name");
        assert_eq!(sanitize_hostname_component("host:name"), "host\\072name");
        assert_eq!(sanitize_hostname_component("plain-host"), "plain-host");
        assert_eq!(sanitize_hostname_component("a/b:c"), "a\\057b\\072c");
    }

    #[test]
    fn real_sanitized_hostname_never_contains_slash_or_colon() {
        let h = sanitized_hostname();
        assert!(!h.is_empty());
        assert!(!h.contains('/'), "got: {h}");
        assert!(!h.contains(':'), "got: {h}");
    }
}
