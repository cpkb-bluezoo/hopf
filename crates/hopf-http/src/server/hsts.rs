// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP Strict Transport Security (RFC 6797).

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::server::header_hook::{HeaderHook, HeaderHookFactory};
use crate::stream::{ServerHandler, ServerHandlerFactory};

/// One year, the floor for the browsers' preload lists.
const PRELOAD_MIN_MAX_AGE: u64 = 31_536_000;

/// A `Strict-Transport-Security` policy (RFC 6797 §6.1).
///
/// ```
/// use std::time::Duration;
/// use hopf_http::HstsPolicy;
///
/// let p = HstsPolicy::new(Duration::from_secs(31_536_000)).include_subdomains();
/// assert_eq!(p.to_string(), "max-age=31536000; includeSubDomains");
/// ```
///
/// HSTS is a long-lived promise: a browser that has seen it refuses plain
/// HTTP to the host, and its subdomains if [`include_subdomains`](Self::include_subdomains)
/// is set, until `max-age` runs out. Start with a short `max-age`, and set
/// `preload` only once you mean it: removing a site from the browsers'
/// preload lists takes months.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HstsPolicy {
    max_age: Duration,
    include_subdomains: bool,
    preload: bool,
}

impl HstsPolicy {
    /// `max-age` only. `Duration::ZERO` tells browsers to forget the host
    /// (RFC 6797 §6.1.1), which is how HSTS is switched off again.
    pub fn new(max_age: Duration) -> Self {
        Self {
            max_age,
            include_subdomains: false,
            preload: false,
        }
    }

    /// Add `includeSubDomains`: the policy covers every subdomain too.
    pub fn include_subdomains(mut self) -> Self {
        self.include_subdomains = true;
        self
    }

    /// Add `preload`, consenting to inclusion in browser preload lists. The
    /// lists require `max-age` of at least one year and `includeSubDomains`;
    /// [`HttpServer::bind`](crate::HttpServer::bind) rejects a policy that
    /// asks for `preload` without them.
    pub fn preload(mut self) -> Self {
        self.preload = true;
        self
    }

    /// Check the policy can be sent as configured.
    pub fn validate(&self) -> io::Result<()> {
        if self.preload {
            if self.max_age.as_secs() < PRELOAD_MIN_MAX_AGE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HSTS preload requires max-age of at least one year (31536000 seconds)",
                ));
            }
            if !self.include_subdomains {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HSTS preload requires includeSubDomains",
                ));
            }
        }
        Ok(())
    }

    /// The header hook: adds the field to responses on secure connections
    /// only, and never over one that already has it.
    pub(crate) fn hook(&self) -> Arc<HeaderHook> {
        let value = self.to_string();
        Arc::new(move |headers, info| {
            // RFC 6797 §7.2: a host MUST NOT send the field over insecure
            // transport, and clients ignore it there anyway. A handler that
            // set its own value keeps it.
            if info.is_secure() && !headers.contains("strict-transport-security") {
                headers.set("Strict-Transport-Security", value.clone());
            }
        })
    }
}

impl fmt::Display for HstsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "max-age={}", self.max_age.as_secs())?;
        if self.include_subdomains {
            f.write_str("; includeSubDomains")?;
        }
        if self.preload {
            f.write_str("; preload")?;
        }
        Ok(())
    }
}

/// [`ServerHandlerFactory`] decorator that adds `Strict-Transport-Security`
/// to every response sent over a secure connection.
///
/// [`HttpServer::hsts`](crate::HttpServer::hsts) applies this for you on TCP
/// listeners; wrap a factory yourself for HTTP/3 (`listen_h3`), which is
/// always secure. Over a plaintext connection the field is never sent.
///
/// It goes on *every* response, error statuses included (RFC 6797 §7.1),
/// unless the handler already set the field itself.
pub struct HstsServerFactory(HeaderHookFactory);

impl HstsServerFactory {
    /// Wrap `inner`. Fails if `policy` is not valid (see [`HstsPolicy::validate`]).
    pub fn new(inner: Arc<dyn ServerHandlerFactory>, policy: &HstsPolicy) -> io::Result<Self> {
        policy.validate()?;
        Ok(Self(HeaderHookFactory::new(inner, policy.hook())))
    }
}

impl ServerHandlerFactory for HstsServerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        self.0.create_handler()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn formats_the_header_value_per_rfc_6797() {
        assert_eq!(HstsPolicy::new(secs(300)).to_string(), "max-age=300");
        assert_eq!(HstsPolicy::new(secs(0)).to_string(), "max-age=0", "zero is the way to clear HSTS");
        assert_eq!(
            HstsPolicy::new(secs(31_536_000)).include_subdomains().to_string(),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(
            HstsPolicy::new(secs(63_072_000)).include_subdomains().preload().to_string(),
            "max-age=63072000; includeSubDomains; preload"
        );
        assert_eq!(HstsPolicy::new(Duration::from_millis(1999)).to_string(), "max-age=1", "sub-second dropped");
    }

    #[test]
    fn preload_needs_a_year_and_subdomains() {
        let year = secs(31_536_000);
        assert!(HstsPolicy::new(year).include_subdomains().preload().validate().is_ok());
        assert!(HstsPolicy::new(year).validate().is_ok(), "without preload anything goes");
        assert!(HstsPolicy::new(secs(0)).validate().is_ok());
        for bad in [
            HstsPolicy::new(secs(31_535_999)).include_subdomains().preload(),
            HstsPolicy::new(year).preload(),
        ] {
            let e = bad.validate().unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad}");
        }
    }
}
