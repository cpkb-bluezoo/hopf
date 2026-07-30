// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Inbound/outbound email authentication: SPF, DKIM, DMARC (Gumdrop
//! `org.bluezoo.gumdrop.smtp.auth` port; RFC 7208, RFC 6376, RFC 8463, RFC 7489).
//!
//! [`AuthPipeline`] implements [`crate::server::SmtpPipeline`] and can be
//! returned from [`crate::MailFromHandler::pipeline`] to run SPF at MAIL FROM
//! and DKIM + DMARC at end-of-DATA, with results delivered via callbacks and
//! a shared [`AuthVerdictHandle`] that [`crate::server::DeferredDelivery`] can
//! wait on when DNS hasn't resolved by the time the transaction completes.

pub mod dkim;
pub mod dmarc;
mod dns_lookup;
mod macros;
mod pipeline;
pub mod psl;
pub mod spf;

pub use dmarc::AuthVerdict;
pub use dns_lookup::{DnsLookup, Lookup};
pub use pipeline::{AuthPipeline, AuthPipelineBuilder, AuthResultsHandle, AuthVerdictHandle};
pub use psl::PublicSuffixList;
