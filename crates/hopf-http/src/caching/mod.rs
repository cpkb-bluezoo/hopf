// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP validators, conditional requests and `Cache-Control` for origin
//! servers (RFC 9110 §8.8, §13; RFC 9111 §5.2).
//!
//! - [`EntityTag`] parses, compares and formats `ETag` values.
//! - [`evaluate_preconditions`] decides what a request's `If-Match`,
//!   `If-Unmodified-Since`, `If-None-Match` and `If-Modified-Since` fields
//!   mean for the current state of a resource, in the order RFC 9110 §13.2.2
//!   requires. Handlers that change state (`PUT`, `DELETE`, ...) call it
//!   *before* acting; for safe methods
//!   [`ConditionalServerFactory`](crate::ConditionalServerFactory) does it
//!   automatically from the validators a handler puts on its response.
//! - [`CacheControl`] builds a response `Cache-Control` value.
//!
//! Scope: this is origin-server correctness. hopf-http is not itself a
//! shared or private cache, so nothing here stores responses.

mod cache_control;
mod entity_tag;
mod precondition;

pub use cache_control::CacheControl;
pub use entity_tag::{parse_entity_tag_list, EntityTag, EntityTagList};
pub use precondition::{evaluate_preconditions, Precondition, Validators};

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod tests;
