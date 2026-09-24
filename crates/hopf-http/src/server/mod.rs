// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! App-facing HTTP server: [`HttpServer`], symmetric to [`crate::HttpClient`].

mod conditional;
mod content_encoding;
mod facade;
mod header_hook;
mod hsts;

pub use crate::content_coding::CompressibleFn;
pub use conditional::ConditionalServerFactory;
pub use content_encoding::{ContentEncodingServerFactory, ServerContentEncodingPolicy};
pub use facade::HttpServer;
pub use hsts::{HstsPolicy, HstsServerFactory};

#[cfg(test)]
mod hsts_e2e_tests;
