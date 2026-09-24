// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! App-facing HTTP server: [`HttpServer`], symmetric to [`crate::HttpClient`].

mod content_encoding;
mod facade;

pub use crate::content_coding::CompressibleFn;
pub use content_encoding::{ContentEncodingServerFactory, ServerContentEncodingPolicy};
pub use facade::HttpServer;
