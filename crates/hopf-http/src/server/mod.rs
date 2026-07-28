// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! App-facing HTTP server: [`HttpServer`], symmetric to [`crate::HttpClient`].

mod facade;

pub use facade::HttpServer;
