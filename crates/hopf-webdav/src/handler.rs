// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV HTTP request handler (RFC 4918 + RFC 9110 file serving).

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use hopf_core::storage::{StorageError, StorageExecutor};
use hopf_http::Headers;
use hopf_http::{parse_http_date, ServerHandler, ServerWriter};

use crate::constants::{
    self, CONTENT_TYPE_XML, DEPTH_0, DEPTH_1, DEPTH_INFINITY, HEADER_DAV, HEADER_DEPTH,
    HEADER_DESTINATION, HEADER_IF, HEADER_LOCK_TOKEN, HEADER_OVERWRITE,
    MAX_WEBDAV_REQUEST_BODY, NAMESPACE,
};
use crate::dead_props::{DeadPropertyStore, is_sidecar_file, is_sidecar_name};
use crate::factory::WebDavConfig;
use crate::if_header::{evaluate_if_header, parse_if_header};
use crate::lock::{WebDavLock, WebDavLockManager};
use crate::parser::{
    parse_webdav_body, PropfindType, ProppatchOp, WebDavParsed, WebDavRequestParser,
};
use crate::path::{canonicalize_path, resolve_path_lexical};
use crate::multistatus::MultistatusWriter;
use crate::xml_out::{
    ensure_trailing_slash_for_collection, href_for_path, write_active_lock,
    write_collection_resourcetype, write_dead_property, write_empty_resourcetype,
    write_live_property, write_lock_discovery, write_supported_lock, PropXmlWriter,
};

/// Per-connection WebDAV handler.
pub struct WebDavHandler {
    config: Arc<WebDavConfig>,
    storage: Arc<StorageExecutor>,
    lock_manager: Arc<WebDavLockManager>,
    dead_store: DeadPropertyStore,
    allowed_options: String,
    welcome_files: Vec<String>,
    content_types: HashMap<String, String>,
    root_path: PathBuf,
    canonical_root: PathBuf,

    method: String,
    request_path: String,
    path: Option<PathBuf>,
    if_modified_since: Option<SystemTime>,
    depth: i32,
    destination: Option<String>,
    overwrite: bool,
    lock_token: Option<String>,
    if_header: Option<String>,
    timeout_header: Option<String>,
    host: Option<String>,

    webdav_body: Vec<u8>,
    webdav_parser: Option<WebDavRequestParser>,
    /// Open destination file for an in-progress PUT; each inbound chunk is
    /// written directly to it as it arrives — never buffered whole.
    put_file: Option<fs::File>,
    put_bytes_written: u64,
    /// Set once a PUT has already been answered (size cap exceeded, or a
    /// write error) — further body chunks are discarded without a second
    /// response.
    put_rejected: bool,
    /// MKCOL deferred until the request body ends so a non-empty body can
    /// be rejected with 415 (RFC 4918 §9.3).
    mkcol_pending: bool,
    mkcol_had_body: bool,
}

impl WebDavHandler {
    pub(crate) fn new(
        config: Arc<WebDavConfig>,
        storage: Arc<StorageExecutor>,
        lock_manager: Arc<WebDavLockManager>,
        dead_store: DeadPropertyStore,
        allowed_options: String,
        welcome_files: Vec<String>,
        content_types: HashMap<String, String>,
        canonical_root: PathBuf,
    ) -> Self {
        let root_path = config.root_path.clone();
        Self {
            config,
            storage,
            lock_manager,
            dead_store,
            allowed_options,
            welcome_files,
            content_types,
            root_path,
            canonical_root,
            method: String::new(),
            request_path: String::new(),
            path: None,
            if_modified_since: None,
            depth: DEPTH_INFINITY,
            destination: None,
            overwrite: true,
            lock_token: None,
            if_header: None,
            timeout_header: None,
            host: None,
            webdav_body: Vec::new(),
            webdav_parser: None,
            put_file: None,
            put_bytes_written: 0,
            put_rejected: false,
            mkcol_pending: false,
            mkcol_had_body: false,
        }
    }

    fn href(&self) -> String {
        href_for_path(&self.request_path)
    }

    fn send_error(w: &mut dyn ServerWriter, code: u16) {
        let mut h = Headers::new();
        h.status(code);
        h.set("Content-Length", "0");
        w.headers(h);
        w.complete();
    }

    fn send_bytes(w: &mut dyn ServerWriter, code: u16, content_type: &str, body: &[u8]) {
        let mut h = Headers::new();
        h.status(code);
        h.set("Content-Type", content_type);
        h.set("Content-Length", body.len().to_string());
        w.headers(h);
        if !body.is_empty() {
            w.start_response_body();
            w.response_body_content(body);
            w.end_response_body();
        }
        w.complete();
    }

    fn offload<F, T>(&self, w: &mut dyn ServerWriter, op: F, on_ok: impl FnOnce(T, &mut dyn ServerWriter) + Send + 'static)
    where
        F: FnOnce() -> Result<T, Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
        T: Send + 'static,
    {
        let rh = w.response_handle();
        let conn = rh.conn_handle().clone();
        self.storage.submit_on(
            conn,
            op,
            move |result| {
                rh.execute(move |writer| match result {
                    Ok(v) => on_ok(v, writer),
                    Err(StorageError::Rejected) => Self::send_error(writer, 503),
                    Err(StorageError::Task(_)) => Self::send_error(writer, 500),
                });
            },
        );
    }
}

impl ServerHandler for WebDavHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        self.method = headers.method().unwrap_or("GET").to_string();
        self.request_path = headers.path().unwrap_or("/").to_string();
        self.host = headers.get("host").map(|s| s.to_string());

        if self.request_path == "*" {
            self.path = None;
        } else {
            self.path = resolve_path_lexical(&self.root_path, &self.request_path);
        }

        if let Some(v) = headers.get("if-modified-since") {
            self.if_modified_since = parse_http_date(v);
        }

        if self.config.webdav_enabled {
            if let Some(d) = headers.get(HEADER_DEPTH) {
                self.depth = match d {
                    "0" => DEPTH_0,
                    "1" => DEPTH_1,
                    _ => DEPTH_INFINITY,
                };
            }
            self.destination = headers.get(HEADER_DESTINATION).map(|s| s.to_string());
            self.overwrite = headers
                .get(HEADER_OVERWRITE)
                .map(|v| !v.eq_ignore_ascii_case("f"))
                .unwrap_or(true);
            self.lock_token = headers.get(HEADER_LOCK_TOKEN).map(|s| s.to_string());
            self.if_header = headers.get(HEADER_IF).map(|s| s.to_string());
            self.timeout_header = headers.get(constants::HEADER_TIMEOUT).map(|s| s.to_string());
        }

        match self.method.as_str() {
            "OPTIONS" => self.handle_options(response),
            "GET" | "HEAD" => self.handle_get_head(response),
            "DELETE" if self.config.allow_write => self.handle_delete(response),
            "PUT" if self.config.allow_write => self.handle_put_headers(response),
            "PROPFIND" if self.config.webdav_enabled => self.start_webdav_body(response),
            "PROPPATCH" if self.config.webdav_enabled && self.config.allow_write => {
                self.start_webdav_body(response)
            }
            "LOCK" if self.config.webdav_enabled && self.config.allow_write => {
                self.start_webdav_body(response)
            }
            "MKCOL" if self.config.webdav_enabled && self.config.allow_write => {
                self.mkcol_pending = true;
                self.mkcol_had_body = false;
            }
            "COPY" if self.config.webdav_enabled && self.config.allow_write => {
                self.handle_copy(response)
            }
            "MOVE" if self.config.webdav_enabled && self.config.allow_write => {
                self.handle_move(response)
            }
            "UNLOCK" if self.config.webdav_enabled && self.config.allow_write => {
                self.handle_unlock(response)
            }
            _ => Self::send_error(response, 405),
        }
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        if self.mkcol_pending {
            if !data.is_empty() {
                self.mkcol_had_body = true;
            }
            return;
        }
        if self.webdav_parser.is_some() {
            self.webdav_body.extend_from_slice(data);
            if let Some(ref mut p) = self.webdav_parser {
                let _ = p.feed(data);
            }
            return;
        }
        if self.put_rejected || self.put_file.is_none() {
            return;
        }
        self.put_bytes_written += data.len() as u64;
        if self.put_bytes_written > self.config.max_put_body {
            self.put_rejected = true;
            self.put_file = None;
            Self::send_error(response, 413);
            return;
        }
        if let Some(f) = self.put_file.as_mut() {
            if f.write_all(data).is_err() {
                self.put_rejected = true;
                self.put_file = None;
                Self::send_error(response, 500);
            }
        }
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.mkcol_pending {
            self.finish_mkcol(response);
            return;
        }
        if self.webdav_parser.take().is_some() {
            if self.webdav_body.len() > MAX_WEBDAV_REQUEST_BODY {
                Self::send_error(response, 413);
                return;
            }
            let body = std::mem::take(&mut self.webdav_body);
            match parse_webdav_body(&body) {
                Ok(parsed) => self.finish_webdav(response, parsed),
                Err(_) => Self::send_error(response, 400),
            }
            return;
        }
        if self.put_rejected {
            return;
        }
        if self.put_file.take().is_some() {
            Self::send_error(response, 201);
        }
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        // MKCOL / PUT with no body still need a response.
        if self.mkcol_pending {
            self.finish_mkcol(response);
        } else if self.put_file.is_some() {
            self.end_request_body(response);
        }
        self.webdav_body.clear();
        self.put_bytes_written = 0;
        self.put_rejected = false;
    }
}

impl WebDavHandler {
    fn handle_options(&self, w: &mut dyn ServerWriter) {
        let mut h = Headers::new();
        h.status(200);
        h.set("Allow", &self.allowed_options);
        if self.config.webdav_enabled {
            h.set(HEADER_DAV, "1,2");
        }
        h.set("Content-Length", "0");
        w.headers(h);
        w.complete();
    }

    fn start_webdav_body(&mut self, w: &mut dyn ServerWriter) {
        self.webdav_parser = Some(WebDavRequestParser::new(MAX_WEBDAV_REQUEST_BODY));
        self.webdav_body.clear();
        let _ = w;
    }

    fn finish_webdav(&mut self, w: &mut dyn ServerWriter, parsed: WebDavParsed) {
        match self.method.as_str() {
            "PROPFIND" => self.handle_propfind(w, parsed),
            "PROPPATCH" => self.handle_proppatch(w, parsed),
            "LOCK" => self.handle_lock(w, parsed),
            _ => Self::send_error(w, 400),
        }
    }

    fn handle_get_head(&mut self, w: &mut dyn ServerWriter) {
        let if_mod = self.if_modified_since;
        let path = self.path.clone();
        let request_path = self.request_path.clone();
        let welcome = self.welcome_files.clone();
        let types = self.content_types.clone();
        let root = self.root_path.clone();
        let canonical = self.canonical_root.clone();
        let is_get = self.method == "GET";

        let rh = w.response_handle();
        let conn = rh.conn_handle().clone();
        let rh_fallback = rh.clone();
        self.storage.submit_on(
            conn,
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let Some(lexical) = path else {
                    rh.execute(|w| Self::send_error(w, 404));
                    return Ok(());
                };
                let Some(resolved) = canonicalize_path(&root, &canonical, &lexical) else {
                    rh.execute(|w| Self::send_error(w, 404));
                    return Ok(());
                };
                if !resolved.exists() || is_sidecar_file(&resolved) {
                    rh.execute(|w| Self::send_error(w, 404));
                    return Ok(());
                }
                let mut target = resolved.clone();
                if resolved.is_dir() {
                    if let Some(index) = find_welcome(&resolved, &welcome) {
                        target = index;
                    } else {
                        let html = build_listing(&request_path, &resolved)?;
                        rh.execute(move |w| {
                            let mut h = Headers::new();
                            h.status(200);
                            h.set("Content-Type", "text/html; charset=utf-8");
                            h.set("Content-Length", html.len().to_string());
                            w.headers(h);
                            if is_get {
                                w.start_response_body();
                                w.response_body_content(&html);
                                w.end_response_body();
                            }
                            w.complete();
                        });
                        return Ok(());
                    }
                }
                let meta = fs::metadata(&target)?;
                let modified = meta.modified()?;
                if let Some(since) = if_mod {
                    if modified <= since {
                        rh.execute(|w| {
                            let mut h = Headers::new();
                            h.status(304);
                            w.headers(h);
                            w.complete();
                        });
                        return Ok(());
                    }
                }
                let content_type = content_type_for(&target, &types);
                let size = meta.len();
                let etag = weak_etag(&target, &meta);
                let last_modified = http_date(modified);
                let stream_body = is_get && size > 0;

                // Open (and fail fast on) the file *before* sending headers,
                // so a "can't open" error still becomes a clean status code
                // instead of a response that already started.
                let file = if stream_body {
                    match fs::File::open(&target) {
                        Ok(f) => Some(f),
                        Err(_) => {
                            rh.execute(|w| Self::send_error(w, 404));
                            return Ok(());
                        }
                    }
                } else {
                    None
                };

                rh.execute(move |w| {
                    let mut h = Headers::new();
                    h.status(200);
                    h.set("Last-Modified", last_modified);
                    h.set("ETag", &etag);
                    h.set("Content-Type", &content_type);
                    h.set("Content-Length", size.to_string());
                    w.headers(h);
                    if stream_body {
                        w.start_response_body();
                    } else {
                        w.complete();
                    }
                });

                if let Some(mut f) = file {
                    let mut buf = [0u8; 8192];
                    let mut clean = true;
                    loop {
                        match f.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let chunk = buf[..n].to_vec();
                                rh.execute(move |w| w.response_body_content(&chunk));
                            }
                            Err(_) => {
                                clean = false;
                                break;
                            }
                        }
                    }
                    if clean {
                        rh.execute(|w| {
                            w.end_response_body();
                            w.complete();
                        });
                    } else {
                        // Headers (with a Content-Length) already went out —
                        // finishing normally would send a truncated body
                        // that still claims the original length. Drop the
                        // connection instead of corrupting the framing.
                        rh.conn_handle().close();
                    }
                }
                Ok(())
            },
            move |result| {
                if result.is_err() {
                    // `op` only reaches here via early `?` before any
                    // response was sent (metadata/listing failures) — safe
                    // to answer with a generic error.
                    rh_fallback.execute(|w| Self::send_error(w, 500));
                }
            },
        );
    }

    fn handle_put_headers(&mut self, w: &mut dyn ServerWriter) {
        if !self.check_mutating_preconditions(w) {
            return;
        }
        let Some(lexical) = self.path.clone() else {
            Self::send_error(w, 404);
            return;
        };
        let Some(resolved) = canonicalize_path(&self.root_path, &self.canonical_root, &lexical)
        else {
            Self::send_error(w, 403);
            return;
        };
        if resolved.is_dir() {
            Self::send_error(w, 409);
            return;
        }
        if let Some(parent) = resolved.parent() {
            if fs::create_dir_all(parent).is_err() {
                Self::send_error(w, 500);
                return;
            }
        }
        // Open now and write each inbound chunk directly to it as it
        // arrives — the request body is never buffered whole. Headers are a
        // fast metadata operation; the potentially large body writes happen
        // per chunk in `request_body_content`, not here.
        match fs::File::create(&resolved) {
            Ok(f) => {
                self.put_file = Some(f);
                self.put_bytes_written = 0;
                self.put_rejected = false;
            }
            Err(_) => Self::send_error(w, 500),
        }
    }

    fn handle_delete(&mut self, w: &mut dyn ServerWriter) {
        if !self.check_mutating_preconditions(w) {
            return;
        }
        let path = self.path.clone();
        let root = self.root_path.clone();
        let canonical = self.canonical_root.clone();
        let href = self.href();
        let mut store = self.dead_store.clone();
        self.offload(w, move || {
            let Some(lexical) = path else {
                return Ok(DeleteOutcome::Status(404));
            };
            let Some(resolved) = canonicalize_path(&root, &canonical, &lexical) else {
                return Ok(DeleteOutcome::Status(404));
            };
            if !resolved.exists() || is_sidecar_file(&resolved) {
                return Ok(DeleteOutcome::Status(404));
            }
            let mut errors: Vec<(String, u16)> = Vec::new();
            delete_recursive(&resolved, &href, &mut store, &mut errors);
            if errors.is_empty() {
                Ok(DeleteOutcome::Status(204))
            } else {
                let mut ms = MultistatusWriter::new();
                for (h, code) in &errors {
                    ms.response(h, |r| {
                        r.status(&format!("HTTP/1.1 {code} {}", hopf_http::reason_phrase(*code)))
                    })
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                }
                Ok(DeleteOutcome::MultiStatus(ms.finish()))
            }
        }, |out, writer| match out {
            DeleteOutcome::Status(code) => {
                if code == 204 {
                    Self::send_error(writer, 204);
                } else {
                    Self::send_error(writer, code);
                }
            }
            DeleteOutcome::MultiStatus(body) => {
                Self::send_bytes(writer, 207, CONTENT_TYPE_XML, &body)
            }
        });
    }

    fn finish_mkcol(&mut self, w: &mut dyn ServerWriter) {
        self.mkcol_pending = false;
        if self.mkcol_had_body {
            self.mkcol_had_body = false;
            Self::send_error(w, 415);
            return;
        }
        self.mkcol_had_body = false;
        if !self.check_mutating_preconditions(w) {
            return;
        }
        let path = self.path.clone();
        let root = self.root_path.clone();
        let canonical = self.canonical_root.clone();
        self.offload(w, move || {
            let Some(lexical) = path else {
                return Ok(404u16);
            };
            let Some(resolved) = canonicalize_path(&root, &canonical, &lexical) else {
                return Ok(403);
            };
            if resolved.exists() {
                return Ok(405);
            }
            // RFC 4918 §9.3: intermediate collections must already exist.
            let Some(parent) = resolved.parent() else {
                return Ok(403);
            };
            if !parent.exists() {
                return Ok(409);
            }
            fs::create_dir(&resolved)?;
            Ok(201)
        }, |code, writer| Self::send_error(writer, code));
    }

    fn handle_copy(&mut self, w: &mut dyn ServerWriter) {
        self.handle_copy_move(w, false);
    }

    fn handle_move(&mut self, w: &mut dyn ServerWriter) {
        self.handle_copy_move(w, true);
    }

    fn handle_copy_move(&mut self, w: &mut dyn ServerWriter, is_move: bool) {
        if !self.check_mutating_preconditions(w) {
            return;
        }
        let Some(dest_hdr) = self.destination.clone() else {
            Self::send_error(w, 400);
            return;
        };
        let src = self.path.clone();
        let root = self.root_path.clone();
        let canonical = self.canonical_root.clone();
        let overwrite = self.overwrite;
        let depth = self.depth;
        let mut store = self.dead_store.clone();
        let max_tree_entries = self.config.max_tree_entries;
        self.offload(w, move || {
            let Some(src_lex) = src else {
                return Ok(404u16);
            };
            let Some(src_path) = canonicalize_path(&root, &canonical, &src_lex) else {
                return Ok(404);
            };
            let dest_path = resolve_destination(&root, &canonical, &dest_hdr)?;
            if !src_path.exists() {
                return Ok(404);
            }
            // MOVE requires Depth: infinity when Depth is present (RFC 4918 §9.9).
            if is_move && depth == DEPTH_0 {
                return Ok(403);
            }
            if dest_path.exists() {
                if !overwrite {
                    return Ok(412);
                }
                if dest_path.is_dir() {
                    fs::remove_dir_all(&dest_path)?;
                } else {
                    fs::remove_file(&dest_path)?;
                }
            }
            if is_move {
                fs::rename(&src_path, &dest_path)?;
                store.delete_properties(&src_path)?;
            } else if src_path.is_dir() {
                if depth == DEPTH_0 {
                    // Copy the collection only — no members (RFC 4918 §9.8.3).
                    fs::create_dir(&dest_path)?;
                } else if let Err(code) =
                    copy_dir_all(&src_path, &dest_path, max_tree_entries, &mut 0)
                {
                    return Ok(code);
                }
            } else {
                if let Some(p) = dest_path.parent() {
                    fs::create_dir_all(p)?;
                }
                fs::copy(&src_path, &dest_path)?;
            }
            store.copy_properties(&src_path, &dest_path)?;
            Ok(201)
        }, |code, writer| Self::send_error(writer, code));
    }

    fn handle_unlock(&mut self, w: &mut dyn ServerWriter) {
        let token = self
            .lock_token
            .clone()
            .or_else(|| self.if_header.clone());
        let Some(token) = token else {
            Self::send_error(w, 400);
            return;
        };
        let token = token.trim().trim_matches(|c| c == '<' || c == '>').to_string();
        if !self.lock_manager.unlock(&token) {
            Self::send_error(w, 409);
        } else {
            Self::send_error(w, 204);
        }
    }

    fn handle_lock(&mut self, w: &mut dyn ServerWriter, parsed: WebDavParsed) {
        let path = self.path.clone();
        let root = self.root_path.clone();
        let canonical = self.canonical_root.clone();
        let href = self.href();
        let depth = self.depth;
        let timeout = parse_timeout_header(self.timeout_header.as_deref());
        let lock_mgr = Arc::clone(&self.lock_manager);
        let lock_req = parsed.lock.unwrap_or_default();
        let refresh_token = self.lock_token.clone();

        if let Some(token) = refresh_token {
            let token = token.trim().trim_matches(|c| c == '<' || c == '>').to_string();
            if let Some(lock) = lock_mgr.refresh(&token, timeout) {
                let body = write_active_lock(&lock, &href);
                Self::send_bytes(w, 200, CONTENT_TYPE_XML, &body);
                return;
            }
            Self::send_error(w, 412);
            return;
        }

        self.offload(w, move || {
            let Some(lex) = path else {
                return Ok(LockOutcome::Status(404));
            };
            let Some(resolved) = canonicalize_path(&root, &canonical, &lex) else {
                return Ok(LockOutcome::Status(404));
            };
            // RFC 4918 §7.3: LOCK on an unmapped URL creates a locked empty
            // non-collection resource (recommended model). Parent collections
            // must already exist — we do not mkdir -p here.
            let created = if !resolved.exists() {
                let Some(parent) = resolved.parent() else {
                    return Ok(LockOutcome::Status(403));
                };
                if !parent.exists() {
                    return Ok(LockOutcome::Status(409));
                }
                if parent.is_file() {
                    return Ok(LockOutcome::Status(409));
                }
                fs::File::create(&resolved)?;
                true
            } else if resolved.is_dir() {
                // Collection locks are fine; no empty-file creation.
                false
            } else {
                false
            };
            let owner = lock_req.owner.unwrap_or_default();
            let lock = match lock_mgr.lock(
                resolved.clone(),
                lock_req.scope,
                lock_req.ty,
                depth,
                owner,
                timeout,
            ) {
                Some(lock) => lock,
                None => {
                    // Conflict after we created the empty placeholder — remove
                    // it so a failed LOCK does not leave an orphan file.
                    if created {
                        let _ = fs::remove_file(&resolved);
                    }
                    return Ok(LockOutcome::Status(423));
                }
            };
            Ok(LockOutcome::Locked { lock, created })
        }, move |out, writer| match out {
            LockOutcome::Status(c) => Self::send_error(writer, c),
            LockOutcome::Locked { lock, created } => {
                let mut h = Headers::new();
                // §7.3: 201 Created when the LOCK mapped a new resource;
                // 200 OK when locking an already-mapped URL.
                h.status(if created { 201 } else { 200 });
                h.set("Content-Type", CONTENT_TYPE_XML);
                h.set("Lock-Token", format!("<{}>", lock.token()));
                let body = write_active_lock(&lock, &href);
                h.set("Content-Length", body.len().to_string());
                writer.headers(h);
                writer.start_response_body();
                writer.response_body_content(&body);
                writer.end_response_body();
                writer.complete();
            }
        });
    }

    fn handle_proppatch(&mut self, w: &mut dyn ServerWriter, parsed: WebDavParsed) {
        if !self.check_mutating_preconditions(w) {
            return;
        }
        let Some(patch) = parsed.proppatch else {
            Self::send_error(w, 400);
            return;
        };
        let path = self.path.clone();
        let root = self.root_path.clone();
        let canonical = self.canonical_root.clone();
        let href = self.href();
        let mut store = self.dead_store.clone();
        self.offload(w, move || {
            let Some(lex) = path else {
                return Ok(ProppatchOutcome::Status(404));
            };
            let Some(resolved) = canonicalize_path(&root, &canonical, &lex) else {
                return Ok(ProppatchOutcome::Status(404));
            };
            if !resolved.exists() {
                return Ok(ProppatchOutcome::Status(404));
            }
            for upd in &patch.updates {
                match upd.operation {
                    ProppatchOp::Set => store.set_property(
                        &resolved,
                        &upd.namespace_uri,
                        &upd.local_name,
                        &upd.value,
                        upd.is_xml,
                    )?,
                    ProppatchOp::Remove => {
                        store.remove_property(&resolved, &upd.namespace_uri, &upd.local_name)?
                    }
                }
            }
            let mut ms = MultistatusWriter::new();
            ms.response(&href, |r| {
                r.propstat("HTTP/1.1 200 OK", |w| {
                    for upd in &patch.updates {
                        write_live_property(w, &upd.namespace_uri, &upd.local_name, "")?;
                    }
                    Ok(())
                })
            })
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(ProppatchOutcome::Body(ms.finish()))
        }, |out, writer| match out {
            ProppatchOutcome::Status(c) => Self::send_error(writer, c),
            ProppatchOutcome::Body(body) => Self::send_bytes(writer, 207, CONTENT_TYPE_XML, &body),
        });
    }

    fn handle_propfind(&mut self, w: &mut dyn ServerWriter, parsed: WebDavParsed) {
        let pf = parsed.propfind.unwrap_or_default();
        let path = self.path.clone();
        let root = self.root_path.clone();
        let canonical = self.canonical_root.clone();
        let depth = self.depth;
        let request_path = self.request_path.clone();
        let mut store = self.dead_store.clone();
        let lock_mgr = Arc::clone(&self.lock_manager);
        let types = self.content_types.clone();
        let content_language = self.config.content_language.clone();
        let max_tree_entries = self.config.max_tree_entries;

        self.offload(w, move || {
            let Some(lex) = path else {
                return Ok(PropfindOutcome::Status(404));
            };
            let Some(resolved) = canonicalize_path(&root, &canonical, &lex) else {
                return Ok(PropfindOutcome::Status(404));
            };
            if !resolved.exists() || is_sidecar_file(&resolved) {
                return Ok(PropfindOutcome::Status(404));
            }
            let resources =
                match collect_propfind_resources(&resolved, &request_path, depth, max_tree_entries)
                {
                    Ok(r) => r,
                    Err(code) => return Ok(PropfindOutcome::Status(code)),
                };
            let mut ms = MultistatusWriter::new();
            for (rpath, rhref) in resources {
                ms.response(&rhref, |r| {
                    r.propstat("HTTP/1.1 200 OK", |w| {
                        append_propfind_props(
                            w,
                            &pf,
                            &rpath,
                            &rhref,
                            &types,
                            &lock_mgr,
                            &mut store,
                            content_language.as_deref(),
                        )
                            .map_err(|c| {
                                io::Error::new(io::ErrorKind::Other, format!("propfind {c}"))
                            })
                    })
                })
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            }
            Ok(PropfindOutcome::Body(ms.finish()))
        }, |out, writer| match out {
            PropfindOutcome::Status(c) => Self::send_error(writer, c),
            PropfindOutcome::Body(body) => Self::send_bytes(writer, 207, CONTENT_TYPE_XML, &body),
        });
    }

    fn check_mutating_preconditions(&self, w: &mut dyn ServerWriter) -> bool {
        let Some(ref path) = self.path else {
            Self::send_error(w, 404);
            return false;
        };
        if self.lock_manager.is_locked(path) {
            if let Some(ref token) = self.lock_token {
                if self.lock_manager.validate_token(path, token) {
                    return true;
                }
            }
            if let Some(ref hdr) = self.if_header {
                let groups = parse_if_header(hdr);
                if evaluate_if_header(&groups, path, &self.href(), &self.lock_manager, None) {
                    return true;
                }
            }
            Self::send_error(w, 423);
            return false;
        }
        true
    }
}

enum DeleteOutcome {
    Status(u16),
    MultiStatus(Vec<u8>),
}

enum ProppatchOutcome {
    Status(u16),
    Body(Vec<u8>),
}

enum PropfindOutcome {
    Status(u16),
    Body(Vec<u8>),
}

enum LockOutcome {
    Status(u16),
    /// Successful LOCK; `created` is true when this LOCK mapped a new empty
    /// resource (RFC 4918 §7.3).
    Locked { lock: WebDavLock, created: bool },
}

fn io_err(msg: &str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg))
}

fn find_welcome(dir: &Path, names: &[String]) -> Option<PathBuf> {
    for name in names {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn build_listing(request_path: &str, dir: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut html = format!(
        "<!DOCTYPE html><html><head><title>Index of {}</title></head><body><h1>Index of {}</h1><ul>",
        html_escape(request_path),
        html_escape(request_path)
    );
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_sidecar_name(&name) {
            continue;
        }
        let href = if request_path.ends_with('/') {
            format!("{}{}", request_path, name)
        } else {
            format!("{}/{}", request_path, name)
        };
        html.push_str("<li><a href=\"");
        html.push_str(&html_escape(&href));
        html.push_str("\">");
        html.push_str(&html_escape(&name));
        html.push_str("</a></li>");
    }
    html.push_str("</ul></body></html>");
    Ok(html.into_bytes())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
}

fn content_type_for(path: &Path, map: &HashMap<String, String>) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .and_then(|e| map.get(&e.to_ascii_lowercase()))
        .cloned()
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

fn weak_etag(path: &Path, meta: &fs::Metadata) -> String {
    let mut h = Sha256::new();
    h.update(path.to_string_lossy().as_bytes());
    h.update(meta.len().to_string().as_bytes());
    if let Ok(t) = meta.modified() {
        h.update(
            t.duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis()
                .to_string()
                .as_bytes(),
        );
    }
    let digest = h.finalize();
    format!("W/\"{:02x}{:02x}{:02x}{:02x}\"", digest[0], digest[1], digest[2], digest[3])
}

fn http_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;
    format_http_date(secs)
}

fn format_http_date(secs: i64) -> String {
    const DAYS: &[&str] = &["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: &[&str] = &[
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs / 86400;
    let time = secs % 86400;
    let hour = (time / 3600) as u32;
    let min = ((time % 3600) / 60) as u32;
    let sec = (time % 60) as u32;
    // 1970-01-01 was Thursday
    let wday = ((days + 3) % 7) as usize;
    let mut y = 1970i64;
    let mut day = days;
    loop {
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let year_days = if leap { 366 } else { 365 };
        if day < year_days {
            break;
        }
        day -= year_days;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut m = 0usize;
    while m < 12 && day >= mdays[m] as i64 {
        day -= mdays[m] as i64;
        m += 1;
    }
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[wday],
        day + 1,
        MONTHS[m],
        y,
        hour,
        min,
        sec
    )
}

fn resolve_destination(
    root: &Path,
    canonical: &Path,
    dest: &str,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let path_part = if let Some(idx) = dest.find("://") {
        let rest = &dest[idx + 3..];
        rest.find('/').map(|i| &rest[i..]).unwrap_or("/")
    } else {
        dest
    };
    let req = path_part.trim_start_matches('/');
    let lexical = resolve_path_lexical(root, req).ok_or_else(|| io_err("bad destination"))?;
    canonicalize_path(root, canonical, &lexical).ok_or_else(|| io_err("bad destination"))
}

fn copy_dir_all(
    src: &Path,
    dst: &Path,
    max_entries: usize,
    count: &mut usize,
) -> Result<(), u16> {
    *count = count.saturating_add(1);
    if *count > max_entries {
        return Err(507);
    }
    fs::create_dir_all(dst).map_err(|_| 500u16)?;
    for entry in fs::read_dir(src).map_err(|_| 500u16)? {
        let entry = entry.map_err(|_| 500u16)?;
        let ty = entry.file_type().map_err(|_| 500u16)?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &target, max_entries, count)?;
        } else {
            *count = count.saturating_add(1);
            if *count > max_entries {
                return Err(507);
            }
            fs::copy(entry.path(), target).map_err(|_| 500u16)?;
        }
    }
    Ok(())
}

/// Recursively delete `path`, recording per-member failures for a 207
/// Multi-Status (RFC 4918 §9.6.1) instead of aborting on the first error.
fn delete_recursive(
    path: &Path,
    href: &str,
    store: &mut DeadPropertyStore,
    errors: &mut Vec<(String, u16)>,
) {
    if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if is_sidecar_name(&name) {
                    continue;
                }
                let child_path = entry.path();
                let child_href = if href.ends_with('/') {
                    format!("{href}{name}")
                } else {
                    format!("{href}/{name}")
                };
                let child_href =
                    ensure_trailing_slash_for_collection(&child_href, child_path.is_dir());
                delete_recursive(&child_path, &child_href, store, errors);
            }
        }
        match fs::remove_dir(path) {
            Ok(()) => {
                let _ = store.delete_properties(path);
            }
            Err(_) => {
                // Children that failed leave the directory non-empty → 424.
                let code = if errors.is_empty() { 403 } else { 424 };
                errors.push((href.to_string(), code));
            }
        }
    } else {
        match fs::remove_file(path) {
            Ok(()) => {
                let _ = store.delete_properties(path);
            }
            Err(_) => errors.push((href.to_string(), 403)),
        }
    }
}

fn collect_propfind_resources(
    root: &Path,
    request_path: &str,
    depth: i32,
    max_entries: usize,
) -> Result<Vec<(PathBuf, String)>, u16> {
    let mut out = Vec::new();
    let base_href = href_for_path(request_path);
    out.push((root.to_path_buf(), base_href.clone()));
    if depth == DEPTH_0 {
        return Ok(out);
    }
    if root.is_dir() {
        collect_propfind_children(
            &mut out,
            root,
            &base_href,
            depth == DEPTH_INFINITY,
            max_entries,
        )?;
    }
    Ok(out)
}

/// Depth 1: immediate children only. Depth infinity: recursive tree.
fn collect_propfind_children(
    out: &mut Vec<(PathBuf, String)>,
    dir: &Path,
    base_href: &str,
    recursive: bool,
    max_entries: usize,
) -> Result<(), u16> {
    for entry in fs::read_dir(dir).map_err(|_| 500u16)? {
        let entry = entry.map_err(|_| 500u16)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_sidecar_name(&name) {
            continue;
        }
        if out.len() >= max_entries {
            return Err(507);
        }
        let child_href = if base_href.ends_with('/') {
            format!("{base_href}{name}")
        } else {
            format!("{base_href}/{name}")
        };
        let path = entry.path();
        let is_dir = path.is_dir();
        let href = ensure_trailing_slash_for_collection(&child_href, is_dir);
        out.push((path.clone(), href.clone()));
        if recursive && is_dir {
            collect_propfind_children(out, &path, &href, true, max_entries)?;
        }
    }
    Ok(())
}

fn append_propfind_props(
    w: &mut PropXmlWriter<Vec<u8>>,
    pf: &crate::parser::PropfindRequest,
    path: &Path,
    href: &str,
    types: &HashMap<String, String>,
    lock_mgr: &WebDavLockManager,
    store: &mut DeadPropertyStore,
    content_language: Option<&str>,
) -> Result<(), u16> {
    let meta = fs::metadata(path).map_err(|_| 500u16)?;
    let is_dir = meta.is_dir();
    let _href = ensure_trailing_slash_for_collection(href, is_dir);

    match pf.kind {
        PropfindType::Propname => {
            for name in live_prop_names() {
                // Only advertise getcontentlanguage when configured.
                if *name == constants::PROP_GETCONTENTLANGUAGE && content_language.is_none() {
                    continue;
                }
                write_live_property(w, NAMESPACE, name, "").map_err(|_| 500u16)?;
            }
        }
        PropfindType::Allprop | PropfindType::Prop => {
            append_live_props(
                w,
                path,
                href,
                &meta,
                is_dir,
                types,
                lock_mgr,
                store,
                content_language,
            )?;
            if pf.kind == PropfindType::Prop {
                for req in &pf.properties {
                    if !is_live_prop(&req.local_name) {
                        let props = store.get_properties(path, Some(is_dir)).map_err(|_| 500u16)?;
                        let key = crate::dead_props::make_key(&req.namespace_uri, &req.local_name);
                        if let Some(dp) = props.get(&key) {
                            write_dead_property(w, dp).map_err(|_| 500u16)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn live_prop_names() -> &'static [&'static str] {
    &[
        constants::PROP_CREATIONDATE,
        constants::PROP_DISPLAYNAME,
        constants::PROP_GETCONTENTLANGUAGE,
        constants::PROP_GETCONTENTLENGTH,
        constants::PROP_GETCONTENTTYPE,
        constants::PROP_GETETAG,
        constants::PROP_GETLASTMODIFIED,
        constants::PROP_RESOURCETYPE,
        constants::PROP_SOURCE,
        constants::PROP_SUPPORTEDLOCK,
        constants::PROP_LOCKDISCOVERY,
    ]
}

fn is_live_prop(name: &str) -> bool {
    live_prop_names().contains(&name)
}

fn append_live_props(
    w: &mut PropXmlWriter<Vec<u8>>,
    path: &Path,
    href: &str,
    meta: &fs::Metadata,
    is_dir: bool,
    types: &HashMap<String, String>,
    lock_mgr: &WebDavLockManager,
    store: &mut DeadPropertyStore,
    content_language: Option<&str>,
) -> Result<(), u16> {
    let created = meta.created().or_else(|_| meta.modified()).ok();
    if let Some(t) = created {
        write_live_property(
            w,
            NAMESPACE,
            constants::PROP_CREATIONDATE,
            &iso8601_date(t),
        )
        .map_err(|_| 500u16)?;
    }
    let display = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    write_live_property(w, NAMESPACE, constants::PROP_DISPLAYNAME, display).map_err(|_| 500u16)?;
    if let Some(lang) = content_language {
        write_live_property(w, NAMESPACE, constants::PROP_GETCONTENTLANGUAGE, lang)
            .map_err(|_| 500u16)?;
    }
    if !is_dir {
        write_live_property(
            w,
            NAMESPACE,
            constants::PROP_GETCONTENTLENGTH,
            &meta.len().to_string(),
        )
        .map_err(|_| 500u16)?;
        write_live_property(
            w,
            NAMESPACE,
            constants::PROP_GETCONTENTTYPE,
            &content_type_for(path, types),
        )
        .map_err(|_| 500u16)?;
        write_live_property(w, NAMESPACE, constants::PROP_GETETAG, &weak_etag(path, meta))
            .map_err(|_| 500u16)?;
    }
    if let Ok(modified) = meta.modified() {
        write_live_property(
            w,
            NAMESPACE,
            constants::PROP_GETLASTMODIFIED,
            &http_date(modified),
        )
        .map_err(|_| 500u16)?;
    }
    if is_dir {
        write_collection_resourcetype(w).map_err(|_| 500u16)?;
    } else {
        write_empty_resourcetype(w).map_err(|_| 500u16)?;
    }
    // RFC 4918 §15.10 — typically empty; still advertised as a live property.
    write_live_property(w, NAMESPACE, constants::PROP_SOURCE, "").map_err(|_| 500u16)?;
    write_supported_lock(w).map_err(|_| 500u16)?;
    let locks = lock_mgr.get_covering_locks(path);
    write_lock_discovery(w, &locks, href).map_err(|_| 500u16)?;
    let dead = store.get_properties(path, Some(is_dir)).map_err(|_| 500u16)?;
    for dp in dead.values() {
        write_dead_property(w, dp).map_err(|_| 500u16)?;
    }
    Ok(())
}

fn iso8601_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;
    // Reuse civil breakdown from IMF-fixdate formatting.
    let imf = format_http_date(secs);
    // "Mon, 01 Jan 2024 00:00:00 GMT" → "2024-01-01T00:00:00Z"
    let rest = imf.split_once(", ").map(|(_, r)| r).unwrap_or(&imf);
    let mut parts = rest.split_whitespace();
    let day = parts.next().unwrap_or("01");
    let month = match parts.next().unwrap_or("Jan") {
        "Jan" => "01",
        "Feb" => "02",
        "Mar" => "03",
        "Apr" => "04",
        "May" => "05",
        "Jun" => "06",
        "Jul" => "07",
        "Aug" => "08",
        "Sep" => "09",
        "Oct" => "10",
        "Nov" => "11",
        "Dec" => "12",
        _ => "01",
    };
    let year = parts.next().unwrap_or("1970");
    let time = parts.next().unwrap_or("00:00:00");
    format!("{year}-{month}-{day}T{time}Z")
}

fn parse_timeout_header(raw: Option<&str>) -> i64 {
    let Some(raw) = raw else {
        return constants::DEFAULT_LOCK_TIMEOUT_SECONDS;
    };
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case(constants::TIMEOUT_INFINITE) {
        return -1;
    }
    if let Some(rest) = raw.strip_prefix(constants::TIMEOUT_SECOND_PREFIX) {
        if let Ok(n) = rest.parse::<i64>() {
            return n
                .max(0)
                .min(constants::MAX_LOCK_TIMEOUT_SECONDS);
        }
    }
    // Also accept bare "Second-N" case variants and comma-separated first token.
    let first = raw.split(',').next().unwrap_or(raw).trim();
    if let Some(rest) = first
        .strip_prefix("Second-")
        .or_else(|| first.strip_prefix("second-"))
    {
        if let Ok(n) = rest.parse::<i64>() {
            return n.max(0).min(constants::MAX_LOCK_TIMEOUT_SECONDS);
        }
    }
    constants::DEFAULT_LOCK_TIMEOUT_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dead_props::DeadPropMode;
    use std::time::Duration;

    #[test]
    fn iso8601_matches_known_instant() {
        let t = UNIX_EPOCH + Duration::from_secs(1704067200);
        assert_eq!(iso8601_date(t), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn delete_recursive_removes_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("col");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();
        let nested = root.join("sub");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("b.txt"), b"b").unwrap();

        let mut store = DeadPropertyStore::new(DeadPropMode::None);
        let mut errors = Vec::new();
        delete_recursive(&root, "/col/", &mut store, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!root.exists());
    }

    #[test]
    fn parse_http_date_from_hopf_http_enables_304_path() {
        let t = parse_http_date("Mon, 01 Jan 2024 00:00:00 GMT").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1704067200
        );
    }
}
