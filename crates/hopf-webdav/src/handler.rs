// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV HTTP request handler (RFC 4918 + RFC 9110 file serving).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use md5::{Digest, Md5};
use hopf_core::storage::{StorageError, StorageExecutor};
use hopf_http::Headers;
use hopf_http::{ServerHandler, ServerWriter};

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
    put_buffers: Vec<u8>,
    put_ready: bool,
    put_path: Option<PathBuf>,
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
            put_buffers: Vec::new(),
            put_ready: false,
            put_path: None,
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
                self.handle_mkcol(response)
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
        if self.webdav_parser.is_some() {
            self.webdav_body.extend_from_slice(data);
            if let Some(ref mut p) = self.webdav_parser {
                let _ = p.feed(data);
            }
            return;
        }
        if self.put_path.is_some() {
            self.put_buffers.extend_from_slice(data);
        }
        let _ = response;
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
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
        if let Some(lexical) = self.put_path.take() {
            let data = std::mem::take(&mut self.put_buffers);
            let root = self.root_path.clone();
            let canonical = self.canonical_root.clone();
            self.offload(
                response,
                move || {
                    let resolved = canonicalize_path(&root, &canonical, &lexical)
                        .ok_or_else(|| io_err("invalid path"))?;
                    if resolved.is_dir() {
                        return Err(io_err("is directory"));
                    }
                    if let Some(parent) = resolved.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&resolved, &data)?;
                    Ok(201u16)
                },
                |code, writer| Self::send_error(writer, code),
            );
        }
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        // PUT with no body still needs a response (empty create).
        if self.put_path.is_some() {
            self.end_request_body(response);
        }
        self.webdav_body.clear();
        self.put_buffers.clear();
        self.put_ready = false;
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
        let method = self.method.clone();
        let method_for_plan = method.clone();

        self.offload(w, move || {
            let mut plan = GetPlan::default();
            let Some(lexical) = path else {
                plan.status = 404;
                return Ok(plan);
            };
            let Some(resolved) = canonicalize_path(&root, &canonical, &lexical) else {
                plan.status = 404;
                return Ok(plan);
            };
            if !resolved.exists() || is_sidecar_file(&resolved) {
                plan.status = 404;
                return Ok(plan);
            }
            let mut target = resolved.clone();
            if resolved.is_dir() {
                if let Some(index) = find_welcome(&resolved, &welcome) {
                    target = index;
                } else {
                    plan.listing = Some(build_listing(&request_path, &resolved)?);
                    plan.is_dir = true;
                    return Ok(plan);
                }
            }
            let meta = fs::metadata(&target)?;
            let modified = meta.modified()?;
            if let Some(since) = if_mod {
                if modified <= since {
                    plan.not_modified = true;
                    return Ok(plan);
                }
            }
            plan.last_modified = Some(modified);
            plan.content_type = content_type_for(&target, &types);
            plan.size = meta.len();
            plan.etag = Some(weak_etag(&target, &meta));
            if method_for_plan == "GET" && plan.size > 0 {
                plan.file_data = Some(fs::read(&target)?);
            }
            Ok(plan)
        }, move |plan, writer| {
            let is_get = method == "GET";
            if plan.status == 404 {
                Self::send_error(writer, 404);
                return;
            }
            if plan.not_modified {
                let mut h = Headers::new();
                h.status(304);
                writer.headers(h);
                writer.complete();
                return;
            }
            if let Some(html) = plan.listing {
                let mut h = Headers::new();
                h.status(200);
                h.set("Content-Type", "text/html; charset=utf-8");
                h.set("Content-Length", html.len().to_string());
                writer.headers(h);
                if is_get {
                    writer.start_response_body();
                    writer.response_body_content(&html);
                    writer.end_response_body();
                }
                writer.complete();
                return;
            }
            let mut h = Headers::new();
            h.status(200);
            if let Some(lm) = plan.last_modified {
                h.set("Last-Modified", http_date(lm));
            }
            if let Some(ref etag) = plan.etag {
                h.set("ETag", etag);
            }
            h.set("Content-Type", &plan.content_type);
            h.set("Content-Length", plan.size.to_string());
            writer.headers(h);
            if is_get {
                if let Some(data) = plan.file_data {
                    writer.start_response_body();
                    writer.response_body_content(&data);
                    writer.end_response_body();
                }
            }
            writer.complete();
        });
    }

    fn handle_put_headers(&mut self, w: &mut dyn ServerWriter) {
        if !self.check_mutating_preconditions(w) {
            return;
        }
        let Some(lexical) = self.path.clone() else {
            Self::send_error(w, 404);
            return;
        };
        // Buffer the full request body; write + respond in `end_request_body`.
        self.put_path = Some(lexical);
        self.put_ready = true;
        self.put_buffers.clear();
        let _ = w;
    }

    fn handle_delete(&mut self, w: &mut dyn ServerWriter) {
        if !self.check_mutating_preconditions(w) {
            return;
        }
        let path = self.path.clone();
        let root = self.root_path.clone();
        let canonical = self.canonical_root.clone();
        let mut store = self.dead_store.clone();
        self.offload(w, move || {
            let Some(lexical) = path else {
                return Ok(404u16);
            };
            let Some(resolved) = canonicalize_path(&root, &canonical, &lexical) else {
                return Ok(404);
            };
            if !resolved.exists() || is_sidecar_file(&resolved) {
                return Ok(404);
            }
            if resolved.is_dir() {
                fs::remove_dir_all(&resolved)?;
            } else {
                fs::remove_file(&resolved)?;
            }
            store.delete_properties(&resolved)?;
            Ok(204)
        }, |code, writer| {
            if code == 404 {
                Self::send_error(writer, 404);
            } else {
                Self::send_error(writer, code);
            }
        });
    }

    fn handle_mkcol(&mut self, w: &mut dyn ServerWriter) {
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
            fs::create_dir_all(&resolved)?;
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
        let mut store = self.dead_store.clone();
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
            } else {
                if src_path.is_dir() {
                    copy_dir_all(&src_path, &dest_path)?;
                } else {
                    if let Some(p) = dest_path.parent() {
                        fs::create_dir_all(p)?;
                    }
                    fs::copy(&src_path, &dest_path)?;
                }
            }
            store.copy_properties(&src_path, &dest_path)?;
            Ok(if is_move { 201 } else { 201 })
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
            let owner = lock_req.owner.unwrap_or_default();
            let lock = lock_mgr
                .lock(
                    resolved,
                    lock_req.scope,
                    lock_req.ty,
                    depth,
                    owner,
                    timeout,
                )
                .ok_or_else(|| io_err("conflict"))?;
            Ok(LockOutcome::Created(lock))
        }, move |out, writer| match out {
            LockOutcome::Status(c) => Self::send_error(writer, c),
            LockOutcome::Created(lock) => {
                let mut h = Headers::new();
                h.status(200);
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
            for upd in patch.updates {
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
            ms.response(&href, |r| r.propstat("HTTP/1.1 200 OK", |_| Ok(())))
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
            let resources = collect_propfind_resources(&resolved, &request_path, depth)
                .map_err(|c| io_err(&format!("{c}")))?;
            let mut ms = MultistatusWriter::new();
            for (rpath, rhref) in resources {
                ms.response(&rhref, |r| {
                    r.propstat("HTTP/1.1 200 OK", |w| {
                        append_propfind_props(w, &pf, &rpath, &rhref, &types, &lock_mgr, &mut store)
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
    Created(WebDavLock),
}

#[derive(Default)]
struct GetPlan {
    status: u16,
    not_modified: bool,
    listing: Option<Vec<u8>>,
    is_dir: bool,
    last_modified: Option<SystemTime>,
    content_type: String,
    size: u64,
    etag: Option<String>,
    file_data: Option<Vec<u8>>,
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
    let mut h = Md5::new();
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

fn parse_http_date(s: &str) -> Option<SystemTime> {
    // Minimal: try RFC3339-like or ignore
    let _ = s;
    None
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

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn collect_propfind_resources(
    root: &Path,
    request_path: &str,
    depth: i32,
) -> Result<Vec<(PathBuf, String)>, u16> {
    let mut out = Vec::new();
    let base_href = href_for_path(request_path);
    out.push((root.to_path_buf(), base_href.clone()));
    if depth == DEPTH_0 {
        return Ok(out);
    }
    if root.is_dir() {
        collect_propfind_children(&mut out, root, &base_href, depth == DEPTH_INFINITY)?;
    }
    Ok(out)
}

/// Depth 1: immediate children only. Depth infinity: recursive tree.
fn collect_propfind_children(
    out: &mut Vec<(PathBuf, String)>,
    dir: &Path,
    base_href: &str,
    recursive: bool,
) -> Result<(), u16> {
    for entry in fs::read_dir(dir).map_err(|_| 500u16)? {
        let entry = entry.map_err(|_| 500u16)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_sidecar_name(&name) {
            continue;
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
            collect_propfind_children(out, &path, &href, true)?;
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
) -> Result<(), u16> {
    let meta = fs::metadata(path).map_err(|_| 500u16)?;
    let is_dir = meta.is_dir();
    let _href = ensure_trailing_slash_for_collection(href, is_dir);

    match pf.kind {
        PropfindType::Propname => {
            for name in live_prop_names() {
                write_live_property(w, NAMESPACE, name, "").map_err(|_| 500u16)?;
            }
        }
        PropfindType::Allprop | PropfindType::Prop => {
            append_live_props(w, path, href, &meta, is_dir, types, lock_mgr, store)?;
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
        constants::PROP_DISPLAYNAME,
        constants::PROP_GETCONTENTLENGTH,
        constants::PROP_GETCONTENTTYPE,
        constants::PROP_GETETAG,
        constants::PROP_GETLASTMODIFIED,
        constants::PROP_RESOURCETYPE,
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
) -> Result<(), u16> {
    let display = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    write_live_property(w, NAMESPACE, constants::PROP_DISPLAYNAME, display).map_err(|_| 500u16)?;
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
    write_supported_lock(w).map_err(|_| 500u16)?;
    let locks = lock_mgr.get_covering_locks(path);
    write_lock_discovery(w, &locks, href).map_err(|_| 500u16)?;
    let dead = store.get_properties(path, Some(is_dir)).map_err(|_| 500u16)?;
    for dp in dead.values() {
        write_dead_property(w, dp).map_err(|_| 500u16)?;
    }
    Ok(())
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
