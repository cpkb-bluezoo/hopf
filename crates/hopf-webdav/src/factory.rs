// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV handler factory.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hopf_core::storage::StorageExecutor;
use hopf_http::{ServerHandler, ServerHandlerFactory};

use crate::dead_props::{DeadPropMode, DeadPropertyStore};
use crate::handler::WebDavHandler;
use crate::lock::WebDavLockManager;

/// WebDAV service configuration.
#[derive(Clone, Debug)]
pub struct WebDavConfig {
    pub root_path: PathBuf,
    pub allow_write: bool,
    pub webdav_enabled: bool,
    pub welcome_file: String,
    pub dead_property_storage: DeadPropMode,
}

impl Default for WebDavConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("."),
            allow_write: false,
            webdav_enabled: false,
            welcome_file: "index.html".to_string(),
            dead_property_storage: DeadPropMode::Auto,
        }
    }
}

/// Shared factory for [`WebDavHandler`] instances.
pub struct WebDavFactory {
    pub(crate) config: Arc<WebDavConfig>,
    pub(crate) storage: Arc<StorageExecutor>,
    pub(crate) lock_manager: Arc<WebDavLockManager>,
    pub(crate) dead_store: DeadPropertyStore,
    pub(crate) allowed_options: String,
    pub(crate) welcome_files: Vec<String>,
    pub(crate) content_types: HashMap<String, String>,
    pub(crate) canonical_root: PathBuf,
}

impl WebDavFactory {
    /// Build a factory; resolves the document root on the local filesystem.
    pub fn new(config: WebDavConfig, storage: Arc<StorageExecutor>) -> io::Result<Self> {
        let root_path = config.root_path.clone();
        std::fs::create_dir_all(&root_path)?;
        let canonical_root = root_path.canonicalize().unwrap_or_else(|_| {
            root_path
                .absolute()
                .unwrap_or(root_path.clone())
                .normalize()
        });

        let allowed_options = build_allow_header(
            config.webdav_enabled,
            config.allow_write,
        );
        let welcome_files = parse_welcome_files(&config.welcome_file);
        let content_types = default_content_types();
        let dead_store = DeadPropertyStore::new(config.dead_property_storage);
        let lock_manager = Arc::new(WebDavLockManager::new());

        Ok(Self {
            config: Arc::new(config),
            storage,
            lock_manager,
            dead_store,
            allowed_options,
            welcome_files,
            content_types,
            canonical_root,
        })
    }

    pub fn root_path(&self) -> &Path {
        &self.config.root_path
    }

    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }
}

impl ServerHandlerFactory for WebDavFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(WebDavHandler::new(
            Arc::clone(&self.config),
            Arc::clone(&self.storage),
            Arc::clone(&self.lock_manager),
            self.dead_store.clone(),
            self.allowed_options.clone(),
            self.welcome_files.clone(),
            self.content_types.clone(),
            self.canonical_root.clone(),
        ))
    }
}

fn build_allow_header(webdav: bool, write: bool) -> String {
    if webdav && write {
        "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"
            .to_string()
    } else if webdav {
        "OPTIONS, GET, HEAD, PROPFIND".to_string()
    } else if write {
        "OPTIONS, GET, HEAD, PUT, DELETE".to_string()
    } else {
        "OPTIONS, GET, HEAD".to_string()
    }
}

fn parse_welcome_files(welcome: &str) -> Vec<String> {
    let trimmed = welcome.trim();
    if trimmed.is_empty() {
        return vec!["index.html".to_string()];
    }
    trimmed
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn default_content_types() -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (ext, ty) in [
        ("html", "text/html"),
        ("htm", "text/html"),
        ("txt", "text/plain"),
        ("css", "text/css"),
        ("js", "application/javascript"),
        ("json", "application/json"),
        ("xml", "application/xml"),
        ("pdf", "application/pdf"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("png", "image/png"),
        ("gif", "image/gif"),
        ("svg", "image/svg+xml"),
        ("ico", "image/x-icon"),
        ("zip", "application/zip"),
    ] {
        m.insert(ext.to_string(), ty.to_string());
    }
    m
}

trait PathAbsolute {
    fn absolute(&self) -> io::Result<PathBuf>;
    fn normalize(&self) -> PathBuf;
}

impl PathAbsolute for PathBuf {
    fn absolute(&self) -> io::Result<PathBuf> {
        if self.is_absolute() {
            Ok(self.clone())
        } else {
            std::env::current_dir().map(|cwd| cwd.join(self))
        }
    }

    fn normalize(&self) -> PathBuf {
        let mut out = PathBuf::new();
        for comp in self.components() {
            use std::path::Component;
            match comp {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other.as_os_str()),
            }
        }
        out
    }
}
