// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV handler factory.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hopf_auth::RolePolicy;
use hopf_core::storage::StorageExecutor;
use hopf_http::{ServerHandler, ServerHandlerFactory};

use crate::dead_props::{DeadPropMode, DeadPropertyStore};
use crate::handler::WebDavHandler;
use crate::lock::WebDavLockManager;

/// WebDAV service configuration.
#[derive(Clone)]
pub struct WebDavConfig {
    pub root_path: PathBuf,
    /// Allow mutating methods (PUT/DELETE/MKCOL/…). Default: `false`.
    pub allow_write: bool,
    /// Advertise and handle WebDAV methods. Default: `false`.
    pub webdav_enabled: bool,
    pub welcome_file: String,
    pub dead_property_storage: DeadPropMode,
    /// Maximum PUT upload size, checked incrementally as chunks arrive.
    /// Default: [`MAX_WEBDAV_PUT_BODY`](crate::constants::MAX_WEBDAV_PUT_BODY)
    /// (16 MiB — align with [`hopf_http::HttpLimits::max_request_body`]).
    pub max_put_body: u64,
    /// Max resources visited on Depth: infinity PROPFIND / recursive COPY.
    /// Default: [`DEFAULT_MAX_TREE_ENTRIES`](crate::constants::DEFAULT_MAX_TREE_ENTRIES).
    /// Depth 0 / 1 are unaffected. Exceeding the cap yields HTTP 507.
    pub max_tree_entries: usize,
    /// Optional default `DAV:getcontentlanguage` live property value
    /// (RFC 4918 §15.4). When `None`, the property is omitted from PROPFIND.
    pub content_language: Option<String>,
    /// Explicit opt-in to expose this factory without HTTP auth wrapping.
    ///
    /// [`WebDavFactory`] has no built-in authentication. When `webdav_enabled`
    /// or `allow_write` is true and this flag is false, [`WebDavFactory::new`]
    /// returns an error — wrap the factory in `hopf_http` Basic/Digest/Bearer
    /// (or mTLS) and set this to acknowledge that auth lives outside the
    /// WebDAV crate, or set it for intentional cleartext demos.
    pub allow_unauthenticated_access: bool,
    /// Optional role map for RFC 3744 ACL live properties and the `ACL`
    /// method. When set together with [`webdav_enabled`](Self::webdav_enabled),
    /// the handler advertises the `access-control` DAV compliance class and
    /// answers PROPFIND for `DAV:acl` / `DAV:current-user-privilege-set` /
    /// related properties. Privileges are checked via
    /// [`RolePolicy::is_user_in_role`] using role names prefixed with
    /// [`crate::constants::ROLE_PREFIX`] (e.g. `webdav:read`).
    pub role_policy: Option<Arc<dyn RolePolicy>>,
    /// `Cache-Control` sent on file `GET`/`HEAD` responses (and their `304`s),
    /// telling caches how long a file stays fresh. `None` (the default) sends
    /// none, leaving caches to their own heuristics, which work from
    /// `Last-Modified`; set e.g. `CacheControl::new().no_cache()` to force
    /// revalidation on every use, or a `max_age` for static assets.
    pub cache_control: Option<hopf_http::CacheControl>,
    /// Directory for WebDAV lock records, or `None` (the default) to keep
    /// locks in this factory's memory (issue #415).
    ///
    /// Locks live in memory by default, which is the right authority for a
    /// single handler on a private content tree — a second handler serving
    /// the same tree has empty in-memory maps and would grant a second
    /// exclusive lock. Setting a lock root switches to file-backed records
    /// there instead, shared by every handler pointed at the same
    /// directory, keyed by each resource's path relative to
    /// [`Self::root_path`] — handlers may mount that same content tree at
    /// different absolute paths.
    ///
    /// Every LOCK/UNLOCK/refresh, and the mutating-request lock check,
    /// then does blocking file I/O rather than an in-memory lookup; the
    /// lock root needs a filesystem where a create-new open is atomic and
    /// a record one handler writes becomes visible to the others before
    /// they finish their own conflict check (a local disk or a typical
    /// `ReadWriteOnce` volume — NFS attribute caching, for one, does not
    /// reliably give you that, and two grants can both succeed).
    pub lock_root: Option<PathBuf>,
    /// Directory for dead-property sidecar files, or `None` (the default)
    /// for the existing xattr-then-sibling-file behaviour (issue #415).
    ///
    /// A sidecar normally lives next to its resource (`.webdav_<name>`, or
    /// `.webdav_.` inside a collection) — fine for a private, writable
    /// content tree, but it collides with a real resource of that name and
    /// needs a writable directory the served tree may not have (a
    /// read-only content volume, or one shared read-only across several
    /// handlers). Setting a sidecar root moves sidecars into their own
    /// tree instead, mirroring [`Self::root_path`] one-to-one, so nothing
    /// is ever written into the content tree and no `.webdav_*` name in it
    /// is treated as a sidecar. Extended attributes are unaffected either
    /// way.
    pub sidecar_root: Option<PathBuf>,
}

impl Default for WebDavConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("."),
            allow_write: false,
            webdav_enabled: false,
            welcome_file: "index.html".to_string(),
            dead_property_storage: DeadPropMode::Auto,
            max_put_body: crate::constants::MAX_WEBDAV_PUT_BODY,
            max_tree_entries: crate::constants::DEFAULT_MAX_TREE_ENTRIES,
            content_language: None,
            allow_unauthenticated_access: false,
            role_policy: None,
            cache_control: None,
            lock_root: None,
            sidecar_root: None,
        }
    }
}

impl WebDavConfig {
    /// Enable mutating methods.
    pub fn with_write(mut self, yes: bool) -> Self {
        self.allow_write = yes;
        self
    }

    /// Send `policy` as `Cache-Control` on file `GET`/`HEAD` responses.
    pub fn with_cache_control(mut self, policy: hopf_http::CacheControl) -> Self {
        self.cache_control = Some(policy);
        self
    }

    /// Enable WebDAV method set (PROPFIND, LOCK, …).
    pub fn with_webdav(mut self, yes: bool) -> Self {
        self.webdav_enabled = yes;
        self
    }

    /// Cap Depth: infinity PROPFIND / recursive COPY resource visits.
    pub fn with_max_tree_entries(mut self, max: usize) -> Self {
        self.max_tree_entries = max.max(1);
        self
    }

    /// Share WebDAV locks across handlers via file-backed records under
    /// `lock_root`, instead of keeping them in this factory's memory
    /// (issue #415; see [`WebDavConfig::lock_root`]).
    pub fn with_lock_root(mut self, lock_root: PathBuf) -> Self {
        self.lock_root = Some(lock_root);
        self
    }

    /// Keep dead-property sidecars under `sidecar_root` instead of next to
    /// their resources (issue #415; see [`WebDavConfig::sidecar_root`]).
    pub fn with_sidecar_root(mut self, sidecar_root: PathBuf) -> Self {
        self.sidecar_root = Some(sidecar_root);
        self
    }

    /// Acknowledge that this factory will be served without (or before)
    /// HTTP-layer authentication — required when write or WebDAV is enabled.
    pub fn allow_unauthenticated_access(mut self) -> Self {
        self.allow_unauthenticated_access = true;
        self
    }

    /// Enable RFC 3744 ACL property support backed by `policy`.
    pub fn with_role_policy(mut self, policy: Arc<dyn RolePolicy>) -> Self {
        self.role_policy = Some(policy);
        self
    }
}

/// Shared factory for [`WebDavHandler`] instances.
pub struct WebDavFactory {
    pub(crate) config: Arc<WebDavConfig>,
    pub(crate) storage: Arc<StorageExecutor>,
    pub(crate) lock_manager: Arc<WebDavLockManager>,
    pub(crate) dead_store: DeadPropertyStore,
    pub(crate) acl_enabled: bool,
    pub(crate) role_policy: Option<Arc<dyn RolePolicy>>,
    pub(crate) allowed_options: String,
    pub(crate) welcome_files: Vec<String>,
    pub(crate) content_types: HashMap<String, String>,
    pub(crate) canonical_root: PathBuf,
}

impl WebDavFactory {
    /// Build a factory; resolves the document root on the local filesystem.
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when WebDAV or write is enabled
    /// without [`WebDavConfig::allow_unauthenticated_access`] — this crate has
    /// no built-in auth, so exposure must be acknowledged (or the factory
    /// wrapped in HTTP auth *and* the flag set, since wrapping happens after
    /// construction).
    pub fn new(config: WebDavConfig, storage: Arc<StorageExecutor>) -> io::Result<Self> {
        if (config.webdav_enabled || config.allow_write) && !config.allow_unauthenticated_access {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WebDavConfig enables WebDAV/write without allow_unauthenticated_access(); \
                 wrap with hopf_http BasicAuthFactory / DigestAuthFactory / BearerAuthFactory \
                 (or mTLS) and call WebDavConfig::allow_unauthenticated_access(), or use that \
                 method alone for intentional cleartext demos",
            ));
        }
        let root_path = config.root_path.clone();
        std::fs::create_dir_all(&root_path)?;
        let canonical_root = root_path.canonicalize().unwrap_or_else(|_| {
            root_path
                .absolute()
                .unwrap_or(root_path.clone())
                .normalize()
        });

        let acl_enabled = config.webdav_enabled && config.role_policy.is_some();
        let allowed_options = build_allow_header(
            config.webdav_enabled,
            config.allow_write,
            acl_enabled,
        );
        let welcome_files = parse_welcome_files(&config.welcome_file);
        let content_types = default_content_types();
        let mut dead_store = DeadPropertyStore::new(config.dead_property_storage);
        dead_store.set_sidecar_root(
            root_path.clone(),
            canonical_root.clone(),
            config.sidecar_root.clone(),
        );
        let lock_manager = Arc::new(match &config.lock_root {
            Some(lock_root) => WebDavLockManager::with_lock_root(
                root_path.clone(),
                canonical_root.clone(),
                lock_root.clone(),
            ),
            None => WebDavLockManager::new(),
        });
        let role_policy = config.role_policy.clone();

        Ok(Self {
            config: Arc::new(config),
            storage,
            lock_manager,
            dead_store,
            acl_enabled,
            role_policy,
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
            self.acl_enabled,
            self.role_policy.clone(),
            self.allowed_options.clone(),
            self.welcome_files.clone(),
            self.content_types.clone(),
            self.canonical_root.clone(),
        ))
    }
}

fn build_allow_header(webdav: bool, write: bool, acl: bool) -> String {
    let acl_suffix = if acl { ", ACL" } else { "" };
    if webdav && write {
        format!(
            "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK{acl_suffix}"
        )
    } else if webdav {
        format!("OPTIONS, GET, HEAD, PROPFIND{acl_suffix}")
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

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::storage::{StorageConfig, StorageExecutor};
    use tempfile::tempdir;

    #[test]
    fn write_without_unauth_opt_in_is_rejected() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(StorageExecutor::new(StorageConfig::default()));
        let result = WebDavFactory::new(
            WebDavConfig {
                root_path: dir.path().to_path_buf(),
                allow_write: true,
                webdav_enabled: true,
                ..Default::default()
            },
            storage,
        );
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected InvalidInput when unauth opt-in is missing"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("allow_unauthenticated_access"));
    }

    #[test]
    fn allow_header_includes_acl_when_role_policy_set() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(StorageExecutor::new(StorageConfig::default()));
        let roles = hopf_auth::RoleMembership::new().shared();
        let factory = WebDavFactory::new(
            WebDavConfig {
                root_path: dir.path().to_path_buf(),
                allow_write: true,
                webdav_enabled: true,
                allow_unauthenticated_access: true,
                role_policy: Some(roles),
                ..Default::default()
            },
            storage,
        )
        .unwrap();
        assert!(factory.allowed_options.contains("ACL"));
    }

    #[test]
    fn unauth_opt_in_allows_factory() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(StorageExecutor::new(StorageConfig::default()));
        WebDavFactory::new(
            WebDavConfig {
                root_path: dir.path().to_path_buf(),
                allow_write: true,
                webdav_enabled: true,
                allow_unauthenticated_access: true,
                ..Default::default()
            },
            storage,
        )
        .unwrap();
    }
}
