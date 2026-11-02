// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! An in-memory [`FtpFileSystem`] and handler for unit tests, so that tests of
//! the control connection touch no real files. It follows the behaviour of
//! [`BasicFtpFileSystem`](crate::server::fs::BasicFtpFileSystem) that the
//! protocol layer relies on: a single root that `..` cannot leave, listings
//! sorted by name, and the same result codes.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use hopf_auth::{IdentityMaterial, PeerContext, TrustDecision, TrustPolicy};

use crate::server::fs::{DirectoryChange, FtpFileInfo, FtpFileOpResult, FtpFileSystem, UniqueName};
use crate::server::handler::{FtpAuthResult, FtpConnectionHandler, FtpConnectionMetadata};

#[derive(Debug, Clone)]
enum Node {
    Dir,
    File(Vec<u8>),
}

/// Absolute, normalised path to node. The root is `/` and always a directory.
type Tree = BTreeMap<String, Node>;

/// A shared in-memory tree; clones see the same files.
#[derive(Clone)]
pub(crate) struct MemoryFtpFileSystem {
    tree: Arc<Mutex<Tree>>,
    unique: Arc<Mutex<u64>>,
}

/// Every instant is the same, so listings do not depend on the clock.
fn modified() -> Option<SystemTime> {
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
}

fn normalize(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            p => stack.push(p),
        }
    }
    if stack.is_empty() { "/".into() } else { format!("/{}", stack.join("/")) }
}

fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => path[..i].to_string(),
    }
}

fn name_of(path: &str) -> String {
    if path == "/" { "/".into() } else { path[path.rfind('/').map_or(0, |i| i + 1)..].to_string() }
}

fn info(path: &str, node: &Node) -> FtpFileInfo {
    FtpFileInfo {
        name: name_of(path),
        path: path.to_string(),
        is_dir: matches!(node, Node::Dir),
        size: match node {
            Node::Dir => 0,
            Node::File(b) => b.len() as u64,
        },
        modified: modified(),
    }
}

impl MemoryFtpFileSystem {
    pub(crate) fn new() -> Self {
        let mut tree = Tree::new();
        tree.insert("/".into(), Node::Dir);
        Self { tree: Arc::new(Mutex::new(tree)), unique: Arc::new(Mutex::new(0)) }
    }

    /// Put a file at `path`, creating the directories above it.
    pub(crate) fn put(&self, path: &str, contents: &[u8]) {
        let path = normalize(path);
        let mut tree = self.tree.lock().unwrap();
        let mut dir = parent_of(&path);
        while dir != "/" {
            tree.entry(dir.clone()).or_insert(Node::Dir);
            dir = parent_of(&dir);
        }
        tree.insert(path, Node::File(contents.to_vec()));
    }

    #[cfg_attr(not(feature = "integration"), allow(dead_code))]
    pub(crate) fn contents(&self, path: &str) -> Option<Vec<u8>> {
        match self.tree.lock().unwrap().get(&normalize(path)) {
            Some(Node::File(b)) => Some(b.clone()),
            _ => None,
        }
    }

    pub(crate) fn exists(&self, path: &str) -> bool {
        self.tree.lock().unwrap().contains_key(&normalize(path))
    }

    pub(crate) fn is_dir(&self, path: &str) -> bool {
        matches!(self.tree.lock().unwrap().get(&normalize(path)), Some(Node::Dir))
    }

    fn parent_exists(tree: &Tree, path: &str) -> Result<(), FtpFileOpResult> {
        match tree.get(&parent_of(path)) {
            Some(Node::Dir) => Ok(()),
            Some(Node::File(_)) => Err(FtpFileOpResult::Invalid),
            None => Err(FtpFileOpResult::NotFound),
        }
    }
}

/// A file being written: the bytes reach the tree as they are written.
struct MemoryWriter {
    tree: Arc<Mutex<Tree>>,
    path: String,
    position: usize,
    append: bool,
}

impl Write for MemoryWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut tree = self.tree.lock().unwrap();
        let Some(Node::File(bytes)) = tree.get_mut(&self.path) else {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        };
        if self.append {
            bytes.extend_from_slice(buf);
        } else {
            if bytes.len() < self.position {
                bytes.resize(self.position, 0);
            }
            let end = self.position + buf.len();
            if bytes.len() < end {
                bytes.resize(end, 0);
            }
            bytes[self.position..end].copy_from_slice(buf);
            self.position = end;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl FtpFileSystem for MemoryFtpFileSystem {
    fn list_directory(&self, path: &str, _meta: &FtpConnectionMetadata) -> Option<Vec<FtpFileInfo>> {
        let dir = normalize(path);
        let tree = self.tree.lock().unwrap();
        if !matches!(tree.get(&dir), Some(Node::Dir)) {
            return None;
        }
        let mut out: Vec<FtpFileInfo> = tree
            .iter()
            .filter(|(p, _)| p.as_str() != "/" && parent_of(p) == dir)
            .map(|(p, n)| info(p, n))
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Some(out)
    }

    fn change_directory(&self, path: &str, cwd: &str, _meta: &FtpConnectionMetadata) -> DirectoryChange {
        let abs = self.resolve(path, cwd);
        match self.tree.lock().unwrap().get(&abs) {
            Some(Node::Dir) => DirectoryChange { result: FtpFileOpResult::Ok, new_cwd: abs },
            Some(Node::File(_)) => DirectoryChange { result: FtpFileOpResult::Invalid, new_cwd: cwd.to_string() },
            None => DirectoryChange { result: FtpFileOpResult::NotFound, new_cwd: cwd.to_string() },
        }
    }

    fn file_info(&self, path: &str, _meta: &FtpConnectionMetadata) -> Option<FtpFileInfo> {
        let path = normalize(path);
        self.tree.lock().unwrap().get(&path).map(|n| info(&path, n))
    }

    fn mkdir(&self, path: &str, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        let path = normalize(path);
        let mut tree = self.tree.lock().unwrap();
        if tree.contains_key(&path) {
            return FtpFileOpResult::Exists;
        }
        if let Err(r) = Self::parent_exists(&tree, &path) {
            return r;
        }
        tree.insert(path, Node::Dir);
        FtpFileOpResult::Ok
    }

    fn rmdir(&self, path: &str, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        let path = normalize(path);
        let mut tree = self.tree.lock().unwrap();
        let empty = !tree.keys().any(|p| p != &path && p.starts_with(&format!("{}/", path.trim_end_matches('/'))));
        match tree.get(&path) {
            Some(Node::Dir) if path != "/" && empty => {
                tree.remove(&path);
                FtpFileOpResult::Ok
            }
            _ => FtpFileOpResult::Failed,
        }
    }

    fn delete(&self, path: &str, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        let path = normalize(path);
        let mut tree = self.tree.lock().unwrap();
        match tree.get(&path) {
            Some(Node::File(_)) => {
                tree.remove(&path);
                FtpFileOpResult::Ok
            }
            _ => FtpFileOpResult::Failed,
        }
    }

    fn rename(&self, from: &str, to: &str, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        let (from, to) = (normalize(from), normalize(to));
        let mut tree = self.tree.lock().unwrap();
        if from == "/" || !tree.contains_key(&from) || Self::parent_exists(&tree, &to).is_err() {
            return FtpFileOpResult::Failed;
        }
        let moved: Vec<String> = tree
            .keys()
            .filter(|p| **p == from || p.starts_with(&format!("{from}/")))
            .cloned()
            .collect();
        for old in moved {
            let node = tree.remove(&old).unwrap();
            tree.insert(format!("{to}{}", &old[from.len()..]), node);
        }
        FtpFileOpResult::Ok
    }

    fn resolve(&self, path: &str, cwd: &str) -> String {
        if path.starts_with('/') {
            normalize(path)
        } else if path.is_empty() || path == "." {
            normalize(cwd)
        } else {
            normalize(&format!("{}/{path}", cwd.trim_end_matches('/')))
        }
    }

    fn open_read(
        &self,
        path: &str,
        restart: u64,
        _meta: &FtpConnectionMetadata,
    ) -> Result<Box<dyn Read + Send>, FtpFileOpResult> {
        match self.tree.lock().unwrap().get(&normalize(path)) {
            Some(Node::File(b)) => {
                let mut cursor = Cursor::new(b.clone());
                cursor.set_position(restart);
                Ok(Box::new(cursor))
            }
            _ => Err(FtpFileOpResult::NotFound),
        }
    }

    fn open_write(
        &self,
        path: &str,
        append: bool,
        restart: u64,
        _meta: &FtpConnectionMetadata,
    ) -> Result<Box<dyn Write + Send>, FtpFileOpResult> {
        let path = normalize(path);
        {
            let mut tree = self.tree.lock().unwrap();
            match tree.get_mut(&path) {
                Some(Node::Dir) => return Err(FtpFileOpResult::Failed),
                Some(Node::File(bytes)) => {
                    if !append && restart == 0 {
                        bytes.clear();
                    }
                }
                None => {
                    Self::parent_exists(&tree, &path)?;
                    tree.insert(path.clone(), Node::File(Vec::new()));
                }
            }
        }
        Ok(Box::new(MemoryWriter {
            tree: Arc::clone(&self.tree),
            path,
            position: if append { 0 } else { restart as usize },
            append,
        }))
    }

    fn generate_unique_name(&self, base: &str, _suggested: Option<&str>, _meta: &FtpConnectionMetadata) -> UniqueName {
        let mut n = self.unique.lock().unwrap();
        loop {
            *n += 1;
            let candidate = self.resolve(&format!("hopf.{:x}", *n), if base.is_empty() { "/" } else { base });
            if !self.exists(&candidate) {
                return UniqueName { result: FtpFileOpResult::Ok, path: candidate };
            }
        }
    }
}

/// The stock handler's behaviour over a [`MemoryFtpFileSystem`]: logins are
/// decided by a trust policy.
pub(crate) struct MemoryFtpHandler {
    policy: Arc<dyn TrustPolicy>,
    fs: MemoryFtpFileSystem,
    shared: Arc<MemoryFtpFileSystem>,
}

impl MemoryFtpHandler {
    pub(crate) fn new(fs: MemoryFtpFileSystem, policy: Arc<dyn TrustPolicy>) -> Self {
        Self { policy, shared: Arc::new(fs.clone()), fs }
    }
}

impl FtpConnectionHandler for MemoryFtpHandler {
    fn authenticate(
        &mut self,
        username: &str,
        password: Option<&str>,
        _account: Option<&str>,
        meta: &FtpConnectionMetadata,
    ) -> FtpAuthResult {
        let Some(password) = password else {
            return FtpAuthResult::NeedPassword;
        };
        let identity = IdentityMaterial::UsernamePassword { username: username.to_string(), password: password.to_string() };
        match self.policy.evaluate(&identity, &PeerContext::from_addr(meta.peer)) {
            TrustDecision::Accept => FtpAuthResult::Success,
            TrustDecision::Reject => FtpAuthResult::Failed,
        }
    }

    fn file_system(&mut self, _meta: &FtpConnectionMetadata) -> &mut dyn FtpFileSystem {
        &mut self.fs
    }

    fn file_system_handle(&mut self, _meta: &FtpConnectionMetadata) -> Option<Arc<dyn FtpFileSystem + Sync>> {
        Some(Arc::clone(&self.shared) as Arc<dyn FtpFileSystem + Sync>)
    }
}
