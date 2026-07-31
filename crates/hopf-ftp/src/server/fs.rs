// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NVFS / TVFS file-system abstraction and chrooted local backend.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use crate::server::handler::FtpConnectionMetadata;

/// Result of a mutating file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpFileOpResult {
    /// Success.
    Ok,
    /// Permission / policy denied.
    PermissionDenied,
    /// Not found.
    NotFound,
    /// Already exists / conflict.
    Exists,
    /// Not a directory / wrong type.
    Invalid,
    /// I/O or other failure.
    Failed,
    /// Read-only file system.
    ReadOnly,
}

/// Directory entry / file metadata.
#[derive(Debug, Clone)]
pub struct FtpFileInfo {
    /// Basename.
    pub name: String,
    /// Absolute NVFS path.
    pub path: String,
    /// Directory?
    pub is_dir: bool,
    /// Size in bytes.
    pub size: u64,
    /// Modified time.
    pub modified: Option<SystemTime>,
}

/// Outcome of CWD.
#[derive(Debug, Clone)]
pub struct DirectoryChange {
    /// Operation result.
    pub result: FtpFileOpResult,
    /// New absolute cwd on success.
    pub new_cwd: String,
}

/// Network virtual file system (RFC 959 §2.2 / RFC 3659 TVFS).
pub trait FtpFileSystem: Send {
    /// List a directory.
    fn list_directory(
        &self,
        path: &str,
        meta: &FtpConnectionMetadata,
    ) -> Option<Vec<FtpFileInfo>>;

    /// Change directory (relative or absolute).
    fn change_directory(
        &self,
        path: &str,
        cwd: &str,
        meta: &FtpConnectionMetadata,
    ) -> DirectoryChange;

    /// Stat a path.
    fn file_info(&self, path: &str, meta: &FtpConnectionMetadata) -> Option<FtpFileInfo>;

    /// Create directory.
    fn mkdir(&self, path: &str, meta: &FtpConnectionMetadata) -> FtpFileOpResult;

    /// Remove directory.
    fn rmdir(&self, path: &str, meta: &FtpConnectionMetadata) -> FtpFileOpResult;

    /// Delete file.
    fn delete(&self, path: &str, meta: &FtpConnectionMetadata) -> FtpFileOpResult;

    /// Rename.
    fn rename(&self, from: &str, to: &str, meta: &FtpConnectionMetadata) -> FtpFileOpResult;

    /// Resolve absolute NVFS path from cwd + arg.
    fn resolve(&self, path: &str, cwd: &str) -> String;

    /// Open for read (RETR); `restart` is REST marker.
    fn open_read(
        &self,
        path: &str,
        restart: u64,
        meta: &FtpConnectionMetadata,
    ) -> Result<Box<dyn Read + Send>, FtpFileOpResult>;

    /// Open for write (STOR/APPE); `restart` is the REST marker (RFC 959
    /// §4.1.3) — meaningful only when `append` is false (APPE always seeks
    /// to EOF regardless of any pending REST).
    fn open_write(
        &self,
        path: &str,
        append: bool,
        restart: u64,
        meta: &FtpConnectionMetadata,
    ) -> Result<Box<dyn Write + Send>, FtpFileOpResult>;
}

/// Chrooted local filesystem backend.
pub struct BasicFtpFileSystem {
    root: PathBuf,
    canonical_root: PathBuf,
    read_only: bool,
}

impl BasicFtpFileSystem {
    /// Create a FS rooted at `root` (must exist and be a directory).
    pub fn new(root: impl AsRef<Path>, read_only: bool) -> io::Result<Self> {
        let root = root.as_ref().canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "ftp root must be a directory",
            ));
        }
        Ok(Self {
            canonical_root: root.clone(),
            root,
            read_only,
        })
    }

    fn join_jail(&self, nvfs: &str) -> Result<PathBuf, FtpFileOpResult> {
        let rel = nvfs.trim_start_matches('/');
        let mut physical = self.root.clone();
        for comp in Path::new(rel).components() {
            match comp {
                Component::Normal(s) => physical.push(s),
                Component::CurDir => {}
                Component::ParentDir => {
                    if !physical.pop() || !physical.starts_with(&self.root) {
                        return Err(FtpFileOpResult::PermissionDenied);
                    }
                }
                _ => return Err(FtpFileOpResult::Invalid),
            }
        }
        match physical.canonicalize() {
            Ok(canon) => {
                if !canon.starts_with(&self.canonical_root) {
                    return Err(FtpFileOpResult::PermissionDenied);
                }
                Ok(canon)
            }
            Err(_) => {
                // `physical` itself doesn't exist yet (STOR to a new file,
                // MKD of a new directory) — falling back to the unresolved
                // path here would let a symlink planted at an
                // intermediate component (e.g. root/foo -> /etc, target
                // root/foo/new.txt) textually pass the jail check while
                // actually resolving outside root. Canonicalize the parent
                // (which must exist) instead and re-append the final
                // component, so the check runs against the real
                // filesystem location the write will land at.
                let file_name = physical.file_name().ok_or(FtpFileOpResult::Invalid)?.to_owned();
                let parent = physical.parent().ok_or(FtpFileOpResult::Invalid)?;
                let canon_parent = parent.canonicalize().map_err(|_| FtpFileOpResult::NotFound)?;
                if !canon_parent.starts_with(&self.canonical_root) {
                    return Err(FtpFileOpResult::PermissionDenied);
                }
                Ok(canon_parent.join(file_name))
            }
        }
    }

    fn to_nvfs(&self, physical: &Path) -> String {
        let rel = physical
            .strip_prefix(&self.canonical_root)
            .unwrap_or(Path::new(""));
        let s = rel.to_string_lossy().replace('\\', "/");
        if s.is_empty() {
            "/".into()
        } else {
            format!("/{s}")
        }
    }

    fn info_for(&self, physical: &Path) -> Option<FtpFileInfo> {
        let meta = fs::metadata(physical).ok()?;
        let name = physical
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/".into());
        Some(FtpFileInfo {
            name,
            path: self.to_nvfs(physical),
            is_dir: meta.is_dir(),
            size: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

impl FtpFileSystem for BasicFtpFileSystem {
    fn list_directory(
        &self,
        path: &str,
        _meta: &FtpConnectionMetadata,
    ) -> Option<Vec<FtpFileInfo>> {
        let dir = self.join_jail(path).ok()?;
        let rd = fs::read_dir(&dir).ok()?;
        let mut out = Vec::new();
        for ent in rd.flatten() {
            if let Some(info) = self.info_for(&ent.path()) {
                out.push(info);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Some(out)
    }

    fn change_directory(
        &self,
        path: &str,
        cwd: &str,
        _meta: &FtpConnectionMetadata,
    ) -> DirectoryChange {
        let abs = self.resolve(path, cwd);
        match self.join_jail(&abs) {
            Ok(p) if p.is_dir() => DirectoryChange {
                result: FtpFileOpResult::Ok,
                new_cwd: self.to_nvfs(&p),
            },
            Ok(_) => DirectoryChange {
                result: FtpFileOpResult::Invalid,
                new_cwd: cwd.to_string(),
            },
            Err(r) => DirectoryChange {
                result: r,
                new_cwd: cwd.to_string(),
            },
        }
    }

    fn file_info(&self, path: &str, _meta: &FtpConnectionMetadata) -> Option<FtpFileInfo> {
        let p = self.join_jail(path).ok()?;
        self.info_for(&p)
    }

    fn mkdir(&self, path: &str, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        if self.read_only {
            return FtpFileOpResult::ReadOnly;
        }
        match self.join_jail(path) {
            Ok(p) => match fs::create_dir(&p) {
                Ok(()) => FtpFileOpResult::Ok,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => FtpFileOpResult::Exists,
                Err(_) => FtpFileOpResult::Failed,
            },
            Err(r) => r,
        }
    }

    fn rmdir(&self, path: &str, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        if self.read_only {
            return FtpFileOpResult::ReadOnly;
        }
        match self.join_jail(path) {
            Ok(p) => match fs::remove_dir(&p) {
                Ok(()) => FtpFileOpResult::Ok,
                Err(_) => FtpFileOpResult::Failed,
            },
            Err(r) => r,
        }
    }

    fn delete(&self, path: &str, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        if self.read_only {
            return FtpFileOpResult::ReadOnly;
        }
        match self.join_jail(path) {
            Ok(p) => match fs::remove_file(&p) {
                Ok(()) => FtpFileOpResult::Ok,
                Err(_) => FtpFileOpResult::Failed,
            },
            Err(r) => r,
        }
    }

    fn rename(&self, from: &str, to: &str, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        if self.read_only {
            return FtpFileOpResult::ReadOnly;
        }
        let a = match self.join_jail(from) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let b = match self.join_jail(to) {
            Ok(p) => p,
            Err(r) => return r,
        };
        match fs::rename(a, b) {
            Ok(()) => FtpFileOpResult::Ok,
            Err(_) => FtpFileOpResult::Failed,
        }
    }

    fn resolve(&self, path: &str, cwd: &str) -> String {
        if path.starts_with('/') {
            normalize_nvfs(path)
        } else if path.is_empty() || path == "." {
            normalize_nvfs(cwd)
        } else {
            let base = if cwd.ends_with('/') {
                cwd.to_string()
            } else {
                format!("{cwd}/")
            };
            normalize_nvfs(&format!("{base}{path}"))
        }
    }

    fn open_read(
        &self,
        path: &str,
        restart: u64,
        _meta: &FtpConnectionMetadata,
    ) -> Result<Box<dyn Read + Send>, FtpFileOpResult> {
        let p = self.join_jail(path)?;
        let mut f = File::open(p).map_err(|_| FtpFileOpResult::NotFound)?;
        if restart > 0 {
            f.seek(SeekFrom::Start(restart))
                .map_err(|_| FtpFileOpResult::Failed)?;
        }
        Ok(Box::new(f))
    }

    fn open_write(
        &self,
        path: &str,
        append: bool,
        restart: u64,
        _meta: &FtpConnectionMetadata,
    ) -> Result<Box<dyn Write + Send>, FtpFileOpResult> {
        if self.read_only {
            return Err(FtpFileOpResult::ReadOnly);
        }
        let p = self.join_jail(path)?;
        let mut opts = OpenOptions::new();
        opts.create(true).write(true);
        if append {
            opts.append(true);
        } else if restart == 0 {
            opts.truncate(true);
        }
        let mut f = opts.open(p).map_err(|_| FtpFileOpResult::Failed)?;
        if !append && restart > 0 {
            f.seek(SeekFrom::Start(restart))
                .map_err(|_| FtpFileOpResult::Failed)?;
        }
        Ok(Box::new(f))
    }
}

fn normalize_nvfs(path: &str) -> String {
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
    if stack.is_empty() {
        "/".into()
    } else {
        format!("/{}", stack.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::handler::FtpConnectionMetadata;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn meta() -> FtpConnectionMetadata {
        FtpConnectionMetadata {
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21),
            user: None,
            tls: false,
        }
    }

    #[test]
    fn parent_of_root_stays_rooted() {
        let dir = tempfile::tempdir().unwrap();
        let fs = BasicFtpFileSystem::new(dir.path(), false).unwrap();
        let r = fs.change_directory("..", "/", &meta());
        assert_eq!(r.result, FtpFileOpResult::Ok);
        assert_eq!(r.new_cwd, "/");
    }

    #[test]
    fn mkdir_list_delete() {
        let dir = tempfile::tempdir().unwrap();
        let fs = BasicFtpFileSystem::new(dir.path(), false).unwrap();
        assert_eq!(fs.mkdir("/a", &meta()), FtpFileOpResult::Ok);
        let list = fs.list_directory("/", &meta()).unwrap();
        assert!(list.iter().any(|e| e.name == "a"));
    }

    /// Issue #3 (3): a symlink planted inside the jail that points outside
    /// it must not let a write to a not-yet-existing path underneath
    /// escape — the old `canonicalize().unwrap_or(physical)` fallback let
    /// the unresolved (symlink-unaware) path textually pass the jail
    /// check even though the real write would follow the symlink.
    #[cfg(unix)]
    #[test]
    fn stor_through_symlinked_directory_is_rejected_for_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let fs = BasicFtpFileSystem::new(dir.path(), false).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();

        // "new.txt" doesn't exist yet under escape/ — exactly the case the
        // canonicalize-fallback bug mishandled.
        let result = fs.open_write("/escape/new.txt", false, 0, &meta());
        assert!(
            result.is_err(),
            "must reject a write through a symlink escaping the jail"
        );
        assert!(
            !outside.path().join("new.txt").exists(),
            "must not have written outside the jail"
        );
    }

    /// Same bug class, for MKD instead of STOR.
    #[cfg(unix)]
    #[test]
    fn mkdir_through_symlinked_directory_is_rejected_for_a_new_directory() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let fs = BasicFtpFileSystem::new(dir.path(), false).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();

        let result = fs.mkdir("/escape/newdir", &meta());
        assert_ne!(
            result,
            FtpFileOpResult::Ok,
            "must reject mkdir through a symlink escaping the jail"
        );
        assert!(!outside.path().join("newdir").exists());
    }

    /// The fix must not break the ordinary (non-symlinked) case: STOR to a
    /// new file inside a legitimate, already-existing subdirectory.
    #[test]
    fn stor_to_new_file_in_legitimate_subdirectory_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let fs = BasicFtpFileSystem::new(dir.path(), false).unwrap();

        let mut w = fs.open_write("/sub/new.txt", false, 0, &meta()).unwrap();
        w.write_all(b"hello").unwrap();
        drop(w);
        assert_eq!(std::fs::read(dir.path().join("sub/new.txt")).unwrap(), b"hello");
    }

    #[test]
    fn open_write_without_restart_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let fs = BasicFtpFileSystem::new(dir.path(), false).unwrap();
        std::fs::write(dir.path().join("f.txt"), b"0123456789").unwrap();
        let mut w = fs.open_write("/f.txt", false, 0, &meta()).unwrap();
        w.write_all(b"AB").unwrap();
        drop(w);
        assert_eq!(std::fs::read(dir.path().join("f.txt")).unwrap(), b"AB");
    }

    #[test]
    fn open_write_with_restart_seeks_instead_of_truncating() {
        // RFC 959 §4.1.3 — REST before STOR resumes at the given offset
        // instead of truncating the file back to empty.
        let dir = tempfile::tempdir().unwrap();
        let fs = BasicFtpFileSystem::new(dir.path(), false).unwrap();
        std::fs::write(dir.path().join("f.txt"), b"0123456789").unwrap();
        let mut w = fs.open_write("/f.txt", false, 5, &meta()).unwrap();
        w.write_all(b"XYZ").unwrap();
        drop(w);
        assert_eq!(std::fs::read(dir.path().join("f.txt")).unwrap(), b"01234XYZ89");
    }

    #[test]
    fn open_write_append_ignores_restart() {
        // APPE always seeks to EOF regardless of any pending REST.
        let dir = tempfile::tempdir().unwrap();
        let fs = BasicFtpFileSystem::new(dir.path(), false).unwrap();
        std::fs::write(dir.path().join("f.txt"), b"0123456789").unwrap();
        let mut w = fs.open_write("/f.txt", true, 5, &meta()).unwrap();
        w.write_all(b"XYZ").unwrap();
        drop(w);
        assert_eq!(
            std::fs::read(dir.path().join("f.txt")).unwrap(),
            b"0123456789XYZ"
        );
    }
}
