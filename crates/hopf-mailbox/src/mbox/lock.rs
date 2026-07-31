// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Exclusive flock and dotlock helpers (Unix).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Advisory exclusive lock on an open file (held for `File` lifetime).
pub struct FileLock {
    file: File,
}

impl FileLock {
    /// Open `path` read/write and take `LOCK_EX`.
    pub fn exclusive(file: File) -> io::Result<Self> {
        let fd = file.as_raw_fd();
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file })
    }

    /// Underlying file (lock held).
    #[allow(dead_code)]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Mutable underlying file (lock held).
    #[allow(dead_code)]
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let fd = self.file.as_raw_fd();
        unsafe {
            let _ = libc::flock(fd, libc::LOCK_UN);
        }
    }
}

/// A lock file older than this is treated as abandoned (its owner crashed
/// or was killed without cleaning up) and reclaimed rather than waited out
/// — the classic mbox dotlock convention.
const STALE_LOCK_AGE: Duration = Duration::from_secs(5 * 60);
const RETRY_INTERVAL: Duration = Duration::from_millis(200);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Classic mbox "dotlock" convention: an atomically-created `<mbox>.lock`
/// sentinel file, held for the `DotLock`'s lifetime and removed on drop.
///
/// Held alongside [`FileLock`]'s `flock` so hopf interoperates with
/// dotlock-only mbox tooling (procmail, mutt, etc.), not just other
/// flock-aware processes — NFS in particular does not reliably honor
/// `flock` across clients, so dotlock is the convention that actually
/// works there.
#[derive(Debug)]
pub struct DotLock {
    path: PathBuf,
}

impl DotLock {
    /// Acquire `<mbox_path>.lock` with the default 10s timeout — see
    /// [`Self::acquire_with_timeout`].
    pub fn acquire(mbox_path: &Path) -> io::Result<Self> {
        Self::acquire_with_timeout(mbox_path, DEFAULT_TIMEOUT)
    }

    /// Acquire `<mbox_path>.lock`, retrying for up to `timeout` if another
    /// process already holds it. A lock file older than
    /// [`STALE_LOCK_AGE`] is reclaimed immediately rather than waited out.
    pub fn acquire_with_timeout(mbox_path: &Path, timeout: Duration) -> io::Result<Self> {
        let lock_path = dotlock_path(mbox_path);
        let deadline = Instant::now() + timeout;
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut f) => {
                    // Best-effort diagnostic content; correctness rests
                    // entirely on the atomic O_EXCL create above.
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(Self { path: lock_path });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if is_stale(&lock_path) {
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("timed out waiting for mbox dotlock {}", lock_path.display()),
                        ));
                    }
                    std::thread::sleep(RETRY_INTERVAL);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for DotLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn is_stale(lock_path: &Path) -> bool {
    fs::metadata(lock_path)
        .and_then(|m| m.modified())
        .and_then(|modified| {
            modified
                .elapsed()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        })
        .map(|age| age > STALE_LOCK_AGE)
        .unwrap_or(false)
}

fn dotlock_path(mbox_path: &Path) -> PathBuf {
    let mut s = mbox_path.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_creates_and_drop_removes_the_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let mbox = dir.path().join("INBOX");
        std::fs::write(&mbox, b"").unwrap();
        let lock_path = dotlock_path(&mbox);
        assert!(!lock_path.exists());
        {
            let _lock = DotLock::acquire(&mbox).unwrap();
            assert!(lock_path.exists());
        }
        assert!(!lock_path.exists(), "lock file must be removed on drop");
    }

    #[test]
    fn second_acquire_times_out_while_first_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let mbox = dir.path().join("INBOX");
        std::fs::write(&mbox, b"").unwrap();
        let _first = DotLock::acquire(&mbox).unwrap();
        let err = DotLock::acquire_with_timeout(&mbox, Duration::from_millis(300)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn second_acquire_succeeds_once_first_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mbox = dir.path().join("INBOX");
        std::fs::write(&mbox, b"").unwrap();
        let first = DotLock::acquire(&mbox).unwrap();
        drop(first);
        let _second = DotLock::acquire_with_timeout(&mbox, Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn stale_lock_file_is_reclaimed_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let mbox = dir.path().join("INBOX");
        std::fs::write(&mbox, b"").unwrap();
        let lock_path = dotlock_path(&mbox);
        std::fs::write(&lock_path, b"12345\n").unwrap();
        // Back-date the lock file's mtime well past STALE_LOCK_AGE (via
        // libc::utimes directly — std::fs::FileTimes needs Rust 1.75, past
        // this workspace's declared 1.70 MSRV).
        let stale_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - (STALE_LOCK_AGE.as_secs() as i64 + 60);
        let c_path = std::ffi::CString::new(lock_path.to_str().unwrap()).unwrap();
        let tv = libc::timeval {
            tv_sec: stale_secs,
            tv_usec: 0,
        };
        let times = [tv, tv];
        let rc = unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
        assert_eq!(rc, 0, "utimes failed: {}", io::Error::last_os_error());

        // Should reclaim immediately rather than waiting out the timeout.
        let start = Instant::now();
        let _lock = DotLock::acquire_with_timeout(&mbox, Duration::from_secs(5)).unwrap();
        assert!(start.elapsed() < Duration::from_secs(1), "stale lock should be reclaimed without waiting");
    }
}
