// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Exclusive flock helper (Unix).

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

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
