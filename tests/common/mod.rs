//! Shared test utilities for integration tests.

#![allow(dead_code)]

use std::path::Path;
use std::time::{Duration, Instant};
use std::thread;

use fanotify_fid::prelude::*;

/// Retry a closure until it returns `Some` or timeout expires.
pub fn retry<T, F: FnMut() -> Option<T>>(mut f: F, timeout: Duration) -> Option<T> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(v) = f() {
            return Some(v);
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Create a temporary directory for testing.
pub fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// Open a mount fd for the given path.
pub fn open_mount_fd(path: &str) -> Option<OwnedFd> {
    open_mount(path).ok()
}

/// Check if the system supports file handle operations.
pub fn check_handle_support() -> bool {
    let mount_fd = match open_mount_fd("/tmp") {
        Some(f) => f,
        None => return false,
    };
    let handle = match name_to_handle_at(Path::new("/tmp")) {
        Ok(h) => h,
        Err(_) => return false,
    };
    open_by_handle_at(mount_fd.as_raw_fd(), &handle).is_ok()
}

use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
