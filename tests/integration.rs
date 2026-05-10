//! Integration tests that require `CAP_SYS_ADMIN` (run as root).
//!
//! Marked `#[ignore]` so they don't run during normal `cargo test`.
//!
//! # Usage
//!
//! ```bash
//! cargo test --test integration --no-run
//! sudo ./target/debug/deps/integration-* --ignored
//! ```

use fanotify_fid::prelude::*;
use fanotify_fid::parse::resolve_with_cache;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};
use std::{fs, thread};

// ── Retry with timeout (for non-blocking fds) ──

fn retry<T, F: FnMut() -> Option<T>>(mut f: F, timeout: Duration) -> Option<T> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(v) = f() {
            return Some(v);
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn open_mount_fd(path: &str) -> Option<std::os::fd::OwnedFd> {
    open_mount(path).ok()
}

fn check_handle_support() -> bool {
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

// ── FID mode: mark a file, modify it, read event ──

#[test]
#[ignore]
fn test_fid_event_on_single_file() {
    let dir = tmpdir();
    let f = dir.path().join("t.txt");
    fs::write(&f, b"x").unwrap();

    let fan = Fanotify::new().report_fid().nonblock().init().unwrap();
    fan.mark(FAN_MARK_ADD, FAN_MODIFY, &f).unwrap();
    fs::write(&f, b"y").unwrap();

    let mount_fd = open_mount_fd("/");
    let mnt: &[std::os::fd::OwnedFd] = mount_fd.as_slice();
    let mut buf = Vec::with_capacity(65536);

    let evts = retry(
        || read_fid_events(fan.as_fd(), mnt, &mut buf, None).ok().filter(|e| !e.is_empty()),
        Duration::from_secs(2),
    )
    .expect("MODIFY event within 2s");

    assert!(evts.iter().any(|e| e.mask & FAN_MODIFY != 0));
}

// ── Legacy mode: mark a file, open it, read event ──

#[test]
#[ignore]
fn test_legacy_event_lifecycle() {
    let dir = tmpdir();
    let f = dir.path().join("r.txt");
    fs::write(&f, b"d").unwrap();

    let fan = Fanotify::new().class_content().nonblock().init().unwrap();
    fan.mark(FAN_MARK_ADD, FAN_OPEN, &f).unwrap();
    let _ = fs::read(&f).ok();

    let evts = retry(
        || fan.read_legacy().ok().filter(|e| !e.is_empty()),
        Duration::from_secs(2),
    )
    .expect("OPEN event within 2s");

    assert!(evts[0].mask & FAN_OPEN != 0);
    assert!(evts[0].fd >= 0);
}

// ── Permission event: respond with FAN_ALLOW ──

#[test]
#[ignore]
fn test_permission_event_response() {
    let dir = tmpdir();
    let f = dir.path().join("p.txt");
    fs::write(&f, b"t").unwrap();

    let fan = Fanotify::new().class_content().init().unwrap();
    fan.mark(FAN_MARK_ADD, FAN_OPEN_PERM, dir.path()).unwrap();

    let fc = f.clone();
    let rdr = thread::spawn(move || {
        for _ in 0..100 {
            match fs::read_to_string(&fc) {
                Ok(s) => return s,
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        }
        panic!("reader: timed out");
    });

    // Blocking read — waits until kernel delivers the permission event
    let evts = fan.read_legacy().expect("read perm event");
    let ev = evts.first().filter(|e| e.mask & FAN_OPEN_PERM != 0)
        .expect("first event should be FAN_OPEN_PERM");
    fan.send_response(&FanotifyResponse { fd: ev.fd, response: FAN_ALLOW })
        .expect("send FAN_ALLOW");

    assert_eq!(rdr.join().expect("reader"), "t");
}

// ── name_to_handle_at on /tmp ──

#[test]
#[ignore]
fn test_name_to_handle_at_real_path() {
    let h = name_to_handle_at(Path::new("/tmp")).unwrap();
    assert!(!h.is_empty());
}

// ── open_by_handle_at (skip if unsupported) ──

#[test]
#[ignore]
fn test_open_by_handle_at_resolve() {
    if !check_handle_support() {
        eprintln!("SKIP: open_by_handle_at unsupported");
        return;
    }
    let h = name_to_handle_at(Path::new("/tmp")).unwrap();
    let m = open_mount_fd("/tmp").unwrap();
    let o = open_by_handle_at(m.as_raw_fd(), &h).unwrap();
    assert!(o.as_raw_fd() >= 0);
}

// ── resolve_file_handle (skip if unsupported) ──

#[test]
#[ignore]
fn test_resolve_file_handle() {
    if !check_handle_support() {
        eprintln!("SKIP: resolve_file_handle unsupported");
        return;
    }
    let m = vec![open_mount_fd("/tmp").unwrap()];
    let h = name_to_handle_at(Path::new("/tmp")).unwrap();
    let p = resolve_file_handle(&m, &h);
    assert!(p.is_some());
}

// ── HandleCache recovery (skip if unsupported) ──

#[test]
#[ignore]
fn test_cache_recovers_deleted_path() {
    if !check_handle_support() {
        eprintln!("SKIP: cache test unsupported");
        return;
    }
    use std::collections::HashMap;

    let dir = tmpdir();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();

    let m = vec![open_mount_fd("/tmp").unwrap()];
    let h = name_to_handle_at(&sub).unwrap();
    let r = resolve_file_handle(&m, &h).unwrap();

    let mut cache = HashMap::new();
    cache.insert(h.clone(), r);

    let mut evts = vec![FidEvent {
        mask: FAN_DELETE_SELF, pid: 1, path: Path::new("").to_path_buf(),
        dfid_name_handle: None, dfid_name_filename: None, self_handle: Some(h),
    }];
    resolve_with_cache(&mut evts, &cache);
    assert!(!evts[0].path.as_os_str().is_empty());
}
