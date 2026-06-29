//! File handle integration tests.
//!
//! These tests verify name_to_handle_at, open_by_handle_at, and
//! HandleCache functionality.
//! Require `CAP_SYS_ADMIN` (run as root).

mod common;

use common::*;
use fanotify_fid::parse::resolve_with_cache;
use fanotify_fid::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::path::Path;

#[test]
#[ignore]
fn test_name_to_handle_at_real_path() {
    let h = name_to_handle_at(Path::new("/tmp")).unwrap();
    assert!(!h.is_empty());
}

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

#[test]
#[ignore]
fn test_cache_recovers_deleted_path() {
    if !check_handle_support() {
        eprintln!("SKIP: cache test unsupported");
        return;
    }

    let dir = tmpdir();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();

    let m = vec![open_mount_fd("/tmp").unwrap()];
    let h = name_to_handle_at(&sub).unwrap();
    let r = resolve_file_handle(&m, &h).unwrap();

    let mut cache = HashMap::new();
    cache.insert(h.clone(), r);

    let mut evts = vec![FidEvent::new(
        FAN_DELETE_SELF,
        1,
        Path::new("").to_path_buf(),
        None,
        None,
        Some(h),
    )];
    resolve_with_cache(&mut evts, &cache);
    assert!(!evts[0].path().as_os_str().is_empty());
}
