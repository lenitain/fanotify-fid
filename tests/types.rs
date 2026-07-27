//! Tests for event types.

use fanotify_fid::prelude::*;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;

#[test]
fn test_fid_event_methods() {
    let ev = FidEvent::new(
        FAN_CREATE | FAN_MODIFY,
        42,
        PathBuf::from("/tmp/foo"),
        None,
        None,
        None,
    );
    assert!(!ev.is_overflow());
    let names: Vec<&str> = ev.event_names().collect();
    assert_eq!(names, vec!["MODIFY", "CREATE"]);
}

#[test]
fn test_fid_event_overflow() {
    let ev = FidEvent::new(FAN_Q_OVERFLOW, 0, PathBuf::new(), None, None, None);
    assert!(ev.is_overflow());
}

#[test]
fn test_fd_event_auto_close_fd() {
    // FdEvent with None fd should not crash on drop
    let ev = FdEvent::new(0, None, 0, PathBuf::new());
    drop(ev);
}

#[test]
fn test_fd_event_methods() {
    let ev = FdEvent::new(FAN_CREATE | FAN_MODIFY, None, 0, PathBuf::new());
    assert!(!ev.is_overflow());
    let names: Vec<&str> = ev.event_names().collect();
    assert_eq!(names, vec!["MODIFY", "CREATE"]);
}

#[test]
fn test_fd_event_into_fd_none() {
    let ev = FdEvent::new(0, None, 0, PathBuf::new());
    assert!(ev.into_fd().is_none());
}

#[test]
fn test_fanotify_response_struct() {
    let fd = unsafe { BorrowedFd::borrow_raw(5) };
    let resp = FanotifyResponse::new(fd, FAN_ALLOW);
    assert_eq!(resp.fd().as_raw_fd(), 5);
    assert_eq!(resp.response(), 0x01);
}

#[test]
fn test_handle_cache_type() {
    use std::collections::HashMap;
    let _cache: HandleCache = HashMap::new();
}
