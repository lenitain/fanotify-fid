//! Tests for event types.

use fanotify_fid::prelude::*;
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
    // FdEvent with fd=-1 should not crash on drop
    let ev = FdEvent::new(0, -1, 0, PathBuf::new());
    drop(ev);
}

#[test]
fn test_fd_event_methods() {
    let ev = FdEvent::new(FAN_CREATE | FAN_MODIFY, -1, 0, PathBuf::new());
    assert!(!ev.is_overflow());
    let names: Vec<&str> = ev.event_names().collect();
    assert_eq!(names, vec!["MODIFY", "CREATE"]);
}

#[test]
fn test_fanotify_response_struct() {
    let resp = FanotifyResponse::new(5, FAN_ALLOW);
    assert_eq!(resp.fd(), 5);
    assert_eq!(resp.response(), 0x01);
}

#[test]
fn test_handle_cache_type() {
    use std::collections::HashMap;
    let _cache: HandleCache = HashMap::new();
}
