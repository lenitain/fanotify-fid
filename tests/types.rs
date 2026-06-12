//! Tests for event types.

use fanotify_fid::prelude::*;
use std::path::PathBuf;

#[test]
fn test_fid_event_methods() {
    let ev = FidEvent {
        mask: FAN_CREATE | FAN_MODIFY,
        pid: 42,
        path: PathBuf::from("/tmp/foo"),
        dfid_name_handle: None,
        dfid_name_filename: None,
        self_handle: None,
    };
    assert!(!ev.is_overflow());
    let names = ev.event_names();
    assert_eq!(names, vec!["MODIFY", "CREATE"]);
}

#[test]
fn test_fid_event_overflow() {
    let ev = FidEvent {
        mask: FAN_Q_OVERFLOW,
        pid: 0,
        path: PathBuf::new(),
        dfid_name_handle: None,
        dfid_name_filename: None,
        self_handle: None,
    };
    assert!(ev.is_overflow());
}

#[test]
fn test_fd_event_auto_close_fd() {
    // FdEvent with fd=-1 should not crash on drop
    let ev = FdEvent {
        mask: 0,
        fd: -1,
        pid: 0,
        path: PathBuf::new(),
    };
    drop(ev);
}

#[test]
fn test_fd_event_methods() {
    let ev = FdEvent {
        mask: FAN_CREATE | FAN_MODIFY,
        fd: -1,
        pid: 0,
        path: PathBuf::new(),
    };
    assert!(!ev.is_overflow());
    let names = ev.event_names();
    assert_eq!(names, vec!["MODIFY", "CREATE"]);
}

#[test]
fn test_fanotify_response_struct() {
    let resp = FanotifyResponse {
        fd: 5,
        response: FAN_ALLOW,
    };
    assert_eq!(resp.fd, 5);
    assert_eq!(resp.response, 0x01);
}

#[test]
fn test_handle_cache_type() {
    use std::collections::HashMap;
    let _cache: HandleCache = HashMap::new();
}
