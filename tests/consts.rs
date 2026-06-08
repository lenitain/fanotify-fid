//! Tests for fanotify constants.

use fanotify_fid::consts;

#[test]
fn test_new_event_constants_exist() {
    // Verify all naughtyfy-sourced constants are accessible
    let _ = consts::FAN_OPEN_PERM;
    let _ = consts::FAN_ACCESS_PERM;
    let _ = consts::FAN_OPEN_EXEC_PERM;
    let _ = consts::FAN_RENAME;
    let _ = consts::FAN_FS_ERROR;
    let _ = consts::FAN_REPORT_TID;
    let _ = consts::FAN_REPORT_PIDFD;
    let _ = consts::FAN_REPORT_TARGET_FID;
    let _ = consts::FAN_UNLIMITED_QUEUE;
    let _ = consts::FAN_UNLIMITED_MARKS;
    let _ = consts::FAN_ENABLE_AUDIT;
    let _ = consts::FAN_CLASS_CONTENT;
    let _ = consts::FAN_CLASS_PRE_CONTENT;
    let _ = consts::FAN_REPORT_DFID_NAME;
    let _ = consts::FAN_REPORT_DFID_NAME_TARGET;
    let _ = consts::FAN_MARK_DONT_FOLLOW;
    let _ = consts::FAN_MARK_ONLYDIR;
    let _ = consts::FAN_MARK_MOUNT;
    let _ = consts::FAN_MARK_IGNORED_MASK;
    let _ = consts::FAN_MARK_IGNORED_SURV_MODIFY;
    let _ = consts::FAN_MARK_EVICTABLE;
    let _ = consts::FAN_MARK_IGNORE;
    let _ = consts::FAN_MARK_IGNORE_SURV;
    let _ = consts::FAN_ALLOW;
    let _ = consts::FAN_DENY;
    let _ = consts::FAN_AUDIT;
    let _ = consts::O_RDONLY;
    let _ = consts::O_WRONLY;
    let _ = consts::O_RDWR;
    let _ = consts::O_APPEND;
    let _ = consts::O_CLOEXEC;
}

#[test]
fn test_deprecated_constants_still_compile() {
    #[allow(deprecated)]
    {
        let _ = consts::FAN_ALL_CLASS_BITS;
        let _ = consts::FAN_ALL_INIT_FLAGS;
        let _ = consts::FAN_ALL_MARK_FLAGS;
        let _ = consts::FAN_ALL_EVENTS;
        let _ = consts::FAN_ALL_PERM_EVENTS;
        let _ = consts::FAN_ALL_OUTGOING_EVENTS;
    }
}

#[test]
fn test_mask_to_event_names_includes_new() {
    let names = consts::mask_to_event_names(
        consts::FAN_OPEN_PERM | consts::FAN_RENAME | consts::FAN_FS_ERROR,
    );
    assert!(names.contains(&"OPEN_PERM"));
    assert!(names.contains(&"RENAME"));
    assert!(names.contains(&"FS_ERROR"));
}

#[test]
fn test_composed_event_masks() {
    let close = consts::FAN_CLOSE;
    assert_eq!(close, consts::FAN_CLOSE_WRITE | consts::FAN_CLOSE_NOWRITE);

    let mv = consts::FAN_MOVE;
    assert_eq!(mv, consts::FAN_MOVED_FROM | consts::FAN_MOVED_TO);

    let dfid_name = consts::FAN_REPORT_DFID_NAME;
    assert_eq!(
        dfid_name,
        consts::FAN_REPORT_DIR_FID | consts::FAN_REPORT_NAME
    );
}
