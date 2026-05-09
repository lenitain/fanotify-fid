//! FAN_* constants from Linux kernel UAPI (`linux/fanotify.h`).
//!
//! Only the subset relevant to FID mode event parsing and file handle operations.

// ── fanotify_init flags ──

/// Default notification class: receive events after they happen (no permission
/// decision).  Use this unless you need `CONTENT` or `PRE_CONTENT`.
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;

/// Set close-on-exec flag on the fanotify file descriptor.
pub const FAN_CLOEXEC: u32 = 0x0000_0001;

/// Make the fanotify fd non-blocking; `read` returns `EAGAIN` when no events
/// are available.
pub const FAN_NONBLOCK: u32 = 0x0000_0002;

/// Report unique file identifier (file handle + fsid) instead of an open fd.
/// Required for FID mode.  Use together with `FAN_REPORT_DIR_FID` and
/// optionally `FAN_REPORT_NAME`.
pub const FAN_REPORT_FID: u32 = 0x0000_0200;

/// Report unique directory identifier for the parent directory.
/// Required when using `FAN_REPORT_NAME`.
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;

/// Report events with the name of the entry within the parent directory.
/// Requires `FAN_REPORT_DIR_FID`.
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;

// ── fanotify_mark flags ──

/// Add events to the mark mask.
pub const FAN_MARK_ADD: u32 = 0x0000_0001;

/// Remove events from the mark mask.
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;

/// Remove all marks from the fanotify group.
pub const FAN_MARK_FLUSH: u32 = 0x0000_0080;

/// Mark the whole filesystem containing the path.
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

/// Special dirfd value meaning "use the current working directory".
pub const AT_FDCWD: i32 = -100;

// ── Event masks (what happened) ──

/// File was accessed (read).
pub const FAN_ACCESS: u64 = 0x0000_0001;
/// File was modified (write).
pub const FAN_MODIFY: u64 = 0x0000_0002;
/// Metadata changed (permissions, timestamps, etc.).
pub const FAN_ATTRIB: u64 = 0x0000_0004;
/// Writable file was closed.
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
/// Read-only file or directory was closed.
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
/// File or directory was opened.
pub const FAN_OPEN: u64 = 0x0000_0020;
/// File was moved from a location (source of rename).
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
/// File was moved to a location (destination of rename).
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
/// File or directory was created.
pub const FAN_CREATE: u64 = 0x0000_0100;
/// File or directory was deleted.
pub const FAN_DELETE: u64 = 0x0000_0200;
/// The watched file or directory itself was deleted.
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;
/// The watched file or directory itself was moved.
pub const FAN_MOVE_SELF: u64 = 0x0000_0800;
/// File was opened for execution.
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;
/// Event queue overflowed — events were lost.
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
/// Event occurred against a directory (flag, not an event type).
pub const FAN_ONDIR: u64 = 0x4000_0000;
/// Only create events for immediate children (flag, not an event type).
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
/// Convenience mask: any close event.
pub const FAN_CLOSE: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
/// Convenience mask: any move event.
pub const FAN_MOVE: u64 = FAN_MOVED_FROM | FAN_MOVED_TO;

// ── fanotify_event_info_header.info_type values ──

/// Info record contains a file handle for the object itself.
pub const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
/// Info record contains a directory file handle + the entry name.
pub const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
/// Info record contains a directory file handle (no name).
pub const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;

/// Sentinel value: `metadata.fd` is set to this in FID mode, meaning no file
/// descriptor is provided.
pub const FAN_NOFD: i32 = -1;

/// Mapping from event mask bits to human-readable names.
///
/// Used by [`mask_to_event_names`].
pub const EVENT_NAMES: &[(u64, &str)] = &[
    (FAN_ACCESS, "ACCESS"),
    (FAN_MODIFY, "MODIFY"),
    (FAN_ATTRIB, "ATTRIB"),
    (FAN_CLOSE_WRITE, "CLOSE_WRITE"),
    (FAN_CLOSE_NOWRITE, "CLOSE_NOWRITE"),
    (FAN_OPEN, "OPEN"),
    (FAN_OPEN_EXEC, "OPEN_EXEC"),
    (FAN_MOVED_FROM, "MOVED_FROM"),
    (FAN_MOVED_TO, "MOVED_TO"),
    (FAN_CREATE, "CREATE"),
    (FAN_DELETE, "DELETE"),
    (FAN_DELETE_SELF, "DELETE_SELF"),
    (FAN_MOVE_SELF, "MOVE_SELF"),
];

/// Convert an event mask bitfield to a list of human-readable event name strings.
///
/// # Example
///
/// ```
/// use fanotify_fid::consts::*;
/// let names = mask_to_event_names(FAN_CREATE | FAN_MODIFY);
/// assert_eq!(names, vec!["MODIFY", "CREATE"]);
/// ```
pub fn mask_to_event_names(mask: u64) -> Vec<&'static str> {
    EVENT_NAMES
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}
