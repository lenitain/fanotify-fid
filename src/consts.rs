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
/// Report thread ID instead of process ID in events.
pub const FAN_REPORT_TID: u32 = 0x0000_0100;
/// Report pidfd for event->pid.
pub const FAN_REPORT_PIDFD: u32 = 0x0000_0080;
/// Report dirent target id (requires FAN_REPORT_DFID_NAME + FAN_REPORT_FID).
pub const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;
/// Remove the limit of 16384 events for the event queue (requires CAP_SYS_ADMIN).
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
/// Remove the limit of 8192 marks (requires CAP_SYS_ADMIN).
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
/// Enable audit log records for permission events.
pub const FAN_ENABLE_AUDIT: u32 = 0x0000_0040;
/// Notification class: receive permission events and access events.
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
/// Notification class: receive permission events before content is available.
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
/// Convenience: `FAN_REPORT_DIR_FID | FAN_REPORT_NAME`.
pub const FAN_REPORT_DFID_NAME: u32 = FAN_REPORT_DIR_FID | FAN_REPORT_NAME;
/// Convenience: all FID flags for full name + target ID reporting.
pub const FAN_REPORT_DFID_NAME_TARGET: u32 =
    FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID;

// ── fanotify_mark flags ──

/// Add events to the mark mask.
pub const FAN_MARK_ADD: u32 = 0x0000_0001;

/// Remove events from the mark mask.
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;

/// Remove all marks from the fanotify group.
pub const FAN_MARK_FLUSH: u32 = 0x0000_0080;

/// Mark the whole filesystem containing the path.
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;
/// If pathname is a symlink, mark the link itself, not the target.
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;
/// Require the marked object to be a directory (returns ENOTDIR otherwise).
pub const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;
/// Mark a mount point (all files under the mount are monitored).
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;
/// Add/remove events from the ignore mask instead of the mark mask.
pub const FAN_MARK_IGNORED_MASK: u32 = 0x0000_0020;
/// The ignore mask survives modify events (not cleared on modify).
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
/// Create an evictable inode mark (does not pin inode in cache).
pub const FAN_MARK_EVICTABLE: u32 = 0x0000_0200;
/// Modern replacement for FAN_MARK_IGNORED_MASK.
pub const FAN_MARK_IGNORE: u32 = 0x0000_0400;
/// Convenience: FAN_MARK_IGNORE with SURV_MODIFY for non-inode marks.
pub const FAN_MARK_IGNORE_SURV: u32 = FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY;

/// Special dirfd value meaning "use the current working directory".
pub const AT_FDCWD: i32 = -100;

// ── open(2) / event_f_flags values ──

/// Read-only access.
pub const O_RDONLY: u32 = 0;
/// Write-only access.
pub const O_WRONLY: u32 = 1;
/// Read-write access.
pub const O_RDWR: u32 = 2;
/// Append mode.
pub const O_APPEND: u32 = 0x400;
/// Non-blocking mode.
pub const O_NONBLOCK: u32 = 0x800;
/// Synchronized I/O data integrity.
pub const O_DSYNC: u32 = 0x1000;
/// Enable large file support (needed on 32-bit systems).
pub const O_LARGEFILE: u32 = 0x8000;
/// Do not update access time.
pub const O_NOATIME: u32 = 0x40000;
/// Set close-on-exec flag on the new fd.
pub const O_CLOEXEC: u32 = 0x80000;

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
/// Filesystem error event.
pub const FAN_FS_ERROR: u64 = 0x0000_8000;
/// Permission check on open.
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
/// Permission check on access.
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;
/// Permission check on exec open.
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
/// File was renamed.
pub const FAN_RENAME: u64 = 0x1000_0000;
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

// ── Permission response flags (for writing to fanotify fd) ──

/// Grant the requested file operation.
pub const FAN_ALLOW: u32 = 0x01;
/// Deny the requested file operation.
pub const FAN_DENY: u32 = 0x02;
/// Create an audit record for the response.
pub const FAN_AUDIT: u32 = 0x10;

/// Sentinel value: `metadata.fd` is set to this in FID mode, meaning no file
/// descriptor is provided.
pub const FAN_NOFD: i32 = -1;

// ── Deprecated constants (do not use in new code) ──

#[deprecated(note = "use FAN_CLASS_NOTIF / FAN_CLASS_CONTENT / FAN_CLASS_PRE_CONTENT instead")]
pub const FAN_ALL_CLASS_BITS: u32 = FAN_CLASS_NOTIF | FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;

#[allow(deprecated)]
#[deprecated(note = "use individual init flags instead")]
pub const FAN_ALL_INIT_FLAGS: u32 =
    FAN_CLOEXEC | FAN_NONBLOCK | FAN_ALL_CLASS_BITS | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS;

#[deprecated(note = "use individual mark flags instead")]
pub const FAN_ALL_MARK_FLAGS: u32 = FAN_MARK_ADD
    | FAN_MARK_REMOVE
    | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR
    | FAN_MARK_MOUNT
    | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY
    | FAN_MARK_FLUSH;

#[deprecated(note = "use individual event masks instead")]
pub const FAN_ALL_EVENTS: u64 = FAN_ACCESS | FAN_MODIFY | FAN_CLOSE | FAN_OPEN;

#[deprecated(note = "use individual permission masks instead")]
pub const FAN_ALL_PERM_EVENTS: u64 = FAN_OPEN_PERM | FAN_ACCESS_PERM;

#[allow(deprecated)]
#[deprecated(note = "use individual event masks instead")]
pub const FAN_ALL_OUTGOING_EVENTS: u64 = FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS | FAN_Q_OVERFLOW;

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
    (FAN_OPEN_PERM, "OPEN_PERM"),
    (FAN_ACCESS_PERM, "ACCESS_PERM"),
    (FAN_OPEN_EXEC_PERM, "OPEN_EXEC_PERM"),
    (FAN_RENAME, "RENAME"),
    (FAN_FS_ERROR, "FS_ERROR"),
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
