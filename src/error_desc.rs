//! Error description helpers for fanotify operations.
//!
//! Each function maps an errno code to a concise diagnostic string.

use std::borrow::Cow;

/// Error description for `fanotify_init` failures.
pub fn errno_desc_init(code: i32) -> Cow<'static, str> {
    match code {
        libc::EINVAL => {
            Cow::Borrowed("Invalid flags — check FAN_REPORT_NAME requires FAN_REPORT_DIR_FID")
        }
        libc::EMFILE => Cow::Borrowed("Too many fanotify groups (per-user limit: 128)"),
        libc::ENOMEM => Cow::Borrowed("Out of memory"),
        libc::ENOSYS => Cow::Borrowed("Kernel does not support fanotify (CONFIG_FANOTIFY missing)"),
        libc::EPERM => Cow::Borrowed("Need CAP_SYS_ADMIN capability"),
        _ => Cow::Owned(format!(
            "Unknown error (errno={}).  See fanotify_init(2) for details.",
            code
        )),
    }
}

/// Error description for `fanotify_mark` failures.
pub fn errno_desc_mark(code: i32) -> Cow<'static, str> {
    match code {
        libc::EBADF => Cow::Borrowed("Invalid file descriptor"),
        libc::EINVAL => Cow::Borrowed("Invalid flags or mask, or wrong notification class"),
        libc::ENODEV => Cow::Borrowed("Filesystem does not support fsid"),
        libc::ENOENT => Cow::Borrowed("Path does not exist"),
        libc::ENOMEM => Cow::Borrowed("Out of memory"),
        libc::ENOSPC => Cow::Borrowed("Too many marks (exceeded 8192 limit)"),
        libc::ENOSYS => Cow::Borrowed("Kernel does not implement fanotify_mark"),
        libc::ENOTDIR => Cow::Borrowed("FAN_MARK_ONLYDIR specified but path is not a directory"),
        libc::EOPNOTSUPP => Cow::Borrowed("Filesystem does not support file handles"),
        libc::EXDEV => Cow::Borrowed("Filesystem subvolume uses a different fsid"),
        _ => Cow::Owned(format!(
            "Unknown error (errno={}).  See fanotify_mark(2) for details.",
            code
        )),
    }
}

/// Error description for event read failures.
pub fn errno_desc_read(code: i32) -> Cow<'static, str> {
    match code {
        libc::EAGAIN => Cow::Borrowed("No events available (non-blocking fd)"),
        libc::EBADF => Cow::Borrowed("Invalid file descriptor"),
        libc::EINTR => Cow::Borrowed("Interrupted by signal — retry"),
        libc::ENOMEM => Cow::Borrowed("Out of memory"),
        _ => Cow::Owned(format!(
            "Unknown error (errno={}).  See fanotify_read(2) for details.",
            code
        )),
    }
}

/// Error description for `open_by_handle_at` failures.
pub fn errno_desc_handle(code: i32) -> Cow<'static, str> {
    match code {
        libc::EBADF => Cow::Borrowed("Invalid mount file descriptor"),
        libc::ENOENT => Cow::Borrowed("File or directory does not exist (deleted or handle stale)"),
        libc::EINVAL => Cow::Borrowed("Invalid handle or flags"),
        libc::EOVERFLOW => Cow::Borrowed("Handle buffer too small"),
        libc::EOPNOTSUPP => Cow::Borrowed("Filesystem does not support file handles"),
        _ => Cow::Owned(format!(
            "Unknown error (errno={}).  See name_to_handle_at(2) for details.",
            code
        )),
    }
}
