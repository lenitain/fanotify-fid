//! Error types for fanotify operations.

use std::borrow::Cow;
use std::fmt;
use std::io;

/// Error type for all fanotify operations.
///
/// Carries semantics: you can match on the variant to know which operation
/// failed, and get the raw OS error code and a human-readable description.
///
/// Each variant's `Display` implementation includes a concise diagnostic
/// message explaining the cause and how to fix it.
///
/// This type is `Send + Sync`.
#[derive(Debug)]
pub enum FanotifyError {
    /// `fanotify_init` failed.
    Init(i32),
    /// `fanotify_mark` failed.
    Mark(i32),
    /// `read` on the fanotify fd failed.
    Read(i32),
    /// File handle resolution failed (via `open_by_handle_at` or
    /// `name_to_handle_at`).
    Handle(i32),
    /// Generic I/O error from internal operations (path resolution, etc.).
    Io(io::Error),
}

impl fmt::Display for FanotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(code) => write!(
                f,
                "fanotify_init failed (errno={}): {}",
                code,
                errno_desc_init(*code)
            ),
            Self::Mark(code) => write!(
                f,
                "fanotify_mark failed (errno={}): {}",
                code,
                errno_desc_mark(*code)
            ),
            Self::Read(code) => write!(
                f,
                "fanotify_read failed (errno={}): {}",
                code,
                errno_desc_read(*code)
            ),
            Self::Handle(code) => write!(
                f,
                "file_handle operation failed (errno={}): {}",
                code,
                errno_desc_handle(*code)
            ),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for FanotifyError {}

impl From<io::Error> for FanotifyError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Alias for `Result<T, FanotifyError>`.
pub type Result<T> = std::result::Result<T, FanotifyError>;

// ── Error description helpers ──

/// Error description for `fanotify_init` failures.
fn errno_desc_init(code: i32) -> Cow<'static, str> {
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
fn errno_desc_mark(code: i32) -> Cow<'static, str> {
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
fn errno_desc_read(code: i32) -> Cow<'static, str> {
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
fn errno_desc_handle(code: i32) -> Cow<'static, str> {
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
