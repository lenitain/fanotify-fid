//! Error types for fanotify operations.

use std::fmt;
use std::io;

/// Error type for all fanotify operations.
///
/// Carries semantics: you can match on the variant to know which operation
/// failed, and get the raw OS error code and a human-readable description.
///
/// Each variant's `Display` implementation includes a multi-paragraph
/// man-page-level explanation of the error cause, common pitfalls, and
/// troubleshooting steps.
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
                crate::error_desc::errno_desc_init(*code)
            ),
            Self::Mark(code) => write!(
                f,
                "fanotify_mark failed (errno={}): {}",
                code,
                crate::error_desc::errno_desc_mark(*code)
            ),
            Self::Read(code) => write!(
                f,
                "fanotify_read failed (errno={}): {}",
                code,
                crate::error_desc::errno_desc_read(*code)
            ),
            Self::Handle(code) => write!(
                f,
                "file_handle operation failed (errno={}): {}",
                code,
                crate::error_desc::errno_desc_handle(*code)
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
