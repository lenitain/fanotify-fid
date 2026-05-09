//! # fanotify-fid
//!
//! Linux fanotify **FID (File Identifier) mode** event parser and file handle utilities.
//!
//! This crate fills the gap left by [`fanotify-rs`](https://crates.io/crates/fanotify-rs),
//! which only supports non-FID (legacy) event reading.  If you pass
//! `FAN_REPORT_FID` / `FAN_REPORT_DIR_FID` / `FAN_REPORT_NAME` to
//! `fanotify_init`, you **must** use this crate (or equivalent code) to
//! correctly parse the variable-length events.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use fanotify_fid::prelude::*;
//! use std::os::fd::OwnedFd;
//!
//! # fn open_mount(_: &str) -> OwnedFd { panic!() }
//!
//! // 1. Create fanotify group in FID mode
//! let fan = Fanotify::new()
//!     .nonblock()
//!     .report_fid()
//!     .report_dir_fid()
//!     .report_name()
//!     .init()
//!     .unwrap();
//!
//! // 2. Add marks (whole filesystem)
//! fan.mark(FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
//!          FAN_CREATE | FAN_DELETE | FAN_MODIFY,
//!          "/").unwrap();
//!
//! // 3. Open mount fds for handle resolution
//! let mount_fds = vec![open_mount("/")];
//!
//! // 4. Read events
//! let mut buf = Vec::with_capacity(65536);
//! let events = fan.read_events(&mount_fds, &mut buf, None).unwrap();
//!
//! for ev in &events {
//!     println!("{:?} {:?}", ev.event_names(), ev.path);
//! }
//! ```

pub mod consts;
pub mod handle;
pub mod parse;
pub mod read;
pub mod types;

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use crate::types::HandleCache;

/// Convenience re-exports for the most common types and constants.
pub mod prelude {
    pub use crate::consts::*;
    pub use crate::handle::{name_to_handle_at, open_by_handle_at, resolve_file_handle};
    pub use crate::parse::parse_fid_events;
    pub use crate::read::{read_fid_events, read_legacy, read_legacy_do, write_response};
    pub use crate::types::{FidEvent, HandleCache, HandleKey, LegacyEvent, FanotifyResponse};
    pub use crate::{fanotify_init, fanotify_mark, open_mount, Fanotify, FanotifyBuilder, FanotifyError};
}

// ── Error type ──

/// Error type for all fanotify operations.
///
/// Carries semantics: you can match on the variant to know which operation
/// failed, and get the raw OS error code and a human-readable description.
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
            Self::Init(code) => write!(f, "fanotify_init failed (errno={}): {}", code, errno_desc_init(*code)),
            Self::Mark(code) => write!(f, "fanotify_mark failed (errno={}): {}", code, errno_desc_mark(*code)),
            Self::Read(code) => write!(f, "fanotify_read failed (errno={}): {}", code, errno_desc_read(*code)),
            Self::Handle(code) => write!(f, "file_handle operation failed (errno={}): {}", code, errno_desc_handle(*code)),
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

fn errno_desc_init(code: i32) -> &'static str {
    match code {
        libc::EINVAL => "invalid flags or event_f_flags",
        libc::EMFILE => "too many fanotify groups for this user (max 128)",
        libc::ENOMEM => "out of memory",
        libc::ENOSYS => "kernel does not support fanotify (CONFIG_FANOTIFY missing)",
        libc::EPERM => "need CAP_SYS_ADMIN capability",
        _ => "unknown error",
    }
}

fn errno_desc_mark(code: i32) -> &'static str {
    match code {
        libc::EBADF => "invalid file descriptor",
        libc::EINVAL => "invalid flags or mask, or wrong notification class",
        libc::ENOENT => "path does not exist",
        libc::ENOMEM => "out of memory",
        libc::ENOSPC => "too many marks (exceeded 8192 limit)",
        libc::ENOTDIR => "FAN_MARK_ONLYDIR but path is not a directory",
        _ => "unknown error",
    }
}

fn errno_desc_read(code: i32) -> &'static str {
    match code {
        libc::EAGAIN => "no events available (non-blocking fd)",
        libc::EBADF => "invalid file descriptor",
        libc::EINTR => "interrupted by signal",
        libc::ENOMEM => "out of memory",
        _ => "unknown error",
    }
}

fn errno_desc_handle(code: i32) -> &'static str {
    match code {
        libc::EBADF => "invalid mount file descriptor",
        libc::ENOENT => "file or directory does not exist (may have been deleted)",
        libc::EINVAL => "invalid handle or flags",
        libc::EOVERFLOW => "handle buffer too small",
        libc::EOPNOTSUPP => "filesystem does not support file handles",
        _ => "unknown error",
    }
}

// Convenience alias.
/// Alias for `Result<T, FanotifyError>`.
pub type Result<T> = std::result::Result<T, FanotifyError>;

// ── High-level Fanotify wrapper ──

/// An RAII fanotify file descriptor with safe `mark` and `read_events`
/// methods.
///
/// The underlying `OwnedFd` is automatically closed on `Drop`.
///
/// Use [`FanotifyBuilder`] (via [`Fanotify::new`]) for ergonomic construction:
///
/// ```rust,no_run
/// use fanotify_fid::prelude::*;
///
/// let fan = Fanotify::new()
///     .report_fid()
///     .report_dir_fid()
///     .report_name()
///     .init()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct Fanotify {
    fd: OwnedFd,
}

impl Fanotify {
    /// Create a [`FanotifyBuilder`] with default settings
    /// (`FAN_CLASS_NOTIF | FAN_CLOEXEC`).
    ///
    /// Call `.init()` on the builder to create the fanotify group.
    pub fn new() -> FanotifyBuilder {
        FanotifyBuilder {
            flags: consts::FAN_CLASS_NOTIF | consts::FAN_CLOEXEC,
            event_f_flags: 0,
        }
    }

    /// Add or remove a mark on the given path.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use fanotify_fid::prelude::*;
    ///
    /// let fan = Fanotify::new().report_fid().init().unwrap();
    /// fan.mark(FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
    ///          FAN_CREATE | FAN_DELETE, "/").unwrap();
    /// ```
    pub fn mark<P: AsRef<OsStr> + ?Sized>(
        &self,
        flags: u32,
        mask: u64,
        path: &P,
    ) -> std::result::Result<(), FanotifyError> {
        fanotify_mark(&self.fd, flags, mask, consts::AT_FDCWD, path)
    }

    /// Read and parse FID-format events from the fanotify file descriptor.
    ///
    /// Convenience wrapper around [`read_fid_events`] that takes `&self`.
    ///
    /// See [`read_fid_events`] for full documentation.
    pub fn read_events(
        &self,
        mount_fds: &[OwnedFd],
        buf: &mut Vec<u8>,
        cache: Option<&mut HandleCache>,
    ) -> std::result::Result<Vec<crate::types::FidEvent>, FanotifyError> {
        crate::read::read_fid_events(&self.fd, mount_fds, buf, cache)
    }

    /// Read legacy (non-FID) events.
    ///
    /// The fanotify fd must NOT have been initialized with `FAN_REPORT_FID`.
    pub fn read_legacy(&self) -> Result<Vec<crate::types::LegacyEvent>> {
        crate::read::read_legacy(&self.fd)
    }

    /// Read legacy events with a callback.
    ///
    /// Convenience wrapper around [`read_legacy_do`](crate::read::read_legacy_do).
    pub fn read_legacy_do<F>(&self, callback: F) -> Result<()>
    where
        F: FnMut(&crate::types::LegacyEvent),
    {
        crate::read::read_legacy_do(&self.fd, callback)
    }

    /// Write a permission response.
    ///
    /// Convenience wrapper around [`write_response`](crate::read::write_response).
    pub fn send_response(&self, response: &crate::types::FanotifyResponse) -> Result<()> {
        crate::read::write_response(&self.fd, response)
    }

    /// Add a mark on a mount point (monitor all files under it).
    pub fn mark_mount<P: AsRef<OsStr> + ?Sized>(
        &self,
        mask: u64,
        path: &P,
    ) -> Result<()> {
        fanotify_mark(
            &self.fd,
            crate::consts::FAN_MARK_ADD | crate::consts::FAN_MARK_MOUNT,
            mask,
            crate::consts::AT_FDCWD,
            path,
        )
    }

    /// Get a reference to the underlying `OwnedFd`.
    pub fn as_fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// Consume the wrapper and return the raw file descriptor.
    ///
    /// The fd will be closed when `OwnedFd` is dropped.
    pub fn into_inner(self) -> OwnedFd {
        self.fd
    }
}

impl AsFd for Fanotify {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

// ── Builder ──

/// Builder for [`Fanotify`].
///
/// Created via [`Fanotify::new()`].
#[derive(Debug, Clone)]
pub struct FanotifyBuilder {
    flags: u32,
    event_f_flags: u32,
}

impl FanotifyBuilder {
    /// Enable close-on-exec (always on by default).
    pub fn cloexec(mut self) -> Self {
        self.flags |= consts::FAN_CLOEXEC;
        self
    }

    /// Make the fanotify fd non-blocking.
    pub fn nonblock(mut self) -> Self {
        self.flags |= consts::FAN_NONBLOCK;
        self
    }

    /// Set notification class to `FAN_CLASS_NOTIF` (default).
    pub fn class_notif(mut self) -> Self {
        self.flags = (self.flags & !0x0C) | consts::FAN_CLASS_NOTIF;
        self
    }

    /// Set notification class to `FAN_CLASS_CONTENT` (for permission events).
    pub fn class_content(mut self) -> Self {
        self.flags = (self.flags & !0x0C) | 0x0000_0004;
        self
    }

    /// Set notification class to `FAN_CLASS_PRE_CONTENT`.
    pub fn class_pre_content(mut self) -> Self {
        self.flags = (self.flags & !0x0C) | 0x0000_0008;
        self
    }

    /// Report file identifiers (file handles) instead of file descriptors.
    pub fn report_fid(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_FID;
        self
    }

    /// Report parent directory identifiers.
    pub fn report_dir_fid(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_DIR_FID;
        self
    }

    /// Report entry names in parent directory events.
    pub fn report_name(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_NAME;
        self
    }

    /// Report thread ID instead of process ID.
    pub fn report_tid(mut self) -> Self {
        self.flags |= 0x0000_0100;
        self
    }

    /// Remove event queue size limit (needs `CAP_SYS_ADMIN`).
    pub fn unlimited_queue(mut self) -> Self {
        self.flags |= 0x0000_0010;
        self
    }

    /// Remove mark count limit (needs `CAP_SYS_ADMIN`).
    pub fn unlimited_marks(mut self) -> Self {
        self.flags |= 0x0000_0020;
        self
    }

    /// Set event_f_flags (flags for opened event fds).
    ///
    /// In FID mode, the fanotify fd doesn't produce event fds, so this
    /// is typically 0.
    pub fn event_flags(mut self, flags: u32) -> Self {
        self.event_f_flags = flags;
        self
    }

    /// Enable audit logging for permission events.
    pub fn enable_audit(mut self) -> Self {
        self.flags |= crate::consts::FAN_ENABLE_AUDIT;
        self
    }

    /// Report pidfd for event->pid.
    pub fn report_pidfd(mut self) -> Self {
        self.flags |= crate::consts::FAN_REPORT_PIDFD;
        self
    }

    /// Report dirent target id.
    pub fn report_target_fid(mut self) -> Self {
        self.flags |= crate::consts::FAN_REPORT_TARGET_FID;
        self
    }

    /// Add arbitrary raw flags.
    pub fn raw_flags(mut self, flags: u32) -> Self {
        self.flags |= flags;
        self
    }

    /// Create the fanotify group.  Returns a [`Fanotify`] handle on success.
    ///
    /// See [`fanotify_init`] for error details.
    pub fn init(self) -> std::result::Result<Fanotify, FanotifyError> {
        let fd = fanotify_init(self.flags, self.event_f_flags)?;
        Ok(Fanotify { fd })
    }
}

impl Default for FanotifyBuilder {
    fn default() -> Self {
        FanotifyBuilder {
            flags: consts::FAN_CLASS_NOTIF | consts::FAN_CLOEXEC,
            event_f_flags: 0,
        }
    }
}

// ── Low-level wrappers ──

/// Thin safe wrapper around `fanotify_init` (raw syscall).
///
/// Returns an `OwnedFd` that will be automatically closed on drop.
///
/// Provided for convenience when you prefer free functions over the
/// [`Fanotify`] struct.
pub fn fanotify_init(flags: u32, event_f_flags: u32) -> std::result::Result<OwnedFd, FanotifyError> {
    // SAFETY: trivially safe — just passes flags to the kernel.
    let fd = unsafe { libc::fanotify_init(flags as libc::c_uint, event_f_flags as libc::c_uint) };
    if fd < 0 {
        return Err(FanotifyError::Init(io::Error::last_os_error().raw_os_error().unwrap_or(0)));
    }
    // SAFETY: we just successfully created this fd and it is owned.
    Ok(unsafe { <OwnedFd as FromRawFd>::from_raw_fd(fd) })
}

/// Thin safe wrapper around `fanotify_mark` (raw syscall).
///
/// `path` can be a `&Path`, `&str`, or anything `AsRef<OsStr>`.
pub fn fanotify_mark<P: AsRef<OsStr> + ?Sized>(
    fanotify_fd: &OwnedFd,
    flags: u32,
    mask: u64,
    dirfd: i32,
    path: &P,
) -> std::result::Result<(), FanotifyError> {
    let mut raw = path.as_ref().as_bytes().to_vec();
    raw.push(0); // null-terminate

    // SAFETY: trivially safe — passes validated args to the kernel.
    let ret = unsafe {
        libc::fanotify_mark(
            fanotify_fd.as_raw_fd() as i32,
            flags as libc::c_uint,
            mask,
            dirfd,
            raw.as_ptr() as *const libc::c_char,
        )
    };
    if ret < 0 {
        return Err(FanotifyError::Mark(io::Error::last_os_error().raw_os_error().unwrap_or(0)));
    }
    Ok(())
}

/// Open a path with `O_PATH` to obtain a mount fd for handle resolution.
///
/// The returned `OwnedFd` is opened with `O_PATH | O_CLOEXEC`, and can be
/// used with [`resolve_file_handle`] and [`read_fid_events`].
///
/// This is equivalent to `open(path, O_PATH | O_CLOEXEC)`.
///
/// # Errors
///
/// Returns `FanotifyError::Io` if the path cannot be opened (permissions,
/// does not exist, etc.).
pub fn open_mount<P: AsRef<OsStr> + ?Sized>(path: &P) -> std::result::Result<OwnedFd, FanotifyError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .read(true)
        .open(path.as_ref())
        .map_err(FanotifyError::Io)?;
    let fd = file.into();
    Ok(fd)
}
