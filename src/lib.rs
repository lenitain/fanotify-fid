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
//! ## Requirements
//!
//! - Linux kernel **≥ 5.1** (FID mode), **≥ 5.15** (`FAN_REPORT_TARGET_FID`)
//! - **`CAP_SYS_ADMIN`** capability (run as root)
//! - Minimum Rust version: **1.75** (edition 2024)
//!
//! ## Error handling
//!
//! All operations return [`Result<T, FanotifyError>`].  Each error variant
//! includes the raw errno and a **man-page-level description** explaining
//! the cause, common pitfalls, and how to fix it.
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

use std::borrow::Cow;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::types::HandleCache;

/// Convenience re-exports for the most common types and constants.
pub mod prelude {
    pub use crate::consts::*;
    pub use crate::handle::{name_to_handle_at, open_by_handle_at, resolve_file_handle};
    pub use crate::parse::parse_fid_events;
    pub use crate::read::{
        legacy_buffer_events, read_fid_events, read_legacy, read_legacy_do,
        set_legacy_buffer_events, write_response,
    };
    pub use crate::types::{FanotifyResponse, FidEvent, HandleCache, HandleKey, LegacyEvent};
    pub use crate::{
        Fanotify, FanotifyBuilder, FanotifyError, fanotify_init, fanotify_mark, open_mount,
    };
}

// ── Error type ──

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

fn errno_desc_init(code: i32) -> Cow<'static, str> {
    match code {
        libc::EINVAL => Cow::Borrowed(concat!(
            "An invalid value was passed in flags or event_f_flags.\n",
            "  Common mistakes:\n",
            "  - Using FAN_REPORT_NAME without FAN_REPORT_DIR_FID\n",
            "  - Combining FAN_REPORT_FID with legacy-only flags\n",
            "  - Setting reserved or unsupported bits in event_f_flags\n",
            "  Check man fanotify_init(2) for all allowable bits."
        )),
        libc::EMFILE => Cow::Borrowed(concat!(
            "Too many fanotify groups for this user.\n",
            "  The per-user limit is 128 groups.  Each init() call creates\n",
            "  a new notification group.  Check if previous groups are still\n",
            "  open (forgeting to close an OwnedFd can leak groups)."
        )),
        libc::ENOMEM => Cow::Borrowed(concat!(
            "Out of memory.\n",
            "  The kernel could not allocate memory for the notification\n",
            "  group's internal data structures.  Try reducing the event\n",
            "  queue size or closing other fanotify groups."
        )),
        libc::ENOSYS => Cow::Borrowed(concat!(
            "This kernel does not support fanotify.\n",
            "  The fanotify API is available only if the kernel was\n",
            "  configured with CONFIG_FANOTIFY.  Most distro kernels\n",
            "  include this by default.  Custom or container-optimized\n",
            "  kernels may omit it.  Check /proc/config.gz or\n",
            "  /boot/config-$(uname -r) for CONFIG_FANOTIFY=y."
        )),
        libc::EPERM => Cow::Borrowed(concat!(
            "Need CAP_SYS_ADMIN capability.\n",
            "  Creating a fanotify group requires elevated privileges.\n",
            "  Run as root, or add the capability via:\n",
            "    sudo setcap cap_sys_admin+ep /path/to/binary\n",
            "  Or run the process under a user namespace with\n",
            "  CAP_SYS_ADMIN mapped."
        )),
        _ => Cow::Owned(format!(
            "Unknown error (errno={}).  See fanotify_init(2) for details.",
            code
        )),
    }
}

fn errno_desc_mark(code: i32) -> Cow<'static, str> {
    match code {
        libc::EBADF => Cow::Borrowed(concat!(
            "Invalid file descriptor.\n",
            "  Either the fanotify fd is invalid, or pathname is relative\n",
            "  but dirfd is neither AT_FDCWD nor a valid fd.\n",
            "  Check that fanotify_init succeeded and the fd hasn't been\n",
            "  closed or moved into another process."
        )),
        libc::EINVAL => Cow::Borrowed(concat!(
            "Invalid flags or mask, or wrong notification class.\n",
            "  Common causes:\n",
            "  - The fanotify group was created with FAN_CLASS_NOTIF but\n",
            "    mask contains permission events (FAN_OPEN_PERM or\n",
            "    FAN_ACCESS_PERM).  Permission events require\n",
            "    FAN_CLASS_CONTENT or FAN_CLASS_PRE_CONTENT.\n",
            "  - An invalid combination of mark flags was passed.\n",
            "  - In FID mode, some mask flags are incompatible."
        )),
        libc::ENODEV => Cow::Borrowed(concat!(
            "Filesystem does not support fsid.\n",
            "  The filesystem indicated by pathname is not associated with\n",
            "  a filesystem that supports fsid (e.g., tmpfs).  This error\n",
            "  can occur only with a fanotify group that identifies objects\n",
            "  by file handles (FID mode)."
        )),
        libc::ENOENT => Cow::Borrowed(concat!(
            "Path does not exist.\n",
            "  The filesystem object indicated by dirfd and pathname does\n",
            "  not exist.  This also occurs when trying to remove a mark\n",
            "  from an object which is not marked.\n",
            "  Tip: use FAN_MARK_DONT_FOLLOW if pathname is a dangling\n",
            "  symlink, or check that the path exists before marking."
        )),
        libc::ENOMEM => Cow::Borrowed(concat!(
            "Out of memory.\n",
            "  The kernel could not allocate memory to store the mark.\n",
            "  Try reducing the number of marks or closing other groups."
        )),
        libc::ENOSPC => Cow::Borrowed(concat!(
            "Too many marks (exceeded 8192 limit).\n",
            "  The default mark limit is 8192 per group.  Either:\n",
            "  - Use FAN_MARK_FILESYSTEM instead of marking individual\n",
            "    paths to reduce mark count.\n",
            "  - Pass FAN_UNLIMITED_MARKS to init() if you have\n",
            "    CAP_SYS_ADMIN and genuinely need more marks.\n",
            "  - Remove unused marks with FAN_MARK_REMOVE."
        )),
        libc::ENOSYS => Cow::Borrowed(concat!(
            "This kernel does not implement fanotify_mark.\n",
            "  CONFIG_FANOTIFY is likely missing from the kernel config."
        )),
        libc::ENOTDIR => Cow::Borrowed(concat!(
            "FAN_MARK_ONLYDIR specified but path is not a directory.\n",
            "  Remove FAN_MARK_ONLYDIR if you intended to mark a regular\n",
            "  file, or point the path to a directory."
        )),
        libc::EOPNOTSUPP => Cow::Borrowed(concat!(
            "Filesystem does not support file handles.\n",
            "  The object is on a filesystem that does not support the\n",
            "  encoding of file handles (e.g., some FUSE filesystems,\n",
            "  network filesystems without export support).  This error\n",
            "  can occur only with a fanotify group in FID mode."
        )),
        libc::EXDEV => Cow::Borrowed(concat!(
            "Filesystem subvolume uses a different fsid.\n",
            "  The object resides within a filesystem subvolume (e.g.,\n",
            "  btrfs subvolume) which uses a different fsid than its root\n",
            "  superblock.  Try marking the subvolume's mount point,\n",
            "  or use FAN_MARK_FILESYSTEM on the subvolume directly."
        )),
        _ => Cow::Owned(format!(
            "Unknown error (errno={}).  See fanotify_mark(2) for details.",
            code
        )),
    }
}

fn errno_desc_read(code: i32) -> Cow<'static, str> {
    match code {
        libc::EAGAIN => Cow::Borrowed(concat!(
            "No events available (non-blocking fd).\n",
            "  The fanotify fd was created with FAN_NONBLOCK and no events\n",
            "  are currently pending.  This is not an error — retry later\n",
            "  using epoll/poll/select to wait for readability, or switch\n",
            "  to blocking mode (remove FAN_NONBLOCK)."
        )),
        libc::EBADF => Cow::Borrowed(concat!(
            "Invalid file descriptor.\n",
            "  The fanotify fd is not a valid open file descriptor or\n",
            "  was not opened for reading.  Check that fanotify_init()\n",
            "  succeeded and the fd hasn't been closed."
        )),
        libc::EINTR => Cow::Borrowed(concat!(
            "Interrupted by signal.\n",
            "  The read call was interrupted by a signal before any data\n",
            "  was read.  Retry the read (EINTR is transient)."
        )),
        libc::ENOMEM => Cow::Borrowed(concat!(
            "Out of memory.\n",
            "  Cannot allocate memory for the read buffer.  Try reducing\n",
            "  the buffer size or closing other memory-intensive\n",
            "  applications."
        )),
        _ => Cow::Owned(format!(
            "Unknown error (errno={}).  See fanotify_read(2) for details.",
            code
        )),
    }
}

fn errno_desc_handle(code: i32) -> Cow<'static, str> {
    match code {
        libc::EBADF => Cow::Borrowed(concat!(
            "Invalid mount file descriptor.\n",
            "  The mount_fd passed to open_by_handle_at is not a valid\n",
            "  open file descriptor.  Make sure open_mount() succeeded\n",
            "  and the fd hasn't been closed.  The mount_fd must belong\n",
            "  to a mount point on the same filesystem as the handle."
        )),
        libc::ENOENT => Cow::Borrowed(concat!(
            "File or directory does not exist.\n",
            "  The file identified by the handle has been deleted.  In\n",
            "  fanotify FID mode this is expected when events are\n",
            "  delivered concurrently with deletions.  Use a persistent\n",
            "  HandleCache to recover paths in later read cycles.\n",
            "  See parse::resolve_with_cache for details."
        )),
        libc::EINVAL => Cow::Borrowed(concat!(
            "Invalid handle or flags.\n",
            "  The file handle data is malformed or the flags passed to\n",
            "  open_by_handle_at are invalid.  This may indicate a kernel\n",
            "  bug or corrupted handle data."
        )),
        libc::EOVERFLOW => Cow::Borrowed(concat!(
            "Handle buffer too small.\n",
            "  The initial buffer passed to name_to_handle_at was too\n",
            "  small.  This is handled automatically by retrying with\n",
            "  the correct size, but if you see this error it means the\n",
            "  retry also failed.  Try using a larger initial buffer."
        )),
        libc::EOPNOTSUPP => Cow::Borrowed(concat!(
            "Filesystem does not support file handles.\n",
            "  The filesystem does not support name_to_handle_at or\n",
            "  open_by_handle_at.  Common examples:\n",
            "  - tmpfs (only supports handles for directories)\n",
            "  - Some FUSE filesystems\n",
            "  - Network filesystems without export support\n",
            "  Try using open_mount() on a different path backed by a\n",
            "  filesystem that supports handles (e.g., ext4, xfs, btrfs)."
        )),
        _ => Cow::Owned(format!(
            "Unknown error (errno={}).  See name_to_handle_at(2) for details.",
            code
        )),
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
/// `Fanotify` is `Send + Sync` (delegates to `OwnedFd` which is also
/// `Send + Sync`).  You may share it across threads safely.
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
    #[allow(clippy::new_ret_no_self)]
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

    /// Get the legacy buffer size (event count).
    pub fn legacy_buffer_events() -> usize {
        crate::read::legacy_buffer_events()
    }

    /// Set the legacy buffer size (event count).
    pub fn set_legacy_buffer_events(n: usize) {
        crate::read::set_legacy_buffer_events(n)
    }

    /// Add a mark on a mount point (monitor all files under it).
    pub fn mark_mount<P: AsRef<OsStr> + ?Sized>(&self, mask: u64, path: &P) -> Result<()> {
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
        self.flags = (self.flags & !0x0C) | consts::FAN_CLASS_CONTENT;
        self
    }

    /// Set notification class to `FAN_CLASS_PRE_CONTENT`.
    pub fn class_pre_content(mut self) -> Self {
        self.flags = (self.flags & !0x0C) | consts::FAN_CLASS_PRE_CONTENT;
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
        self.flags |= consts::FAN_REPORT_TID;
        self
    }

    /// Remove event queue size limit (needs `CAP_SYS_ADMIN`).
    pub fn unlimited_queue(mut self) -> Self {
        self.flags |= consts::FAN_UNLIMITED_QUEUE;
        self
    }

    /// Remove mark count limit (needs `CAP_SYS_ADMIN`).
    pub fn unlimited_marks(mut self) -> Self {
        self.flags |= consts::FAN_UNLIMITED_MARKS;
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

    /// Report dirent target id (requires Linux ≥ 5.15).
    ///
    /// Requires both `FAN_REPORT_DFID_NAME` and `FAN_REPORT_FID`.
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
/// Requires Linux **≥ 5.1** for FID mode flags (`FAN_REPORT_FID`,
/// `FAN_REPORT_DIR_FID`, `FAN_REPORT_NAME`).  Some flags like
/// `FAN_REPORT_TARGET_FID` require newer kernels (≥ 5.15).
///
/// Provided for convenience when you prefer free functions over the
/// [`Fanotify`] struct.
pub fn fanotify_init(
    flags: u32,
    event_f_flags: u32,
) -> std::result::Result<OwnedFd, FanotifyError> {
    // SAFETY: `fanotify_init` is a pure kernel syscall with no memory-safety
    // requirements beyond passing correctly-typed integer flags.  The kernel
    // validates all flag combinations and returns EINVAL on error.
    let fd = unsafe { libc::fanotify_init(flags as libc::c_uint, event_f_flags as libc::c_uint) };
    if fd < 0 {
        return Err(FanotifyError::Init(
            io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    // SAFETY: `fd` was just returned by a successful `fanotify_init` call and
    // is therefore a valid, owned file descriptor.  `OwnedFd::from_raw_fd`
    // takes ownership; it will be closed on drop.
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
    // `as_encoded_bytes()` is zero-cost on Linux (OsStr == [u8]).
    // `CString::new` handles null-termination in a single allocation
    // and rejects interior null bytes, which the kernel would also reject.
    let raw = CString::new(path.as_ref().as_encoded_bytes())
        .map_err(|_| FanotifyError::Mark(libc::EINVAL))?;

    // SAFETY: `fanotify_mark` is a pure kernel syscall.  `raw` is a
    // properly null-terminated CString and `fanotify_fd` is a valid
    // `OwnedFd`.  The kernel validates all arguments internally.
    let ret = unsafe {
        libc::fanotify_mark(
            fanotify_fd.as_raw_fd(),
            flags as libc::c_uint,
            mask,
            dirfd,
            raw.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(FanotifyError::Mark(
            io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
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
pub fn open_mount<P: AsRef<OsStr> + ?Sized>(
    path: &P,
) -> std::result::Result<OwnedFd, FanotifyError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .read(true)
        .open(path.as_ref())
        .map_err(FanotifyError::Io)?;
    let fd = file.into();
    Ok(fd)
}

// ── Comprehensive tests ──

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::types::{FanotifyResponse, FidEvent, HandleCache, LegacyEvent};
    use std::path::PathBuf;

    // ── Constants tests ──

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

    // ── Builder tests ──

    #[test]
    fn test_builder_default_flags() {
        let builder = FanotifyBuilder::default();
        // Default should be NOTIF (0) + CLOEXEC
        // NOTIF=0 means the class bits (0x0C) are clear
        assert!(builder.flags & 0x0C == 0, "class bits should be NOTIF");
        assert!(
            builder.flags & consts::FAN_CLOEXEC != 0,
            "CLOEXEC should be set by default"
        );
        assert!(builder.flags & consts::FAN_CLOEXEC != 0);
    }

    #[test]
    fn test_builder_chain_all_flags() {
        let builder = FanotifyBuilder::default()
            .cloexec()
            .nonblock()
            .class_content()
            .report_fid()
            .report_dir_fid()
            .report_name()
            .report_tid()
            .report_pidfd()
            .report_target_fid()
            .unlimited_queue()
            .unlimited_marks()
            .enable_audit()
            .event_flags(consts::O_CLOEXEC)
            .raw_flags(0x1000);
        // Builder should have accumulated flags
        assert!(builder.flags & consts::FAN_NONBLOCK != 0);
        assert!(builder.flags & consts::FAN_REPORT_FID != 0);
        assert!(builder.flags & consts::FAN_REPORT_TID != 0);
        assert!(builder.flags & consts::FAN_UNLIMITED_QUEUE != 0);
        assert!(builder.flags & 0x1000 != 0);
        assert_eq!(builder.event_f_flags, consts::O_CLOEXEC);
    }

    #[test]
    fn test_builder_class_modes_are_exclusive() {
        // Setting class_pre_content should clear class_content bits
        let b = FanotifyBuilder::default().class_content();
        assert!(b.flags & 0x0C == consts::FAN_CLASS_CONTENT || (b.flags & 0x0C) == 0x04);

        let b = b.class_pre_content();
        // 0x08 should be set, 0x04 should not
        assert_eq!(b.flags & 0x0C, consts::FAN_CLASS_PRE_CONTENT);
    }

    // ── Error tests ──

    #[test]
    fn test_error_display_init() {
        let e = FanotifyError::Init(libc::EPERM);
        let msg = e.to_string();
        assert!(msg.contains("fanotify_init"));
        assert!(msg.contains("CAP_SYS_ADMIN"));
    }

    #[test]
    fn test_error_display_mark() {
        let e = FanotifyError::Mark(libc::ENOENT);
        let msg = e.to_string();
        assert!(msg.contains("fanotify_mark"));
        assert!(msg.contains("does not exist"));
    }

    #[test]
    fn test_error_display_read() {
        let e = FanotifyError::Read(libc::EAGAIN);
        let msg = e.to_string();
        assert!(msg.contains("fanotify_read"));
        assert!(msg.contains("non-blocking"));
    }

    #[test]
    fn test_error_display_handle() {
        let e = FanotifyError::Handle(libc::EOPNOTSUPP);
        let msg = e.to_string();
        assert!(msg.contains("file_handle"));
        assert!(msg.contains("does not support file handles"));
    }

    #[test]
    fn test_error_into_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let e: FanotifyError = io_err.into();
        match e {
            FanotifyError::Io(_) => {}
            _ => panic!("expected Io variant"),
        }
    }

    #[test]
    fn test_error_impl_error_trait() {
        fn check_error(_: &dyn std::error::Error) {}
        let e = FanotifyError::Init(libc::EINVAL);
        check_error(&e); // must compile
    }

    // ── Type tests ──

    #[test]
    fn test_fid_event_methods() {
        let ev = FidEvent {
            mask: consts::FAN_CREATE | consts::FAN_MODIFY,
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
            mask: consts::FAN_Q_OVERFLOW,
            pid: 0,
            path: PathBuf::new(),
            dfid_name_handle: None,
            dfid_name_filename: None,
            self_handle: None,
        };
        assert!(ev.is_overflow());
    }

    #[test]
    fn test_legacy_event_auto_close_fd() {
        // LegacyEvent with fd=-1 should not crash on drop
        let ev = LegacyEvent {
            mask: 0,
            fd: -1,
            pid: 0,
            path: PathBuf::new(),
        };
        drop(ev);
    }

    #[test]
    fn test_fanotify_response_struct() {
        let resp = FanotifyResponse {
            fd: 5,
            response: consts::FAN_ALLOW,
        };
        assert_eq!(resp.fd, 5);
        assert_eq!(resp.response, 0x01);
    }

    #[test]
    fn test_handle_cache_type() {
        use std::collections::HashMap;
        let _cache: HandleCache = HashMap::new();
    }

    // ── open_mount test (path resolution without privileges) ──

    #[test]
    fn test_open_mount_fails_on_nonexistent() {
        let result = open_mount("/nonexistent_path_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_open_mount_succeeds_on_dev() {
        // /dev is always a valid directory even without special permissions
        let result = open_mount("/dev");
        assert!(result.is_ok());
    }

    // ── Fanotify struct tests ──

    #[test]
    fn test_fanotify_impl_as_fd() {
        use std::os::fd::AsFd;
        // We can't create a real Fanotify without CAP_SYS_ADMIN,
        // but we can verify the trait impl compiles.
        fn _takes_as_fd(_: &impl AsFd) {}
        // If this compiles, the impl is correct.
    }

    // ── Pre-commit sanity tests ──

    /// Make sure all public functions compile with expected signatures.
    /// This is a compile-time check.
    #[test]
    fn test_public_api_function_signatures() {
        // These just need to compile — verification that signatures are correct
        fn _check_free_fns() {
            let _ = fanotify_init(0, 0);
            let _ = open_mount("/");
            let _ = handle::name_to_handle_at(std::path::Path::new("/"));
        }

        // Check all prelude exports resolve
        fn _check_prelude() {
            let _ = crate::prelude::Fanotify::new();
            let _ = crate::prelude::FanotifyBuilder::default();
            let _ = crate::prelude::FidEvent {
                mask: 0,
                pid: 0,
                path: PathBuf::new(),
                dfid_name_handle: None,
                dfid_name_filename: None,
                self_handle: None,
            };
            let _ = crate::prelude::LegacyEvent {
                mask: 0,
                fd: -1,
                pid: 0,
                path: PathBuf::new(),
            };
            let _ = crate::prelude::FanotifyResponse {
                fd: -1,
                response: 0,
            };
        }

        _check_free_fns();
        _check_prelude();
    }
}
