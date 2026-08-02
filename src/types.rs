//! Kernel data structures and parsed event types for fanotify FID mode.

use std::collections::HashMap;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

// ── Internal size constants ──

/// Size of [`FanMetadata`] (`sizeof(struct fanotify_event_metadata)`).
pub(crate) const META_SIZE: usize = mem::size_of::<FanMetadata>();

/// Size of [`FanInfoHeader`] (`sizeof(struct fanotify_event_info_header)`).
pub(crate) const INFO_HDR_SIZE: usize = mem::size_of::<FanInfoHeader>();

/// Size of `__kernel_fsid_t` (two `i32` values).
pub(crate) const FSID_SIZE: usize = 8;

/// Size of the fixed portion of `struct file_handle`:
/// `handle_bytes` (u32) + `handle_type` (i32).
pub(crate) const FH_HDR_SIZE: usize = 8;

// ── Kernel structure definitions ──

/// `struct fanotify_event_metadata` — fixed-size header present at the start
/// of every fanotify event.
///
/// In FID mode, `fd` is always `FAN_NOFD` (-1).  The header is followed by
/// zero or more [`FanInfoHeader`] records containing file handles and optional
/// filenames.  Use `event_len` to advance to the next event in a buffer.
#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct FanMetadata {
    /// Total byte length of this event (header + all info records).
    /// Use this (not `META_SIZE`) to skip to the next event.
    pub event_len: u32,
    /// Must equal `FANOTIFY_METADATA_VERSION` (3).
    pub vers: u8,
    /// Reserved, do not use.
    pub reserved: u8,
    /// Byte offset from the start of this event to the first info record.
    /// Typically equals `META_SIZE`.
    pub metadata_len: u16,
    /// Bitmask of event types (e.g. `FAN_CREATE | FAN_MODIFY`).
    pub mask: u64,
    /// File descriptor (always `FAN_NOFD` = -1 in FID mode).
    pub fd: i32,
    /// PID of the process that triggered the event.
    pub pid: i32,
}

/// `struct fanotify_event_info_header` — type-length header that precedes
/// each variable-length info record within a FID event.
///
/// After this header comes the payload:
/// - `FID` / `DFID`: fsid (8 bytes) + file_handle (variable)
/// - `DFID_NAME`: fsid + file_handle + null-terminated filename + padding
#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct FanInfoHeader {
    /// Info type: one of [`FAN_EVENT_INFO_TYPE_FID`](crate::consts::FAN_EVENT_INFO_TYPE_FID),
    /// [`DFID`](crate::consts::FAN_EVENT_INFO_TYPE_DFID), or
    /// [`DFID_NAME`](crate::consts::FAN_EVENT_INFO_TYPE_DFID_NAME).
    pub info_type: u8,
    /// Padding (unused).
    pub pad: u8,
    /// Total byte length of this info record (header + payload).
    pub len: u16,
}

// ── Handle type ──

/// Opaque file handle key: file_handle bytes (8-byte header + variable payload)
/// from a fanotify FID event info record.
///
/// Uniquely identifies a file or directory within a filesystem.  Used as a
/// lookup key when caching handle → path mappings to recover paths for
/// events on deleted directories.
pub type HandleKey = Vec<u8>;

/// Minimal handle→path store abstraction so callers can plug in their own
/// cache (bounded, TTL, ...) instead of being forced into a plain `HashMap`.
/// `HandleCache` (the `HashMap` alias) implements this trait.
pub trait PathStore {
    fn get(&self, key: &[u8]) -> Option<PathBuf>;
    fn insert(&mut self, key: Vec<u8>, path: PathBuf);
}

impl PathStore for HashMap<HandleKey, PathBuf> {
    fn get(&self, key: &[u8]) -> Option<PathBuf> {
        self.get(key).cloned()
    }

    fn insert(&mut self, key: Vec<u8>, path: PathBuf) {
        self.insert(key, path);
    }
}

/// Persistent cache mapping file handle keys to resolved paths.
///
/// Used to recover paths for events whose directories were deleted
/// concurrently with event delivery.
///
/// Update with successfully-resolved [`FidEvent`]s before calling
/// [`resolve_with_cache`](crate::parse::resolve_with_cache).
pub type HandleCache = HashMap<HandleKey, PathBuf>;

// ── Parsed event ──

/// A fully parsed fanotify FID event.
///
/// Contains the event mask, PID, the best-effort resolved path, and optionally
/// the raw handle keys from the event's info records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidEvent {
    mask: u64,
    pid: i32,
    path: PathBuf,
    dfid_name_handle: Option<HandleKey>,
    dfid_name_filename: Option<String>,
    self_handle: Option<HandleKey>,
}

impl FidEvent {
    /// Create a new `FidEvent`.
    pub fn new(
        mask: u64,
        pid: i32,
        path: PathBuf,
        dfid_name_handle: Option<HandleKey>,
        dfid_name_filename: Option<String>,
        self_handle: Option<HandleKey>,
    ) -> Self {
        Self {
            mask,
            pid,
            path,
            dfid_name_handle,
            dfid_name_filename,
            self_handle,
        }
    }

    /// Event mask (one or more of `FAN_CREATE`, `FAN_MODIFY`, etc.).
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// PID of the process that triggered the event.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Resolved absolute path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Parent directory's handle key (from `DFID_NAME` info record).
    pub fn dfid_name_handle(&self) -> Option<&HandleKey> {
        self.dfid_name_handle.as_ref()
    }

    /// Filename within the parent directory (from `DFID_NAME` info record).
    pub fn dfid_name_filename(&self) -> Option<&str> {
        self.dfid_name_filename.as_deref()
    }

    /// Object's own handle key (from `FID` or `DFID` info record).
    pub fn self_handle(&self) -> Option<&HandleKey> {
        self.self_handle.as_ref()
    }

    /// Returns `true` if this event indicates a queue overflow.
    pub fn is_overflow(&self) -> bool {
        self.mask & crate::consts::FAN_Q_OVERFLOW != 0
    }

    /// Human-readable event names from the mask (e.g. `["CREATE", "MODIFY"]`).
    pub fn event_names(&self) -> impl Iterator<Item = &'static str> {
        crate::consts::mask_to_event_names(self.mask)
    }

    /// Set the resolved path.
    pub fn set_path(&mut self, path: PathBuf) {
        self.path = path;
    }
}

// ── fd-based (non-FID) event ──

/// A parsed fd-based (non-FID) fanotify event.
///
/// fd-based events carry an owned file descriptor for the accessed file.
/// The fd is automatically closed when this event is dropped (RAII).
/// Use [`fd()`](Self::fd) to borrow the fd, or [`into_fd()`](Self::into_fd)
/// to take ownership.
#[derive(Debug)]
pub struct FdEvent {
    mask: u64,
    fd: Option<OwnedFd>,
    pid: i32,
    path: PathBuf,
}

impl FdEvent {
    /// Create a new `FdEvent`.
    ///
    /// The `fd` will be closed when this event is dropped.
    /// Pass `None` for overflow events (where `mask` contains `FAN_Q_OVERFLOW`).
    pub fn new(mask: u64, fd: Option<OwnedFd>, pid: i32, path: PathBuf) -> Self {
        Self {
            mask,
            fd,
            pid,
            path,
        }
    }

    /// Event mask (one or more of `FAN_ACCESS`, `FAN_MODIFY`, etc.).
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// Borrow the open file descriptor for the object being accessed.
    ///
    /// Returns `None` for overflow events.  The returned `BorrowedFd` is
    /// valid for the lifetime of this event.
    pub fn fd(&self) -> Option<BorrowedFd<'_>> {
        self.fd.as_ref().map(|fd| fd.as_fd())
    }

    /// Consume the event and return the owned file descriptor.
    ///
    /// Returns `None` for overflow events.  After calling this, the fd
    /// will **not** be closed when the event is dropped (ownership was
    /// transferred to the caller).
    pub fn into_fd(self) -> Option<OwnedFd> {
        self.fd
    }

    /// PID of the process that triggered the event.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Resolved path (via `readlink("/proc/self/fd/N")`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns `true` if this event indicates a queue overflow.
    pub fn is_overflow(&self) -> bool {
        self.mask & crate::consts::FAN_Q_OVERFLOW != 0
    }

    /// Human-readable event names from the mask.
    pub fn event_names(&self) -> impl Iterator<Item = &'static str> {
        crate::consts::mask_to_event_names(self.mask)
    }
}

// ── Permission response ──

/// A response to a permission event (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`,
/// `FAN_OPEN_EXEC_PERM`).
///
/// Write this to the fanotify fd after receiving a permission event to
/// grant or deny the operation.  The `fd` field should be borrowed from
/// the [`FdEvent`] that triggered the permission check.
///
/// The lifetime `'a` is tied to the event's file descriptor, ensuring
/// the response cannot outlive the event fd.
pub struct FanotifyResponse<'a> {
    fd: BorrowedFd<'a>,
    response: u32,
}

impl std::fmt::Debug for FanotifyResponse<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FanotifyResponse")
            .field("fd", &self.fd.as_raw_fd())
            .field("response", &self.response)
            .finish()
    }
}

impl<'a> FanotifyResponse<'a> {
    /// Create a new `FanotifyResponse`.
    ///
    /// - `fd`: The file descriptor borrowed from the `FdEvent` that triggered
    ///   the permission check.
    /// - `response`: `FAN_ALLOW` to grant, `FAN_DENY` to deny.
    pub fn new(fd: BorrowedFd<'a>, response: u32) -> Self {
        Self { fd, response }
    }

    /// The file descriptor from the `FdEvent` that triggered the permission check.
    pub fn fd(&self) -> BorrowedFd<'a> {
        self.fd
    }

    /// `FAN_ALLOW` to grant, `FAN_DENY` to deny.
    pub fn response(&self) -> u32 {
        self.response
    }
}
