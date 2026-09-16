//! Kernel data structures and parsed event types for fanotify FID mode.

use std::collections::HashMap;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
///
/// # Info records without a dedicated field
///
/// Some record types have no typed accessor here — currently
/// `FAN_EVENT_INFO_TYPE_RANGE` (6) and `FAN_EVENT_INFO_TYPE_MNT` (7), plus any
/// type a future kernel adds.  Those records are **not** discarded silently:
/// their raw payloads are preserved and exposed by
/// [`unknown_info_records()`](Self::unknown_info_records).
#[derive(Debug, Clone)]
pub struct FidEvent {
    mask: u64,
    pid: i32,
    path: PathBuf,
    dfid_name_handle: Option<HandleKey>,
    dfid_name_filename: Option<String>,
    self_handle: Option<HandleKey>,
    pidfd: Option<Arc<OwnedFd>>,
    fs_error: Option<(i32, u32)>,
    rename_source: Option<RenameSide>,
    rename_target: Option<RenameSide>,
    unknown_info_records: Vec<(u8, Vec<u8>)>,
}

/// One side of a `FAN_RENAME` event.
///
/// `handle` identifies the **parent directory** and `name` is the entry name
/// within it — the same shape as `FAN_EVENT_INFO_TYPE_DFID_NAME`, which is what
/// the kernel uses for these records.  The source side arrives as
/// `FAN_EVENT_INFO_TYPE_OLD_DFID_NAME` (10) and the target side as
/// `FAN_EVENT_INFO_TYPE_NEW_DFID_NAME` (12); they are independent records, so a
/// rename that leaves the watched subtree reports only the side the mark
/// matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameSide {
    /// Handle of the parent directory containing the entry.
    pub handle: HandleKey,
    /// Entry name within that parent directory.
    pub name: String,
}

impl PartialEq for FidEvent {
    /// Compares every field except the identity of the pidfd.
    ///
    /// A file descriptor has no meaningful value equality, and two events
    /// differing only in which descriptor names the same process are still the
    /// same event, so two events that both carry a pidfd compare equal there.
    fn eq(&self, other: &Self) -> bool {
        let pidfd_eq = match (&self.pidfd, &other.pidfd) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a.as_raw_fd() == b.as_raw_fd(),
            _ => false,
        };
        self.mask == other.mask
            && self.pid == other.pid
            && self.path == other.path
            && self.dfid_name_handle == other.dfid_name_handle
            && self.dfid_name_filename == other.dfid_name_filename
            && self.self_handle == other.self_handle
            && pidfd_eq
            && self.fs_error == other.fs_error
            && self.rename_source == other.rename_source
            && self.rename_target == other.rename_target
            && self.unknown_info_records == other.unknown_info_records
    }
}

impl Eq for FidEvent {}

impl FidEvent {
    /// Create a new `FidEvent`.
    ///
    /// Covers the three original record kinds (`FID`, `DFID`, `DFID_NAME`).
    /// The remaining records are attached by the parser through the
    /// `with_*` methods below, so this signature stays valid for existing
    /// callers.
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
            pidfd: None,
            fs_error: None,
            rename_source: None,
            rename_target: None,
            unknown_info_records: Vec::new(),
        }
    }

    /// Attach the pidfd reported for this event (`FAN_EVENT_INFO_TYPE_PIDFD`).
    ///
    /// The descriptor is owned by this crate and closed when the event is
    /// dropped; borrow it with [`pidfd()`](Self::pidfd) or take ownership with
    /// [`into_pidfd()`](Self::into_pidfd).
    pub fn with_pidfd(mut self, pidfd: OwnedFd) -> Self {
        self.pidfd = Some(Arc::new(pidfd));
        self
    }

    /// Attach the filesystem error payload (`FAN_EVENT_INFO_TYPE_ERROR`).
    ///
    /// `error` is a negative errno and `error_count` is how many errors the
    /// kernel merged into this one event.
    pub fn with_fs_error(mut self, error: i32, error_count: u32) -> Self {
        self.fs_error = Some((error, error_count));
        self
    }

    /// Attach the rename source side (`FAN_EVENT_INFO_TYPE_OLD_DFID_NAME`).
    pub fn with_rename_source(mut self, handle: HandleKey, name: String) -> Self {
        self.rename_source = Some(RenameSide { handle, name });
        self
    }

    /// Attach the rename target side (`FAN_EVENT_INFO_TYPE_NEW_DFID_NAME`).
    pub fn with_rename_target(mut self, handle: HandleKey, name: String) -> Self {
        self.rename_target = Some(RenameSide { handle, name });
        self
    }

    /// Record an info record this crate did not parse.
    ///
    /// `info_type` is the raw `fanotify_event_info_header.info_type`; `payload`
    /// is the record body following the 4-byte header.
    pub fn push_unknown_info_record(&mut self, info_type: u8, payload: Vec<u8>) {
        self.unknown_info_records.push((info_type, payload));
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

    /// Pidfd of the process that triggered the event (`FAN_REPORT_PIDFD`).
    ///
    /// This is the race-free alternative to [`pid()`](Self::pid): a pidfd stays
    /// valid for exactly one process, so it cannot be confused by PID reuse.
    /// Requires a group created with [`FAN_REPORT_PIDFD`], which the kernel
    /// permits only with `CAP_SYS_ADMIN`.
    ///
    /// [`FAN_REPORT_PIDFD`]: crate::consts::FAN_REPORT_PIDFD
    pub fn pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.pidfd.as_ref().map(|fd| fd.as_fd())
    }

    /// Take ownership of the pidfd, closing it when the returned value drops.
    ///
    /// Duplicates the descriptor if the event was cloned, so the returned value
    /// is always solely owned.  Returns `None` if the descriptor could not be
    /// duplicated.
    pub fn into_pidfd(self) -> Option<OwnedFd> {
        self.pidfd.and_then(|fd| match Arc::try_unwrap(fd) {
            Ok(owned) => Some(owned),
            // SAFETY: `fd` is a live descriptor; fcntl(F_DUPFD_CLOEXEC) either
            // returns a new descriptor owned by us or -1, which is checked.
            Err(shared) => {
                let raw = unsafe { libc::fcntl(shared.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0_i32) };
                if raw < 0 {
                    None
                } else {
                    Some(unsafe { OwnedFd::from_raw_fd(raw) })
                }
            }
        })
    }

    /// Filesystem error code and repeat count (from `ERROR` info record).
    ///
    /// Only present for `FAN_FS_ERROR` events on a filesystem mark.  `error` is
    /// a negative errno; `error_count` counts how many errors the kernel merged
    /// into this event.
    pub fn fs_error(&self) -> Option<(i32, u32)> {
        self.fs_error
    }

    /// Rename source: parent directory handle + old entry name.
    ///
    /// Only present for `FAN_RENAME` events, and only for the side(s) the mark
    /// matched.  This is *not* what [`dfid_name_handle`](Self::dfid_name_handle)
    /// reports — the kernel uses distinct info types (10 and 12) for rename,
    /// and this crate keeps them separate rather than overloading the
    /// `DFID_NAME` accessors.
    pub fn rename_source(&self) -> Option<&RenameSide> {
        self.rename_source.as_ref()
    }

    /// Rename target: parent directory handle + new entry name.
    ///
    /// See [`rename_source()`](Self::rename_source).
    pub fn rename_target(&self) -> Option<&RenameSide> {
        self.rename_target.as_ref()
    }

    /// Info records this crate recognised no typed field for.
    ///
    /// Each entry is `(info_type, payload)` where `payload` is the record body
    /// after its 4-byte header.  Currently this covers
    /// `FAN_EVENT_INFO_TYPE_RANGE` (6), `FAN_EVENT_INFO_TYPE_MNT` (7), and any
    /// type a future kernel introduces.
    ///
    /// This exists so that "the parser dropped data" is observable rather than
    /// silent: an empty slice means the event was fully understood.
    pub fn unknown_info_records(&self) -> &[(u8, Vec<u8>)] {
        &self.unknown_info_records
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

    /// Set the parent-directory handle and entry name (`DFID_NAME`).
    ///
    /// Lets a caller synthesise one event from another — splitting a
    /// `FAN_RENAME` into its two sides, for instance — while keeping the
    /// handle/name pair that path resolution and cache seeding rely on.
    pub fn set_dfid_name(&mut self, handle: HandleKey, filename: String) {
        self.dfid_name_handle = Some(handle);
        self.dfid_name_filename = Some(filename);
    }

    /// Set the object's own handle (`FID` / `DFID`).
    pub fn set_self_handle(&mut self, handle: HandleKey) {
        self.self_handle = Some(handle);
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
