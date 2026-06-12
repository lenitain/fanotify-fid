//! Kernel data structures and parsed event types for fanotify FID mode.

use std::collections::HashMap;
use std::mem;
use std::path::PathBuf;

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
#[derive(Debug, Clone)]
pub struct FidEvent {
    /// Event mask (one or more of `FAN_CREATE`, `FAN_MODIFY`, etc.).
    pub mask: u64,
    /// PID of the process that triggered the event.
    pub pid: i32,
    /// Resolved absolute path.
    ///
    /// This is best-effort: it may be empty if the file or its parent directory
    /// was deleted before the path could be resolved.  Use a persistent cache
    /// (see [`parse::resolve_with_cache`](crate::parse::resolve_with_cache)) to
    /// recover paths in a later read cycle.
    pub path: PathBuf,
    /// If the event includes a `DFID_NAME` info record: the parent directory's
    /// handle key.  Useful for caching directory → path mappings.
    pub dfid_name_handle: Option<HandleKey>,
    /// If the event includes a `DFID_NAME` info record: the filename within
    /// the parent directory.
    pub dfid_name_filename: Option<String>,
    /// If the event includes a `FID` or `DFID` info record: the object's own
    /// handle key.  Useful for caching the object's path for future lookups.
    pub self_handle: Option<HandleKey>,
}

impl FidEvent {
    /// Returns `true` if this event indicates a queue overflow.
    pub fn is_overflow(&self) -> bool {
        self.mask & crate::consts::FAN_Q_OVERFLOW != 0
    }

    /// Human-readable event names from the mask (e.g. `["CREATE", "MODIFY"]`).
    pub fn event_names(&self) -> Vec<&'static str> {
        crate::consts::mask_to_event_names(self.mask)
    }
}

// ── fd-based (non-FID) event ──

/// A parsed fd-based (non-FID) fanotify event.
///
/// fd-based events carry an open file descriptor for the accessed file.
/// The fd is automatically closed when this event is dropped (RAII).
/// If you need the fd to outlive the event, use `libc::dup(ev.fd)` to
/// obtain a copy.
#[derive(Debug)]
pub struct FdEvent {
    /// Event mask (one or more of `FAN_ACCESS`, `FAN_MODIFY`, etc.).
    pub mask: u64,
    /// Open file descriptor for the object being accessed.
    /// Automatically closed on drop.
    pub fd: i32,
    /// PID of the process that triggered the event.
    pub pid: i32,
    /// Resolved path (via `readlink("/proc/self/fd/N")`).
    ///
    /// This is best-effort; may be empty if resolution fails.
    pub path: PathBuf,
}

impl Drop for FdEvent {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

impl FdEvent {
    /// Returns `true` if this event indicates a queue overflow.
    pub fn is_overflow(&self) -> bool {
        self.mask & crate::consts::FAN_Q_OVERFLOW != 0
    }

    /// Human-readable event names from the mask.
    pub fn event_names(&self) -> Vec<&'static str> {
        crate::consts::mask_to_event_names(self.mask)
    }
}

// ── Permission response ──

/// A response to a permission event (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`,
/// `FAN_OPEN_EXEC_PERM`).
///
/// Write this to the fanotify fd after receiving a permission event to
/// grant or deny the operation.  The `fd` field should be copied from the
/// [`FdEvent`] that triggered the permission check.
#[derive(Debug, Clone)]
pub struct FanotifyResponse {
    /// The file descriptor from the `FdEvent` that triggered the
    /// permission check.
    pub fd: i32,
    /// `FAN_ALLOW` to grant, `FAN_DENY` to deny.
    pub response: u32,
}
