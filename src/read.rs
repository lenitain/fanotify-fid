//! High-level fanotify FID event reader.
//!
//! Combines `read` from a fanotify file descriptor with FID event parsing
//! and optional cache-based path recovery.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

use crate::FanotifyError;
use crate::parse::{parse_fid_events, resolve_with_cache};
use crate::types::{FanotifyResponse, FidEvent, HandleCache, LegacyEvent};

/// Read and parse FID-format events from a fanotify file descriptor.
///
/// This is the main entry point for consuming fanotify events in FID mode.
/// It reads raw bytes from `fan_fd`, parses them into [`FidEvent`]s, resolves
/// file handles to paths, and optionally uses a persistent cache to recover
/// paths for events on deleted directories.
///
/// # Arguments
///
/// * `fan_fd` — The fanotify file descriptor, as returned by
///   [`fanotify_init`](crate::fanotify_init) with `FAN_REPORT_FID` (and
///   optionally `FAN_REPORT_DIR_FID` / `FAN_REPORT_NAME`).
/// * `mount_fds` — Open [`OwnedFd`]s for mount points on the filesystems under
///   monitoring.  These are needed to resolve file handles to paths via
///   [`open_by_handle_at`](crate::handle::open_by_handle_at).  Obtain them
///   with [`open_mount`](crate::open_mount).
/// * `buf` — A mutable byte buffer, reused across calls to avoid repeated
///   allocation.  It will be grown to at least 64 KiB on first use.
/// * `cache` — An optional persistent cache mapping handle keys to resolved
///   paths.  When provided, the cache is updated with successfully-resolved
///   paths from the current batch, and used to recover paths for events whose
///   directories were deleted in previous read cycles.
///
/// # Buffer sizing
///
/// The buffer is automatically grown to 64 KiB on first call.  For workloads
/// that produce many events per read, pre-allocate a larger buffer:
///
/// ```rust,no_run
/// let mut buf: Vec<u8> = Vec::with_capacity(256 * 1024);
/// ```
///
/// # Returns
///
/// A list of parsed events.  Events where the file or directory was deleted
/// before path resolution may have an empty `path` field.
///
/// # Errors
///
/// Returns [`FanotifyError::Read`] if `read` on the fanotify fd fails, or
/// [`FanotifyError::Io`] for internal I/O errors.
///
/// # Example
///
/// ```rust,no_run
/// use fanotify_fid::read::read_fid_events;
/// use std::os::fd::{FromRawFd, OwnedFd};
///
/// let fan_fd = unsafe { OwnedFd::from_raw_fd(3) }; // from fanotify_init
/// let mount_fds = vec![unsafe { OwnedFd::from_raw_fd(4) }]; // from open(O_PATH)
/// let mut buf = Vec::with_capacity(65536);
///
/// let events = read_fid_events(&fan_fd, &mount_fds, &mut buf, None).unwrap();
/// for ev in &events {
///     println!("pid={} {:?} {}", ev.pid, ev.event_names(), ev.path.display());
/// }
/// ```
pub fn read_fid_events(
    fan_fd: &OwnedFd,
    mount_fds: &[OwnedFd],
    buf: &mut Vec<u8>,
    mut cache: Option<&mut HandleCache>,
) -> Result<Vec<FidEvent>, FanotifyError> {
    use std::os::fd::AsRawFd;

    // Ensure buffer is large enough
    if buf.capacity() < 65536 {
        buf.reserve(65536 - buf.capacity());
    }

    // SAFETY: `read` on a fanotify fd is safe as long as fd is valid.
    let n = unsafe {
        libc::read(
            fan_fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.capacity(),
        )
    };

    if n < 0 {
        return Err(FanotifyError::Read(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    if n == 0 {
        return Ok(Vec::new());
    }

    let n = n as usize;
    // SAFETY: read wrote n bytes; we only read up to n.
    unsafe { buf.set_len(n) };
    let buf = &buf[..n];

    let mut events = parse_fid_events(buf, mount_fds);

    // Second-pass cache resolution: multiple passes for nested deletions
    if let Some(ref mut cache) = cache {
        for _ in 0..10 {
            // Update cache from successfully-resolved events
            for ev in events.iter() {
                if ev.path.as_os_str().is_empty() {
                    continue;
                }
                if let Some(ref key) = ev.self_handle {
                    cache.entry(key.clone()).or_insert_with(|| ev.path.clone());
                }
                if let (Some(key), Some(filename)) = (&ev.dfid_name_handle, &ev.dfid_name_filename)
                {
                    let dir_path = if !filename.is_empty() {
                        ev.path.parent().map(|p| p.to_path_buf())
                    } else {
                        Some(ev.path.clone())
                    };
                    if let Some(dp) = dir_path {
                        cache.entry(key.clone()).or_insert(dp);
                    }
                }
            }

            if !resolve_with_cache(&mut events, cache) {
                break;
            }
        }
    }

    Ok(events)
}

// ── Legacy event reading ──

use smallvec::SmallVec;
use std::sync::Mutex;

/// Default number of legacy events per read (200 events × 24 bytes = 4800 bytes
/// on stack via `SmallVec`, zero heap allocation at this size).
const DEFAULT_LEGACY_EVENTS: usize = 200;

/// Global configuration for the number of legacy events to read per syscall.
///
/// Defaults to 200 (4800 bytes on stack).  Increase for workloads that produce
/// many events per read cycle.  The buffer uses `SmallVec`, so it stays on
/// stack at the default size and only spills to heap when configured larger.
static LEGACY_BUF_EVENTS: Mutex<usize> = Mutex::new(DEFAULT_LEGACY_EVENTS);

/// Get the current legacy event buffer size (in event count).
pub fn legacy_buffer_events() -> usize {
    LEGACY_BUF_EVENTS
        .lock()
        .map(|g| *g)
        .unwrap_or(DEFAULT_LEGACY_EVENTS)
}

/// Set the legacy event buffer size (in event count).
///
/// The buffer is `SmallVec<[u8; 4800]>` (4800 = 24 bytes × 200 events).  At
/// the default of 200, zero heap allocation.  Values > 200 spill to heap.
pub fn set_legacy_buffer_events(n: usize) {
    let n = n.max(1); // at least 1 event
    *LEGACY_BUF_EVENTS.lock().unwrap() = n;
}

/// Read and parse legacy (non-FID) events from a fanotify file descriptor.
///
/// The fanotify fd must NOT have been created with `FAN_REPORT_FID` flags.
/// Each returned [`LegacyEvent`] carries an open file descriptor that is
/// automatically closed when the event is dropped (RAII).
///
/// Buffer size is configured via [`set_legacy_buffer_events`]; default is
/// 200 events (4800 bytes on stack, zero heap allocation).
///
/// # Errors
///
/// Returns [`FanotifyError::Read`] if the `read` syscall fails.
///
/// # Example
///
/// ```rust,no_run
/// use fanotify_fid::read::read_legacy;
/// use std::os::fd::{FromRawFd, OwnedFd};
///
/// let fan_fd = unsafe { OwnedFd::from_raw_fd(3) };
/// let events = read_legacy(&fan_fd).unwrap();
/// for ev in &events {
///     println!("pid={} {:?} {}", ev.pid, ev.event_names(), ev.path.display());
/// }
/// ```
pub fn read_legacy(fan_fd: &OwnedFd) -> Result<Vec<LegacyEvent>, FanotifyError> {
    use crate::types::FanMetadata;
    use std::os::fd::AsRawFd;

    let event_count = LEGACY_BUF_EVENTS
        .lock()
        .map(|g| *g)
        .unwrap_or(DEFAULT_LEGACY_EVENTS);
    let buf_size = 24 * event_count;
    // SmallVec: 4800 bytes on stack (default 200 ev), spills to heap if > 200.
    let mut buf: SmallVec<[u8; 4800]> = SmallVec::new();
    buf.resize(buf_size, 0);

    // SAFETY: buf is a valid mutable byte slice of known size.
    let n = unsafe {
        libc::read(
            fan_fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf_size,
        )
    };

    if n < 0 {
        return Err(FanotifyError::Read(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    if n == 0 {
        return Ok(Vec::new());
    }

    let n = n as usize;
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + 24 <= n {
        // SAFETY: bounds verified above.
        let meta =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FanMetadata) };
        let event_len = meta.event_len as usize;
        if event_len < 24 || offset + event_len > n {
            break;
        }

        let path = if meta.fd >= 0 {
            std::fs::read_link(format!("/proc/self/fd/{}", meta.fd)).unwrap_or_default()
        } else {
            PathBuf::new()
        };

        events.push(LegacyEvent {
            mask: meta.mask,
            fd: meta.fd,
            pid: meta.pid,
            path,
        });

        offset += event_len;
    }

    Ok(events)
}

/// Read legacy events and apply a callback to each.
///
/// Like [`read_legacy`] but processes events via `callback` as they are
/// parsed, without collecting into a `Vec` first.
///
/// # Errors
///
/// Returns [`FanotifyError::Read`] if the `read` syscall fails.
///
/// # Example
///
/// ```rust,no_run
/// use fanotify_fid::read::read_legacy_do;
/// use std::os::fd::{FromRawFd, OwnedFd};
///
/// let fan_fd = unsafe { OwnedFd::from_raw_fd(3) };
/// read_legacy_do(&fan_fd, |ev| {
///     println!("pid={} {:?}", ev.pid, ev.event_names());
/// }).unwrap();
/// ```
pub fn read_legacy_do<F>(fan_fd: &OwnedFd, mut callback: F) -> Result<(), FanotifyError>
where
    F: FnMut(&LegacyEvent),
{
    let events = read_legacy(fan_fd)?;
    for ev in &events {
        callback(ev);
    }
    Ok(())
}

/// Write a permission response to the fanotify fd.
///
/// Must be called after receiving a permission event (`FAN_OPEN_PERM`,
/// `FAN_ACCESS_PERM`, or `FAN_OPEN_EXEC_PERM`) to grant or deny the
/// operation.
///
/// The `response.fd` should be copied from the [`LegacyEvent`] that
/// triggered the permission check.
///
/// # Errors
///
/// Returns [`FanotifyError::Read`] if the `write` syscall fails.
///
/// # Example
///
/// ```rust,no_run
/// use fanotify_fid::read::write_response;
/// use fanotify_fid::types::FanotifyResponse;
/// use std::os::fd::{FromRawFd, OwnedFd};
///
/// let fan_fd = unsafe { OwnedFd::from_raw_fd(3) };
/// let resp = FanotifyResponse { fd: 5, response: 0x01 }; // FAN_ALLOW
/// write_response(&fan_fd, &resp).unwrap();
/// ```
pub fn write_response(fan_fd: &OwnedFd, response: &FanotifyResponse) -> Result<(), FanotifyError> {
    use std::os::fd::AsRawFd;

    // SAFETY: fanotify_response is a plain-old-data struct.
    let resp = libc::fanotify_response {
        fd: response.fd,
        response: response.response,
    };

    let ret = unsafe {
        libc::write(
            fan_fd.as_raw_fd(),
            &resp as *const libc::fanotify_response as *const libc::c_void,
            std::mem::size_of::<libc::fanotify_response>(),
        )
    };

    if ret < 0 {
        return Err(FanotifyError::Read(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FanMetadata;

    // ── Buffer config tests ──

    #[test]
    fn test_buffer_config_default() {
        assert_eq!(legacy_buffer_events(), 200);
    }

    #[test]
    fn test_buffer_config_set_and_get() {
        set_legacy_buffer_events(50);
        assert_eq!(legacy_buffer_events(), 50);
        set_legacy_buffer_events(200); // reset
    }

    #[test]
    fn test_buffer_config_min_one() {
        set_legacy_buffer_events(0);
        assert_eq!(legacy_buffer_events(), 1);
        set_legacy_buffer_events(200); // reset
    }

    #[test]
    fn test_buffer_config_large_spills_to_heap() {
        // Setting to 1000 events = 24000 bytes, way beyond SmallVec's inline 4800
        set_legacy_buffer_events(1000);
        assert_eq!(legacy_buffer_events(), 1000);
        // Reading /dev/null with large buffer still works (returns empty)
        let fd = std::fs::File::open("/dev/null").unwrap();
        let owned: OwnedFd = fd.into();
        let result = read_legacy(&owned);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        set_legacy_buffer_events(200); // reset
    }

    // ── Legacy read/parse tests ──

    fn build_legacy_raw(mask: u64, pid: i32, fd: i32, event_len: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&event_len.to_ne_bytes());
        buf.push(3); // vers = FANOTIFY_METADATA_VERSION
        buf.push(0); // reserved
        buf.extend_from_slice(&24u16.to_ne_bytes()); // metadata_len
        buf.extend_from_slice(&mask.to_ne_bytes());
        buf.extend_from_slice(&fd.to_ne_bytes());
        buf.extend_from_slice(&pid.to_ne_bytes());
        buf
    }

    #[test]
    fn test_legacy_parse_single_event() {
        let raw = build_legacy_raw(0x0000_0001, 1234, 5, 24);
        let meta: FanMetadata = unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const _) };
        assert_eq!(meta.mask, 0x0000_0001);
        assert_eq!(meta.pid, 1234);
        assert_eq!(meta.fd, 5);
        assert_eq!(meta.event_len, 24);
    }

    #[test]
    fn test_legacy_dev_null_read_empty() {
        // Opening /dev/null and reading from it gives EOF (0 bytes).
        // read_legacy should return Ok(empty vec) for 0 bytes read.
        let fd = std::fs::File::open("/dev/null").unwrap();
        let owned: OwnedFd = fd.into();
        let result = read_legacy(&owned);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_legacy_parse_multiple_raw_events() {
        let ev1 = build_legacy_raw(0x0000_0001, 10, 3, 24);
        let ev2 = build_legacy_raw(0x0000_0002, 20, 4, 30); // larger event_len
        let combined = [ev1, ev2].concat();

        // Manually parse: event 1
        let meta1: FanMetadata = unsafe { std::ptr::read_unaligned(combined.as_ptr() as *const _) };
        assert_eq!(meta1.mask, 0x0000_0001);
        assert_eq!(meta1.pid, 10);
        // event 2 offset
        let off2 = meta1.event_len as usize;
        let meta2: FanMetadata =
            unsafe { std::ptr::read_unaligned(combined.as_ptr().add(off2) as *const _) };
        assert_eq!(meta2.mask, 0x0000_0002);
        assert_eq!(meta2.pid, 20);
    }

    #[test]
    fn test_legacy_overflow_flag() {
        let ev = LegacyEvent {
            mask: crate::consts::FAN_Q_OVERFLOW,
            fd: -1,
            pid: 0,
            path: PathBuf::new(),
        };
        assert!(ev.is_overflow());
    }

    #[test]
    fn test_legacy_event_names() {
        let ev = LegacyEvent {
            mask: crate::consts::FAN_CREATE | crate::consts::FAN_MODIFY,
            fd: -1,
            pid: 0,
            path: PathBuf::new(),
        };
        let names = ev.event_names();
        assert_eq!(names, vec!["MODIFY", "CREATE"]);
    }

    #[test]
    fn test_legacy_drop_closes_fd() {
        // We can't easily test real fd close without opening a real fd,
        // but we can verify the Drop impl doesn't crash on invalid fd.
        let ev = LegacyEvent {
            mask: 0,
            fd: -1, // FAN_NOFD — should be safely ignored by Drop
            pid: 0,
            path: PathBuf::new(),
        };
        drop(ev); // should not panic or crash
    }

    #[test]
    fn test_fanotify_response_size() {
        assert_eq!(std::mem::size_of::<libc::fanotify_response>(), 8);
    }
}
