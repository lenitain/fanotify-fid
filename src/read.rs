//! High-level fanotify FID event reader.
//!
//! Combines `read` from a fanotify file descriptor with FID event parsing
//! and optional cache-based path recovery.

use std::collections::HashMap;
use std::io;

use crate::parse::{parse_fid_events, resolve_with_cache};
use crate::types::{FidEvent, HandleKey};

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
/// * `mount_fds` — Open file descriptors for mount points on the filesystems
///   under monitoring.  These are needed to resolve file handles to paths via
///   [`open_by_handle_at`](crate::handle::open_by_handle_at).
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
/// Returns `io::Error` if `read` on the fanotify fd fails (e.g. the fd is
/// invalid or was closed).
///
/// # Example
///
/// ```rust,no_run
/// use fanotify_fid::read::read_fid_events;
///
/// let fan_fd = 3; // from fanotify_init
/// let mount_fds = &[4]; // from open(O_PATH)
/// let mut buf = Vec::with_capacity(65536);
///
/// let events = read_fid_events(fan_fd, mount_fds, &mut buf, None).unwrap();
/// for ev in &events {
///     println!("pid={} {:?} {}", ev.pid, ev.event_names(), ev.path.display());
/// }
/// ```
pub fn read_fid_events(
    fan_fd: i32,
    mount_fds: &[i32],
    buf: &mut Vec<u8>,
    mut cache: Option<&mut HashMap<HandleKey, std::path::PathBuf>>,
) -> io::Result<Vec<FidEvent>> {
    // Ensure buffer is large enough
    if buf.capacity() < 65536 {
        buf.reserve(65536 - buf.capacity());
    }

    // SAFETY: `read` on a fanotify fd is safe as long as fd is valid.
    // The buffer is a valid mutable byte slice.
    let n = unsafe {
        libc::read(
            fan_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.capacity(),
        )
    };

    if n < 0 {
        return Err(io::Error::last_os_error());
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
                    cache
                        .entry(key.clone())
                        .or_insert_with(|| ev.path.clone());
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
