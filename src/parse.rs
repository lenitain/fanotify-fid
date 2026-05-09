//! Low-level parsing of fanotify FID-format events from a raw byte buffer.
//!
//! # FID event binary layout
//!
//! ```text
//! ┌──────────────────────────────┐
//! │ FanMetadata (24 bytes)       │  ← fixed-size header
//! │   event_len = total size     │  ← use this to skip to next event
//! │   fd = -1 (FAN_NOFD)         │
//! │   mask, pid                  │
//! ├──────────────────────────────┤
//! │ FanInfoHeader (4 bytes)      │  ← one or more info records
//! │   info_type = DFID_NAME      │
//! │   len = total info size      │
//! ├──────────────────────────────┤
//! │ fsid (8 bytes)               │
//! │ file_handle (8+N bytes)      │
//! │ filename (null-terminated)   │
//! │ padding (alignment)          │
//! ├──────────────────────────────┤
//! │ FanInfoHeader (4 bytes)      │  ← another info record (DFID / FID)
//! │ ...                          │
//! └──────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::path::PathBuf;

use crate::consts::{
    FAN_EVENT_INFO_TYPE_DFID, FAN_EVENT_INFO_TYPE_DFID_NAME, FAN_EVENT_INFO_TYPE_FID,
};
use crate::handle::resolve_file_handle;
use crate::types::{
    FanInfoHeader, FanMetadata, FidEvent, HandleKey, FSID_SIZE, FH_HDR_SIZE, INFO_HDR_SIZE,
    META_SIZE,
};

/// Parse a buffer of raw fanotify FID events into a [`Vec<FidEvent>`].
///
/// This is a **pure parsing function** — it takes a buffer filled by
/// `read(fan_fd, …)`, walks the events using each event's `event_len` field
/// (instead of fixed-size steps), extracts file handles from info records,
/// and attempts to resolve paths via `mount_fds`.
///
/// # Arguments
///
/// * `buf` — A byte buffer containing one or more fanotify events (as returned
///   by `read()` from a fanotify fd initialized with FID flags).
/// * `mount_fds` — Open file descriptors for mount points on the filesystems
///   being monitored.  Used by [`resolve_file_handle`] to convert file handles
///   back to paths.
///
/// # Path resolution caveat
///
/// If a directory is deleted concurrently with event delivery, the file handle
/// may still be valid but the path cannot be resolved.  In that case,
/// `FidEvent.path` will be empty.  To recover these paths, maintain a
/// persistent cache and call [`resolve_with_cache`] after updating it with
/// successfully-resolved events.
pub fn parse_fid_events(buf: &[u8], mount_fds: &[i32]) -> Vec<FidEvent> {
    let n = buf.len();
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + META_SIZE <= n {
        // SAFETY: we verify offset + META_SIZE <= n, and event_len bounds below.
        let meta = unsafe { &*(buf.as_ptr().add(offset) as *const FanMetadata) };
        let event_len = meta.event_len as usize;

        if event_len < META_SIZE || offset + event_len > n {
            break;
        }

        let mut path = PathBuf::new();
        let mut dfid_name_handle: Option<HandleKey> = None;
        let mut dfid_name_filename: Option<String> = None;
        let mut self_handle: Option<HandleKey> = None;

        let mut info_off = offset + meta.metadata_len as usize;
        let event_end = offset + event_len;

        while info_off + INFO_HDR_SIZE <= event_end {
            // SAFETY: same bounds check pattern as above.
            let hdr = unsafe { &*(buf.as_ptr().add(info_off) as *const FanInfoHeader) };
            let info_len = hdr.len as usize;

            if info_len < INFO_HDR_SIZE || info_off + info_len > event_end {
                break;
            }

            match hdr.info_type {
                FAN_EVENT_INFO_TYPE_DFID_NAME => {
                    if let Some((key, filename, resolved)) =
                        extract_dfid_name(buf, info_off, info_len, mount_fds)
                    {
                        dfid_name_handle = Some(key);
                        dfid_name_filename = Some(filename);
                        if let Some(p) = resolved {
                            path = p;
                        }
                    }
                }
                FAN_EVENT_INFO_TYPE_FID | FAN_EVENT_INFO_TYPE_DFID => {
                    if let Some((key, resolved)) = extract_fid(buf, info_off, info_len, mount_fds) {
                        self_handle = Some(key);
                        if path.as_os_str().is_empty() {
                            if let Some(p) = resolved {
                                path = p;
                            }
                        }
                    }
                }
                _ => {}
            }

            info_off += info_len;
        }

        events.push(FidEvent {
            mask: meta.mask,
            pid: meta.pid,
            path,
            dfid_name_handle,
            dfid_name_filename,
            self_handle,
        });

        offset += event_len;
    }

    events
}

/// Second-pass resolution: fill in empty paths using a persistent cache.
///
/// When directories are deleted concurrently with event delivery,
/// [`parse_fid_events`] may return events with empty `path` fields.  If you
/// maintain a persistent cache mapping [`HandleKey`] → [`PathBuf`] across
/// read cycles, you can call this function to recover those paths.
///
/// The cache should be updated with successfully-resolved events before
/// calling this function.
///
/// # Returns
///
/// `true` if at least one path was recovered.  For deeply nested directory
/// deletions, multiple passes may be needed; call this in a loop until it
/// returns `false`.
///
/// # Example
///
/// ```rust,no_run
/// use std::collections::HashMap;
/// use fanotify_fid::parse::{parse_fid_events, resolve_with_cache};
/// use fanotify_fid::types::HandleKey;
///
/// let buf: &[u8] = &[];
/// let mount_fds: &[i32] = &[];
/// let mut cache: HashMap<HandleKey, std::path::PathBuf> = HashMap::new();
///
/// let mut events = parse_fid_events(buf, mount_fds);
/// // Update cache from successfully-resolved events...
/// resolve_with_cache(&mut events, &cache);
/// ```
pub fn resolve_with_cache(
    events: &mut [FidEvent],
    cache: &HashMap<HandleKey, PathBuf>,
) -> bool {
    let mut made_progress = false;

    for ev in events.iter_mut() {
        if !ev.path.as_os_str().is_empty() {
            continue;
        }

        // Try DFID_NAME: parent directory handle → cached dir path + filename
        if let (Some(key), Some(filename)) = (&ev.dfid_name_handle, &ev.dfid_name_filename) {
            if let Some(dir_path) = cache.get(key) {
                ev.path = if filename.is_empty() {
                    dir_path.clone()
                } else {
                    dir_path.join(filename)
                };
                made_progress = true;
            }
        }

        // Try self handle → cached path
        if ev.path.as_os_str().is_empty() {
            if let Some(ref key) = ev.self_handle {
                if let Some(cached_path) = cache.get(key) {
                    ev.path = cached_path.clone();
                    made_progress = true;
                }
            }
        }
    }

    made_progress
}

// ── Internal helpers ──

/// Parse a DFID_NAME info record: extract directory handle, filename, and
/// attempt path resolution.
///
/// Layout: `InfoHeader(4) | fsid(8) | file_handle(8+N) | filename(\0-padded)`
///
/// Returns `(handle_key, filename, optional_resolved_path)`.  Even if path
/// resolution fails (deleted directory), the handle key and filename are
/// returned so they can be used later with a persistent cache.
fn extract_dfid_name(
    buf: &[u8],
    info_off: usize,
    info_len: usize,
    mount_fds: &[i32],
) -> Option<(HandleKey, String, Option<PathBuf>)> {
    let fsid_off = info_off + INFO_HDR_SIZE;
    let fh_off = fsid_off + FSID_SIZE;
    let record_end = info_off + info_len;

    if fh_off + FH_HDR_SIZE > record_end {
        return None;
    }

    let handle_bytes = u32::from_ne_bytes(buf[fh_off..fh_off + 4].try_into().ok()?) as usize;
    let fh_total = FH_HDR_SIZE + handle_bytes;
    let name_off = fh_off + fh_total;

    if name_off > record_end {
        return None;
    }

    // Extract null-terminated filename
    let name_bytes = &buf[name_off..record_end];
    let name = name_bytes.split(|&b| b == 0).next().unwrap_or(&[]);
    let filename = std::str::from_utf8(name).ok()?.to_string();

    // Build handle key: file_handle bytes
    let key = HandleKey::from(&buf[fh_off..fh_off + fh_total]);

    // Try to resolve directory handle → path
    let dir_path = resolve_file_handle(mount_fds, &buf[fh_off..fh_off + fh_total]);
    let full_path = dir_path.map(|dp| {
        if filename.is_empty() {
            dp
        } else {
            dp.join(&filename)
        }
    });

    Some((key, filename, full_path))
}

/// Parse a FID or DFID info record: extract self handle key and attempt path
/// resolution.
///
/// Layout: `InfoHeader(4) | fsid(8) | file_handle(8+N)`
fn extract_fid(
    buf: &[u8],
    info_off: usize,
    info_len: usize,
    mount_fds: &[i32],
) -> Option<(HandleKey, Option<PathBuf>)> {
    let fsid_off = info_off + INFO_HDR_SIZE;
    let fh_off = fsid_off + FSID_SIZE;
    let record_end = info_off + info_len;

    if fh_off + FH_HDR_SIZE > record_end {
        return None;
    }

    let handle_bytes = u32::from_ne_bytes(buf[fh_off..fh_off + 4].try_into().ok()?) as usize;
    let fh_total = FH_HDR_SIZE + handle_bytes;

    if fh_off + fh_total > record_end {
        return None;
    }

    let key = HandleKey::from(&buf[fh_off..fh_off + fh_total]);
    let path = resolve_file_handle(mount_fds, &buf[fh_off..fh_off + fh_total]);

    Some((key, path))
}
