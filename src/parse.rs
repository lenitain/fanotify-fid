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
use std::ptr;

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
        // SAFETY: bounds verified above; use read_unaligned because the buffer
        // may not satisfy FanMetadata's alignment requirement (u64 at offset 8).
        let meta = unsafe { ptr::read_unaligned(buf.as_ptr().add(offset) as *const FanMetadata) };
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
            // SAFETY: bounds verified above; read_unaligned for the same reason.
            let hdr = unsafe { ptr::read_unaligned(buf.as_ptr().add(info_off) as *const FanInfoHeader) };
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
                        if path.as_os_str().is_empty()
                            && let Some(p) = resolved {
                                path = p;
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
        if let (Some(key), Some(filename)) = (&ev.dfid_name_handle, &ev.dfid_name_filename)
            && let Some(dir_path) = cache.get(key) {
                ev.path = if filename.is_empty() {
                    dir_path.clone()
                } else {
                    dir_path.join(filename)
                };
                made_progress = true;
            }

        // Try self handle → cached path
        if ev.path.as_os_str().is_empty()
            && let Some(ref key) = ev.self_handle
                && let Some(cached_path) = cache.get(key) {
                    ev.path = cached_path.clone();
                    made_progress = true;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::META_SIZE;

    // ── Helpers to construct synthetic FID events ──

    fn build_metadata(event_len: u32, mask: u64, pid: i32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(META_SIZE);
        buf.extend_from_slice(&event_len.to_ne_bytes());
        buf.push(3); // vers = FANOTIFY_METADATA_VERSION
        buf.push(0); // reserved
        buf.extend_from_slice(&(META_SIZE as u16).to_ne_bytes()); // metadata_len
        buf.extend_from_slice(&mask.to_ne_bytes());
        buf.extend_from_slice(&(-1i32).to_ne_bytes()); // fd = FAN_NOFD
        buf.extend_from_slice(&pid.to_ne_bytes());
        buf
    }

    fn build_info_header(info_type: u8, payload_len: u16) -> Vec<u8> {
        let total_len = 4 + payload_len;
        let mut buf = Vec::with_capacity(4);
        buf.push(info_type);
        buf.push(0); // pad
        buf.extend_from_slice(&total_len.to_ne_bytes());
        buf
    }

    fn build_file_handle(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.extend_from_slice(&(payload.len() as u32).to_ne_bytes()); // handle_bytes
        buf.extend_from_slice(&1i32.to_ne_bytes()); // handle_type = FILEID_INO32_GEN
        buf.extend_from_slice(payload);
        buf
    }

    fn build_fsid(a: i32, b: i32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&a.to_ne_bytes());
        buf.extend_from_slice(&b.to_ne_bytes());
        buf
    }

    fn dfid_name_record(filename: &str, handle_payload: &[u8]) -> Vec<u8> {
        let fh = build_file_handle(handle_payload);
        let name_bytes = filename.as_bytes();
        // null-terminated, padded to 4-byte alignment
        let padded_len = (name_bytes.len() + 1 + 3) & !3;
        let mut name_padded = name_bytes.to_vec();
        name_padded.push(0);
        name_padded.resize(padded_len, 0);

        let payload_len = 8 + fh.len() + name_padded.len(); // fsid + fh + name
        let mut hdr = build_info_header(FAN_EVENT_INFO_TYPE_DFID_NAME, payload_len as u16);
        hdr.extend_from_slice(&build_fsid(100, 200));
        hdr.extend_from_slice(&fh);
        hdr.extend_from_slice(&name_padded);
        hdr
    }

    fn fid_record(handle_payload: &[u8]) -> Vec<u8> {
        let fh = build_file_handle(handle_payload);
        let payload_len = 8 + fh.len(); // fsid + fh
        let mut hdr = build_info_header(FAN_EVENT_INFO_TYPE_FID, payload_len as u16);
        hdr.extend_from_slice(&build_fsid(100, 200));
        hdr.extend_from_slice(&fh);
        hdr
    }

    fn dfid_record(handle_payload: &[u8]) -> Vec<u8> {
        let fh = build_file_handle(handle_payload);
        let payload_len = 8 + fh.len(); // fsid + fh
        let mut hdr = build_info_header(FAN_EVENT_INFO_TYPE_DFID, payload_len as u16);
        hdr.extend_from_slice(&build_fsid(100, 200));
        hdr.extend_from_slice(&fh);
        hdr
    }

    // ── Tests for parse_fid_events ──

    #[test]
    fn test_empty_buffer() {
        let events = parse_fid_events(&[], &[]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_garbage_data_no_crash() {
        let garbage = vec![0xffu8; 256];
        let events = parse_fid_events(&garbage, &[]);
        // Should not crash; may return 0 or some "events" with garbage masks
        // That's acceptable — kernel never sends this
        assert!(events.len() <= 256 / META_SIZE);
    }

    #[test]
    fn test_single_fid_event() {
        let fh_payload = b"\x01\x02\x03\x04";
        let info = fid_record(fh_payload);
        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0100, 1234); // FAN_CREATE
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mask, 0x0000_0100);
        assert_eq!(events[0].pid, 1234);
        assert!(events[0].path.as_os_str().is_empty()); // no mount_fds to resolve
        assert!(events[0].dfid_name_handle.is_none());
        assert!(events[0].dfid_name_filename.is_none());
        assert!(events[0].self_handle.is_some());
    }

    #[test]
    fn test_single_dfid_name_event() {
        let fh_payload = b"\xaa\xbb\xcc\xdd";
        let info = dfid_name_record("hello.txt", fh_payload);
        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0001, 5678); // FAN_ACCESS
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mask, 0x0000_0001);
        assert_eq!(events[0].pid, 5678);
        assert!(events[0].path.as_os_str().is_empty()); // no mount_fds
        assert!(events[0].dfid_name_handle.is_some());
        assert_eq!(events[0].dfid_name_filename.as_deref(), Some("hello.txt"));
        assert!(events[0].self_handle.is_none());
    }

    #[test]
    fn test_fid_and_dfid_name_in_one_event() {
        let obj_fh = b"\x11\x22\x33\x44";
        let dir_fh = b"\xaa\xbb\xcc\xdd";

        let fid_info = fid_record(obj_fh);
        let dfid_info = dfid_name_record("foo.txt", dir_fh);

        let info = [fid_info.as_slice(), dfid_info.as_slice()].concat();
        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0100, 42);
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 42);
        assert!(events[0].self_handle.is_some());
        assert!(events[0].dfid_name_handle.is_some());
        assert_eq!(events[0].dfid_name_filename.as_deref(), Some("foo.txt"));
    }

    #[test]
    fn test_multiple_events_in_buffer() {
        let fh1 = b"\x01\x02";
        let fh2 = b"\x03\x04\x05\x06";

        // Event 1: DFID_NAME "a.txt"
        let info1 = dfid_name_record("a.txt", fh1);
        let len1 = (META_SIZE + info1.len()) as u32;
        let mut ev1 = build_metadata(len1, 0x0000_0002, 10); // FAN_MODIFY
        ev1.extend_from_slice(&info1);

        // Event 2: FID
        let info2 = fid_record(fh2);
        let len2 = (META_SIZE + info2.len()) as u32;
        let mut ev2 = build_metadata(len2, 0x0000_0008, 20); // FAN_CLOSE_WRITE
        ev2.extend_from_slice(&info2);

        let buf = [ev1, ev2].concat();
        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].pid, 10);
        assert_eq!(events[0].mask, 0x0000_0002);
        assert_eq!(events[0].dfid_name_filename.as_deref(), Some("a.txt"));
        assert_eq!(events[1].pid, 20);
        assert_eq!(events[1].mask, 0x0000_0008);
        assert!(events[1].self_handle.is_some());
    }

    #[test]
    fn test_single_dfid_event() {
        let fh_payload = b"\xde\xad\xbe\xef";
        let info = dfid_record(fh_payload);
        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0004, 333); // FAN_ATTRIB
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mask, 0x0000_0004);
        assert_eq!(events[0].pid, 333);
        assert!(events[0].self_handle.is_some());
        assert!(events[0].dfid_name_handle.is_none());
    }

    // ── Edge cases ──

    #[test]
    fn test_truncated_metadata() {
        let buf = vec![0u8; META_SIZE - 1];
        let events = parse_fid_events(&buf, &[]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_event_len_smaller_than_metadata() {
        let buf = build_metadata(10, 0, 0); // event_len=10 < META_SIZE=24
        let events = parse_fid_events(&buf, &[]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_event_len_beyond_buffer() {
        let buf = build_metadata(100, 0x0000_0100, 1); // claims 100 but buf is only 24
        let events = parse_fid_events(&buf, &[]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_event_len_zero() {
        let buf = build_metadata(0, 0x0000_0100, 1);
        let events = parse_fid_events(&buf, &[]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_info_len_smaller_than_info_header() {
        // Put a valid metadata, but the info header says len=2 (< INFO_HDR_SIZE=4)
        let info_hdr = vec![1u8, 0, 2, 0]; // info_type=1, pad=0, len=2
        let event_len = (META_SIZE + 4) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0001, 1);
        buf.extend_from_slice(&info_hdr);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        // The info record is skipped, so no handles extracted
        assert!(events[0].self_handle.is_none());
        assert!(events[0].dfid_name_handle.is_none());
    }

    #[test]
    fn test_info_len_beyond_event() {
        let mut info_hdr = vec![1u8, 0, 0, 0];
        let big_len: u16 = 200;
        info_hdr[2..4].copy_from_slice(&big_len.to_ne_bytes());

        let event_len = (META_SIZE + 4) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0001, 1);
        buf.extend_from_slice(&info_hdr);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        // Info record skipped due to bounds check
        assert!(events[0].self_handle.is_none());
    }

    #[test]
    fn test_unknown_info_type_skipped() {
        // Info type 99 should be silently skipped
        let fh = build_file_handle(b"\x01\x02");
        let payload_len = 8 + fh.len();
        let mut info = build_info_header(99, payload_len as u16);
        info.extend_from_slice(&build_fsid(0, 0));
        info.extend_from_slice(&fh);

        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0001, 1);
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        assert!(events[0].self_handle.is_none());
    }

    #[test]
    fn test_empty_filename_in_dfid_name() {
        let fh_payload = b"\xaa\xbb";
        let info = dfid_name_record("", fh_payload); // empty filename
        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0080, 99); // FAN_MOVED_TO
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dfid_name_filename.as_deref(), Some(""));
    }

    #[test]
    fn test_unicode_filename_in_dfid_name() {
        let fh_payload = b"\x11\x22";
        let info = dfid_name_record("文件.txt", fh_payload);
        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0100, 77);
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dfid_name_filename.as_deref(), Some("文件.txt"));
    }

    #[test]
    fn test_long_filename_in_dfid_name() {
        let name = "a".repeat(255);
        let fh_payload = b"\x01";
        let info = dfid_name_record(&name, fh_payload);
        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0001, 1);
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dfid_name_filename.as_deref(), Some(name.as_str()));
    }

    #[test]
    fn test_handle_bytes_overflow() {
        // Info header says payload is big enough, but handle_bytes says it needs more
        let _fake_handle = [0u8; 4];
        let mut info = build_info_header(FAN_EVENT_INFO_TYPE_FID, 20); // says 20 bytes
        info.extend_from_slice(&build_fsid(0, 0));
        // Now write file_handle with handle_bytes = 1000 (way beyond what's available)
        let mut fh = vec![0u8; 8];
        fh[0..4].copy_from_slice(&1000u32.to_ne_bytes()); // handle_bytes = 1000
        fh[4..8].copy_from_slice(&1i32.to_ne_bytes()); // handle_type
        info.extend_from_slice(&fh);

        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0001, 1);
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        // The corrupt handle should be gracefully skipped
        assert!(events[0].self_handle.is_none());
    }

    #[test]
    fn test_multiple_fid_info_records() {
        let fh1 = build_file_handle(b"\x01\x02");
        let fh2 = build_file_handle(b"\x03\x04");

        let info1 = {
            let payload_len = 8 + fh1.len();
            let mut hdr = build_info_header(FAN_EVENT_INFO_TYPE_FID, payload_len as u16);
            hdr.extend_from_slice(&build_fsid(1, 2));
            hdr.extend_from_slice(&fh1);
            hdr
        };
        let info2 = {
            let payload_len = 8 + fh2.len();
            let mut hdr = build_info_header(FAN_EVENT_INFO_TYPE_DFID, payload_len as u16);
            hdr.extend_from_slice(&build_fsid(3, 4));
            hdr.extend_from_slice(&fh2);
            hdr
        };

        let info = [info1, info2].concat();
        let event_len = (META_SIZE + info.len()) as u32;
        let mut buf = build_metadata(event_len, 0x0000_0001, 1);
        buf.extend_from_slice(&info);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1);
        // Only the last self_handle is kept (FID takes priority)
        // Actually, DFID overwrites self_handle because match checks FID then DFID
        // Both have handle payloads, so self_handle should be set
        assert!(events[0].self_handle.is_some());
    }

    // ── Tests for resolve_with_cache ──

    #[test]
    fn test_resolve_with_cache_noop_when_all_resolved() {
        let mut events = vec![
            FidEvent {
                mask: 0,
                pid: 0,
                path: "/tmp/foo".into(),
                dfid_name_handle: None,
                dfid_name_filename: None,
                self_handle: None,
            },
        ];
        let cache = HashMap::new();
        assert!(!resolve_with_cache(&mut events, &cache));
        assert_eq!(events[0].path.to_str(), Some("/tmp/foo"));
    }

    #[test]
    fn test_resolve_with_cache_dfid_name() {
        let dir_handle = HandleKey::from(b"dir_handle" as &[u8]);
        let mut events = vec![
            FidEvent {
                mask: 0,
                pid: 0,
                path: PathBuf::new(),
                dfid_name_handle: Some(dir_handle.clone()),
                dfid_name_filename: Some("bar.txt".into()),
                self_handle: None,
            },
        ];
        let mut cache = HashMap::new();
        cache.insert(dir_handle, "/tmp/mydir".into());

        assert!(resolve_with_cache(&mut events, &cache));
        assert_eq!(events[0].path.to_str(), Some("/tmp/mydir/bar.txt"));
    }

    #[test]
    fn test_resolve_with_cache_dfid_name_empty_filename() {
        let dir_handle = HandleKey::from(b"dir_handle" as &[u8]);
        let mut events = vec![
            FidEvent {
                mask: 0,
                pid: 0,
                path: PathBuf::new(),
                dfid_name_handle: Some(dir_handle.clone()),
                dfid_name_filename: Some(String::new()),
                self_handle: None,
            },
        ];
        let mut cache = HashMap::new();
        cache.insert(dir_handle, "/tmp/mydir".into());

        assert!(resolve_with_cache(&mut events, &cache));
        assert_eq!(events[0].path.to_str(), Some("/tmp/mydir"));
    }

    #[test]
    fn test_resolve_with_cache_self_handle() {
        let handle = HandleKey::from(b"self_key" as &[u8]);
        let mut events = vec![
            FidEvent {
                mask: 0,
                pid: 0,
                path: PathBuf::new(),
                dfid_name_handle: None,
                dfid_name_filename: None,
                self_handle: Some(handle.clone()),
            },
        ];
        let mut cache = HashMap::new();
        cache.insert(handle, "/cached/path.txt".into());

        assert!(resolve_with_cache(&mut events, &cache));
        assert_eq!(events[0].path.to_str(), Some("/cached/path.txt"));
    }

    #[test]
    fn test_resolve_with_cache_no_match() {
        let handle = HandleKey::from(b"unknown" as &[u8]);
        let mut events = vec![
            FidEvent {
                mask: 0,
                pid: 0,
                path: PathBuf::new(),
                dfid_name_handle: Some(handle),
                dfid_name_filename: Some("x.txt".into()),
                self_handle: None,
            },
        ];
        let cache = HashMap::new(); // empty cache
        assert!(!resolve_with_cache(&mut events, &cache));
        assert!(events[0].path.as_os_str().is_empty());
    }

    #[test]
    fn test_resolve_with_cache_prefers_dfid_name_over_self() {
        let dir_handle = HandleKey::from(b"dir" as &[u8]);
        let self_handle = HandleKey::from(b"self" as &[u8]);
        let mut events = vec![
            FidEvent {
                mask: 0,
                pid: 0,
                path: PathBuf::new(),
                dfid_name_handle: Some(dir_handle.clone()),
                dfid_name_filename: Some("name.txt".into()),
                self_handle: Some(self_handle),
            },
        ];
        let mut cache = HashMap::new();
        cache.insert(dir_handle, "/dirpath".into());

        assert!(resolve_with_cache(&mut events, &cache));
        // Should use DFID_NAME (dir + filename) rather than just self handle
        assert_eq!(events[0].path.to_str(), Some("/dirpath/name.txt"));
    }

    // ── Integration: multiple events + resolve_with_cache ──

    #[test]
    fn test_cache_resolves_multiple_unresolved_events() {
        let dh1 = HandleKey::from(b"dir1" as &[u8]);
        let dh2 = HandleKey::from(b"dir2" as &[u8]);
        let mut events = vec![
            FidEvent {
                mask: 0, pid: 1, path: PathBuf::new(),
                dfid_name_handle: Some(dh1.clone()),
                dfid_name_filename: Some("a.txt".into()),
                self_handle: None,
            },
            FidEvent {
                mask: 0, pid: 2, path: PathBuf::new(),
                dfid_name_handle: Some(dh2.clone()),
                dfid_name_filename: Some("b.txt".into()),
                self_handle: None,
            },
        ];
        let mut cache = HashMap::new();
        cache.insert(dh1, "/dir1".into());
        cache.insert(dh2, "/dir2".into());

        assert!(resolve_with_cache(&mut events, &cache));
        assert_eq!(events[0].path.to_str(), Some("/dir1/a.txt"));
        assert_eq!(events[1].path.to_str(), Some("/dir2/b.txt"));
    }

    #[test]
    fn test_resolve_with_cache_does_not_overwrite_existing() {
        let dh = HandleKey::from(b"dir" as &[u8]);
        let mut events = vec![
            FidEvent {
                mask: 0, pid: 0, path: "/existing/path".into(),
                dfid_name_handle: Some(dh.clone()),
                dfid_name_filename: Some("new.txt".into()),
                self_handle: None,
            },
        ];
        let mut cache = HashMap::new();
        cache.insert(dh, "/cached/dir".into());

        // Already has a path, should NOT be overwritten
        assert!(!resolve_with_cache(&mut events, &cache));
        assert_eq!(events[0].path.to_str(), Some("/existing/path"));
    }

    // ── Tests for consts ──

    #[test]
    fn test_mask_to_event_names_overflow() {
        let names = crate::consts::mask_to_event_names(crate::consts::FAN_Q_OVERFLOW);
        assert!(names.is_empty()); // FAN_Q_OVERFLOW is not in EVENT_NAMES
    }

    #[test]
    fn test_mask_to_event_names_create_modify() {
        let names = crate::consts::mask_to_event_names(
            crate::consts::FAN_CREATE | crate::consts::FAN_MODIFY,
        );
        assert_eq!(names, vec!["MODIFY", "CREATE"]);
    }

    #[test]
    fn test_mask_to_event_names_empty() {
        let names = crate::consts::mask_to_event_names(0);
        assert!(names.is_empty());
    }
}
