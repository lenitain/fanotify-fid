//! Regression tests for info records that the parser used to discard.
//!
//! These go through the **public API only**, because the defect they guard
//! against was that the public surface silently dropped data: `FAN_RENAME`
//! resolved to an empty path with no name, and no caller could tell that apart
//! from a rename whose information genuinely was not available.
//!
//! Synthetic buffers are used deliberately — no root, no live kernel events, and
//! they run on CI's unprivileged runner.

use fanotify_fid::prelude::*;

const META_SIZE: usize = 24;

fn metadata(event_len: u32, mask: u64, pid: i32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(META_SIZE);
    buf.extend_from_slice(&event_len.to_ne_bytes());
    buf.push(3); // FANOTIFY_METADATA_VERSION
    buf.push(0);
    buf.extend_from_slice(&(META_SIZE as u16).to_ne_bytes());
    buf.extend_from_slice(&mask.to_ne_bytes());
    buf.extend_from_slice(&(-1i32).to_ne_bytes()); // FAN_NOFD
    buf.extend_from_slice(&pid.to_ne_bytes());
    buf
}

fn info_header(info_type: u8, payload_len: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.push(info_type);
    buf.push(0);
    buf.extend_from_slice(&(4 + payload_len).to_ne_bytes());
    buf
}

fn dfid_name_payload(filename: &str, handle: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&100i32.to_ne_bytes()); // fsid
    payload.extend_from_slice(&200i32.to_ne_bytes());
    payload.extend_from_slice(&(handle.len() as u32).to_ne_bytes()); // handle_bytes
    payload.extend_from_slice(&1i32.to_ne_bytes()); // handle_type
    payload.extend_from_slice(handle);
    payload.extend_from_slice(filename.as_bytes());
    payload.push(0);
    while payload.len() % 4 != 0 {
        payload.push(0);
    }
    payload
}

fn rename_side(info_type: u8, filename: &str, handle: &[u8]) -> Vec<u8> {
    let payload = dfid_name_payload(filename, handle);
    let mut record = info_header(info_type, payload.len() as u16);
    record.extend_from_slice(&payload);
    record
}

fn single_event(info: &[u8], mask: u64, pid: i32) -> Vec<u8> {
    let mut buf = metadata((META_SIZE + info.len()) as u32, mask, pid);
    buf.extend_from_slice(info);
    buf
}

#[test]
fn rename_sides_survive_parsing() {
    let mut info = rename_side(FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, "before.txt", b"\xaa\x01");
    info.extend_from_slice(&rename_side(
        FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
        "after.txt",
        b"\xbb\x02",
    ));
    let buf = single_event(&info, FAN_RENAME, 4242);

    let events = parse_fid_events(&buf, &[]);
    assert_eq!(events.len(), 1);
    let ev = &events[0];

    assert_eq!(ev.event_names().collect::<Vec<_>>(), vec!["RENAME"]);
    assert_eq!(
        ev.rename_source().map(|s| s.name.as_str()),
        Some("before.txt"),
        "rename source must not be dropped"
    );
    assert_eq!(
        ev.rename_target().map(|s| s.name.as_str()),
        Some("after.txt"),
        "rename target must not be dropped"
    );
    // The audit's finding was that a caller cannot tell "no data" from "data
    // thrown away"; an empty escape hatch proves nothing was thrown away.
    assert!(ev.unknown_info_records().is_empty());
}

#[test]
fn unrecognised_record_is_observable() {
    let mut info = info_header(99, 12);
    info.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    info.extend_from_slice(&[0u8; 8]);
    let buf = single_event(&info, FAN_CREATE, 7);

    let events = parse_fid_events(&buf, &[]);
    let unknown = events[0].unknown_info_records();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].0, 99);
    assert_eq!(&unknown[0].1[..4], &[0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn fs_error_payload_is_exposed() {
    let mut info = info_header(FAN_EVENT_INFO_TYPE_ERROR, 8);
    info.extend_from_slice(&(-5i32).to_ne_bytes()); // -EIO
    info.extend_from_slice(&3u32.to_ne_bytes());
    let buf = single_event(&info, FAN_FS_ERROR, 1);

    let events = parse_fid_events(&buf, &[]);
    assert_eq!(events[0].fs_error(), Some((-5, 3)));
}

#[test]
fn every_info_type_constant_reaches_the_parser() {
    // Guard against the class of bug the audit found: a constant exported but
    // not honoured.  Each record below is structurally valid for its type, and
    // must produce *some* observable result rather than vanishing.
    let cases: &[(u8, Vec<u8>)] = &[
        // fsid + file_handle(8 + 4 bytes of handle)
        (
            FAN_EVENT_INFO_TYPE_FID,
            dfid_name_payload("", b"\x01\x02\x03\x04"),
        ),
        (
            FAN_EVENT_INFO_TYPE_DFID,
            dfid_name_payload("", b"\x01\x02\x03\x04"),
        ),
        (
            FAN_EVENT_INFO_TYPE_DFID_NAME,
            dfid_name_payload("entry.txt", b"\x01\x02\x03\x04"),
        ),
        // pidfd: -1 keeps this test from opening real descriptors.
        (FAN_EVENT_INFO_TYPE_PIDFD, (-1i32).to_ne_bytes().to_vec()),
        // error + error_count
        (
            FAN_EVENT_INFO_TYPE_ERROR,
            (-5i32)
                .to_ne_bytes()
                .iter()
                .chain(2u32.to_ne_bytes().iter())
                .copied()
                .collect(),
        ),
        // pad + offset + count
        (
            FAN_EVENT_INFO_TYPE_RANGE,
            0u32.to_ne_bytes()
                .iter()
                .chain(4096u64.to_ne_bytes().iter())
                .chain(512u64.to_ne_bytes().iter())
                .copied()
                .collect(),
        ),
        // mnt_id
        (FAN_EVENT_INFO_TYPE_MNT, 77u64.to_ne_bytes().to_vec()),
        (
            FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
            dfid_name_payload("old.txt", b"\x01\x02\x03\x04"),
        ),
        (
            FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
            dfid_name_payload("new.txt", b"\x01\x02\x03\x04"),
        ),
    ];

    for (info_type, payload) in cases {
        let mut info = info_header(*info_type, payload.len() as u16);
        info.extend_from_slice(payload);
        let buf = single_event(&info, FAN_CREATE, 1);

        let events = parse_fid_events(&buf, &[]);
        assert_eq!(events.len(), 1, "info type {info_type} broke event framing");

        let ev = &events[0];
        let observed = ev.self_handle().is_some()
            || ev.dfid_name_handle().is_some()
            || ev.fs_error().is_some()
            || ev.rename_source().is_some()
            || ev.rename_target().is_some()
            || !ev.unknown_info_records().is_empty();
        assert!(
            observed,
            "info type {info_type} is exported but produced no observable result"
        );
    }
}

#[test]
fn recognised_type_with_truncated_payload_is_preserved() {
    // A record whose type we know but whose payload is too short to parse must
    // still be visible, so the no-silent-loss rule has no exception.
    let mut info = info_header(FAN_EVENT_INFO_TYPE_ERROR, 4);
    info.extend_from_slice(&(-5i32).to_ne_bytes()); // error_count missing
    let buf = single_event(&info, FAN_FS_ERROR, 1);

    let events = parse_fid_events(&buf, &[]);
    assert!(events[0].fs_error().is_none());
    assert_eq!(
        events[0].unknown_info_records(),
        &[(FAN_EVENT_INFO_TYPE_ERROR, (-5i32).to_ne_bytes().to_vec())]
    );
}

/// `PartialEq` is now hand-written (the pidfd is an `OwnedFd`, which has no
/// derived equality). It must stay equivalent to the old `#[derive]` for every
/// event a pre-0.7.1 caller could hold — i.e. anything built through
/// `FidEvent::new`, where the new fields are all empty.
#[test]
fn fid_event_equality_unchanged_for_constructor_built_events() {
    fn ev(mask: u64, path: &str, name: Option<&str>) -> fanotify_fid::types::FidEvent {
        fanotify_fid::types::FidEvent::new(
            mask,
            7,
            std::path::PathBuf::from(path),
            Some(vec![1, 2, 3]),
            name.map(str::to_string),
            None,
        )
    }

    assert_eq!(
        ev(FAN_CREATE, "/a/b", Some("b")),
        ev(FAN_CREATE, "/a/b", Some("b")),
        "identical events must compare equal"
    );
    assert_ne!(
        ev(FAN_CREATE, "/a/b", Some("b")),
        ev(FAN_DELETE, "/a/b", Some("b")),
        "a differing mask must compare unequal"
    );
    assert_ne!(
        ev(FAN_CREATE, "/a/b", Some("b")),
        ev(FAN_CREATE, "/a/c", Some("b")),
        "a differing path must compare unequal"
    );
    assert_ne!(
        ev(FAN_CREATE, "/a/b", Some("b")),
        ev(FAN_CREATE, "/a/b", Some("c")),
        "a differing filename must compare unequal"
    );
    assert_ne!(
        ev(FAN_CREATE, "/a/b", Some("b")),
        ev(FAN_CREATE, "/a/b", None),
        "a differing dfid_name must compare unequal"
    );
}

/// `Clone` is still `#[derive]`d. It has to be, now that the event can own a
/// pidfd: a clone shares the descriptor rather than closing it twice.
#[test]
fn fid_event_clone_is_still_available() {
    let original = fanotify_fid::types::FidEvent::new(
        FAN_CREATE,
        1,
        std::path::PathBuf::from("/x"),
        None,
        None,
        None,
    );
    let copy = original.clone();
    assert_eq!(original, copy);
}
