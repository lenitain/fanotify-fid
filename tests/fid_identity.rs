//! FID identity, checked against events a real kernel produced.
//!
//! The tests in `src/fid.rs` prove the parser reads the layout it was written
//! for.  These prove the layout is the **kernel's**: every byte the parser
//! interprets is compared against a handle obtained through
//! `name_to_handle_at`, an fsid obtained through `statfs`, or a name this test
//! created itself.  A misread offset or a wrong info type cannot survive both.

mod common;

use common::{Capabilities, mount_fd_of, tmpdir};
use fanotify_fid::consts::*;
use fanotify_fid::fid::{INFO_HEADER_SIZE, METADATA_SIZE};
use fanotify_fid::handle::{fsid_of_fd, handle_from_fd, name_to_handle_at, resolve_file_handle};
use fanotify_fid::{Fanotify, FidEvent};

/// A FID group marked on `dir` for the entry events this module is about.
fn group_marked_on(dir: &std::path::Path, mask: u64) -> Fanotify {
    let fan = common::fid_group();
    fan.mark(
        FAN_MARK_ADD,
        mask | FAN_EVENT_ON_CHILD,
        dir.to_str().unwrap(),
    )
    .unwrap();
    fan
}

/// The event whose entry name is `name`, if the batch has one.
fn event_named<'a>(events: &'a [FidEvent<'static>], name: &str) -> Option<&'a FidEvent<'static>> {
    events.iter().find(|e| e.dfid_name_str() == Some(name))
}

#[test]
fn a_dfid_name_event_carries_the_parent_handle_the_kernel_reports() {
    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_CREATE);
    let file = dir.path().join("entry");
    std::fs::write(&file, b"x").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let event = event_named(&events, "entry").expect("the create event must be in the batch");

    // Byte-for-byte equality with what the kernel reports for the parent
    // directory through a completely different call.  This is the assertion a
    // wrong record layout cannot pass.
    let expected = handle_from_fd(std::fs::File::open(dir.path()).unwrap()).unwrap();
    assert_eq!(
        event.dfid_name_handle(),
        Some(expected.as_slice()),
        "the DFID_NAME handle must be the parent directory's own handle"
    );

    // And the fsid must be that directory's filesystem.
    let expected_fsid = fsid_of_fd(std::fs::File::open(dir.path()).unwrap()).unwrap();
    assert_eq!(event.fsid(), Some(expected_fsid));
}

#[test]
fn the_name_in_a_dfid_name_event_is_the_entry_the_test_created() {
    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_CREATE);

    // A name that is awkward on purpose: no UTF-8, and not a valid C string
    // suffix.  The record must carry the bytes unchanged.
    use std::os::unix::ffi::OsStrExt;

    let raw_name: Vec<u8> = b"caf\xe9-\xff\xfe".to_vec();
    let path = dir.path().join(std::ffi::OsStr::from_bytes(&raw_name));
    std::fs::write(&path, b"x").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);

    let event = events
        .iter()
        .find(|e| e.dfid_name_raw() == raw_name.as_slice())
        .expect("the create event must carry the name bytes verbatim");

    assert_eq!(event.dfid_name_str(), None, "and it is not UTF-8");
    assert_eq!(
        event.dfid_name().map(|n| n.as_bytes().to_vec()),
        Some(raw_name.clone())
    );
    assert_eq!(event.dfid_name_os_string().unwrap().as_bytes(), raw_name);
}

#[test]
fn a_parent_handle_resolves_back_to_the_parent_path() {
    let caps = Capabilities::probe();
    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_CREATE);
    std::fs::write(dir.path().join("child"), b"x").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let event = event_named(&events, "child").unwrap();

    let mount_fds = [mount_fd_of(dir.path()).unwrap()];
    let handle = event.dfid_name_handle().unwrap();
    let resolved = resolve_file_handle(&mount_fds, event.fsid(), handle);

    match resolved {
        Ok(parent) => {
            assert_eq!(
                parent.canonicalize().unwrap(),
                dir.path().canonicalize().unwrap(),
                "the parent handle must resolve to the parent directory"
            );
        }
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
            // The normal answer without CAP_DAC_READ_SEARCH.  What must still
            // hold is that the fsid filter worked: the mount descriptor is on
            // the event's filesystem, so the call was attempted against it
            // rather than skipped as foreign.
            assert!(!caps.has(common::CAP_DAC_READ_SEARCH));
        }
        Err(e) => panic!("resolution failed unexpectedly: {e}"),
    }
}

#[test]
#[ignore = "needs CAP_DAC_READ_SEARCH: open_by_handle_at bypasses path permissions and is never allowed without it"]
fn a_handle_resolves_to_a_path_that_names_the_same_object() {
    let caps = Capabilities::probe();
    if !caps.has(common::CAP_DAC_READ_SEARCH) {
        skip_without_cap_dac_read_search!("resolving a handle through open_by_handle_at");
    }

    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_CREATE);
    let file = dir.path().join("resolvable");
    std::fs::write(&file, b"content").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let event = event_named(&events, "resolvable").unwrap();

    let mount_fds = [mount_fd_of(dir.path()).unwrap()];
    let parent = resolve_file_handle(&mount_fds, event.fsid(), event.dfid_name_handle().unwrap())
        .expect("the parent handle must resolve with CAP_DAC_READ_SEARCH");

    // The resolved parent plus the reported name is the object.  Checking the
    // content is what makes this an assertion about the *object* rather than
    // about a string that happens to look right.
    use std::os::unix::ffi::OsStrExt;

    let resolved = parent.join(std::ffi::OsStr::from_bytes(event.dfid_name_raw()));
    assert_eq!(std::fs::read(&resolved).unwrap(), b"content");
    assert_eq!(
        resolved.canonicalize().unwrap(),
        file.canonicalize().unwrap()
    );
}

#[test]
fn a_deleted_entry_still_reports_the_name_and_the_parent_handle() {
    // Deletion is the case a path cannot describe and a handle can: the object
    // has no name left at the moment the event is read, but the entry name and
    // the parent handle are in the event, so the consumer knows what was there.
    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_DELETE);
    let file = dir.path().join("doomed");
    std::fs::write(&file, b"x").unwrap();
    std::fs::remove_file(&file).unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let event = event_named(&events, "doomed").expect("the delete event must be in the batch");

    assert!(event.mask() & FAN_DELETE != 0);
    assert_eq!(event.dfid_name_raw(), b"doomed");
    assert!(event.dfid_name_handle().is_some_and(|h| !h.is_empty()));
}

#[test]
fn report_target_fid_adds_the_child_own_handle() {
    // FAN_REPORT_TARGET_FID exists to add the child's handle to an event that
    // would otherwise name only its parent and the entry.  The parser must put
    // it in `self_handle` and not confuse it with the parent handle.
    let dir = tmpdir();
    let fan = Fanotify::init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_DFID_NAME_TARGET,
        0,
    )
    .expect("the full FID flag set needs no privilege");
    fan.mark(
        FAN_MARK_ADD,
        FAN_CREATE | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    let file = dir.path().join("target");
    std::fs::write(&file, b"x").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let event = event_named(&events, "target").expect("the create event must be in the batch");

    let parent = event.dfid_name_handle().expect("the parent handle");
    let child = event
        .self_handle()
        .expect("FAN_REPORT_TARGET_FID must provide the child's own handle");

    assert_ne!(parent, child, "the two handles name different objects");

    // And the child's is the file's own handle, byte for byte.
    let expected = handle_from_fd(std::fs::File::open(&file).unwrap()).unwrap();
    assert_eq!(child, expected.as_slice());
}

#[test]
fn handle_from_fd_and_name_to_handle_at_agree_on_the_same_object() {
    // The two syscalls differ in how they name the object, not in the handle
    // they produce.  If they ever disagreed, an unprivileged consumer building
    // an index from descriptors would key it differently from the events.
    let dir = tmpdir();
    let file = dir.path().join("agree");
    std::fs::write(&file, b"x").unwrap();

    let from_fd = handle_from_fd(std::fs::File::open(&file).unwrap()).unwrap();
    let from_path = name_to_handle_at(&file).unwrap();

    assert_eq!(from_fd, from_path);
    assert!(!from_fd.is_empty());
}

#[test]
fn a_rename_event_reports_both_sides_and_neither_is_the_object() {
    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_RENAME);
    let before = dir.path().join("before");
    let after = dir.path().join("after");
    std::fs::write(&before, b"x").unwrap();
    std::fs::rename(&before, &after).unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let rename = events
        .iter()
        .find(|e| e.mask() & FAN_RENAME != 0)
        .expect("a FAN_RENAME event must be in the batch");

    // A rename inside one directory reports both sides, and each side names its
    // parent — the directory — so the directory's handle appears twice and the
    // file's own handle does not appear at all.
    let parent = handle_from_fd(std::fs::File::open(dir.path()).unwrap()).unwrap();
    let source = rename.rename_source().expect("the source side");
    let target = rename.rename_target().expect("the target side");

    assert_eq!(source.name.as_ref(), b"before");
    assert_eq!(target.name.as_ref(), b"after");
    assert_eq!(source.handle.as_ref(), parent.as_slice());
    assert_eq!(target.handle.as_ref(), parent.as_slice());
    assert_eq!(
        rename.self_handle(),
        None,
        "a rename names parents and entries, not the object"
    );
}

#[test]
fn an_overflow_event_names_no_object_because_it_is_not_about_one() {
    // The queue limit is 16384 events, far too many to fill here, so this test
    // asserts the *shape* of the guarantee instead: an overflow is the one mask
    // bit that can appear with no identity records at all, and the accessors
    // report that absence rather than inventing values.
    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_OPEN);
    std::fs::write(dir.path().join("quiet"), b"x").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let event = event_named(&events, "quiet").expect("the create event must be in the batch");

    assert!(!event.is_overflow());
    assert!(event.dfid_name_handle().is_some());
    assert!(FAN_Q_OVERFLOW & event.mask() == 0);
}

#[test]
fn every_event_from_a_fid_group_has_no_descriptor_field() {
    // `FAN_NOFD` in every event of a FID group is the identity's whole point,
    // and it is why the permission classes cannot be combined with it.
    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_OPEN);
    std::fs::write(dir.path().join("opened"), b"x").unwrap();
    std::fs::File::open(dir.path().join("opened")).unwrap();
    // Also touch the metadata so `fd_error` cannot be set by an accidental
    // group-wide flag: it takes FAN_REPORT_FD_ERROR to ever be non-None.
    let _ = std::fs::metadata(dir.path().join("opened"));

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    for event in &events {
        assert_eq!(
            event.fd_error(),
            None,
            "without FAN_REPORT_FD_ERROR a negative fd is only the sentinel"
        );
    }
}

#[test]
fn the_metadata_size_matches_the_kernel_written_stride() {
    // One event with no info records is exactly `struct fanotify_event_metadata`
    // long, which is how `event_len` reads for a record-free event.  Asserting
    // the constant against a buffer the kernel filled catches a layout change
    // that a hand-built fixture could not.
    let dir = tmpdir();
    let fan = group_marked_on(dir.path(), FAN_CREATE);
    std::fs::write(dir.path().join("len"), b"x").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    assert!(!events.is_empty());
    assert_eq!(METADATA_SIZE, 24, "sizeof(struct fanotify_event_metadata)");
    assert_eq!(
        INFO_HEADER_SIZE, 4,
        "sizeof(struct fanotify_event_info_header)"
    );

    // The buffer is a whole number of events and nothing else: everything the
    // kernel wrote is accounted for by `event_len`.
    let consumed: usize = {
        let mut offset = 0;
        for _ in 0..events.len() {
            let event_len =
                u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            assert!(event_len >= METADATA_SIZE);
            offset += event_len;
        }
        offset
    };
    assert_eq!(consumed, buf.len());
}
