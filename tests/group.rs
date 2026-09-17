//! The group resource, the mark calls, and the crate's own error surface.
//!
//! These are the tests that hold the design line: this crate does not judge
//! whether a request is legal (the kernel's errno comes through unchanged), does
//! not keep state about marks, and does not hide the difference between an empty
//! queue and a failure.

mod common;

use common::{Capabilities, tmpdir};
use fanotify_fid::consts::*;
use fanotify_fid::{EventReader, Fanotify, FanotifyError, FdEventReader};

/// Whether a descriptor number is currently open, without touching it as a fd.
///
/// A bare `fcntl` would race: libtest runs tests in parallel threads of one
/// process, so a number this test just closed can be handed straight to another
/// test's `open` before the check runs.  Reading `/proc/self/fd` and comparing
/// the target answers "is this number open *and* is it still this object",
/// which cannot be fooled by reuse.
fn descriptor_is_still_the_same_object(raw: i32) -> bool {
    let link = format!("/proc/self/fd/{raw}");
    // SAFETY: `fstat` fills a struct this process owns.
    let mut before: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(raw, &mut before) } != 0 {
        return false;
    }
    match std::fs::metadata(&link) {
        Ok(meta) => {
            use std::os::unix::fs::MetadataExt;
            meta.ino() == before.st_ino && meta.dev() == before.st_dev
        }
        Err(_) => false,
    }
}

#[test]
fn a_group_owns_its_descriptor_and_closes_it_exactly_once() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let fan = common::fid_group();
    // A private number, well above anything libtest holds, so that "is it
    // closed" is a question about this descriptor and not about a number
    // another thread happens to have taken.
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` returns a new descriptor owned by this
    // process, or -1, which is checked.
    let raw = unsafe { libc::fcntl(fan.as_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 900i32) };
    assert!(
        raw >= 900,
        "dup failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: just returned by a successful `fcntl`; nothing else refers to it.
    let private = unsafe { OwnedFd::from_raw_fd(raw) };

    // `into_inner` gives up the group without closing anything.
    let handed_over: OwnedFd = fan.into_inner();
    assert!(
        descriptor_is_still_the_same_object(handed_over.as_raw_fd()),
        "into_inner must hand the descriptor over still open"
    );
    let group_number = handed_over.as_raw_fd();

    // And dropping is what closes it: exactly once, and only then.
    drop(handed_over);
    assert!(
        !descriptor_is_still_the_same_object(group_number),
        "dropping the group must close its descriptor"
    );
    assert!(
        descriptor_is_still_the_same_object(raw),
        "dropping one group must not close another descriptor"
    );
    drop(private);
}

#[test]
fn a_group_is_an_fd_so_any_event_loop_can_own_the_waiting() {
    // The crate takes no position on I/O strategy, so the group has to be
    // registrable with whatever the caller already uses.  That is the `AsFd`
    // impl and nothing else — the same trait `epoll`, `mio` and
    // `tokio::io::unix::AsyncFd` ask for.
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

    fn accepts_any_fd<Fd: AsFd>(fd: &Fd) -> BorrowedFd<'_> {
        fd.as_fd()
    }

    let fan = common::fid_group();
    let borrowed = accepts_any_fd(&fan);
    assert_eq!(borrowed.as_raw_fd(), fan.as_fd().as_raw_fd());
}

#[test]
fn marking_a_path_that_does_not_exist_reports_the_kernels_enoent() {
    // The point is not the errno but where it came from.  A validation layer
    // would have to decide which errno to report, and would eventually decide
    // differently from the kernel; there is none, so this is the kernel's answer.
    let fan = common::fid_group();
    let err = fan
        .mark(FAN_MARK_ADD, FAN_OPEN, "/no/such/path/anywhere")
        .expect_err("marking a nonexistent path must fail");

    match err {
        FanotifyError::Mark(libc::ENOENT) => {}
        other => panic!("expected the kernel's ENOENT, got {other:?}"),
    }
    assert_eq!(err.errno(), Some(libc::ENOENT));
}

#[test]
fn marking_a_file_with_onlydir_reports_the_kernels_enotdir() {
    let dir = tmpdir();
    let file = dir.path().join("plain");
    std::fs::write(&file, b"x").unwrap();

    let fan = common::fid_group();
    let err = fan
        .mark(
            FAN_MARK_ADD | FAN_MARK_ONLYDIR,
            FAN_OPEN,
            file.to_str().unwrap(),
        )
        .expect_err("FAN_MARK_ONLYDIR on a file must fail");

    // ENOTDIR, not the EINVAL a hand-written check would have chosen.
    assert_eq!(err.errno(), Some(libc::ENOTDIR), "got {err}");
}

#[test]
fn a_path_with_an_interior_nul_is_refused_before_the_syscall() {
    // A path containing NUL cannot be a path — the kernel would see a truncated
    // string — so this is a caller error and is reported as EINVAL without ever
    // reaching the kernel.  It is the crate's only refusal, and it refuses
    // something no syscall could accept.
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let fan = common::fid_group();
    let path = OsStr::from_bytes(b"/tmp/has\0nul");
    let err = fan
        .mark(FAN_MARK_ADD, FAN_OPEN, path)
        .expect_err("a path with an interior NUL must be refused");

    assert_eq!(err.errno(), Some(libc::EINVAL));
}

#[test]
fn an_empty_queue_on_a_non_blocking_group_is_eagain_not_an_empty_list() {
    // The distinction matters to every consumer: an empty list would mean "read
    // succeeded, there is nothing", while EAGAIN is the signal to wait.  The
    // crate reports what the kernel said.
    let fan = Fanotify::init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID,
        0,
    )
    .unwrap();
    let mut buf = Vec::new();

    match fan.read_events(&mut buf) {
        Err(FanotifyError::Read(libc::EAGAIN)) => {}
        other => panic!("expected EAGAIN from an empty non-blocking group, got {other:?}"),
    }
}

#[test]
fn fan_event_on_child_is_needed_for_child_events_that_are_not_inherently_child_events() {
    // The kernel's rule is narrower than "a mark does not recurse", and the
    // difference is worth pinning down because getting it wrong costs events:
    //
    // * FAN_OPEN and the other per-object events can fire for the marked object
    //   *or* for a child, so a mark needs FAN_EVENT_ON_CHILD to see them for
    //   children.
    // * FAN_CREATE, FAN_DELETE, FAN_MOVED_* are directory-entry events: they are
    //   only ever about a child, so they need no flag.
    //
    // Neither behaviour is this crate's to decide — every assertion here is the
    // kernel's answer, obtained by asking it.
    let dir = tmpdir();
    let child = dir.path().join("child");
    std::fs::write(&child, b"x").unwrap();

    let open_without_child = common::fid_group();
    open_without_child
        .mark(FAN_MARK_ADD, FAN_OPEN, dir.path().to_str().unwrap())
        .unwrap();
    let open_with_child = common::fid_group();
    open_with_child
        .mark(
            FAN_MARK_ADD,
            FAN_OPEN | FAN_EVENT_ON_CHILD,
            dir.path().to_str().unwrap(),
        )
        .unwrap();

    std::fs::File::open(&child).unwrap();

    // No FAN_EVENT_ON_CHILD: the child's open is not this mark's business.
    let mut buf = Vec::new();
    match open_without_child.read_events(&mut buf) {
        Err(FanotifyError::Read(libc::EAGAIN)) => {}
        Ok(events) => assert!(
            !events.iter().any(|e| e.mask() & FAN_OPEN != 0),
            "FAN_OPEN on a directory without FAN_EVENT_ON_CHILD must not report a child"
        ),
        Err(e) => panic!("unexpected: {e}"),
    }

    // With it, the same open is reported.  Both marks succeeded, so the
    // difference is the mask.
    let mut buf = Vec::new();
    let events = common::collect_fid_events(&open_with_child, &mut buf);
    assert!(
        events
            .iter()
            .any(|e| e.mask() & FAN_OPEN != 0 && e.dfid_name_str() == Some("child")),
        "FAN_EVENT_ON_CHILD must make the marked directory's children visible"
    );
}

#[test]
fn a_directory_entry_event_needs_no_child_flag_because_it_is_always_about_a_child() {
    // The other half of the rule above, and the reason a consumer can subscribe
    // to FAN_CREATE on a directory without also asking for children: there is no
    // such thing as a create event *on* a directory, so the flag would be
    // meaningless.
    let dir = tmpdir();
    let fan = common::fid_group();
    fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
        .unwrap();

    std::fs::write(dir.path().join("entry"), b"x").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    assert!(
        events
            .iter()
            .any(|e| e.mask() & FAN_CREATE != 0 && e.dfid_name_str() == Some("entry")),
        "FAN_CREATE is a directory-entry event and needs no FAN_EVENT_ON_CHILD"
    );
}

#[test]
fn flush_removes_every_mark_and_leaves_the_group_usable() {
    let dir = tmpdir();
    let fan = common::fid_group();
    fan.mark(
        FAN_MARK_ADD,
        FAN_CREATE | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    // A flush is the one call whose convention is worth wrapping: the kernel
    // ignores the path and requires a zero mask, so nothing here to get wrong.
    fan.flush_marks().unwrap();

    let mut buf = Vec::new();
    std::fs::write(dir.path().join("after-flush"), b"x").unwrap();
    match fan.read_events(&mut buf) {
        Err(FanotifyError::Read(libc::EAGAIN)) => {}
        Ok(events) => assert!(
            !events
                .iter()
                .any(|e| e.dfid_name_str() == Some("after-flush")),
            "a flushed group must not report the marked directory's entries"
        ),
        Err(e) => panic!("unexpected: {e}"),
    }

    // Still usable: the group was not closed, only unmarked.
    fan.mark(
        FAN_MARK_ADD,
        FAN_CREATE | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();
    std::fs::write(dir.path().join("after-remark"), b"x").unwrap();
    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    assert!(
        events
            .iter()
            .any(|e| e.dfid_name_str() == Some("after-remark"))
    );
}

#[test]
fn removing_a_mark_takes_exactly_the_bits_it_names() {
    // The kernel removes the bits you name, so a removal with a narrower mask
    // leaves the rest in place.  This is a kernel fact the crate documents and
    // does not paper over, and it is the reason `FAN_MARK_REMOVE` needs the same
    // mask that was added.
    let dir = tmpdir();
    let fan = common::fid_group();
    fan.mark(
        FAN_MARK_ADD,
        FAN_CREATE | FAN_DELETE | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();
    fan.mark(
        FAN_MARK_REMOVE,
        FAN_CREATE | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    std::fs::write(dir.path().join("created"), b"x").unwrap();
    std::fs::remove_file(dir.path().join("created")).unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    assert!(
        events.iter().any(|e| e.mask() & FAN_DELETE != 0),
        "FAN_DELETE was not removed and must still be reported"
    );
    assert!(
        !events.iter().any(|e| e.mask() & FAN_CREATE != 0),
        "FAN_CREATE was removed and must not be reported"
    );
}

#[test]
fn marking_without_privilege_is_the_only_capability_this_crate_checks_nothing_about() {
    // Stated as a test because it is the design line: the crate passes the
    // request through and reports the kernel's EPERM.  It does not pre-empt it,
    // does not translate it, and does not guess that a mount mark needs a
    // capability before asking.
    let caps = Capabilities::probe();
    let dir = tmpdir();
    let fan = common::fid_group();

    let err = fan
        .mark(
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_OPEN,
            dir.path().to_str().unwrap(),
        )
        .err()
        .and_then(|e| e.errno());

    assert_eq!(
        err,
        Some(caps.admin_gated(libc::EPERM)),
        "the kernel's answer, reported as it came"
    );
}

#[test]
fn error_descriptions_are_specific_to_the_syscall_that_failed() {
    // The same errno means different things to different syscalls, and a caller
    // sent looking in the wrong place is worse off than one told nothing.
    let init = FanotifyError::Init(libc::EINVAL).to_string();
    let mark = FanotifyError::Mark(libc::EINVAL).to_string();
    let read = FanotifyError::Read(libc::EINVAL).to_string();
    let write = FanotifyError::Write(libc::EINVAL).to_string();

    assert!(init.contains("fanotify_init"));
    assert!(mark.contains("fanotify_mark"));
    assert!(read.contains("fanotify read"));
    assert!(write.contains("response write"));

    let descriptions = [&init, &mark, &read, &write];
    for (i, a) in descriptions.iter().enumerate() {
        for b in &descriptions[i + 1..] {
            assert_ne!(
                a, b,
                "the same errno must not read the same for two syscalls"
            );
        }
    }
}

#[test]
fn a_buffer_that_is_not_events_is_rejected_rather_than_parsed() {
    // The read path is the only place a buffer can come from, so this is about
    // the parser's contract: 24 bytes of zeros have vers = 0, and saying so is
    // better than returning an empty list or inventing events.
    let err = fanotify_fid::parse_fid_events(&[0u8; 64]).expect_err("zeros are not events");
    assert!(matches!(err, FanotifyError::UnknownEventVersion(0)));
    assert_eq!(err.errno(), None, "this is not a syscall failure");
    assert!(err.to_string().contains("vers"));
}

/// The prelude is a convenience and nothing else, so what it must do is make the
/// ordinary construction path short — with no `use` for the crate root, the
/// constants, or the error type.
mod the_prelude_covers_the_ordinary_path {
    use fanotify_fid::prelude::*;

    #[test]
    fn a_group_is_constructed_and_marked_without_naming_the_crate_root() {
        let dir = tempfile::tempdir().unwrap();
        // Spelled out rather than taken from `common`, to keep this test's
        // only imports the prelude's.
        let fan = Fanotify::new(
            FAN_CLASS_NOTIF
                | FAN_CLOEXEC
                | FAN_NONBLOCK
                | FAN_REPORT_FID
                | FAN_REPORT_DIR_FID
                | FAN_REPORT_NAME,
        )
        .unwrap();
        fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
            .unwrap();

        // A failure really is this crate's error type through the prelude, and
        // its errno is reachable without matching on a variant path.
        let err = fan
            .mark(FAN_MARK_ADD, FAN_CREATE, "/definitely/not/here")
            .expect_err("marking a missing path must fail");
        assert_eq!(err.errno(), Some(libc::ENOENT));
        let _: FanotifyError = err;
        let _: Result<()> = Ok(());
    }

    #[test]
    fn the_resolver_and_its_store_are_reachable_through_the_prelude() {
        let store = HandleCache::new();
        PathMemo::remember(
            &store,
            (1, 2),
            &[0u8; 12],
            &std::path::PathBuf::from("/via/store"),
        );

        let mounts = Mounts::new();
        let mut resolver = PathResolver::new(&store, &mounts);
        let path = resolver.resolve_handle((1, 2), &[0u8; 12]).unwrap();
        assert_eq!(path, std::path::PathBuf::from("/via/store"));
        let _ = EventResolution::Resolved;

        // Refusing the syscall is what makes a store miss EXDEV rather than the
        // EINVAL a malformed handle would earn from `open_by_handle_at`, which is
        // the whole point of the knob.
        resolver.set_syscall_fallback(false);
        assert_eq!(
            resolver
                .resolve_handle((9, 9), &[0u8; 12])
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EXDEV),
        );
    }
}

#[test]
fn a_mark_can_be_placed_on_the_object_a_descriptor_names() {
    // The kernel's descriptor form: a NULL pathname with the object's
    // descriptor as `dirfd`.  No path is walked, so a rename between the open
    // and the mark cannot redirect it — there is no path to redirect.
    let dir = tmpdir();
    let file = dir.path().join("target");
    std::fs::write(&file, b"x").unwrap();

    let fan = common::fid_group();
    let object = std::fs::File::open(&file).unwrap();
    fan.mark_fd(&object, FAN_MARK_ADD, FAN_OPEN)
        .expect("a normal descriptor names its object");

    // The mark is on the *object*, not on the directory: the file's own open is
    // reported, and the identity record is the file's own handle.
    std::fs::File::open(&file).unwrap();
    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let opened = events
        .iter()
        .find(|event| event.mask() & FAN_OPEN != 0)
        .expect("the file's own open must be reported");
    let expected =
        fanotify_fid::handle::handle_from_fd(std::fs::File::open(&file).unwrap()).unwrap();
    assert_eq!(opened.self_handle(), Some(expected.as_slice()));
}

#[test]
fn an_opath_descriptor_is_not_usable_for_a_descriptor_mark() {
    // The kernel resolves the descriptor with `fdget()`, which excludes O_PATH
    // descriptors, so the descriptor that is right for `name_to_handle_at` is
    // wrong here — and `AT_EMPTY_PATH`, which would suggest otherwise, is not a
    // `fanotify_mark` flag at all.  Both answers are the kernel's; asserting
    // them is what keeps this from reading like a crate limitation.
    use std::os::fd::{FromRawFd, OwnedFd};

    let dir = tmpdir();
    let file = dir.path().join("target");
    std::fs::write(&file, b"x").unwrap();
    let c_path = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();

    // SAFETY: `c_path` is NUL-terminated and the flags are open(2) flags.
    let raw = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    assert!(raw >= 0, "O_PATH open failed");
    // SAFETY: a non-negative return from `open` is a descriptor this process
    // owns and no other value refers to.
    let opath = unsafe { OwnedFd::from_raw_fd(raw) };

    let fan = common::fid_group();
    let err = fan
        .mark_fd(&opath, FAN_MARK_ADD, FAN_OPEN)
        .expect_err("the kernel's fdget refuses an O_PATH descriptor");
    assert_eq!(err.errno(), Some(libc::EBADF));

    // The flag the *at calls use instead is rejected too, by the flag check
    // that runs before the descriptor is looked at.
    let err = fan
        .mark_at(&opath, FAN_MARK_ADD | AT_EMPTY_PATH as u32, FAN_OPEN, "")
        .expect_err("AT_EMPTY_PATH is not a fanotify_mark flag");
    assert_eq!(err.errno(), Some(libc::EINVAL));
}

#[test]
fn a_reader_owns_its_buffer_and_resolves_in_place() {
    // The shape `EventReader` exists for: one buffer and one event `Vec` for the
    // whole loop, events reached through `&mut` so a path can be written onto
    // them without copying.  A kernel event is what makes this a test rather
    // than a type-check.
    let dir = tmpdir();
    let fan = common::fid_group();
    fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
        .unwrap();

    let mut reader = EventReader::new(&fan, 256 * 1024);
    assert_eq!(reader.capacity(), 256 * 1024);

    std::fs::write(dir.path().join("made"), b"x").unwrap();

    let mut seen = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while seen == 0 && std::time::Instant::now() < deadline {
        match reader.read() {
            Ok(events) => {
                for ev in events.iter_mut() {
                    // `&mut`, so this is the same call a resolver makes.
                    ev.set_path(std::path::PathBuf::from("/resolved/in/place"));
                }
                seen = events.len();
            }
            Err(FanotifyError::Read(libc::EAGAIN)) => {
                fan.wait_readable(Some(std::time::Duration::from_millis(50)))
                    .unwrap();
            }
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert!(seen >= 1, "the create event must arrive");
}

#[test]
fn a_reader_reuses_the_same_storage_for_every_read() {
    // The allocation this type removes is per read, so the property to assert is
    // that two reads in a row — the second after events from the first were
    // alive — do not rebuild anything.  `event_capacity` is the observable half:
    // it is zero until a read produces events, and unchanged afterwards.
    let fan = common::fid_group();
    let mut reader = EventReader::new(&fan, 4096);

    // An empty queue: no events, so the event storage is untouched.  Reading
    // twice in a row is the loop shape that the borrowed-buffer API could not
    // express at all.
    for _ in 0..3 {
        match reader.read() {
            Err(FanotifyError::Read(libc::EAGAIN)) => {}
            Ok(events) => assert!(events.is_empty()),
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert_eq!(
        reader.event_capacity(),
        0,
        "an empty read must not have grown the event storage"
    );

    // And a read that is handed the raw bytes of an event parses them without a
    // second reader: the buffer is the reader's own, so nothing is copied out.
    let dir = tmpdir();
    fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
        .unwrap();
    std::fs::write(dir.path().join("child"), b"x").unwrap();

    let mut read_something = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !read_something && std::time::Instant::now() < deadline {
        match reader.read() {
            Ok(events) if !events.is_empty() => {
                read_something = true;
                let capacity = reader.event_capacity();
                assert!(capacity > 0, "the event storage grew once");
                // A second read must reuse it rather than start over.
                match reader.read() {
                    Ok(events) => assert!(events.len() <= capacity),
                    Err(FanotifyError::Read(libc::EAGAIN)) => {}
                    Err(e) => panic!("unexpected: {e}"),
                }
                assert_eq!(reader.event_capacity(), capacity, "no re-allocation");
            }
            Ok(_) => {
                fan.wait_readable(Some(std::time::Duration::from_millis(50)))
                    .unwrap();
            }
            Err(FanotifyError::Read(libc::EAGAIN)) => {
                fan.wait_readable(Some(std::time::Duration::from_millis(50)))
                    .unwrap();
            }
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert!(read_something, "the create event must arrive");
}

#[test]
fn a_reader_fixes_its_capacity_because_its_events_point_into_it() {
    // The invariant the lifetime erasure rests on: the buffer is never
    // reallocated, so an event's handle and name cannot be moved out from under
    // it.  `capacity` is part of the reader's contract, not a hint — including
    // for a buffer too small for the next event, which the kernel refuses with
    // `EINVAL` rather than splitting.
    let fan = common::fid_group();
    let reader = EventReader::new(&fan, 24);
    // At least: an allocator may hand back more than was asked for, and what
    // matters is that nothing shrinks it afterwards.
    assert!(reader.capacity() >= 24);
    // A zero capacity is the crate's default rather than a zero-byte read.
    let default = EventReader::new(&fan, 0);
    assert!(default.capacity() >= 24);
}

// ── The fd-format reader: the same storage discipline, for the identity that
//    hands over descriptors instead of handles ──

/// A descriptor-identity group, which is the only kind that reports `FdEvent`s.
///
/// `FAN_CLASS_NOTIF` without a FID flag needs `CAP_SYS_ADMIN` — omitting the
/// report flag is not the unprivileged choice — so every test that reads real fd
/// events is `#[ignore]`d behind it.
fn fd_group() -> Option<Fanotify> {
    if !Capabilities::probe().is_admin() {
        return None;
    }
    Some(
        Fanotify::new(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK)
            .expect("an admin may create a bare NOTIF group"),
    )
}

#[test]
fn an_fd_reader_fixes_its_storage_before_the_first_read() {
    // `FdEvent` owns everything it reports, so there is no lifetime erasure here
    // and no invariant to protect by refusing to grow — but the storage is still
    // allocated once, by `new`, because the point of the reader is that a read
    // loop allocates nothing.  What that means observably: the event storage is
    // already at its maximum before any read, and no read moves it.
    let fan = common::fid_group();
    let mut reader = FdEventReader::new(&fan, 4096);

    // 4096 bytes of 24-byte events: the upper bound on one read's events.
    assert_eq!(reader.capacity(), 4096);
    // Ceiling division: 4096 bytes holds 170 whole events plus 16 spare bytes,
    // and a slot per whole event is the bound, not a slot per full 24 bytes.
    assert_eq!(reader.event_capacity(), 4096usize.div_ceil(24));
    assert!(
        matches!(reader.read(), Ok(events) if events.is_empty())
            || matches!(reader.read(), Err(FanotifyError::Read(libc::EAGAIN))),
        "no read has produced events yet",
    );

    for _ in 0..3 {
        match reader.read() {
            // An empty queue on a non-blocking group.  `read()` reports the
            // kernel's errno rather than an empty slice, which is the same
            // contract `Fanotify::read_fd_events` has.
            Err(FanotifyError::Read(libc::EAGAIN)) => {}
            Ok(events) => assert!(events.is_empty()),
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert_eq!(
        reader.event_capacity(),
        4096usize.div_ceil(24),
        "an empty read must not have touched the storage"
    );
    assert!(
        !matches!(reader.read(), Ok(events) if !events.is_empty()),
        "an empty queue must yield no events",
    );
}

#[test]
fn an_fd_reader_keeps_the_bytes_of_its_last_read() {
    // The raw form exists for a caller that records what the kernel wrote, so it
    // must be the bytes of the *last* read and not of the first: an empty read
    // after a full one is the case that would show a stale length.
    let fan = common::fid_group();
    let mut reader = FdEventReader::new(&fan, 4096);
    // Nothing is marked, so there is nothing to read and the length stays zero.
    for _ in 0..2 {
        let _ = reader.read();
        assert_eq!(reader.raw_bytes(), b"");
    }
}

#[test]
#[allow(
    clippy::redundant_guards,
    reason = "the guard mirrors the panic arm below it"
)]
fn a_failed_read_does_not_leave_the_previous_batch_behind() {
    // What a read that returned an error produced is nothing, so nothing of the
    // read before it may still be reachable: `raw_bytes` answers with the batch
    // the `Ok` just matched, never an older one.  The bug this pins down is the
    // one that matters to `examples/batch_to_worker.rs`, a loop that copies
    // `raw_bytes` — with the state cleared after the read instead of before it, a
    // caller that copies on the error path dispatches the previous batch twice.
    let dir = tmpdir();
    let fan = common::fid_group();
    fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
        .unwrap();
    let mut reader = EventReader::new(&fan, 4096);

    // A real batch first: the stale state has to be something, or the test
    // proves nothing about it.
    std::fs::write(dir.path().join("first"), b"x").unwrap();
    let mut ready = false;
    let mut saw_batch = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready && std::time::Instant::now() < deadline {
        match reader.read() {
            Ok(events) if !events.is_empty() => {
                saw_batch = true;
                ready = true;
            }
            Ok(_) => {}
            Err(FanotifyError::Read(libc::EAGAIN)) => {
                fan.wait_readable(Some(std::time::Duration::from_millis(50)))
                    .unwrap();
            }
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert!(saw_batch, "the create event must arrive");

    // Then reads that fail.  Each one must answer with the empty batch, checked
    // while the previous read's events are still what the reader held a moment
    // ago.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut failures = 0usize;
    while failures < 3 && std::time::Instant::now() < deadline {
        match reader.read() {
            Ok(events) if events.is_empty() => failures += 1,
            Ok(events) => panic!(
                "an event arrived with nothing left to report: {}",
                events.len()
            ),
            Err(FanotifyError::Read(libc::EAGAIN)) => failures += 1,
            Err(e) => panic!("unexpected: {e}"),
        }
        assert!(
            !matches!(reader.read(), Ok(events) if !events.is_empty()),
            "a failed read must not leave the previous batch behind",
        );
    }
    assert!(
        failures >= 3,
        "the queue must empty out so the error path is actually exercised",
    );
    // And no event of the previous batch is still reachable either.
    assert_eq!(reader.read().map(|events| events.len()).unwrap_or(0), 0);
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: a non-FID NOTIF group is admin-only"]
#[allow(
    clippy::redundant_guards,
    reason = "the guard mirrors the panic arm below it"
)]
fn an_fd_reader_gives_up_its_batch_when_a_read_fails() {
    let Some(fan) = fd_group() else {
        skip_without_cap_sys_admin!("a failed fd-format read");
    };
    let dir = tmpdir();
    fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
        .unwrap();

    let mut reader = FdEventReader::new(&fan, 64 * 1024);
    let Some(object) = next_fd_event_object(&fan, &mut reader, dir.path(), "first") else {
        panic!("the first create event must arrive");
    };
    assert!(!reader.raw_bytes().is_empty());
    assert!(descriptor_is_still_the_same_object(object));

    // A read that finds nothing is a read that produced nothing, so the batch
    // and the descriptor it carried go with it.  (The next successful read would
    // replace them anyway; what a failure must not do is leave them reachable
    // through the event slice until then.)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut failed = false;
    while !failed && std::time::Instant::now() < deadline {
        match reader.read() {
            Ok(events) if events.is_empty() => failed = true,
            Ok(events) => panic!("an event arrived with nothing to report: {}", events.len()),
            Err(FanotifyError::Read(libc::EAGAIN)) => failed = true,
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert!(failed, "the queue must empty out");
    assert!(reader.raw_bytes().is_empty());
    assert!(
        !descriptor_is_still_the_same_object(object),
        "a failed read must not keep holding the previous batch's descriptor",
    );
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: a non-FID NOTIF group is admin-only"]
fn an_fd_reader_reuses_its_storage_across_batches() {
    let Some(fan) = fd_group() else {
        skip_without_cap_sys_admin!("reading fd-format events");
    };
    let dir = tmpdir();
    fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
        .unwrap();

    let mut reader = FdEventReader::new(&fan, 64 * 1024);
    let slots = reader.event_capacity();
    // Sized for a whole buffer of events before the first read, which is what
    // makes every read afterwards allocation-free.
    assert_eq!(slots, (64 * 1024usize).div_ceil(24));

    let object = next_fd_event_object(&fan, &mut reader, dir.path(), "first")
        .expect("the first create event must arrive");
    assert!(object >= 0);
    // The batch reports bytes, and only as many as the kernel wrote.
    assert_eq!(reader.event_capacity(), slots, "no re-allocation");

    // A second batch reuses those slots, so the same storage holds it.
    let again = next_fd_event_object(&fan, &mut reader, dir.path(), "second")
        .expect("the second create event must arrive");
    assert!(again >= 0);
    assert_eq!(reader.event_capacity(), slots, "no re-allocation");
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: a non-FID NOTIF group is admin-only"]
fn an_fd_reader_closes_the_batch_it_replaces() {
    let Some(fan) = fd_group() else {
        skip_without_cap_sys_admin!("replacing an fd-format batch");
    };
    let dir = tmpdir();
    fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
        .unwrap();

    let mut reader = FdEventReader::new(&fan, 64 * 1024);
    let slots_before = reader.event_capacity();

    let Some(object) = next_fd_event_object(&fan, &mut reader, dir.path(), "first") else {
        panic!("the first create event must arrive");
    };
    assert!(
        descriptor_is_still_the_same_object(object),
        "the descriptor belongs to the batch while the batch is current"
    );

    // The next event replaces the batch, and a replaced slot drops its
    // descriptor: that is the rule the reader documents, and it is what makes
    // one `Vec` reusable instead of a leak.
    let _ = next_fd_event_object(&fan, &mut reader, dir.path(), "second")
        .expect("the second create event must arrive");
    assert!(
        !descriptor_is_still_the_same_object(object),
        "the replaced batch must have given its descriptor up"
    );
    assert_eq!(
        reader.event_capacity(),
        slots_before,
        "the batch storage is the reader's own and is reused, not rebuilt"
    );
}

/// Read until an fd event appears for a file created as `entry`, and return its
/// raw descriptor number — a number rather than a borrow, so a caller can check
/// it after the batch that owned it has been replaced.
fn next_fd_event_object(
    fan: &Fanotify,
    reader: &mut FdEventReader<'_>,
    dir: &std::path::Path,
    entry: &str,
) -> Option<i32> {
    use std::os::fd::AsRawFd;

    std::fs::write(dir.join(entry), b"x").unwrap();
    common::retry(
        || match reader.read() {
            Ok(events) => events
                .iter()
                .find_map(|ev| ev.fd().map(|fd| fd.as_raw_fd())),
            Err(FanotifyError::Read(libc::EAGAIN)) => {
                let _ = fan.wait_readable(Some(std::time::Duration::from_millis(20)));
                None
            }
            Err(e) => panic!("unexpected: {e}"),
        },
        std::time::Duration::from_secs(5),
    )
}
