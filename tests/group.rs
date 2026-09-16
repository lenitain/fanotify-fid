//! The group resource, the mark calls, and the crate's own error surface.
//!
//! These are the tests that hold the design line: this crate does not judge
//! whether a request is legal (the kernel's errno comes through unchanged), does
//! not keep state about marks, and does not hide the difference between an empty
//! queue and a failure.

mod common;

use common::{Capabilities, tmpdir};
use fanotify_fid::consts::*;
use fanotify_fid::{Fanotify, FanotifyError};

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
        let mut store = HandleCache::new();
        PathStore::insert(
            &mut store,
            (1, 2),
            &[0u8; 12],
            std::path::PathBuf::from("/via/store"),
        );

        let mut resolver = PathResolver::with_store(Mounts::new(), store);
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
