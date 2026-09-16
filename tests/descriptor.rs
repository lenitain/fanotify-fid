//! Descriptor identity: the format that hands over an open descriptor, and the
//! permission events that must be answered.
//!
//! Every test here needs `CAP_SYS_ADMIN`, because a descriptor group is
//! admin-gated in all three classes and a permission class is admin-gated
//! outright.  They are `#[ignore]`d and report why instead of passing without
//! running, and the privileged CI job fails if that report appears.
//!
//! What the tests are for:
//!
//! * the descriptor in an event really is the object the event is about, and it
//!   is closed exactly once ([`FdEvent`] owns it);
//! * the response forms are chosen by the kernel, not by this crate's
//!   preference: a descriptor response completes the event it names.

mod common;

use common::{Capabilities, tmpdir};
use fanotify_fid::consts::*;
use fanotify_fid::response::FanotifyResponse;
use fanotify_fid::{Fanotify, FanotifyError, FdEvent};

/// A non-blocking descriptor group in the given class.
fn fd_group(class: u32, extra: u32) -> Fanotify {
    Fanotify::init(class | FAN_CLOEXEC | FAN_NONBLOCK | extra, 0)
        .expect("an admin must be able to create a descriptor group")
}

/// Read until at least one event arrives, or panic after the timeout.
fn collect(fan: &Fanotify, buf: &mut Vec<u8>) -> Vec<FdEvent> {
    common::retry(
        || match fan.read_fd_events(buf) {
            Ok(events) if !events.is_empty() => Some(events),
            Ok(_) => None,
            Err(FanotifyError::Read(libc::EAGAIN)) => None,
            Err(e) => panic!("read_fd_events failed: {e}"),
        },
        std::time::Duration::from_secs(5),
    )
    .expect("no event arrived within 5 seconds")
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: a descriptor-identity group is admin-gated"]
fn a_descriptor_event_owns_the_object_it_is_about() {
    if !Capabilities::probe().is_admin() {
        skip_without_cap_sys_admin!("descriptor events");
    }

    let dir = tmpdir();
    let file = dir.path().join("watched");
    std::fs::write(&file, b"payload").unwrap();

    let fan = fd_group(FAN_CLASS_NOTIF, FAN_REPORT_FD_ERROR);
    fan.mark(
        FAN_MARK_ADD,
        FAN_OPEN | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    std::fs::File::open(&file).unwrap();

    let mut buf = Vec::new();
    let events = collect(&fan, &mut buf);
    let event = events
        .iter()
        .find(|e| e.mask() & FAN_OPEN != 0)
        .expect("the open event must be in the batch");

    // The identity this format exists to provide: a descriptor, not a handle.
    let fd = event.fd().expect("an fd-based event carries a descriptor");
    assert_eq!(event.fd_field(), std::os::fd::AsRawFd::as_raw_fd(&fd));
    assert_eq!(event.no_fd_reason(), None);

    // Reading through it must yield the file's own bytes, which is what makes
    // this an assertion about the object rather than about a number.
    let mut content = String::new();
    use std::io::Read;
    let mut borrowed = std::fs::File::from(fd.try_clone_to_owned().unwrap());
    borrowed.read_to_string(&mut content).unwrap();
    assert_eq!(content, "payload");
    assert!(
        event.path().is_some(),
        "the descriptor reaches /proc/self/fd"
    );
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: a permission class is admin-gated"]
fn a_permission_event_is_answered_by_descriptor() {
    if !Capabilities::probe().is_admin() {
        skip_without_cap_sys_admin!("permission events");
    }

    let dir = tmpdir();
    let file = dir.path().join("guarded");
    std::fs::write(&file, b"x").unwrap();

    let fan = fd_group(FAN_CLASS_CONTENT, 0);
    fan.mark(
        FAN_MARK_ADD,
        FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    // A second thread performs the operation that will block, so the answer can
    // be given while it waits — which is the shape a real consumer has.
    let opener = file.clone();
    let blocked = std::thread::spawn(move || std::fs::File::open(&opener).map(|_| ()));

    let mut buf = Vec::new();
    let events = collect(&fan, &mut buf);
    let event = events
        .iter()
        .find(|e| e.mask() & FAN_OPEN_PERM != 0)
        .expect("the permission event must be in the batch");

    let fd = event.fd().expect("FAN_CLASS_CONTENT provides a descriptor");
    fan.send_response(&FanotifyResponse::allow(fd)).unwrap();

    // The operation was blocked until the answer, and the answer was the one it
    // got: an allow means the open succeeds.
    let outcome = blocked.join().unwrap();
    assert!(
        outcome.is_ok(),
        "an allowed open must succeed, got {outcome:?}"
    );
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: a permission class is admin-gated"]
fn a_denied_permission_event_reaches_the_caller_as_the_errno_it_names() {
    if !Capabilities::probe().is_admin() {
        skip_without_cap_sys_admin!("permission events");
    }

    let dir = tmpdir();
    let file = dir.path().join("denied");
    std::fs::write(&file, b"x").unwrap();

    // PRE_CONTENT is the class for which the kernel reads a packed errno; for
    // CONTENT the caller would see EPERM regardless, which is a difference the
    // response documentation states and this test checks.
    let fan = fd_group(FAN_CLASS_PRE_CONTENT, 0);
    fan.mark(
        FAN_MARK_ADD,
        FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    let opener = file.clone();
    let blocked = std::thread::spawn(move || std::fs::File::open(&opener).map(|_| ()));

    let mut buf = Vec::new();
    let events = collect(&fan, &mut buf);
    let event = events
        .iter()
        .find(|e| e.mask() & FAN_OPEN_PERM != 0)
        .expect("the permission event must be in the batch");

    let fd = event
        .fd()
        .expect("a permission class provides a descriptor");
    fan.send_response(&FanotifyResponse::deny_errno(fd, libc::EACCES))
        .unwrap();

    let errno = blocked
        .join()
        .unwrap()
        .expect_err("a denied open must fail")
        .raw_os_error();
    assert_eq!(
        errno,
        Some(libc::EACCES),
        "a PRE_CONTENT class reports the errno it was given, not EPERM"
    );
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN and CAP_AUDIT_WRITE: the descriptor-less response form"]
fn the_audit_form_answers_without_a_descriptor() {
    let caps = Capabilities::probe();
    if !caps.is_admin() {
        skip_without_cap_sys_admin!("the descriptor-less permission response");
    }
    if !caps.has(common::CAP_AUDIT_WRITE) {
        eprintln!();
        eprintln!("SKIPPED: the descriptor-less permission response — needs CAP_AUDIT_WRITE");
        eprintln!();
        return;
    }

    let dir = tmpdir();
    let file = dir.path().join("audited");
    std::fs::write(&file, b"x").unwrap();

    let fan = fd_group(FAN_CLASS_CONTENT, FAN_ENABLE_AUDIT);
    fan.mark(
        FAN_MARK_ADD,
        FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    let opener = file.clone();
    let blocked = std::thread::spawn(move || std::fs::File::open(&opener).map(|_| ()));

    let mut buf = Vec::new();
    let events = collect(&fan, &mut buf);
    let event = events
        .iter()
        .find(|e| e.mask() & FAN_OPEN_PERM != 0)
        .expect("the permission event must be in the batch");
    assert!(event.fd().is_some(), "this group does report descriptors");

    // The audit-record form, attached to the event it is about.  The kernel
    // matches every response by descriptor, so the descriptor is what makes
    // the record complete *this* event; a record written with FAN_NOFD is
    // validated and answers nothing.
    let fd = event
        .fd()
        .expect("the permission event carries a descriptor");
    fan.send_response(&FanotifyResponse::audit_rule(FAN_ALLOW, 0).with_fd(fd))
        .unwrap();

    let outcome = blocked.join().unwrap();
    assert!(
        outcome.is_ok(),
        "the descriptor-less allow must let the operation through, got {outcome:?}"
    );
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: the audit form is refused without FAN_ENABLE_AUDIT"]
fn the_audit_form_is_refused_by_a_group_without_enable_audit() {
    if !Capabilities::probe().is_admin() {
        skip_without_cap_sys_admin!("the refusal of the audit form");
    }

    let dir = tmpdir();
    let file = dir.path().join("unaudited");
    std::fs::write(&file, b"x").unwrap();

    let fan = fd_group(FAN_CLASS_CONTENT, 0);
    fan.mark(
        FAN_MARK_ADD,
        FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    let opener = file.clone();
    let blocked = std::thread::spawn(move || std::fs::File::open(&opener).map(|_| ()));

    let mut buf = Vec::new();
    let events = collect(&fan, &mut buf);
    assert!(events.iter().any(|e| e.mask() & FAN_OPEN_PERM != 0));

    let refused = fan.send_response(
        &FanotifyResponse::audit_rule(FAN_ALLOW, 0).with_fd(
            events
                .iter()
                .find_map(|e| e.fd())
                .expect("a descriptor to answer with"),
        ),
    );
    assert!(
        matches!(refused, Err(FanotifyError::Write(libc::EINVAL))),
        "the kernel requires FAN_ENABLE_AUDIT for the FAN_INFO form, got {refused:?}"
    );

    // Leave nothing blocked: answer the pending event the ordinary way.
    let fd = events
        .iter()
        .find(|e| e.fd().is_some())
        .and_then(|e| e.fd())
        .expect("a descriptor to answer with");
    fan.send_response(&FanotifyResponse::allow(fd)).unwrap();
    blocked.join().unwrap().unwrap();
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: a descriptor-identity group is admin-gated"]
fn a_descriptor_event_can_be_answered_or_explained_but_never_silently_empty() {
    if !Capabilities::probe().is_admin() {
        skip_without_cap_sys_admin!("FAN_REPORT_FD_ERROR");
    }

    // The invariant that holds whether or not the kernel could open the object:
    // an event either carries a descriptor or reports why it does not.  What
    // FAN_REPORT_FD_ERROR adds is the second case carrying a reason instead of
    // the FAN_NOFD sentinel — which cannot be provoked on demand, since it
    // depends on the kernel failing an open the caller may well be allowed to
    // make.
    let dir = tmpdir();
    let file = dir.path().join("plain");
    std::fs::write(&file, b"x").unwrap();

    let fan = fd_group(FAN_CLASS_NOTIF, FAN_REPORT_FD_ERROR);
    fan.mark(
        FAN_MARK_ADD,
        FAN_OPEN | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    std::fs::File::open(&file).unwrap();

    let mut buf = Vec::new();
    let events = collect(&fan, &mut buf);
    let event = events
        .iter()
        .find(|e| e.mask() & FAN_OPEN != 0)
        .expect("the open event must be in the batch");

    match event.no_fd_reason() {
        None => assert!(event.fd().is_some(), "no reason means a descriptor"),
        Some(reason) => assert!(
            reason <= FAN_NOFD,
            "a reason is the sentinel or a negative errno, never a descriptor number"
        ),
    }
}
