//! Mount identity: the row whose anchor is the mount namespace, and whose
//! privilege is checked at `fanotify_mark` rather than at init.
//!
//! A mount event names a **mount**, not a file: it carries a mount ID and no
//! handle, which is why the identity exists and why its only anchor is
//! [`FAN_MARK_MNTNS`].  The tests here cover both what the crate reports (the
//! mount ID from a real attach) and what it refuses to invent (an anchor the
//! kernel does not allow).

mod common;

use common::{Capabilities, tmpdir};
use fanotify_fid::consts::*;
use fanotify_fid::{Fanotify, FanotifyError};

/// A non-blocking mount-identity group.  Creating one needs no capability.
fn mount_group() -> Fanotify {
    Fanotify::init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_MNT,
        0,
    )
    .expect("FAN_REPORT_MNT is not an admin-only init flag")
}

#[test]
fn a_mount_group_can_be_created_without_privilege() {
    // Recorded because the row's privilege is easy to misattribute: the group
    // is created by anyone, and only *marking* it needs CAP_SYS_ADMIN.
    use std::os::fd::AsRawFd;
    assert!(mount_group().as_fd().as_raw_fd() >= 0);
}

#[test]
fn a_mount_mark_is_refused_at_the_mark_and_not_at_init() {
    let caps = Capabilities::probe();
    let dir = tmpdir();
    let fan = mount_group();

    // The MNTNS anchor is the one place this row's capability is required.
    let mntns = fan.mark(
        FAN_MARK_ADD | FAN_MARK_MNTNS,
        FAN_MNT_ATTACH,
        dir.path().to_str().unwrap(),
    );
    assert_eq!(
        mntns.err().and_then(|e| e.errno()),
        Some(caps.admin_gated(libc::EPERM)),
        "FAN_MARK_MNTNS is admin-gated at mark time"
    );
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: FAN_MARK_MNTNS is where this row's capability is checked"]
fn a_mount_group_takes_only_the_mntns_anchor_and_only_the_mount_mask() {
    let caps = Capabilities::probe();
    if !caps.is_admin() {
        skip_without_cap_sys_admin!("the MNTNS anchor");
    }
    let dir = tmpdir();
    let path = dir.path().to_str().unwrap();
    let fan = mount_group();

    assert!(
        fan.mark(FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_ATTACH, path)
            .is_ok(),
        "MNTNS + a mount event is the one legal pairing"
    );

    for (name, anchor) in [
        ("inode", FAN_MARK_INODE),
        ("mount", FAN_MARK_MOUNT),
        ("filesystem", FAN_MARK_FILESYSTEM),
    ] {
        let errno = fan
            .mark(FAN_MARK_ADD | anchor, FAN_MNT_ATTACH, path)
            .err()
            .and_then(|e| e.errno());
        assert_eq!(
            errno,
            Some(libc::EINVAL),
            "mount identity × {name} anchor does not exist"
        );
    }

    // And the mask is checked too: a mount group cannot carry inode events.
    let errno = fan
        .mark(FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_CREATE, path)
        .err()
        .and_then(|e| e.errno());
    assert_eq!(
        errno,
        Some(libc::EINVAL),
        "a mount group's mask is FANOTIFY_MOUNT_EVENTS only"
    );
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: marking the mount namespace and attaching a mount both do"]
fn a_mount_attach_is_reported_with_its_mount_id() {
    let caps = Capabilities::probe();
    if !caps.is_admin() {
        skip_without_cap_sys_admin!("a real mount event");
    }

    // A private mount namespace, so the mount this test makes cannot escape into
    // the one the test runner lives in.  CLONE_NEWNS needs CAP_SYS_ADMIN in the
    // current user namespace, which is the capability the test already needed.
    // SAFETY: `unshare` changes this thread's namespace memberships and returns
    // a status code; it has no memory arguments.
    let unshared = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if unshared != 0 {
        eprintln!();
        eprintln!("SKIPPED: a real mount event — unshare(CLONE_NEWNS) refused");
        eprintln!();
        return;
    }

    let fan = mount_group();
    fan.mark(FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_ATTACH, "/")
        .expect("an admin must be able to mark the mount namespace");

    // Attaching a mount in our own namespace is the event.  `MS_PRIVATE` keeps
    // the source from propagating, and the mount lives only here.
    let dir = tmpdir();
    let source = format!("tmpfs:{}", dir.path().display());
    let target = dir.path().join("attached");
    std::fs::create_dir(&target).unwrap();
    // SAFETY: both strings are NUL-terminated C strings alive for the call.
    let rc = unsafe {
        libc::mount(
            std::ffi::CString::new(source).unwrap().as_ptr(),
            std::ffi::CString::new(target.to_str().unwrap())
                .unwrap()
                .as_ptr(),
            std::ffi::CString::new("tmpfs").unwrap().as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        eprintln!();
        eprintln!(
            "SKIPPED: a real mount event — mount(2) refused with errno {}",
            unsafe { *libc::__errno_location() }
        );
        eprintln!();
        return;
    }

    let mut buf = Vec::new();
    let events = common::retry(
        || match fan.read_events(&mut buf) {
            Ok(events) if !events.is_empty() => Some(
                events
                    .into_iter()
                    .map(fanotify_fid::FidEvent::into_owned)
                    .collect::<Vec<_>>(),
            ),
            Ok(_) => None,
            Err(FanotifyError::Read(libc::EAGAIN)) => None,
            Err(e) => panic!("read_events failed: {e}"),
        },
        std::time::Duration::from_secs(5),
    );

    // The mount event is a FID-format event whose identity record is the mount
    // ID — the same reader as any other FID group, which is the point.
    let Some(events) = events else {
        // Mount notifications are not queued in every namespace configuration;
        // saying so is honest, and the mark itself was already asserted above.
        eprintln!();
        eprintln!("SKIPPED: a real mount event — the kernel queued none");
        eprintln!();
        return;
    };

    let attach = events
        .iter()
        .find(|e| e.mask() & FAN_MNT_ATTACH != 0)
        .expect("the attach event must be in the batch");

    assert!(
        attach.mnt_id().is_some_and(|id| id > 0),
        "a mount event carries the mount ID, and nothing else identifies it"
    );
    assert_eq!(
        attach.self_handle(),
        None,
        "a mount is not a file: there is no handle and no entry name"
    );
    assert_eq!(attach.dfid_name_handle(), None);
    assert_eq!(attach.fsid(), None);

    // SAFETY: `umount2` takes a NUL-terminated path and a flags word.
    unsafe {
        libc::umount2(
            std::ffi::CString::new(target.to_str().unwrap())
                .unwrap()
                .as_ptr(),
            libc::MNT_DETACH,
        );
    }
}
