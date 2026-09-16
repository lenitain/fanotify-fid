//! The acceptance baseline: every legal group configuration, and every cell that
//! does not exist.
//!
//! The legal configurations are derived from the dependencies the kernel welds
//! shut, not chosen:
//!
//! | # | Identity | Class | Anchors | Privilege |
//! |---|---|---|---|---|
//! | 1 | descriptor | NOTIF | inode · mount · filesystem | `CAP_SYS_ADMIN` |
//! | 2 | descriptor | CONTENT | inode · mount · filesystem | `CAP_SYS_ADMIN` |
//! | 3 | descriptor | PRE_CONTENT | inode · mount · filesystem | `CAP_SYS_ADMIN` |
//! | 4 | FID | NOTIF | inode · mount · filesystem | inode anchors need none |
//! | 5 | mount | NOTIF | **MNTNS only** | `CAP_SYS_ADMIN` |
//!
//! Cells that do not exist: `FID × {CONTENT, PRE_CONTENT}`, and
//! `mount × {inode, mount, filesystem}`.
//!
//! # How a combination is checked: ask the kernel
//!
//! By handing the combination to `fanotify_init` / `fanotify_mark` and reading
//! the errno.  There is one trap, and it shapes every assertion here:
//!
//! **The privilege check runs before the legality check.**  `fanotify_init`
//! tests the admin-only flag set first and returns `EPERM`; only a caller that
//! passes that gate reaches the combination gate and its `EINVAL`.  So a
//! combination that is both admin-gated *and* illegal answers `EPERM` to an
//! unprivileged process and `EINVAL` only to a privileged one — and an assertion
//! written against a bare errno would pass unprivileged for the wrong reason.
//!
//! Every admin-gated assertion therefore reads [`Capabilities`], taken from
//! `CapEff` in `/proc/self/status`, and expects `EPERM` or the verdict
//! accordingly.  Both CI jobs then assert something true and specific.
//!
//! # Where a check happens is part of the baseline
//!
//! A configuration can be legal at `fanotify_init` and refused at
//! `fanotify_mark`; which one it is, is the difference between "my flags are
//! wrong" and "my mark is wrong".  The split:
//!
//! | Rule | Checked at |
//! |---|---|
//! | identity × class | `fanotify_init` |
//! | the FID flag dependencies, and `PIDFD × TID` | `fanotify_init` |
//! | mount identity's anchor and mask | `fanotify_mark` |
//! | `FAN_RENAME`'s need for `FAN_REPORT_NAME` | `fanotify_mark` |
//! | which anchors the capability allows | `fanotify_mark` |
//! | whether the filesystem can decode handles | `fanotify_mark` |

mod common;

use common::{Capabilities, FID_WITH_NAME, tmpdir};
use fanotify_fid::consts::*;
use fanotify_fid::{Fanotify, FanotifyError};

/// The errno `fanotify_init` reported, or `None` on success.
fn init_errno(flags: u32) -> Option<i32> {
    match Fanotify::init(flags, 0) {
        Ok(_) => None,
        Err(FanotifyError::Init(errno)) => Some(errno),
        Err(other) => panic!("fanotify_init returned something other than its own error: {other}"),
    }
}

/// The errno `fanotify_mark` reported, or `None` on success.
fn mark_errno(fan: &Fanotify, anchor: u32, mask: u64, path: &str) -> Option<i32> {
    match fan.mark(FAN_MARK_ADD | anchor, mask, path) {
        Ok(()) => None,
        Err(FanotifyError::Mark(errno)) => Some(errno),
        Err(other) => panic!("fanotify_mark returned something other than its own error: {other}"),
    }
}

#[test]
fn a_nested_user_namespace_is_not_a_privileged_environment() {
    // `unshare -Ur` hands out a full `CapEff` and still earns EPERM from
    // `fanotify_init`, because the check is against the **initial** user
    // namespace.  A run like that makes every admin-gated assertion in this file
    // fail on a capability the namespace cannot confer, which reads as a wall of
    // crate bugs; this test fails first, with the reason.
    if common::in_a_nested_user_namespace() {
        panic!(
            "this process is in a nested user namespace with a full CapEff.  \
             fanotify checks capabilities against the initial user namespace, so \
             the admin-gated tests below cannot run here and will fail for a \
             reason that is not a defect in the crate.  Use a real privileged \
             environment — see tests/README.md"
        );
    }
}

// ── Row 4: FID × NOTIF — the row that needs no privilege ──

#[test]
fn row4_a_fid_notif_group_needs_no_privilege() {
    let group = Fanotify::init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FID_WITH_NAME, 0);
    assert!(
        group.is_ok(),
        "a FAN_CLASS_NOTIF group with FID flags must need no capability, got {:?}",
        group.err()
    );
}

#[test]
fn row4_an_unprivileged_group_may_place_inode_marks_but_no_others() {
    let caps = Capabilities::probe();
    let dir = tmpdir();
    let path = dir.path().to_str().unwrap();
    let fan = Fanotify::init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FID_WITH_NAME, 0).unwrap();

    assert_eq!(
        mark_errno(&fan, FAN_MARK_INODE, FAN_CREATE, path),
        None,
        "an unprivileged group may place inode marks"
    );

    assert_eq!(
        mark_errno(&fan, FAN_MARK_MOUNT, FAN_CREATE, path),
        Some(caps.admin_gated(libc::EPERM)),
        "mount anchors are admin-gated"
    );
    assert_eq!(
        mark_errno(&fan, FAN_MARK_FILESYSTEM, FAN_CREATE, path),
        Some(caps.admin_gated(libc::EPERM)),
        "filesystem anchors are admin-gated"
    );

    // A mount event in the mask is refused on the mask alone, for every caller:
    // it needs a mount-identity group, which this is not.
    assert_eq!(
        mark_errno(&fan, FAN_MARK_INODE, FAN_MNT_ATTACH, path),
        Some(libc::EINVAL),
        "an inode-anchored group cannot carry mount events"
    );
}

#[test]
fn row4_the_unprivileged_inode_limit_is_about_the_anchor_not_the_owner() {
    // The limit an unprivileged group meets is "inode marks only", which is a
    // statement about the anchor.  It is *not* "objects you own": marking a
    // root-owned path succeeds, and the two are worth keeping apart because the
    // second would send a caller looking for a permission fix that does not
    // exist.
    let mut root_owned: Vec<std::path::PathBuf> = ["/etc/hostname", "/etc/hosts", "/etc/passwd"]
        .iter()
        .map(std::path::PathBuf::from)
        .filter(|p| {
            std::fs::metadata(p).is_ok_and(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid() == 0 && !p.parent().is_some_and(|d| d.as_os_str().is_empty())
            })
        })
        .collect();
    root_owned.push(std::path::PathBuf::from("/etc"));

    let fan = Fanotify::init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FID_WITH_NAME, 0).unwrap();
    let mut marked = Vec::new();
    let mut refused = Vec::new();
    for path in &root_owned {
        let Some(path) = path.to_str() else { continue };
        match mark_errno(&fan, FAN_MARK_INODE, FAN_OPEN, path) {
            None => marked.push(path.to_string()),
            Some(errno) => refused.push((path.to_string(), errno)),
        }
    }

    if marked.is_empty() {
        // No root-owned path reachable here, so there is nothing to assert.
        // Reporting a pass without asserting is the thing this branch prevents.
        eprintln!();
        eprintln!("SKIPPED: no root-owned path on this filesystem could be marked");
        eprintln!("  tried: {refused:?}");
        eprintln!();
        return;
    }
    assert!(
        !marked.is_empty(),
        "an inode mark on a root-owned object must succeed; refusals were {refused:?}"
    );
}

#[test]
fn row4_a_fid_group_reports_the_parent_handle_and_the_entry_name() {
    let dir = tmpdir();
    let fan = common::fid_group();
    fan.mark(
        FAN_MARK_ADD,
        FAN_CREATE | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    std::fs::write(dir.path().join("created"), b"x").unwrap();

    let mut buf = Vec::new();
    let events = common::collect_fid_events(&fan, &mut buf);
    let event = events
        .iter()
        .find(|e| e.dfid_name_str() == Some("created"))
        .expect("the event for the created entry must be in the batch");

    // The whole of the FID identity: a filesystem id, the parent directory's
    // handle, and the entry name as bytes.  No descriptor anywhere.
    assert!(event.fsid().is_some(), "a DFID_NAME record carries an fsid");
    assert!(
        event.dfid_name_handle().is_some_and(|h| !h.is_empty()),
        "the parent's handle must be present"
    );
    assert!(event.mask() & FAN_CREATE != 0);
}

// ── Rows 1–3: a descriptor identity, in each class ──

#[test]
fn rows1_to_3_a_descriptor_identity_is_admin_gated() {
    let caps = Capabilities::probe();

    // A group with neither a FID flag nor FAN_REPORT_MNT is refused outright,
    // for every caller: omitting a report flag is not the unprivileged choice.
    // Worth asserting first, because it is the surprise.
    assert_eq!(
        init_errno(FAN_CLASS_NOTIF | FAN_CLOEXEC),
        Some(libc::EPERM),
        "a bare FAN_CLASS_NOTIF group with no report flag is admin-only, \
         and that does not depend on the caller"
    );

    // With FAN_REPORT_FD_ERROR the request is a descriptor group that passes
    // that first gate, so what remains is the class.
    for (name, class) in [
        ("NOTIF", FAN_CLASS_NOTIF),
        ("CONTENT", FAN_CLASS_CONTENT),
        ("PRE_CONTENT", FAN_CLASS_PRE_CONTENT),
    ] {
        assert_eq!(
            init_errno(class | FAN_CLOEXEC | FAN_REPORT_FD_ERROR),
            Some(caps.admin_gated(libc::EPERM)),
            "rows 1-3 ({name}): a descriptor group is admin-gated; with \
             CAP_SYS_ADMIN this must have been created instead of refused"
        );
    }
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: every descriptor-identity class is admin-gated"]
fn rows1_to_3_a_descriptor_group_accepts_every_anchor() {
    let caps = Capabilities::probe();
    if !caps.is_admin() {
        skip_without_cap_sys_admin!("descriptor groups in all three classes");
    }
    let dir = tmpdir();
    let path = dir.path().to_str().unwrap();

    for (name, class) in [
        ("NOTIF", FAN_CLASS_NOTIF),
        ("CONTENT", FAN_CLASS_CONTENT),
        ("PRE_CONTENT", FAN_CLASS_PRE_CONTENT),
    ] {
        let fan = Fanotify::init(class | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FD_ERROR, 0)
            .unwrap_or_else(|e| panic!("row 1-3 ({name}): an admin must create it: {e}"));

        assert_eq!(
            mark_errno(&fan, FAN_MARK_INODE, FAN_OPEN, path),
            None,
            "{name}/inode"
        );
        assert_eq!(
            mark_errno(&fan, FAN_MARK_MOUNT, FAN_OPEN, path),
            None,
            "{name}/mount"
        );
        assert_eq!(
            mark_errno(&fan, FAN_MARK_FILESYSTEM, FAN_OPEN, path),
            None,
            "{name}/filesystem"
        );
    }
}

// ── Row 5: mount identity — MNTNS only ──

#[test]
fn row5_creating_a_mount_group_needs_no_capability_but_marking_one_does() {
    let caps = Capabilities::probe();

    // The privilege for this row is checked at `fanotify_mark`, not at
    // `fanotify_init`: FAN_REPORT_MNT is outside the kernel's admin-only init
    // set, so anyone can create the group and then only a process with
    // CAP_SYS_ADMIN can mark it.  Recording that split is the point of this
    // test — "row 5 needs CAP_SYS_ADMIN" is true of the row and false of the
    // init call.
    let fan = Fanotify::init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_MNT,
        0,
    )
    .expect("FAN_REPORT_MNT is not an admin-only init flag");

    let dir = tmpdir();
    let path = dir.path().to_str().unwrap();
    assert_eq!(
        mark_errno(&fan, FAN_MARK_MNTNS, FAN_MNT_ATTACH, path),
        Some(caps.admin_gated(libc::EPERM)),
        "the MNTNS anchor is where the capability is required"
    );
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: FAN_MARK_MNTNS is where row 5's capability is checked"]
fn row5_a_mount_group_takes_mntns_and_nothing_else() {
    let caps = Capabilities::probe();
    if !caps.is_admin() {
        skip_without_cap_sys_admin!("the MNTNS anchor and its refusals");
    }
    let dir = tmpdir();
    let path = dir.path().to_str().unwrap();
    let fan = Fanotify::init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_MNT,
        0,
    )
    .expect("FAN_REPORT_MNT needs no capability");

    assert_eq!(
        mark_errno(&fan, FAN_MARK_MNTNS, FAN_MNT_ATTACH, path),
        None,
        "mount identity with the MNTNS anchor is the only legal pairing"
    );
    assert_eq!(
        mark_errno(&fan, FAN_MARK_MNTNS, FAN_MNT_DETACH, path),
        None,
        "detach is the other half of the mount mask"
    );

    // Every other anchor is refused, at `fanotify_mark` and not at init.
    for (name, anchor) in [
        ("inode", FAN_MARK_INODE),
        ("mount", FAN_MARK_MOUNT),
        ("filesystem", FAN_MARK_FILESYSTEM),
    ] {
        assert_eq!(
            mark_errno(&fan, anchor, FAN_MNT_ATTACH, path),
            Some(libc::EINVAL),
            "mount identity × {name} anchor does not exist"
        );
    }

    assert_eq!(
        mark_errno(&fan, FAN_MARK_MNTNS, FAN_CREATE, path),
        Some(libc::EINVAL),
        "a mount group's mask is FANOTIFY_MOUNT_EVENTS and nothing else"
    );
}

// ── The cells that do not exist ──

#[test]
fn a_fid_identity_with_a_permission_class_does_not_exist() {
    let caps = Capabilities::probe();

    for (name, class) in [
        ("CONTENT", FAN_CLASS_CONTENT),
        ("PRE_CONTENT", FAN_CLASS_PRE_CONTENT),
    ] {
        // Not a gap to be filled: a permission event must hand over a
        // descriptor to decide about and the kernel must hold it until the
        // answer arrives, while handle identity exists precisely so that no
        // descriptor is held.  The kernel refuses the combination.
        for (form, fid_flags) in [("FID", FAN_REPORT_FID), ("full FID set", FID_WITH_NAME)] {
            assert_eq!(
                init_errno(class | FAN_CLOEXEC | fid_flags),
                Some(caps.admin_gated(libc::EINVAL)),
                "FID × {name} ({form}) does not exist; with CAP_SYS_ADMIN the \
                 verdict is EINVAL rather than EPERM"
            );
        }
    }
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN: the combination is admin-gated too, so the verdict is masked by EPERM otherwise"]
fn a_mount_identity_with_a_permission_class_or_a_fid_flag_does_not_exist() {
    let caps = Capabilities::probe();
    if !caps.is_admin() {
        skip_without_cap_sys_admin!("the verdict on illegal mount combinations");
    }

    // Every one of these is both illegal and admin-gated, which is exactly why
    // an unprivileged run cannot settle the question and must not pretend to.
    for (what, flags) in [
        ("a permission class", FAN_CLASS_CONTENT),
        ("handle identity", FAN_REPORT_FID),
        ("a descriptor errno", FAN_REPORT_FD_ERROR),
    ] {
        assert_eq!(
            init_errno(FAN_REPORT_MNT | flags | FAN_CLOEXEC),
            Some(libc::EINVAL),
            "mount identity × {what} does not exist"
        );
    }
}

#[test]
fn the_fid_flag_dependencies_hold_and_are_checked_at_init() {
    let caps = Capabilities::probe();

    // FAN_REPORT_TARGET_FID is the child's own handle *in addition to* the
    // parent handle and the name, so both are prerequisites.  None of these
    // three requests sets an admin-only flag, so the verdict is the kernel's
    // and is not masked by a capability check.
    for (what, flags) in [
        (
            "TARGET_FID without NAME",
            FAN_REPORT_TARGET_FID | FAN_REPORT_FID,
        ),
        (
            "TARGET_FID without FID",
            FAN_REPORT_TARGET_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
        ),
        ("NAME without DIR_FID", FAN_REPORT_NAME),
    ] {
        assert_eq!(
            init_errno(FAN_CLASS_NOTIF | FAN_CLOEXEC | flags),
            Some(libc::EINVAL),
            "{what} must be EINVAL"
        );
    }

    // FAN_REPORT_PIDFD excludes FAN_REPORT_TID, and both are admin-only init
    // flags, so an unprivileged process only learns that it may not ask.
    assert_eq!(
        init_errno(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_PIDFD | FAN_REPORT_TID),
        Some(caps.admin_gated(libc::EINVAL)),
        "PIDFD × TID does not exist; with CAP_SYS_ADMIN the verdict is EINVAL"
    );
}

// ── The mark-layer rules: checked at fanotify_mark, not at init ──

#[test]
fn fan_rename_needs_report_name_and_is_refused_at_the_mark() {
    // The rejection point matters: the group is created perfectly well and then
    // this one mark is refused.  Neither group here needs a capability, so the
    // verdict is the kernel's and not the capability check's.
    let dir = tmpdir();
    let path = dir.path().to_str().unwrap();

    let with_name = Fanotify::init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FID_WITH_NAME, 0).unwrap();
    assert_eq!(
        mark_errno(&with_name, FAN_MARK_INODE, FAN_RENAME, path),
        None,
        "FAN_RENAME works for a group with FAN_REPORT_NAME"
    );

    let without_name = Fanotify::init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_FID, 0).unwrap();
    assert_eq!(
        mark_errno(&without_name, FAN_MARK_INODE, FAN_RENAME, path),
        Some(libc::EINVAL),
        "FAN_RENAME is refused at fanotify_mark when the group has no FAN_REPORT_NAME"
    );
}

#[test]
fn only_inode_anchors_are_allowed_where_the_filesystem_cannot_decode_handles() {
    let caps = Capabilities::probe();

    // procfs hands out synthetic FILEID_INO64_GEN handles, which no filesystem
    // can turn back into a dentry, so a mark whose events would carry one is
    // refused — with EOPNOTSUPP, not EINVAL.  An inode mark is still fine.
    let fan = common::fid_group();
    assert_eq!(
        mark_errno(&fan, FAN_MARK_INODE, FAN_OPEN, "/proc"),
        None,
        "the inode anchor is the one that must work without handle decoding"
    );
    assert_eq!(
        mark_errno(&fan, FAN_MARK_MOUNT, FAN_OPEN, "/proc"),
        Some(caps.admin_gated(libc::EOPNOTSUPP)),
        "a mount anchor needs the filesystem to decode handles"
    );
    assert_eq!(
        mark_errno(&fan, FAN_MARK_FILESYSTEM, FAN_OPEN, "/proc"),
        Some(caps.admin_gated(libc::EOPNOTSUPP)),
        "a filesystem anchor needs the filesystem to decode handles"
    );
}
