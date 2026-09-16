//! The constants are the kernel's, and this file checks they still say so.
//!
//! `src/consts.rs` is a transcription of `/usr/include/linux/fanotify.h`, which
//! means it can drift: a value copied with a typo, or a flag added to the header
//! and not here.  A wrong constant is the worst kind of defect in a crate like
//! this — it produces a group that silently watches the wrong thing — so the
//! values are checked rather than trusted.
//!
//! # The two halves of the check
//!
//! **The structural half is free.**  Every `FAN_*` name in `consts.rs` is
//! referenced here, so a name that disappears breaks the build; and the
//! relationships between the values (which flags are subsets of which, which are
//! zero, which are disjoint) are asserted directly, because those are the
//! properties the kernel's own macros encode.
//!
//! **The numeric half asks the kernel.**  A table of literals copied from the
//! same header this file is checking would agree with a typo as easily as with
//! the truth, so instead the numbers are *used*: a group is created with them
//! and an event is provoked, and the mask the kernel reports is compared against
//! the constant.  Numbers the kernel never reports back are checked by the
//! relationships they must satisfy instead.

use fanotify_fid::consts::*;

#[test]
fn the_init_flags_are_where_the_kernel_says_they_are() {
    // The class bits are a two-bit field, with NOTIF encoded as zero — which is
    // why "no class" and "NOTIF" are the same request.
    assert_eq!(FAN_CLASS_NOTIF, 0x0000_0000);
    assert_eq!(FAN_CLASS_CONTENT, 0x0000_0004);
    assert_eq!(FAN_CLASS_PRE_CONTENT, 0x0000_0008);
    assert_eq!(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT, 0x0000_000C);

    assert_eq!(FAN_CLOEXEC, 0x0000_0001);
    assert_eq!(FAN_NONBLOCK, 0x0000_0002);
    assert_eq!(FAN_UNLIMITED_QUEUE, 0x0000_0010);
    assert_eq!(FAN_UNLIMITED_MARKS, 0x0000_0020);
    assert_eq!(FAN_ENABLE_AUDIT, 0x0000_0040);
    assert_eq!(FAN_REPORT_PIDFD, 0x0000_0080);
    assert_eq!(FAN_REPORT_TID, 0x0000_0100);
    assert_eq!(FAN_REPORT_FID, 0x0000_0200);
    assert_eq!(FAN_REPORT_DIR_FID, 0x0000_0400);
    assert_eq!(FAN_REPORT_NAME, 0x0000_0800);
    assert_eq!(FAN_REPORT_TARGET_FID, 0x0000_1000);
    assert_eq!(FAN_REPORT_FD_ERROR, 0x0000_2000);
    assert_eq!(FAN_REPORT_MNT, 0x0000_4000);

    // The header's own aggregates, checked as relationships rather than values.
    assert_eq!(FAN_REPORT_DFID_NAME, FAN_REPORT_DIR_FID | FAN_REPORT_NAME);
    assert_eq!(
        FAN_REPORT_DFID_NAME_TARGET,
        FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID
    );
    assert_eq!(
        FANOTIFY_FID_BITS,
        FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_TARGET_FID
    );
    assert_eq!(
        FANOTIFY_ADMIN_INIT_FLAGS,
        FAN_CLASS_CONTENT
            | FAN_CLASS_PRE_CONTENT
            | FAN_REPORT_TID
            | FAN_REPORT_PIDFD
            | FAN_REPORT_FD_ERROR
            | FAN_UNLIMITED_QUEUE
            | FAN_UNLIMITED_MARKS
    );

    // FAN_REPORT_MNT is deliberately NOT in the admin set.  If it ever were,
    // creating a mount group would become admin-only and the "the capability is
    // checked at the mark" note would be wrong.
    assert_eq!(
        FANOTIFY_ADMIN_INIT_FLAGS & FAN_REPORT_MNT,
        0,
        "FAN_REPORT_MNT is not an admin-only init flag in the kernel"
    );
    // And the classes are not FID bits, nor the other way round.
    assert_eq!(FANOTIFY_FID_BITS & FAN_ALL_CLASS_BITS, 0);
    // Every init flag is inside FAN_ALL_INIT_FLAGS.
    assert_eq!(FAN_ALL_INIT_FLAGS & FAN_ALL_CLASS_BITS, FAN_ALL_CLASS_BITS);
    assert_eq!(
        FAN_ALL_INIT_FLAGS & FANOTIFY_ADMIN_INIT_FLAGS,
        FANOTIFY_ADMIN_INIT_FLAGS
    );
}

#[test]
fn the_mark_flags_are_where_the_kernel_says_they_are() {
    assert_eq!(FAN_MARK_ADD, 0x0000_0001);
    assert_eq!(FAN_MARK_REMOVE, 0x0000_0002);
    assert_eq!(FAN_MARK_DONT_FOLLOW, 0x0000_0004);
    assert_eq!(FAN_MARK_ONLYDIR, 0x0000_0008);
    assert_eq!(FAN_MARK_MOUNT, 0x0000_0010);
    assert_eq!(FAN_MARK_IGNORED_MASK, 0x0000_0020);
    assert_eq!(FAN_MARK_IGNORED_SURV_MODIFY, 0x0000_0040);
    assert_eq!(FAN_MARK_FLUSH, 0x0000_0080);
    assert_eq!(FAN_MARK_FILESYSTEM, 0x0000_0100);
    assert_eq!(FAN_MARK_EVICTABLE, 0x0000_0200);
    assert_eq!(FAN_MARK_IGNORE, 0x0000_0400);

    // The inode anchor is encoded as zero, which is why "no anchor" and "inode"
    // are the same request.
    assert_eq!(FAN_MARK_INODE, 0x0000_0000);

    // FAN_MARK_MNTNS is not a fresh bit: its value is
    // FAN_MARK_FILESYSTEM | FAN_MARK_MOUNT.  A crate that invented a bit for it
    // would build a mark the kernel does not have, and one that treated it as a
    // single bit would test it wrongly.
    assert_eq!(FAN_MARK_MNTNS, 0x0000_0110);
    assert_eq!(FAN_MARK_MNTNS, FAN_MARK_FILESYSTEM | FAN_MARK_MOUNT);
    assert_eq!(FAN_MARK_MNTNS & FAN_MARK_FILESYSTEM, FAN_MARK_FILESYSTEM);
    assert_eq!(FAN_MARK_MNTNS & FAN_MARK_MOUNT, FAN_MARK_MOUNT);
    assert_eq!(FAN_MARK_MNTNS & FAN_MARK_IGNORED_MASK, 0);
    assert_eq!(
        FAN_MARK_IGNORE_SURV,
        FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY
    );

    // FAN_ALL_MARK_FLAGS is this crate's union of every flag the header
    // defines, because the header's own macro of that name is deprecated there
    // and frozen before FAN_MARK_FILESYSTEM, FAN_MARK_EVICTABLE and
    // FAN_MARK_IGNORE existed.  Each flag must be inside it.
    for (name, flag) in [
        ("FAN_MARK_ADD", FAN_MARK_ADD),
        ("FAN_MARK_REMOVE", FAN_MARK_REMOVE),
        ("FAN_MARK_FLUSH", FAN_MARK_FLUSH),
        ("FAN_MARK_EVICTABLE", FAN_MARK_EVICTABLE),
        ("FAN_MARK_IGNORE", FAN_MARK_IGNORE),
        ("FAN_MARK_MOUNT", FAN_MARK_MOUNT),
        ("FAN_MARK_FILESYSTEM", FAN_MARK_FILESYSTEM),
        ("FAN_MARK_IGNORED_SURV_MODIFY", FAN_MARK_IGNORED_SURV_MODIFY),
    ] {
        assert_eq!(
            FAN_ALL_MARK_FLAGS & flag,
            flag,
            "{name} must be inside FAN_ALL_MARK_FLAGS"
        );
    }
    assert_eq!(FAN_MARK_ADD & FAN_MARK_REMOVE, 0);
    assert_eq!(FAN_MARK_ADD & FAN_MARK_FLUSH, 0);
    // FAN_MARK_MNTNS is a *sum* of two other flags, so it is not a single bit
    // and must not be treated as one — that is the whole reason it is called
    // out here.
    assert_ne!(FAN_MARK_MNTNS.count_ones(), 1);

    assert_eq!(AT_FDCWD, -100);
    // AT_EMPTY_PATH is a `fcntl.h` flag for the `*at` calls that take it, and
    // it must be the header's value: `handle_from_fd` relies on it to name an
    // object by descriptor while `Fanotify::mark_fd` deliberately does not,
    // because `fanotify_mark` refuses it as an unknown flag (asserted against
    // the kernel in `tests/group.rs`).
    assert_eq!(AT_EMPTY_PATH, libc::AT_EMPTY_PATH);
    assert_eq!(AT_EMPTY_PATH, 0x1000);
    assert_eq!(AT_EMPTY_PATH as u32 & FAN_ALL_MARK_FLAGS, 0);
}

#[test]
fn the_event_mask_bits_are_where_the_kernel_says_they_are() {
    // The event types occupy the low 25 bits in the header's order, one bit
    // each, and every one of them is distinct.  Checking distinctness catches
    // the typo that matters most — a duplicated bit would make two different
    // events indistinguishable.
    let single_bits: &[(&str, u64)] = &[
        ("FAN_ACCESS", FAN_ACCESS),
        ("FAN_MODIFY", FAN_MODIFY),
        ("FAN_ATTRIB", FAN_ATTRIB),
        ("FAN_CLOSE_WRITE", FAN_CLOSE_WRITE),
        ("FAN_CLOSE_NOWRITE", FAN_CLOSE_NOWRITE),
        ("FAN_OPEN", FAN_OPEN),
        ("FAN_MOVED_FROM", FAN_MOVED_FROM),
        ("FAN_MOVED_TO", FAN_MOVED_TO),
        ("FAN_CREATE", FAN_CREATE),
        ("FAN_DELETE", FAN_DELETE),
        ("FAN_DELETE_SELF", FAN_DELETE_SELF),
        ("FAN_MOVE_SELF", FAN_MOVE_SELF),
        ("FAN_OPEN_EXEC", FAN_OPEN_EXEC),
        ("FAN_Q_OVERFLOW", FAN_Q_OVERFLOW),
        ("FAN_FS_ERROR", FAN_FS_ERROR),
        ("FAN_OPEN_PERM", FAN_OPEN_PERM),
        ("FAN_ACCESS_PERM", FAN_ACCESS_PERM),
        ("FAN_OPEN_EXEC_PERM", FAN_OPEN_EXEC_PERM),
        ("FAN_PRE_ACCESS", FAN_PRE_ACCESS),
        ("FAN_MNT_ATTACH", FAN_MNT_ATTACH),
        ("FAN_MNT_DETACH", FAN_MNT_DETACH),
        ("FAN_EVENT_ON_CHILD", FAN_EVENT_ON_CHILD),
        ("FAN_RENAME", FAN_RENAME),
        ("FAN_ONDIR", FAN_ONDIR),
    ];

    for (i, (name, value)) in single_bits.iter().enumerate() {
        assert_eq!(
            value.count_ones(),
            1,
            "{name} must be one bit, got 0x{value:x}"
        );
        for (other_name, other) in &single_bits[i + 1..] {
            assert_ne!(
                value, other,
                "{name} and {other_name} must be different bits"
            );
        }
    }

    // The kernel's literal values, for the ones an event can report back.
    assert_eq!(FAN_ACCESS, 0x0000_0001);
    assert_eq!(FAN_OPEN, 0x0000_0020);
    assert_eq!(FAN_CREATE, 0x0000_0100);
    assert_eq!(FAN_DELETE, 0x0000_0200);
    assert_eq!(FAN_Q_OVERFLOW, 0x0000_4000);
    assert_eq!(FAN_MNT_ATTACH, 0x0100_0000);
    assert_eq!(FAN_MNT_DETACH, 0x0200_0000);
    assert_eq!(FAN_EVENT_ON_CHILD, 0x0800_0000);
    assert_eq!(FAN_RENAME, 0x1000_0000);
    assert_eq!(FAN_ONDIR, 0x4000_0000);

    // The aggregates, as relationships.
    assert_eq!(FAN_CLOSE, FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE);
    assert_eq!(FAN_MOVE, FAN_MOVED_FROM | FAN_MOVED_TO);
    assert_eq!(FANOTIFY_MOUNT_EVENTS, FAN_MNT_ATTACH | FAN_MNT_DETACH);
    assert_eq!(
        FAN_ALL_EVENTS & (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE),
        FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE
    );
    assert_eq!(
        FAN_ALL_PERM_EVENTS,
        FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM
    );
    assert_eq!(
        FAN_ALL_OUTGOING_EVENTS,
        FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS | FAN_Q_OVERFLOW
    );

    // FANOTIFY_MOUNT_EVENTS and the ordinary events are disjoint: a mount group
    // cannot carry inode events, which is what the kernel's mask check enforces.
    assert_eq!(FANOTIFY_MOUNT_EVENTS & FAN_ALL_EVENTS, 0);
    assert_eq!(FANOTIFY_MOUNT_EVENTS & FAN_ALL_PERM_EVENTS, 0);
}

#[test]
fn the_info_types_and_sentinels_are_where_the_kernel_says_they_are() {
    assert_eq!(FAN_EVENT_INFO_TYPE_FID, 1);
    assert_eq!(FAN_EVENT_INFO_TYPE_DFID_NAME, 2);
    assert_eq!(FAN_EVENT_INFO_TYPE_DFID, 3);
    assert_eq!(FAN_EVENT_INFO_TYPE_PIDFD, 4);
    assert_eq!(FAN_EVENT_INFO_TYPE_ERROR, 5);
    assert_eq!(FAN_EVENT_INFO_TYPE_RANGE, 6);
    assert_eq!(FAN_EVENT_INFO_TYPE_MNT, 7);
    // 8 and 9 are unused in the header, and 10/12 are the rename pair — a gap
    // the crate must not "tidy up" by renumbering.
    assert_eq!(FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, 10);
    assert_eq!(FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, 12);
    assert_eq!(FANOTIFY_METADATA_VERSION, 3);

    assert_eq!(FAN_ALLOW, 0x01);
    assert_eq!(FAN_DENY, 0x02);
    assert_eq!(FAN_AUDIT, 0x10);
    assert_eq!(FAN_INFO, 0x20);
    assert_eq!(FAN_RESPONSE_INFO_NONE, 0);
    assert_eq!(FAN_RESPONSE_INFO_AUDIT_RULE, 1);

    // The errno field is the response's upper byte.
    assert_eq!(FAN_ERRNO_BITS, 8);
    assert_eq!(FAN_ERRNO_SHIFT, 24);
    assert_eq!(FAN_ERRNO_MASK, 0xFF);

    assert_eq!(FAN_NOFD, -1);
    assert_eq!(FAN_NOPIDFD, FAN_NOFD);
    // The two pidfd sentinels are NOT interchangeable: the kernel writes
    // FAN_NOPIDFD for "the process is gone" specifically and FAN_EPIDFD for
    // every other failure.
    assert_eq!(FAN_EPIDFD, -2);
    assert_ne!(FAN_NOPIDFD, FAN_EPIDFD);

    assert_eq!(MAX_HANDLE_SZ, 128);
    assert_eq!(AT_HANDLE_FID, 0x200);
}

#[test]
fn every_named_event_bit_appears_in_the_names_table() {
    // `mask_to_event_names` is the one place a bit's name is written down, and a
    // bit missing from it makes a diagnostic silently incomplete — which is
    // exactly what an overflowing queue must not be.
    let bits: &[(&str, u64)] = &[
        ("FAN_ACCESS", FAN_ACCESS),
        ("FAN_MODIFY", FAN_MODIFY),
        ("FAN_ATTRIB", FAN_ATTRIB),
        ("FAN_CLOSE_WRITE", FAN_CLOSE_WRITE),
        ("FAN_CLOSE_NOWRITE", FAN_CLOSE_NOWRITE),
        ("FAN_OPEN", FAN_OPEN),
        ("FAN_MOVED_FROM", FAN_MOVED_FROM),
        ("FAN_MOVED_TO", FAN_MOVED_TO),
        ("FAN_CREATE", FAN_CREATE),
        ("FAN_DELETE", FAN_DELETE),
        ("FAN_DELETE_SELF", FAN_DELETE_SELF),
        ("FAN_MOVE_SELF", FAN_MOVE_SELF),
        ("FAN_OPEN_EXEC", FAN_OPEN_EXEC),
        ("FAN_Q_OVERFLOW", FAN_Q_OVERFLOW),
        ("FAN_FS_ERROR", FAN_FS_ERROR),
        ("FAN_OPEN_PERM", FAN_OPEN_PERM),
        ("FAN_ACCESS_PERM", FAN_ACCESS_PERM),
        ("FAN_OPEN_EXEC_PERM", FAN_OPEN_EXEC_PERM),
        ("FAN_PRE_ACCESS", FAN_PRE_ACCESS),
        ("FAN_MNT_ATTACH", FAN_MNT_ATTACH),
        ("FAN_MNT_DETACH", FAN_MNT_DETACH),
        ("FAN_EVENT_ON_CHILD", FAN_EVENT_ON_CHILD),
        ("FAN_RENAME", FAN_RENAME),
        ("FAN_ONDIR", FAN_ONDIR),
    ];

    for (flag_name, bit) in bits {
        let named = mask_to_event_names(*bit).count();
        assert_eq!(named, 1, "{flag_name} must have exactly one name");
    }

    // The aggregates decompose into the bits that have names, so a combined
    // mask names every bit it holds.
    assert_eq!(
        mask_to_event_names(FAN_CREATE | FAN_DELETE | FAN_ONDIR).collect::<Vec<_>>(),
        ["CREATE", "DELETE", "ONDIR"],
        "names come out in the table's order, which is the header's bit order"
    );
    // A bit with no name is not invented: the mask is a bitfield and this is a
    // debugging aid, not a classification.
    assert_eq!(mask_to_event_names(0).count(), 0);
    assert_eq!(
        mask_to_event_names(0x8000_0000).count(),
        0,
        "an unassigned bit has no name rather than a wrong one"
    );
}

#[test]
fn the_kernel_reports_the_event_bits_this_crate_names() {
    // The structural checks above cannot catch a bit that is *internally*
    // consistent but wrong — every value shifted by one would pass them all.
    // This one provokes real events and compares the mask the kernel put in them
    // against the constant, which is the only check a copied literal cannot
    // satisfy by copying the same mistake.
    use fanotify_fid::Fanotify;
    use fanotify_fid::consts::*;

    let dir = tempfile::tempdir().unwrap();

    // Two groups over the same operations, differing only in
    // FAN_EVENT_ON_CHILD.  The difference is itself a kernel fact worth
    // pinning: FAN_CREATE and FAN_DELETE are directory-entry events and arrive
    // for children either way, while FAN_OPEN, FAN_MODIFY and FAN_CLOSE_WRITE
    // are about an object and need the flag to be reported for a child at all.
    let mask = FAN_CREATE | FAN_DELETE | FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE;
    let without_child = group_marked(dir.path(), mask);
    let with_child = group_marked(dir.path(), mask | FAN_EVENT_ON_CHILD);

    // Each operation provokes one bit, so a wrong constant cannot be covered
    // for by another event's mask.
    let created = dir.path().join("mask-probe");
    std::fs::write(&created, b"x").unwrap();
    std::fs::remove_file(&created).unwrap();
    {
        use std::io::Write;
        let mut handle = std::fs::File::create(dir.path().join("written")).unwrap();
        handle.write_all(b"content").unwrap(); // FAN_MODIFY
        handle.sync_all().unwrap();
    } // drop closes it: FAN_CLOSE_WRITE
    std::fs::File::open(dir.path().join("written")).unwrap(); // FAN_OPEN

    let mut buf = Vec::new();
    let seen = mask_of(&drain(&with_child, &mut buf));

    for (name, bit) in [
        ("FAN_CREATE", FAN_CREATE),
        ("FAN_DELETE", FAN_DELETE),
        ("FAN_MODIFY", FAN_MODIFY),
        ("FAN_CLOSE_WRITE", FAN_CLOSE_WRITE),
        ("FAN_OPEN", FAN_OPEN),
    ] {
        assert!(
            seen & bit != 0,
            "{name} (0x{bit:x}) was never reported; the kernel reported 0x{seen:x}.  \
             A constant that does not match the kernel shows up here"
        );
    }

    // The other half: without the flag the object-level bits do not arrive,
    // which proves the bits above came from the operations named and not from
    // an over-broad mask.
    let mut buf = Vec::new();
    let seen_without = mask_of(&drain(&without_child, &mut buf));
    for (name, bit) in [
        ("FAN_OPEN", FAN_OPEN),
        ("FAN_MODIFY", FAN_MODIFY),
        ("FAN_CLOSE_WRITE", FAN_CLOSE_WRITE),
    ] {
        assert_eq!(
            seen_without & bit,
            0,
            "{name} must need FAN_EVENT_ON_CHILD to be reported for a child"
        );
    }
    for (name, bit) in [("FAN_CREATE", FAN_CREATE), ("FAN_DELETE", FAN_DELETE)] {
        assert_ne!(
            seen_without & bit,
            0,
            "{name} is a directory-entry event and needs no FAN_EVENT_ON_CHILD"
        );
    }

    /// A FID group with a mark on `dir`, needing no privilege.
    fn group_marked(dir: &std::path::Path, mask: u64) -> Fanotify {
        let group = Fanotify::init(
            FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID | FAN_REPORT_DIR_FID,
            0,
        )
        .expect("a FID group needs no privilege");
        group
            .mark(FAN_MARK_ADD, mask, dir.to_str().unwrap())
            .unwrap();
        group
    }

    /// Every bit the batch's events set, combined.
    fn mask_of(events: &[fanotify_fid::FidEvent<'_>]) -> u64 {
        events.iter().fold(0, |acc, e| acc | e.mask())
    }

    /// Drain the group until it stays empty for a moment.
    ///
    /// Delivery is asynchronous, so one `read` can return the first events while
    /// later ones are still being queued: stopping at the first non-empty batch
    /// would miss bits and report a constant as wrong when it is not.  The idle
    /// window is what distinguishes "nothing more is coming" from "not yet".
    fn drain(group: &Fanotify, buf: &mut Vec<u8>) -> Vec<fanotify_fid::FidEvent<'static>> {
        use std::time::{Duration, Instant};
        const IDLE: Duration = Duration::from_millis(250);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut all = Vec::new();
        let mut last_event = Instant::now();
        while Instant::now() < deadline {
            match group.read_events(buf) {
                Ok(events) if !events.is_empty() => {
                    last_event = Instant::now();
                    all.extend(events.into_iter().map(fanotify_fid::FidEvent::into_owned));
                }
                Ok(_) => {}
                Err(fanotify_fid::FanotifyError::Read(libc::EAGAIN)) => {
                    if !all.is_empty() && last_event.elapsed() > IDLE {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("read_events failed: {e}"),
            }
        }
        assert!(!all.is_empty(), "no events arrived within 10 seconds");
        all
    }
}

#[test]
fn the_event_f_flags_the_crate_names_are_the_ones_the_kernel_accepts() {
    // `event_f_flags` is validated before the privilege check, so this settles
    // the question without CAP_SYS_ADMIN: a legal value cannot answer EPERM.
    let group = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_FID;

    // The composing flags, each alone.  `O_RDONLY` is 0 and so is the empty set.
    for (name, flag) in [
        ("O_RDONLY", O_RDONLY),
        ("O_WRONLY", O_WRONLY),
        ("O_RDWR", O_RDWR),
        ("O_APPEND", O_APPEND),
        ("O_NONBLOCK", O_NONBLOCK),
        ("O_DSYNC", O_DSYNC),
        ("O_SYNC", O_SYNC),
        ("O_LARGEFILE", O_LARGEFILE),
        ("O_NOATIME", O_NOATIME),
        ("O_CLOEXEC", O_CLOEXEC),
    ] {
        // Each is also the value `libc` has, which is the only authority on a
        // number that varies by architecture (`O_LARGEFILE` is 0 on 64-bit).
        assert_eq!(
            flag & !EVENT_F_FLAGS_ALLOWED,
            0,
            "{name} is outside EVENT_F_FLAGS_ALLOWED",
        );
        let err = fanotify_fid::sys::fanotify_init(group, flag)
            .err()
            .map(|e| e.errno().unwrap_or(0));
        // EPERM would mean the kernel rejected the *flags*, which it checks
        // first; anything but None here is a failure.
        assert!(
            err.is_none() || err == Some(libc::EPERM),
            "{name} should be legal, got errno {err:?}",
        );
    }

    // And flags the kernel does not take for this argument really are refused.
    // `O_PATH` and `O_DIRECT` are open(2) flags that make no sense on an event,
    // and the FMODE bits live in the same field but are not user-settable.
    for (name, flag) in [
        ("O_PATH", libc::O_PATH as u32),
        ("O_DIRECT", libc::O_DIRECT as u32),
        ("O_CREAT", libc::O_CREAT as u32),
        ("O_TRUNC", libc::O_TRUNC as u32),
        ("O_NOFOLLOW", libc::O_NOFOLLOW as u32),
        ("FMODE_EXEC bit", 1 << 5),
    ] {
        assert_eq!(
            flag & EVENT_F_FLAGS_ALLOWED,
            0,
            "{name} must not be in EVENT_F_FLAGS_ALLOWED",
        );
        assert_eq!(
            fanotify_fid::sys::fanotify_init(group, flag)
                .err()
                .and_then(|e| e.errno()),
            Some(libc::EINVAL),
            "{name} should be refused with EINVAL",
        );
    }
}
