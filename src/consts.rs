//! `FAN_*` constants from the Linux kernel UAPI header `linux/fanotify.h`.
//!
//! These are a **mirror of the header, not a wrapper around it**: each value is
//! transcribed with the numeric literal the header gives it, so a caller can
//! compare this file against `/usr/include/linux/fanotify.h` line by line.  No
//! constant here carries behaviour, and none of them is validated by this crate
//! — the kernel is the authority on what a given combination does (see the
//! crate docs, "What this crate does not do").
//!
//! Two consequences worth stating, because they are easy to get wrong:
//!
//! * Several flags are encoded as **zero** ([`FAN_CLASS_NOTIF`],
//!   [`FAN_MARK_INODE`]), so "absent" and "chosen" are the same bit pattern.
//!   Pass them explicitly when you mean them.
//! * The aggregates ([`FAN_ALL_INIT_FLAGS`], [`FANOTIFY_FID_BITS`], ...) are the
//!   header's own macros, transcribed for reference.  They are useful for
//!   *reading* a group's flags back, not for requesting anything.

// ── fanotify_init(2) flags ──

/// `FAN_CLOEXEC` — set close-on-exec on the fanotify descriptor.
pub const FAN_CLOEXEC: u32 = 0x0000_0001;

/// `FAN_NONBLOCK` — `read` returns `EAGAIN` instead of waiting.
pub const FAN_NONBLOCK: u32 = 0x0000_0002;

/// `FAN_CLASS_NOTIF` — report events after they happen; no decision is awaited.
///
/// This is the class encoded as **zero**, so it is also what an omitted class
/// means.  It is not the "unprivileged" class: a group with no report flag at
/// all requires `CAP_SYS_ADMIN` regardless of its class.
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;

/// `FAN_CLASS_CONTENT` — report permission events for content access.
///
/// An admin-only class, and **mutually exclusive with every FID flag**: the
/// kernel rejects the combination with `EINVAL`, because a permission event must
/// hand the process a descriptor to decide on, while file-handle identity exists
/// precisely so the kernel does *not* hold one.
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;

/// `FAN_CLASS_PRE_CONTENT` — report permission events before content is
/// available.  Admin-only, and exclusive with the FID flags like
/// [`FAN_CLASS_CONTENT`].
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;

/// `FAN_ALL_CLASS_BITS` — the union of the three classes.
pub const FAN_ALL_CLASS_BITS: u32 = FAN_CLASS_NOTIF | FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;

/// `FAN_UNLIMITED_QUEUE` — lift the per-group event-queue limit.
/// Requires `CAP_SYS_ADMIN`.
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;

/// `FAN_UNLIMITED_MARKS` — lift the per-group mark limit.
/// Requires `CAP_SYS_ADMIN`.
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;

/// `FAN_ENABLE_AUDIT` — allow `FAN_AUDIT` responses.
/// Requires `CAP_AUDIT_WRITE`, **not** `CAP_SYS_ADMIN`.
pub const FAN_ENABLE_AUDIT: u32 = 0x0000_0040;

/// `FAN_REPORT_PIDFD` — add a pidfd record to every event.
/// Requires `CAP_SYS_ADMIN`; mutually exclusive with [`FAN_REPORT_TID`].
pub const FAN_REPORT_PIDFD: u32 = 0x0000_0080;

/// `FAN_REPORT_TID` — report a thread id in `metadata.pid` instead of a pid.
/// Requires `CAP_SYS_ADMIN`; mutually exclusive with [`FAN_REPORT_PIDFD`].
pub const FAN_REPORT_TID: u32 = 0x0000_0100;

/// `FAN_REPORT_FID` — identify objects by file handle + fsid rather than by an
/// open descriptor.  The base flag of FID identity.
pub const FAN_REPORT_FID: u32 = 0x0000_0200;

/// `FAN_REPORT_DIR_FID` — report the parent directory's handle for
/// directory-entry events.  Requires nothing beyond being a FID group.
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;

/// `FAN_REPORT_NAME` — include the entry name alongside the parent handle.
/// Requires [`FAN_REPORT_DIR_FID`]; the kernel rejects it alone with `EINVAL`.
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;

/// `FAN_REPORT_TARGET_FID` — include the child's own handle for directory-entry
/// events.  Requires **both** [`FAN_REPORT_NAME`] and [`FAN_REPORT_FID`].
pub const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;

/// `FAN_REPORT_FD_ERROR` — let `metadata.fd` carry a negative errno explaining
/// why an event descriptor could not be opened, instead of only `FAN_NOFD`.
/// Requires `CAP_SYS_ADMIN`; mutually exclusive with [`FAN_REPORT_MNT`].
pub const FAN_REPORT_FD_ERROR: u32 = 0x0000_2000;

/// `FAN_REPORT_MNT` — report mount attach/detach events, identified by mount ID.
///
/// Requires `CAP_SYS_ADMIN`, requires [`FAN_CLASS_NOTIF`], and is mutually
/// exclusive with every FID flag and with [`FAN_REPORT_FD_ERROR`].  A group
/// created with it can only be marked with [`FAN_MARK_MNTNS`], and only with a
/// mask drawn from [`FAN_MNT_ATTACH`] / [`FAN_MNT_DETACH`] — that second rule is
/// checked by `fanotify_mark`, not by `fanotify_init`.
pub const FAN_REPORT_MNT: u32 = 0x0000_4000;

/// `FAN_REPORT_DFID_NAME` — `FAN_REPORT_DIR_FID | FAN_REPORT_NAME`.
pub const FAN_REPORT_DFID_NAME: u32 = FAN_REPORT_DIR_FID | FAN_REPORT_NAME;

/// `FAN_REPORT_DFID_NAME_TARGET` —
/// `FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID`.
pub const FAN_REPORT_DFID_NAME_TARGET: u32 =
    FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID;

/// `FANOTIFY_FID_BITS` — the union of the four FID flags.
///
/// The kernel treats a group as having file-handle identity when **any** of
/// these bits is set, which is why "is this a FID group" is a bit test and not
/// an equality test.  Reading it back is useful; asking for it is a mistake (it
/// would set `FAN_REPORT_TARGET_FID` without its prerequisites).
pub const FANOTIFY_FID_BITS: u32 =
    FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_TARGET_FID;

/// `FANOTIFY_ADMIN_INIT_FLAGS` — the init flags that require `CAP_SYS_ADMIN`.
///
/// The kernel's rule is a single test: without `CAP_SYS_ADMIN`, a request that
/// sets any of these bits, or that sets no FID bit and no [`FAN_REPORT_MNT`],
/// is refused with `EPERM`.  Note what that does *not* include — a FID group's
/// inode marks need no capability, and neither does marking a file it does not
/// own.
pub const FANOTIFY_ADMIN_INIT_FLAGS: u32 = FAN_CLASS_CONTENT
    | FAN_CLASS_PRE_CONTENT
    | FAN_REPORT_TID
    | FAN_REPORT_PIDFD
    | FAN_REPORT_FD_ERROR
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS;

/// `FAN_ALL_INIT_FLAGS` — every flag `fanotify_init` accepts.
pub const FAN_ALL_INIT_FLAGS: u32 = FAN_CLOEXEC
    | FAN_NONBLOCK
    | FAN_ALL_CLASS_BITS
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS
    | FAN_ENABLE_AUDIT
    | FAN_REPORT_PIDFD
    | FAN_REPORT_TID
    | FAN_REPORT_FID
    | FAN_REPORT_DIR_FID
    | FAN_REPORT_NAME
    | FAN_REPORT_TARGET_FID
    | FAN_REPORT_FD_ERROR
    | FAN_REPORT_MNT;

// ── fanotify_mark(2) flags ──

/// `FAN_MARK_ADD` — add the mask bits to the mark.
pub const FAN_MARK_ADD: u32 = 0x0000_0001;

/// `FAN_MARK_REMOVE` — remove the mask bits from the mark.
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;

/// `FAN_MARK_DONT_FOLLOW` — mark a symlink itself, not its target.
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;

/// `FAN_MARK_ONLYDIR` — fail with `ENOTDIR` if the object is not a directory.
pub const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;

/// `FAN_MARK_MOUNT` — anchor the mark at the mount point: every object on that
/// mount is covered.  Requires `CAP_SYS_ADMIN`.
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;

/// `FAN_MARK_IGNORED_MASK` — apply the mask to the ignore mask instead.
pub const FAN_MARK_IGNORED_MASK: u32 = 0x0000_0020;

/// `FAN_MARK_IGNORED_SURV_MODIFY` — the ignore mask survives a modify event.
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;

/// `FAN_MARK_FLUSH` — drop every mark the group holds.
///
/// The kernel ignores the path and requires a zero mask for this call, which is
/// why [`Fanotify::flush_marks`](crate::Fanotify::flush_marks) takes neither:
/// passing the path you marked earns no error and has no effect.
pub const FAN_MARK_FLUSH: u32 = 0x0000_0080;

/// `FAN_MARK_FILESYSTEM` — anchor the mark at the filesystem: every object on it
/// is covered.  Requires `CAP_SYS_ADMIN`, and the filesystem must be able to
/// decode the handles its events will carry.
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

/// `FAN_MARK_EVICTABLE` — let the kernel evict the inode mark under memory
/// pressure (inode marks only).
pub const FAN_MARK_EVICTABLE: u32 = 0x0000_0200;

/// `FAN_MARK_IGNORE` — the modern replacement for [`FAN_MARK_IGNORED_MASK`],
/// with different semantics for which events the ignore mask suppresses.
pub const FAN_MARK_IGNORE: u32 = 0x0000_0400;

/// `FAN_MARK_INODE` — anchor the mark at the inode named by the path/fd.
///
/// Encoded as **zero**, so it is also what "no anchor flag" means.  It is the
/// only anchor an unprivileged group may use — and *not* because of file
/// ownership: marking a root-owned file succeeds.
pub const FAN_MARK_INODE: u32 = 0x0000_0000;

/// `FAN_MARK_MNTNS` — anchor the mark at a mount namespace (Linux 6.14+).
///
/// The only anchor a [`FAN_REPORT_MNT`] group can use.
///
/// Its value, `0x110`, is **not a fresh bit**: it is
/// `FAN_MARK_FILESYSTEM | FAN_MARK_MOUNT`, a combination the older kernels had
/// no name for.  Treat it as one opaque constant — testing it with `&` against
/// a single bit, or adding it to a mask that already holds either half, is a
/// mistake this value's shape invites.
pub const FAN_MARK_MNTNS: u32 = 0x0000_0110;

/// `FAN_MARK_IGNORE_SURV` — `FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY`.
pub const FAN_MARK_IGNORE_SURV: u32 = FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY;

/// The flags `fanotify_mark` accepts in `flags`.
///
/// **Not the header's [`FAN_ALL_MARK_FLAGS`]**, which is marked deprecated
/// there and frozen at the eight flags that existed when it was written — it
/// omits [`FAN_MARK_FILESYSTEM`], [`FAN_MARK_EVICTABLE`] and
/// [`FAN_MARK_IGNORE`], all of which the kernel accepts today.  This is the
/// union of every flag the header defines, which is what the name promises.
pub const FAN_ALL_MARK_FLAGS: u32 = FAN_MARK_ADD
    | FAN_MARK_REMOVE
    | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR
    | FAN_MARK_MOUNT
    | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY
    | FAN_MARK_FLUSH
    | FAN_MARK_FILESYSTEM
    | FAN_MARK_EVICTABLE
    | FAN_MARK_IGNORE
    | FAN_MARK_MNTNS;

/// `AT_FDCWD` — resolve the mark's path relative to the current directory.
pub const AT_FDCWD: i32 = -100;

/// `AT_EMPTY_PATH` from `linux/fcntl.h` — operate on the object a descriptor
/// names, with an empty path.
///
/// The `*at` calls that take it — `name_to_handle_at`, `linkat`, `fstatat`,
/// `readlinkat` — then act on the `dirfd` object itself, which is the
/// TOCTOU-free way to name it: no path is walked, so no rename can change what
/// the descriptor means.  It is what
/// [`handle_from_fd`](crate::handle::handle_from_fd) passes to
/// `name_to_handle_at`.
///
/// **`fanotify_mark` is not one of those calls.**  Its descriptor form is a
/// `NULL` pathname with the object's descriptor as `dirfd` — the kernel takes
/// the path straight from the descriptor — and it answers `EINVAL` for this
/// flag like any other bit it does not know.  See
/// [`Fanotify::mark_fd`](crate::Fanotify::mark_fd) for that form.
pub const AT_EMPTY_PATH: i32 = 0x1000;

// ── event_f_flags: the open(2) flags `fanotify_init` will accept ──
//
// Transcribed from `libc` rather than from a header, because these are
// architecture-dependent and a wrong value is silent: `O_LARGEFILE` is `0x10000`
// on a 32-bit system and `0` on a 64-bit one, so a hard-coded number is correct
// on exactly one of them — and the kernel answers `EINVAL` for the wrong one.
// Re-exporting the value `libc` already has keeps one source of truth.
// `tests/consts.rs` checks these against the kernel.

/// `O_RDONLY` — the descriptors in fd-based events are opened read-only.
pub const O_RDONLY: u32 = libc::O_RDONLY as u32;
/// `O_WRONLY` — opened write-only.  Rarely what a monitor wants.
pub const O_WRONLY: u32 = libc::O_WRONLY as u32;
/// `O_RDWR` — opened read-write.
pub const O_RDWR: u32 = libc::O_RDWR as u32;
/// `O_APPEND` — writes append, which suits a logging consumer.
pub const O_APPEND: u32 = libc::O_APPEND as u32;
/// `O_NONBLOCK` — useful when monitoring something slow, such as a tape device.
pub const O_NONBLOCK: u32 = libc::O_NONBLOCK as u32;
/// `O_DSYNC` — data-integrity completion, for a consumer that must not lose writes.
pub const O_DSYNC: u32 = libc::O_DSYNC as u32;
/// `O_SYNC` — file-integrity completion.
pub const O_SYNC: u32 = libc::O_SYNC as u32;
/// `O_LARGEFILE` — for files over 2 GB on a 32-bit system.  **Zero on a 64-bit
/// one**, which is why this is read from `libc` and not written out.
pub const O_LARGEFILE: u32 = libc::O_LARGEFILE as u32;
/// `O_NOATIME` — do not update access time, which a monitoring consumer rarely wants.
pub const O_NOATIME: u32 = libc::O_NOATIME as u32;
/// `O_CLOEXEC` — the event descriptors close on exec, which matters when
/// separate processes scan the files.
pub const O_CLOEXEC: u32 = libc::O_CLOEXEC as u32;

/// Every flag `fanotify_init` accepts in `event_f_flags`.
///
/// The kernel validates this argument — since 3.18, via
/// `FANOTIFY_INIT_ALL_EVENT_F_BITS` — and answers `EINVAL` for anything outside
/// the set.  What is **excluded** is the point: the creation flags (`O_CREAT`,
/// `O_EXCL`, `O_TRUNC`, `O_NOFOLLOW`, `O_DIRECTORY`, `O_NOCTTY`, `O_TTY_INIT`),
/// the flags that make no sense for an event (`__O_TMPFILE`, `O_PATH`,
/// `O_DIRECT`, `FASYNC`), and the kernel's own internal `FMODE_*` bits, which
/// share the same field and would otherwise be settable from user space.
///
/// Pass this, or any subset of the `O_*` constants above, as
/// [`Fanotify::init`](crate::Fanotify::init)'s second argument.  A group with
/// [`Fanotify::new`](crate::Fanotify::new) uses `0`, which is `O_RDONLY` and the
/// right answer for nearly every consumer.
pub const EVENT_F_FLAGS_ALLOWED: u32 = O_RDONLY
    | O_WRONLY
    | O_RDWR
    | O_APPEND
    | O_NONBLOCK
    | O_DSYNC
    | O_SYNC
    | O_LARGEFILE
    | O_NOATIME
    | O_CLOEXEC;

// ── Event mask bits ──

/// `FAN_ACCESS` — the object was read.
pub const FAN_ACCESS: u64 = 0x0000_0001;
/// `FAN_MODIFY` — the object was written.
pub const FAN_MODIFY: u64 = 0x0000_0002;
/// `FAN_ATTRIB` — metadata changed.
pub const FAN_ATTRIB: u64 = 0x0000_0004;
/// `FAN_CLOSE_WRITE` — a file open for writing was closed.
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
/// `FAN_CLOSE_NOWRITE` — a file open read-only was closed.
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
/// `FAN_OPEN` — the object was opened.
pub const FAN_OPEN: u64 = 0x0000_0020;
/// `FAN_MOVED_FROM` — a directory entry was renamed away from here.
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
/// `FAN_MOVED_TO` — a directory entry was renamed to here.
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
/// `FAN_CREATE` — a directory entry was created.
pub const FAN_CREATE: u64 = 0x0000_0100;
/// `FAN_DELETE` — a directory entry was deleted.
pub const FAN_DELETE: u64 = 0x0000_0200;
/// `FAN_DELETE_SELF` — the marked object itself was deleted.
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;
/// `FAN_MOVE_SELF` — the marked object itself was renamed.
pub const FAN_MOVE_SELF: u64 = 0x0000_0800;
/// `FAN_OPEN_EXEC` — the object was opened for execution.
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;

/// `FAN_Q_OVERFLOW` — the queue overflowed and events were dropped.
///
/// This is not an event about an object: it is the kernel saying that an
/// unknown number of events never arrived, and they cannot be recovered from the
/// queue.  It carries no info records, no handle and no useful pid.  The limit
/// is 16384 events unless the group was created with [`FAN_UNLIMITED_QUEUE`].
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

/// `FAN_FS_ERROR` — a filesystem error was detected.  Requires a filesystem
/// mark, which requires `CAP_SYS_ADMIN`.
pub const FAN_FS_ERROR: u64 = 0x0000_8000;

/// `FAN_OPEN_PERM` — permission check before an open.
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
/// `FAN_ACCESS_PERM` — permission check before a read.
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;
/// `FAN_OPEN_EXEC_PERM` — permission check before an exec open.
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;

/// `FAN_PRE_ACCESS` — pre-content access hook (Linux 6.13+): the event is
/// delivered *before* the read and carries a range record.
pub const FAN_PRE_ACCESS: u64 = 0x0010_0000;

/// `FAN_MNT_ATTACH` — a mount was attached to the namespace.  Only a
/// [`FAN_REPORT_MNT`] group can be marked for it.
pub const FAN_MNT_ATTACH: u64 = 0x0100_0000;

/// `FAN_MNT_DETACH` — a mount was detached from the namespace.
pub const FAN_MNT_DETACH: u64 = 0x0200_0000;

/// `FAN_EVENT_ON_CHILD` — also report events on the marked object's immediate
/// children.  It is a modifier, not an event type.
///
/// Two things it is easy to get wrong:
///
/// * It reaches **immediate** children only.  It never makes a mark cover a
///   subtree, so covering a tree means one mark per directory, placed by you.
/// * It only changes anything for masks that are about an **object** —
///   [`FAN_OPEN`], [`FAN_ACCESS`], [`FAN_MODIFY`],
///   [`FAN_CLOSE_WRITE`], the `_PERM` events.  Without it,
///   those are reported for the marked object alone.  The directory-**entry**
///   events ([`FAN_CREATE`], [`FAN_DELETE`], [`FAN_MOVED_FROM`],
///   [`FAN_MOVED_TO`], [`FAN_RENAME`]) are only ever about a child and need no
///   flag.
///
/// Which mask bits fall on which side is the kernel's rule, not this crate's;
/// `tests/group.rs` asserts both halves against the kernel.
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;

/// `FAN_RENAME` — an entry was renamed within the watched object.
///
/// Needs a group with [`FAN_REPORT_NAME`]; the kernel rejects the mark, not the
/// group, when that is missing.  Carries up to two records — the source side and
/// the target side — and only for the side(s) the mark matched.
pub const FAN_RENAME: u64 = 0x1000_0000;

/// `FAN_ONDIR` — report events on directories too, not only on files.
pub const FAN_ONDIR: u64 = 0x4000_0000;

/// `FAN_CLOSE` — `FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE`.
pub const FAN_CLOSE: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;

/// `FAN_MOVE` — `FAN_MOVED_FROM | FAN_MOVED_TO`.
pub const FAN_MOVE: u64 = FAN_MOVED_FROM | FAN_MOVED_TO;

/// `FANOTIFY_MOUNT_EVENTS` — the only mask bits a [`FAN_REPORT_MNT`] group's
/// marks may name.
pub const FANOTIFY_MOUNT_EVENTS: u64 = FAN_MNT_ATTACH | FAN_MNT_DETACH;

/// `FAN_ALL_EVENTS` — every non-permission event type, overflow excluded.
pub const FAN_ALL_EVENTS: u64 =
    FAN_ACCESS | FAN_MODIFY | FAN_ATTRIB | FAN_CLOSE | FAN_OPEN | FAN_OPEN_EXEC;

/// `FAN_ALL_PERM_EVENTS` — every permission event type.
pub const FAN_ALL_PERM_EVENTS: u64 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM;

/// `FAN_ALL_OUTGOING_EVENTS` — everything a group can be marked to receive.
pub const FAN_ALL_OUTGOING_EVENTS: u64 = FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS | FAN_Q_OVERFLOW;

// ── `fanotify_event_info_header.info_type` ──

/// `FAN_EVENT_INFO_TYPE_FID` — handle of the object the event is about.
pub const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
/// `FAN_EVENT_INFO_TYPE_DFID_NAME` — parent directory handle + entry name.
pub const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
/// `FAN_EVENT_INFO_TYPE_DFID` — parent directory handle, no name.
pub const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;
/// `FAN_EVENT_INFO_TYPE_PIDFD` — pidfd of the process that caused the event.
pub const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;
/// `FAN_EVENT_INFO_TYPE_ERROR` — filesystem error code and repeat count.
pub const FAN_EVENT_INFO_TYPE_ERROR: u8 = 5;
/// `FAN_EVENT_INFO_TYPE_RANGE` — byte range of a `FAN_PRE_ACCESS` event.
pub const FAN_EVENT_INFO_TYPE_RANGE: u8 = 6;
/// `FAN_EVENT_INFO_TYPE_MNT` — mount ID of a mount event.
pub const FAN_EVENT_INFO_TYPE_MNT: u8 = 7;
/// `FAN_EVENT_INFO_TYPE_OLD_DFID_NAME` — rename source: parent handle + old name.
pub const FAN_EVENT_INFO_TYPE_OLD_DFID_NAME: u8 = 10;
/// `FAN_EVENT_INFO_TYPE_NEW_DFID_NAME` — rename target: parent handle + new name.
pub const FAN_EVENT_INFO_TYPE_NEW_DFID_NAME: u8 = 12;

/// `FANOTIFY_METADATA_VERSION` — the value `metadata.vers` carries.
///
/// It has been 3 since fanotify was introduced.  A different value means the
/// header layout is not the one this crate parses, and it says so rather than
/// guessing: see
/// [`FanotifyError::UnknownEventVersion`](crate::FanotifyError::UnknownEventVersion).
pub const FANOTIFY_METADATA_VERSION: u8 = 3;

// ── Response flags and sentinels ──

/// `FAN_ALLOW` — grant the operation the permission event asked about.
pub const FAN_ALLOW: u32 = 0x01;

/// `FAN_DENY` — refuse it.  The caller sees `EPERM` unless an errno is packed
/// in (see [`FAN_ERRNO_SHIFT`]) **and** the group is `FAN_CLASS_PRE_CONTENT`.
pub const FAN_DENY: u32 = 0x02;

/// `FAN_AUDIT` — ask the kernel to emit an audit record for this response.
pub const FAN_AUDIT: u32 = 0x10;

/// `FAN_INFO` — a `fanotify_response_info_header` follows the response.
///
/// This bit is also what makes the kernel complete the oldest pending event
/// **without matching a descriptor**, which is the only way to answer a group
/// that reports no descriptor.
pub const FAN_INFO: u32 = 0x20;

/// `FAN_ERRNO_BITS` — how many bits of a deny response carry the errno.
pub const FAN_ERRNO_BITS: u32 = 8;

/// `FAN_ERRNO_SHIFT` — where those bits start.
pub const FAN_ERRNO_SHIFT: u32 = 32 - FAN_ERRNO_BITS;

/// `FAN_ERRNO_MASK` — selects the errno out of a deny response.
pub const FAN_ERRNO_MASK: u32 = (1 << FAN_ERRNO_BITS) - 1;

/// `FAN_RESPONSE_INFO_NONE` — `fanotify_response_info_header.type`: no payload.
pub const FAN_RESPONSE_INFO_NONE: u8 = 0;

/// `FAN_RESPONSE_INFO_AUDIT_RULE` — `fanotify_response_info_header.type`: the
/// payload is an audit rule number.  This is the only type the kernel defines.
pub const FAN_RESPONSE_INFO_AUDIT_RULE: u8 = 1;

/// `FAN_NOFD` — `metadata.fd` in an event that carries no descriptor.
///
/// Numerically `-1`, and ambiguous on its own: without
/// [`FAN_REPORT_FD_ERROR`] the kernel writes exactly this whether or not a
/// descriptor could have been opened.
pub const FAN_NOFD: i32 = -1;

/// `FAN_NOPIDFD` — a pidfd record that could not create a pidfd because the
/// target process was already gone.
///
/// The kernel's rule is `pidfd = pidfd == -ESRCH ? FAN_NOPIDFD : FAN_EPIDFD`,
/// so this sentinel means "gone" specifically — which is **not** what
/// [`FAN_EPIDFD`] means.
pub const FAN_NOPIDFD: i32 = FAN_NOFD;

/// `FAN_EPIDFD` — a pidfd record that failed for a reason other than the target
/// being gone.
pub const FAN_EPIDFD: i32 = -2;

/// `MAX_HANDLE_SZ` from `linux/exportfs.h` — the largest file handle any
/// filesystem may produce, and therefore the largest buffer
/// `name_to_handle_at` accepts.  A larger capacity is refused with `EINVAL`.
pub const MAX_HANDLE_SZ: usize = 128;

/// `AT_HANDLE_FID` from `linux/fcntl.h` (Linux 6.13+).
///
/// Asks `name_to_handle_at` for a **FID** — the flavour fanotify reports —
/// rather than an openable handle.  The two are not the same request:
/// filesystems with no `fh_to_dentry` operation (procfs, sysfs, debugfs,
/// tracefs, bpf, devpts) hand out synthetic `FILEID_INO64_GEN` FIDs that no
/// handle can be opened from, and a plain `name_to_handle_at` fails on them with
/// `EOPNOTSUPP`.
pub const AT_HANDLE_FID: i32 = 0x200;

// ── Display helper ──

/// Event mask bits paired with the name of the bit, for
/// [`mask_to_event_names`].
pub const EVENT_NAMES: &[(u64, &str)] = &[
    (FAN_ACCESS, "ACCESS"),
    (FAN_MODIFY, "MODIFY"),
    (FAN_ATTRIB, "ATTRIB"),
    (FAN_CLOSE_WRITE, "CLOSE_WRITE"),
    (FAN_CLOSE_NOWRITE, "CLOSE_NOWRITE"),
    (FAN_OPEN, "OPEN"),
    (FAN_OPEN_EXEC, "OPEN_EXEC"),
    (FAN_MOVED_FROM, "MOVED_FROM"),
    (FAN_MOVED_TO, "MOVED_TO"),
    (FAN_CREATE, "CREATE"),
    (FAN_DELETE, "DELETE"),
    (FAN_DELETE_SELF, "DELETE_SELF"),
    (FAN_MOVE_SELF, "MOVE_SELF"),
    (FAN_Q_OVERFLOW, "Q_OVERFLOW"),
    (FAN_FS_ERROR, "FS_ERROR"),
    (FAN_OPEN_PERM, "OPEN_PERM"),
    (FAN_ACCESS_PERM, "ACCESS_PERM"),
    (FAN_OPEN_EXEC_PERM, "OPEN_EXEC_PERM"),
    (FAN_PRE_ACCESS, "PRE_ACCESS"),
    (FAN_MNT_ATTACH, "MNT_ATTACH"),
    (FAN_MNT_DETACH, "MNT_DETACH"),
    (FAN_EVENT_ON_CHILD, "EVENT_ON_CHILD"),
    (FAN_RENAME, "RENAME"),
    (FAN_ONDIR, "ONDIR"),
];

/// The names of the event bits set in `mask`, in the order of [`EVENT_NAMES`].
///
/// This is a debugging aid, not a classification: the mask is a bitfield, and
/// several bits are commonly set at once.
///
/// ```
/// use fanotify_fid::consts::{FAN_CREATE, FAN_MODIFY, mask_to_event_names};
///
/// let names: Vec<&str> = mask_to_event_names(FAN_CREATE | FAN_MODIFY).collect();
/// assert_eq!(names, ["MODIFY", "CREATE"]);
/// ```
pub fn mask_to_event_names(mask: u64) -> impl Iterator<Item = &'static str> {
    EVENT_NAMES
        .iter()
        .filter(move |(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
}
