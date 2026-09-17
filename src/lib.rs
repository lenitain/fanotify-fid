//! Linux fanotify, as a library that hands out what the kernel reports and
//! decides as little as possible for you.
//!
//! # What fanotify is
//!
//! One syscall creates a **group** (`fanotify_init`), another says **what to
//! watch** (`fanotify_mark`), and `read`/`write` on the group are the event
//! queue and the place permission decisions are answered.  It is not inotify
//! with more events: inotify watches *directory entries*, so it can tell you a
//! name changed; fanotify watches *operations on an object*, so it can tell you
//! **who opened this object**, and it can stop the operation and wait for a
//! decision.
//!
//! # Three axes, and three dependencies the kernel welds shut
//!
//! Every group is a point in a three-dimensional space.  Two of the dimensions
//! are chosen at `fanotify_init`, the third at `fanotify_mark`:
//!
//! | Axis | Values |
//! |---|---|
//! | **Identity** — how an event names its object | descriptor · file handle + fsid (FID) · mount ID |
//! | **Class** — whether the kernel waits for a decision | [`FAN_CLASS_NOTIF`](consts::FAN_CLASS_NOTIF) · [`FAN_CLASS_CONTENT`](consts::FAN_CLASS_CONTENT) · [`FAN_CLASS_PRE_CONTENT`](consts::FAN_CLASS_PRE_CONTENT) |
//! | **Anchor** — what a mark is attached to | [`FAN_MARK_INODE`](consts::FAN_MARK_INODE) · [`FAN_MARK_MOUNT`](consts::FAN_MARK_MOUNT) · [`FAN_MARK_FILESYSTEM`](consts::FAN_MARK_FILESYSTEM) · [`FAN_MARK_MNTNS`](consts::FAN_MARK_MNTNS) |
//!
//! Not every point exists, and the missing ones are not gaps to be filled —
//! they are ruled out by what the objects *are*:
//!
//! 1. **FID × a permission class does not exist.**  A permission event has to
//!    hand the process a descriptor for the object being decided about, and the
//!    kernel must hold it until the answer arrives.  File-handle identity exists
//!    precisely so that the kernel holds *no* descriptor.  The two cannot both
//!    hold, so the kernel refuses the combination with `EINVAL`.
//! 2. **Mount identity × any anchor but MNTNS does not exist.**  A mount event
//!    is scoped to a mount namespace, not to an inode, so the anchor is pinned
//!    to [`FAN_MARK_MNTNS`](consts::FAN_MARK_MNTNS) and the mask to
//!    [`FAN_MNT_ATTACH`](consts::FAN_MNT_ATTACH) /
//!    [`FAN_MNT_DETACH`](consts::FAN_MNT_DETACH).  This is checked at
//!    `fanotify_mark`, **not** at `fanotify_init` — a group can be created for
//!    mount events and then be unusable if you mark it wrongly.
//! 3. **[`FAN_REPORT_TARGET_FID`](consts::FAN_REPORT_TARGET_FID) needs
//!    [`FAN_REPORT_NAME`](consts::FAN_REPORT_NAME) and
//!    [`FAN_REPORT_FID`](consts::FAN_REPORT_FID)** — the child's own handle is
//!    reported *in addition to* the parent handle and name, so the flags that
//!    describe the pair are prerequisites.
//!
//! The **legal group configurations are therefore five**, and this crate can
//! express all of them:
//!
//! | # | Identity | Class | Anchors | Privilege |
//! |---|---|---|---|---|
//! | 1 | descriptor | NOTIF | inode · mount · filesystem | `CAP_SYS_ADMIN` |
//! | 2 | descriptor | CONTENT | inode · mount · filesystem | `CAP_SYS_ADMIN` |
//! | 3 | descriptor | PRE_CONTENT | inode · mount · filesystem | `CAP_SYS_ADMIN` |
//! | 4 | FID | NOTIF | inode · mount · filesystem | inode anchors need none |
//! | 5 | mount | NOTIF | **MNTNS only** | `CAP_SYS_ADMIN` |
//!
//! Row 4 is the one that changes what is practical: a FID group needs no
//! privilege for inode marks, and identifies objects without holding a
//! descriptor for each — which is what makes whole-filesystem monitoring
//! possible at all.
//!
//! # What this crate does, and does not do
//!
//! > Whatever you cannot get right **without understanding fanotify** belongs
//! > here.  Whatever is **your own decision** belongs to you.
//!
//! The crate provides:
//!
//! * **the three identities and their wire formats** — parsing a FID event
//!   ([`parse_fid_events`], and
//!   [`Fanotify::read_events`]), an fd-based event
//!   ([`Fanotify::read_fd_events`] and its reader [`FdEventReader`]), and a mount
//!   event (the same FID reader: a
//!   mount event is a FID-format event whose identity record is
//!   [`FidEvent::mnt_id`]).  A FID event **borrows the buffer it was parsed
//!   from**, so a stream of handles and names costs no per-record allocation;
//!   [`FidEvent::into_owned`] is the explicit conversion for an event that has
//!   to outlive the read, and the stateless [`Fanotify::read_events`] is the
//!   cheaper one for a whole batch that has to, because there the buffer is the
//!   caller's own and the batch is copied **once as bytes** (see
//!   `examples/batch_to_worker.rs`).  Both formats have a `*_reported`
//!   entry point whose [`ParseReport`] says whether the buffer was walked to the
//!   end, because a truncated buffer and an empty queue must not look alike;
//! * **the two ways to answer a permission event** — matched by descriptor, or
//!   without one ([`response`]);
//! * **the kernel's primitives, as themselves** — every anchor, mask and action
//!   is a constant you pass through ([`consts`]), and
//!   [`fanotify_init`](sys::fanotify_init) /
//!   [`fanotify_mark`](sys::fanotify_mark) are the syscalls;
//! * **the event's payload** — fsid, handles, entry names, mount ID, pidfd,
//!   access range, filesystem error, and both sides of a rename;
//! * **file handles**, the syscalls that produce and consume them ([`handle`]),
//!   because a FID event is uninterpretable without them;
//! * **the two facts that are only documented, never implemented**: a mark's
//!   reach — its own object and, for the event types that are about an object,
//!   its immediate children (see [`Fanotify::mark`]) — and that an overflowing
//!   queue drops events (see [`FidEvent::is_overflow`]).
//!
//! And deliberately does **not**:
//!
//! * **judge legality.**  The kernel is the authority.  A validation layer here
//!   would eventually disagree with it about an errno or a rule, and the cost of
//!   that disagreement is a caller sent looking in the wrong place — this
//!   crate's check reporting `EINVAL` where the kernel would have said `EPERM`,
//!   or refusing something a newer kernel allows.  Call the kernel and read its
//!   answer.
//! * **keep state for you.**  No record of which paths are marked, no
//!   handle→path cache, no eviction policy, no re-scan after an overflow.  A
//!   mark lives in the kernel and dies with the inode or the group; a cache is a
//!   policy about memory and staleness that only the caller can choose.
//! * **walk trees.**  An anchor does not recurse, so "watch this tree" is a
//!   strategy — one mark per directory, one mount mark, or your own index.
//!   Which one is right is a property of what you are building.
//! * **attribute processes.**  The pid and pidfd the kernel reports are handed
//!   over as reported; what they mean about a process is not this crate's to
//!   decide.
//! * **wrap things that are already expressible.**  An adapter that saves a few
//!   lines adds surface area, invents its own semantics, and creates one more
//!   place to disagree with the kernel.
//!
//! # Checking a combination against your kernel
//!
//! Whether a group configuration works is a question for the kernel, not for
//! this crate's documentation, and the way to ask is to ask it.  A successful
//! call means legal and permitted; a failure means one of two different things,
//! **and the two are not distinguishable from a single errno**:
//!
//! * `EPERM` — legal, but the caller lacks the capability.  The privilege check
//!   runs **first**, so an unprivileged caller sees this for combinations that
//!   are also illegal.
//! * `EINVAL` — illegal.  Only root gets to see this for a combination that is
//!   both, which is why "run it as root" is the only way to settle legality for
//!   the admin-only rows of the table above.
//!
//! # Privileges, in one place
//!
//! | Needs `CAP_SYS_ADMIN` | Why |
//! |---|---|
//! | a bare [`FAN_CLASS_NOTIF`](consts::FAN_CLASS_NOTIF) with no report flag | *omitting* a report flag is not the unprivileged choice |
//! | [`FAN_CLASS_CONTENT`](consts::FAN_CLASS_CONTENT) / [`FAN_CLASS_PRE_CONTENT`](consts::FAN_CLASS_PRE_CONTENT) | admin-only classes |
//! | [`FAN_MARK_MOUNT`](consts::FAN_MARK_MOUNT) / [`FAN_MARK_FILESYSTEM`](consts::FAN_MARK_FILESYSTEM) / [`FAN_MARK_MNTNS`](consts::FAN_MARK_MNTNS) | an unprivileged group may place inode marks only — and that limit is about the **anchor**, not the file: marking a root-owned file succeeds |
//! | [`FAN_REPORT_PIDFD`](consts::FAN_REPORT_PIDFD), [`FAN_REPORT_TID`](consts::FAN_REPORT_TID), [`FAN_REPORT_FD_ERROR`](consts::FAN_REPORT_FD_ERROR) | admin-only init flags |
//! | [`FAN_UNLIMITED_QUEUE`](consts::FAN_UNLIMITED_QUEUE), [`FAN_UNLIMITED_MARKS`](consts::FAN_UNLIMITED_MARKS) | admin-only init flags |
//! | [`FAN_REPORT_MNT`](consts::FAN_REPORT_MNT) **marks** | creating the group needs nothing — unlike every other row here, the capability is asked for at `fanotify_mark` |
//! | [`FAN_FS_ERROR`](consts::FAN_FS_ERROR) events | inherited from the filesystem mark they need |
//! | [`FAN_ENABLE_AUDIT`](consts::FAN_ENABLE_AUDIT) | needs `CAP_AUDIT_WRITE`, **not** `CAP_SYS_ADMIN` |
//!
//! Two capabilities outside this list matter just as much:
//!
//! * **`CAP_DAC_READ_SEARCH`** for
//!   [`open_by_handle_at`](handle::open_by_handle_at), and therefore for turning
//!   a handle into a path ([`resolve_file_handle`]).
//!   This is the second, stricter privilege question: receiving events needs
//!   nothing, and resolving them needs the capability that bypasses path
//!   permissions.  An unprivileged consumer works from the handles and names the
//!   events carry, and needs no syscall at all.
//! * **`CAP_AUDIT_WRITE`** for [`FAN_ENABLE_AUDIT`](consts::FAN_ENABLE_AUDIT),
//!   without which an audited response (`FAN_AUDIT`, and therefore
//!   [`FanotifyResponse::audit_rule`]) is refused.
//!
//! An unprivileged group still receives events, but the kernel blanks
//! `metadata.pid` for events caused by *other* processes, so
//! [`FidEvent::pid`] degrades to `0` there.
//!
//! # Kernel feature floors
//!
//! Fanotify itself is Linux 2.6.36; FID identity starts at 5.1 and each flag
//! after it has its own floor: [`FAN_REPORT_DIR_FID`](consts::FAN_REPORT_DIR_FID)
//! and [`FAN_REPORT_NAME`](consts::FAN_REPORT_NAME) 5.9, an unprivileged FID
//! group 5.13, [`FAN_REPORT_TARGET_FID`](consts::FAN_REPORT_TARGET_FID) 5.17,
//! [`FAN_REPORT_MNT`](consts::FAN_REPORT_MNT) and
//! [`FAN_MARK_MNTNS`](consts::FAN_MARK_MNTNS) 6.14,
//! [`FAN_PRE_ACCESS`](consts::FAN_PRE_ACCESS) 6.13, and
//! [`AT_HANDLE_FID`](consts::AT_HANDLE_FID) 6.13.
//!
//! There is no feature detection here and there should not be: the way to find
//! out whether a kernel supports something is to ask it and read the errno —
//! `EINVAL` for a flag it does not know, `ENOSYS` for a call it does not have.
//! Guessing from a version number would be a second source of truth, and a
//! wrong one on a distribution kernel that backported the feature.
//!
//! # Requirements
//!
//! Linux only — the crate fails to compile elsewhere with that message.  Rust
//! 1.88 or newer (edition 2024).  One dependency, `libc`, for the syscalls.
//!
//! # Reading a FID group
//!
//! ```rust,no_run
//! use fanotify_fid::{Fanotify, FanotifyError, consts::*};
//! use fanotify_fid::handle::{Mounts, resolve_file_handle_in};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! // 1. A group that identifies objects by handle.  No privilege needed.
//! let fan = Fanotify::new(
//!     FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
//!         | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
//! )?;
//!
//! // 2. Mark an object.  This covers the directory and its immediate children,
//! //    not the subtree — covering a tree is your strategy to choose.
//! fan.mark(FAN_MARK_ADD, FAN_CREATE | FAN_DELETE | FAN_EVENT_ON_CHILD, "/srv/data")?;
//!
//! // 3. Resolving a handle to a path needs CAP_DAC_READ_SEARCH.  A mount
//! //    descriptor says which filesystem a handle belongs to, which is what
//! //    makes the resolution correct rather than merely possible — and `Mounts`
//! //    learns each descriptor's filesystem once, so resolution does not repeat
//! //    that `fstatfs` per event the way a bare `&[OwnedFd]` has to.
//! let mounts = Mounts::new().with_fd(std::fs::File::open("/srv/data")?)?;
//!
//! // 4. Read.
//! let mut buf = Vec::new();
//! loop {
//!     match fan.read_events(&mut buf) {
//!         Ok(events) => {
//!             for ev in &events {
//!                 if ev.is_overflow() {
//!                     // Events were lost and cannot be recovered from the queue.
//!                     eprintln!("queue overflow: reconcile by re-scanning");
//!                     continue;
//!                 }
//!                 // The raw identity the kernel reported.
//!                 println!("{:?} fsid={:?} name={:?}",
//!                     ev.event_names().collect::<Vec<_>>(),
//!                     ev.fsid(),
//!                     ev.dfid_name_str());
//!
//!                 // A path, if you have the privilege and want one.
//!                 if let (Some(fsid), Some(handle)) = (ev.fsid(), ev.dfid_name_handle()) {
//!                     println!("parent: {:?}", resolve_file_handle_in(mounts.candidates(), Some(fsid), handle));
//!                 }
//!             }
//!         }
//!         // An empty queue is not a failure: wait for the next event.
//!         Err(e) if e.is_would_block() => {
//!             fan.wait_readable(None)?;
//!         }
//!         Err(e) => return Err(e.into()),
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Answering a permission event
//!
//! ```rust,no_run
//! use fanotify_fid::{Fanotify, FanotifyError, consts::*};
//! use fanotify_fid::response::FanotifyResponse;
//!
//! # fn main() -> Result<(), FanotifyError> {
//! // Permission events need CAP_SYS_ADMIN, and a descriptor-identity group:
//! // the FID flags cannot be combined with a permission class.
//! let fan = Fanotify::new(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK)?;
//! fan.mark(FAN_MARK_ADD, FAN_OPEN_PERM, "/srv/data")?;
//!
//! let mut buf = Vec::new();
//! loop {
//!     for ev in fan.read_fd_events(&mut buf)? {
//!         let Some(fd) = ev.fd() else { continue };
//!         // The event's own descriptor is what the kernel matches on.
//!         let decision = if ev.mask() & FAN_OPEN_PERM != 0 {
//!             FanotifyResponse::allow(fd)
//!         } else {
//!             FanotifyResponse::deny_errno(fd, libc::EACCES)
//!         };
//!         fan.send_response(&decision)?;
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("fanotify-fid only supports Linux");

// Including the README here is what puts any Rust example in it through the
// doctest runner, so an example cannot drift from the API without failing
// `cargo test --doc`.  It currently carries none: a real example needs privilege
// and a real path, so it would have to be `no_run` and would assert nothing.  The
// compile-checked examples live in `examples/` instead.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

pub mod consts;
pub mod error;
pub mod fd;
pub mod fid;
pub mod handle;
pub mod parse;
pub mod resolve;
pub mod response;
pub mod sys;

mod group;

pub use error::{FanotifyError, Result};
pub use fd::{FdEvent, parse_fd_events};
pub use fid::{
    FidEvent, Pidfd, RenameSide, parse_fid_events, parse_fid_events_into, parse_fid_events_reported,
};
pub use group::{EventReader, Fanotify, FdEventReader};
pub use handle::{
    Candidate, FileHandle, Fsid, HandleCache, Mounts, NoCache, PathMemo, PathStore,
    resolve_file_handle, resolve_file_handle_in,
};
pub use parse::{EventStop, ParseReport};
pub use resolve::{EventResolution, PathResolver, Resolution};
pub use response::FanotifyResponse;

/// The names most callers need, in one import.
///
/// ```
/// use fanotify_fid::prelude::*;
///
/// let fan = Fanotify::new(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_FID)?;
/// let flags = fan.as_fd();
/// # let _ = flags;
/// # Ok::<(), FanotifyError>(())
/// ```
///
/// # Why this exists, and why it is listed rather than wildcarded
///
/// The interface is wide and flat — nearly a hundred constants, a type per
/// identity, and a free function for every operation — so naming every item at
/// every call site is real friction with nothing bought by it.  A prelude
/// chooses no default,
/// hides no policy and changes no meaning; it only saves the import lines, which
/// is why it belongs here and not to the caller.
///
/// It is **curated rather than `pub use crate::*`**: the modules `fd`, `fid`,
/// `handle`, `resolve` and `response` stay unglobbed, because a caller that wants
/// [`FdEvent`] can name it and because globbing module
/// trees is how a prelude starts colliding with the caller's own names.  What is
/// here is what the crate's own examples use.
pub mod prelude {
    pub use crate::consts::*;
    pub use crate::handle::{
        Candidate, FileHandle, Fsid, HandleCache, Mounts, NoCache, PathMemo, PathStore, fsid_of_fd,
        fsid_of_path, handle_from_fd, name_to_handle_at, open_by_handle_at, resolve_file_handle,
        resolve_file_handle_in,
    };
    pub use crate::resolve::{EventResolution, PathResolver, Resolution};
    pub use crate::sys::{fanotify_init, fanotify_mark};
    pub use crate::{
        EventReader, EventStop, Fanotify, FanotifyError, FanotifyResponse, FdEvent, FdEventReader,
        FidEvent, ParseReport, Pidfd, RenameSide, Result, parse_fd_events, parse_fid_events,
        parse_fid_events_into, parse_fid_events_reported,
    };
}
