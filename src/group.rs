//! The group: the one resource this crate owns, and the reads that only it can
//! make safely.
//!
//! A fanotify group is a file descriptor.  Two syscalls define it —
//! `fanotify_init` creates it and decides how events are reported,
//! `fanotify_mark` decides what is watched — and `read`/`write` on it are the
//! event queue and the place decisions are answered.  [`Fanotify`] is the RAII
//! owner of that descriptor, and nothing more: **marks are kernel state**, not
//! objects this crate tracks, so there is no `Mark` type, no set of marked
//! paths, and no way to ask this crate what is marked.  A mark lives in the
//! inode (or mount, or filesystem) and disappears with it or with the group.
//!
//! # Why the reads live here
//!
//! An fd-based event carries a descriptor the kernel installed for this process,
//! and a FID event may carry a pidfd.  Turning either number into an
//! [`OwnedFd`] is only sound when the bytes it came from are the kernel's answer
//! to a `read(2)` performed here, for this call, exactly once.  That is a
//! property of where the bytes come from, not of their content — which is why
//! the parsers are internal and these methods are the public way in.
//!
//! # Marks do not recurse, and a mark's reach is two things, not one
//!
//! A mark never covers a **subtree**.  What it covers is the object it names —
//! plus, for events that can be about a child, that object's **immediate**
//! children.  Whether a given event needs
//! [`FAN_EVENT_ON_CHILD`](crate::consts::FAN_EVENT_ON_CHILD) follows from what
//! that event can be about:
//!
//! | Mask bits | Needs `FAN_EVENT_ON_CHILD`? |
//! |---|---|
//! | [`FAN_OPEN`](crate::consts::FAN_OPEN), [`FAN_ACCESS`](crate::consts::FAN_ACCESS), [`FAN_MODIFY`](crate::consts::FAN_MODIFY), [`FAN_CLOSE_WRITE`](crate::consts::FAN_CLOSE_WRITE), the `_PERM` events, ... | **yes** — they are about an object, so without the flag they are reported for the marked object only |
//! | [`FAN_CREATE`](crate::consts::FAN_CREATE), [`FAN_DELETE`](crate::consts::FAN_DELETE), [`FAN_MOVED_FROM`](crate::consts::FAN_MOVED_FROM), [`FAN_MOVED_TO`](crate::consts::FAN_MOVED_TO) | no — a directory *entry* event is only ever about a child, so there is nothing to extend |
//!
//! Getting this wrong costs events silently, which is why it is worth stating
//! rather than leaving to the flag's name.  It is still the kernel's rule and
//! not this crate's: the tests in `tests/group.rs` assert both halves against
//! the kernel rather than against this paragraph.
//!
//! The consequence is that watching a tree is a strategy and not a call —
//! an inode mark with the right flag for every directory, one
//! [`FAN_MARK_MOUNT`](crate::consts::FAN_MARK_MOUNT) /
//! [`FAN_MARK_FILESYSTEM`](crate::consts::FAN_MARK_FILESYSTEM) mark, or
//! something keyed off an index you already keep.  Which is right depends on
//! what you are building, so it is yours to choose and not this crate's to
//! assume.

use std::ffi::OsStr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::consts;
use crate::error::{FanotifyError, Result};
use crate::fd::{self, FdEvent};
use crate::fid::{self, FidEvent};
use crate::parse::{EventStop, ParseReport};
use crate::response::{self, FanotifyResponse};
use crate::sys;

/// A fanotify group, owning its descriptor.
///
/// The descriptor is closed on drop, which also releases every mark the group
/// holds and unblocks any file operation still waiting on a permission event.
///
/// # Constructing one
///
/// [`Fanotify::init`] passes its flags to `fanotify_init` unchanged — no
/// combination is filtered, rewritten, or judged here, so the kernel's answer is
/// the one you see:
///
/// ```rust,no_run
/// use fanotify_fid::{Fanotify, consts::*};
///
/// // FID identity, non-blocking, after-the-fact events.  This combination
/// // needs no privilege.
/// let flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
///     | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME;
/// let fan = Fanotify::new(flags)?;
///
/// // A mark covers the object and its immediate children, not the subtree.
/// fan.mark(FAN_MARK_ADD, FAN_CREATE | FAN_DELETE | FAN_EVENT_ON_CHILD, "/srv/data")?;
/// # Ok::<(), fanotify_fid::FanotifyError>(())
/// ```
///
/// `event_f_flags` is the `open(2)` flag set the kernel uses for the descriptors
/// it puts in fd-based events, so it is meaningful only for a group without a
/// FID flag; a FID group never opens anything and the kernel ignores it.
#[derive(Debug)]
pub struct Fanotify {
    fd: OwnedFd,
}

impl Fanotify {
    /// Create a group with flags alone: `event_f_flags = 0`.
    ///
    /// The form almost every caller wants.  `event_f_flags` is the `open(2)`
    /// flag set the kernel uses for the descriptors it puts in **fd-based**
    /// events, so it is meaningful only for a group without a FID flag — a FID
    /// group never opens anything and the kernel ignores the argument.  Zero is
    /// `O_RDONLY`, which is what a consumer that reads the object wants.
    ///
    /// ```rust,no_run
    /// use fanotify_fid::{Fanotify, consts::*};
    ///
    /// // FID identity, non-blocking, after-the-fact events: no privilege needed.
    /// let fan = Fanotify::new(
    ///     FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
    ///         | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
    /// )?;
    /// # Ok::<(), fanotify_fid::FanotifyError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`init`](Self::init).
    pub fn new(flags: u32) -> Result<Self> {
        Self::init(flags, 0)
    }

    /// Create a group: `fanotify_init` and nothing else.
    ///
    /// `event_f_flags` is passed through unchanged, so the kernel's answer is
    /// the one you see.  It selects how the descriptors in fd-based events are
    /// opened, and only these flags are accepted — anything else is `EINVAL`,
    /// which is the kernel refusing to let user space set its internal
    /// `FMODE_*` bits through this argument.  See
    /// [`EVENT_F_FLAGS_ALLOWED`](consts::EVENT_F_FLAGS_ALLOWED) for the set and
    /// [`new`](Self::new) for the common case, which needs none of it.
    ///
    /// # Errors
    ///
    /// [`FanotifyError::Init`] with the kernel's errno — `EINVAL` for a flag
    /// combination it refuses, `EPERM` when the capability is missing.  Note that
    /// **the privilege check runs first**, so a combination that is both
    /// admin-only and illegal answers `EPERM` to an unprivileged caller and
    /// `EINVAL` only to root: one errno cannot settle legality by itself.
    pub fn init(flags: u32, event_f_flags: u32) -> Result<Self> {
        Ok(Self {
            fd: sys::fanotify_init(flags, event_f_flags)?,
        })
    }

    /// Add or remove a mark, anchored at `dir_fd` + `path`.
    ///
    /// `flags` selects the anchor and the action: exactly one of
    /// [`FAN_MARK_ADD`](consts::FAN_MARK_ADD),
    /// [`FAN_MARK_REMOVE`](consts::FAN_MARK_REMOVE),
    /// [`FAN_MARK_FLUSH`](consts::FAN_MARK_FLUSH), plus any of
    /// [`FAN_MARK_MOUNT`](consts::FAN_MARK_MOUNT),
    /// [`FAN_MARK_FILESYSTEM`](consts::FAN_MARK_FILESYSTEM),
    /// [`FAN_MARK_MNTNS`](consts::FAN_MARK_MNTNS),
    /// [`FAN_MARK_DONT_FOLLOW`](consts::FAN_MARK_DONT_FOLLOW),
    /// [`FAN_MARK_ONLYDIR`](consts::FAN_MARK_ONLYDIR),
    /// [`FAN_MARK_EVICTABLE`](consts::FAN_MARK_EVICTABLE) and the
    /// [`FAN_MARK_IGNORE`](consts::FAN_MARK_IGNORE) pair.  `mask` is the set of
    /// event bits the mark is about.
    ///
    /// Pass [`AT_FDCWD`](consts::AT_FDCWD) for `dir_fd` to resolve `path`
    /// against the working directory, or a directory descriptor you already hold
    /// — which is what makes the call race-free against a rename, since the path
    /// is then resolved from a descriptor rather than walked again.
    ///
    /// # A mark is not a subscription you can query
    ///
    /// The kernel owns it.  Removing bits that are not set, or removing a mark
    /// that does not exist, is not an error: the call is an instruction, and
    /// `FAN_MARK_REMOVE` with the same mask you added is how you take a mark
    /// back.  Because a mask is a bitfield, removing a *subset* leaves the rest.
    ///
    /// # Errors
    ///
    /// [`FanotifyError::Mark`] with the kernel's errno.  The rules that depend on
    /// the group are checked **here**, not at `init`: which anchors this group
    /// may use, whether the mask suits its class, and whether the filesystem can
    /// decode the handles its events would carry (`EOPNOTSUPP`, which is why a
    /// filesystem that hands out synthetic handles admits inode marks only).
    pub fn mark<P: AsRef<OsStr> + ?Sized>(&self, flags: u32, mask: u64, path: &P) -> Result<()> {
        sys::fanotify_mark(&self.fd, flags, mask, consts::AT_FDCWD, path)
    }

    /// Add or remove a mark, anchored at a **directory descriptor**.
    ///
    /// The same call as [`mark`](Self::mark), except that `path` is resolved
    /// from `dir_fd` instead of the working directory.  That is what makes this
    /// form race-free: a path re-resolved at mark time is a path that may have
    /// changed since you looked at it, while a descriptor names the directory
    /// you already opened.
    ///
    /// `path` is relative to `dir_fd`, so `.` marks the directory itself.  With
    /// [`FAN_MARK_DONT_FOLLOW`](consts::FAN_MARK_DONT_FOLLOW) and a descriptor
    /// opened `O_NOFOLLOW | O_DIRECTORY`, the whole call names one fixed object.
    ///
    /// ```rust,no_run
    /// use fanotify_fid::{Fanotify, consts::*};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let fan = Fanotify::new(FAN_CLASS_NOTIF | FAN_REPORT_FID)?;
    /// let dir = std::fs::File::open("/srv/data")?;
    /// fan.mark_at(&dir, FAN_MARK_ADD, FAN_CREATE | FAN_EVENT_ON_CHILD, ".")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`mark`](Self::mark).
    pub fn mark_at<Fd: AsFd, P: AsRef<OsStr> + ?Sized>(
        &self,
        dir_fd: Fd,
        flags: u32,
        mask: u64,
        path: &P,
    ) -> Result<()> {
        sys::fanotify_mark(&self.fd, flags, mask, dir_fd.as_fd().as_raw_fd(), path)
    }

    /// Add or remove a mark on the object a **descriptor** names.
    ///
    /// The third way to name the thing to watch, and the one that resolves no
    /// path at all:
    ///
    /// | Call | The object |
    /// |---|---|
    /// | [`mark`](Self::mark) | a path from the working directory, walked at mark time |
    /// | [`mark_at`](Self::mark_at) | a path relative to a directory descriptor, walked from it |
    /// | `mark_fd` | the object `fd` itself: the kernel takes its path straight from the descriptor |
    ///
    /// That last form is what makes a mark race-free against a rename without
    /// needing a directory anchor: the descriptor names one object, and no
    /// concurrent rename can change which.  It is the kernel's `NULL`-pathname
    /// form of `fanotify_mark`, and it works for files and directories alike.
    ///
    /// # The descriptor must be a real open, not `O_PATH`
    ///
    /// The kernel resolves it with `fdget()`, which **excludes `O_PATH`** and
    /// answers `EBADF` — the same descriptor that is the right answer for
    /// `name_to_handle_at` and other `AT_EMPTY_PATH` calls is the wrong one
    /// here, and `fanotify_mark` does not accept `AT_EMPTY_PATH` either.  Pass a
    /// descriptor opened for reading; the kernel requires read permission on
    /// the object for any mark, so that is no extra restriction.
    ///
    /// ```rust,no_run
    /// use fanotify_fid::{Fanotify, consts::*};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let fan = Fanotify::new(FAN_CLASS_NOTIF | FAN_REPORT_FID)?;
    /// let file = std::fs::File::open("/srv/data/report")?;
    /// // Marks that object, whatever happens to its path afterwards.
    /// fan.mark_fd(&file, FAN_MARK_ADD, FAN_OPEN)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`FanotifyError::Mark`] with the kernel's errno: `EBADF` when the object
    /// descriptor is closed or `O_PATH`, `ENOTDIR` under
    /// [`FAN_MARK_ONLYDIR`](consts::FAN_MARK_ONLYDIR), and everything
    /// [`mark`](Self::mark) lists.
    pub fn mark_fd<Fd: AsFd>(&self, fd: Fd, flags: u32, mask: u64) -> Result<()> {
        sys::fanotify_mark_by_fd(&self.fd, flags, mask, fd.as_fd())
    }

    /// Remove **every** mark this group holds.
    ///
    /// [`FAN_MARK_FLUSH`](consts::FAN_MARK_FLUSH) is the reason this exists as a
    /// method: the kernel ignores the path for a flush and requires the mask to
    /// be zero, so a caller who reasonably passes the path they marked, or the
    /// mask they added, gets **no error and no effect**.  There is nothing to
    /// pass here, so there is nothing to get wrong.
    ///
    /// Marks of every anchor — inode, mount, filesystem — go.  The group stays
    /// usable and can be marked again afterwards.
    ///
    /// # Errors
    ///
    /// [`FanotifyError::Mark`] if the syscall fails.
    pub fn flush_marks(&self) -> Result<()> {
        // The kernel ignores the path for a flush but still dereferences the
        // pointer, so pass the one path that always exists.
        sys::fanotify_mark(&self.fd, consts::FAN_MARK_FLUSH, 0, consts::AT_FDCWD, "/")
    }

    /// Read the events a **FID** group has queued.
    ///
    /// The group must have been created with a FID flag; a group without one
    /// produces events of the same header shape whose identity is a descriptor,
    /// which [`read_fd_events`](Self::read_fd_events) is the reader for.  Both
    /// formats share the 24-byte header, so reading one with the other's reader
    /// yields events with the wrong identity rather than an error — nothing in
    /// the header says which identity the group reports, and this reader does
    /// not pretend to check.
    ///
    /// `buf` is scratch space the caller keeps between calls; its contents are
    /// ignored, and its **capacity is the read size**: a buffer with no capacity
    /// is grown to 64 KiB, while one you sized yourself
    /// (`Vec::with_capacity`) is used as it is.  A larger buffer means fewer
    /// syscalls when the queue is deep, never a partial event — the kernel
    /// refuses the read with `EINVAL` rather than splitting one, which is what
    /// the message for that errno says.
    ///
    /// # The events borrow `buf`
    ///
    /// Nothing is copied out of the read buffer: the handles and names the
    /// events report point into it, which is what keeps a whole-filesystem
    /// event rate free of per-record allocation.  The consequence is the loop
    /// below: events live inside one iteration and are gone before the next
    /// read, so the borrow checker enforces exactly the order a consumer needs.
    /// An event that must outlive the buffer is made owned with
    /// [`FidEvent::into_owned`](crate::FidEvent::into_owned).
    ///
    /// ```rust,no_run
    /// use fanotify_fid::{Fanotify, FanotifyError, consts::*};
    ///
    /// # let fan = Fanotify::new(FAN_CLASS_NOTIF | FAN_REPORT_FID)?;
    /// let mut buf = Vec::new();
    /// loop {
    ///     match fan.read_events(&mut buf) {
    ///         Ok(events) => {
    ///             for ev in &events {
    ///                 // The kernel reported these; using them is the caller's
    ///                 // decision.
    ///                 println!("{:?} fsid={:?} name={:?}",
    ///                     ev.event_names().collect::<Vec<_>>(),
    ///                     ev.fsid(),
    ///                     ev.dfid_name_str());
    ///             }
    ///         }
    ///         // A non-blocking group with an empty queue: not a failure.
    ///         Err(FanotifyError::Read(libc::EAGAIN)) => {
    ///             fan.wait_readable(None)?;
    ///         }
    ///         Err(e) => return Err(e),
    ///     }
    /// }
    /// # Ok::<(), FanotifyError>(())
    /// ```
    ///
    /// # Descriptors in the events
    ///
    /// A pidfd record becomes an owned [`Pidfd::Fd`](crate::Pidfd::Fd) here and only here: this is
    /// the call that knows the buffer came from the kernel's queue for this
    /// process.  [`fid::parse_fid_events`](crate::fid::parse_fid_events) — which
    /// is handed a `&[u8]` and can prove nothing about it — reports the number
    /// instead, so a byte buffer can never close a descriptor.
    ///
    /// # Errors
    ///
    /// [`FanotifyError::Read`] with the kernel's errno.  **An empty queue on a
    /// non-blocking group is `EAGAIN`, not an empty list**; see
    /// [`wait_readable`](Self::wait_readable).
    ///
    /// A buffer that is not FID events at all is refused with
    /// [`FanotifyError::UnknownEventVersion`], because a header read under the
    /// wrong layout is a wrong answer, not a short one.  Use
    /// [`read_events_reported`](Self::read_events_reported) when the bytes and
    /// the version both need to be seen.
    pub fn read_events<'buf>(&self, buf: &'buf mut Vec<u8>) -> Result<Vec<FidEvent<'buf>>> {
        let (events, report) = self.read_events_reported(buf)?;
        if let EventStop::UnknownVersion(vers) = report.stop {
            return Err(FanotifyError::UnknownEventVersion(vers));
        }
        Ok(events)
    }

    /// [`read_events`](Self::read_events), reporting how far the parse got.
    ///
    /// The same read and the same adoption, plus a [`ParseReport`] that says
    /// whether the whole buffer became events — [`ParseReport::is_complete`] —
    /// and where it stopped if not.  A kernel `read(2)` returns whole events,
    /// so a non-complete report from here means something is wrong with the
    /// stream rather than with the caller, and `bytes_left` is the tail that was
    /// not interpreted.
    ///
    /// This is also the only read form that does not turn an unknown `vers`
    /// into an error: it reports [`EventStop::UnknownVersion`] and returns the
    /// events before it, so a caller recording raw bytes can keep them together
    /// with the reason they were not parsed.
    ///
    /// # Errors
    ///
    /// As [`read_events`](Self::read_events) for the syscall; a parse problem
    /// is in the report, not in the error.
    pub fn read_events_reported<'buf>(
        &self,
        buf: &'buf mut Vec<u8>,
    ) -> Result<(Vec<FidEvent<'buf>>, ParseReport)> {
        sys::read_events(&self.fd, buf)?;
        // SAFETY-propagation, not a new unsafe block: `sys::read_events`
        // performed the `read(2)` that filled `buf`, so a non-negative pidfd
        // number in it is a descriptor the kernel installed for this process.
        // Each number is adopted at most once, which the adopt helper enforces.
        let (mut events, report) = fid::parse_fid_events_reported(buf);
        let mut adopted = Vec::new();
        for event in &mut events {
            let Some(raw) = fid::reported_pidfd_number(event.pidfd()) else {
                continue;
            };
            *event.pidfd_mut() = fid::adopt_reported_pidfd(raw, &mut adopted);
        }
        Ok((events, report))
    }

    /// Read the events a group **without** a FID flag has queued.
    ///
    /// Each event owns an open descriptor for the object it is about — the
    /// identity this format exists to provide — closed when the event drops.
    /// Borrow it with [`FdEvent::fd`], hand it to a
    /// [`FanotifyResponse`](crate::response::FanotifyResponse) to answer a
    /// permission event, or take it with [`FdEvent::into_fd`].
    ///
    /// `buf` is scratch space, as in [`read_events`](Self::read_events), and its
    /// capacity is the read size in the same way.  It is also the only knob for
    /// this format: the kernel will not split an event across two reads, so a
    /// buffer too small for the next one earns `EINVAL` rather than a partial
    /// event.
    ///
    /// # Errors
    ///
    /// As [`read_events`](Self::read_events): the kernel's errno, with `EAGAIN`
    /// for an empty queue on a non-blocking group.
    pub fn read_fd_events(&self, buf: &mut Vec<u8>) -> Result<Vec<FdEvent>> {
        fd::read_fd_events(&self.fd, buf)
    }

    /// [`read_fd_events`](Self::read_fd_events), reporting how far the parse got.
    ///
    /// The same adoption — each event's descriptor becomes owned — plus a
    /// [`ParseReport`] saying whether the whole buffer became events and where
    /// the walk stopped if not.  A non-complete report from a kernel read means
    /// the stream, not the caller, and `bytes_left` is the tail that was not
    /// interpreted.
    pub fn read_fd_events_reported(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<(Vec<FdEvent>, ParseReport)> {
        fd::read_fd_events_reported(&self.fd, buf)
    }

    /// Answer a permission event: allow it, deny it, or deny it with an errno.
    ///
    /// The [`FanotifyResponse`](crate::response::FanotifyResponse) chooses the
    /// wire format from its shape — the plain word, or the word plus a response
    /// record — and the kernel validates every part of it: the decision bits,
    /// the errno, the record's `type`/`pad`/`len`, and the descriptor the answer
    /// must match.  See [`crate::response`] for the rules.
    ///
    /// # Errors
    ///
    /// [`FanotifyError::Write`] with the kernel's errno: `EINVAL` if the group
    /// lacks [`FAN_ENABLE_AUDIT`](consts::FAN_ENABLE_AUDIT) for an audit
    /// response or the word or record
    /// does not fit the flags, `ENOENT` if nothing is pending for that
    /// descriptor, `EBADF` if the group is not writable.
    pub fn send_response(&self, response: &FanotifyResponse<'_>) -> Result<()> {
        response::write_response(&self.fd, response)
    }

    /// Wait until the group has events to read, or until `timeout` elapses.
    ///
    /// Returns `true` if there is something to read.  This is the whole of the
    /// crate's I/O strategy: a readiness wait, so a non-blocking group can be
    /// consumed without polling and without this crate choosing an event loop
    /// for you.  For the same reason the group is an [`AsFd`], so it can be
    /// registered with whatever you already use — `epoll`, `mio`,
    /// `tokio::io::unix::AsyncFd`.
    ///
    /// `None` waits indefinitely.  On a blocking group this is redundant:
    /// [`read_events`](Self::read_events) already waits.
    ///
    /// # Errors
    ///
    /// [`FanotifyError::Read`] if `poll` fails.  `EINTR` is reported rather than
    /// retried, so a caller with its own signal handling decides what to do.
    pub fn wait_readable(&self, timeout: Option<std::time::Duration>) -> Result<bool> {
        let mut poll_fd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = match timeout {
            None => -1,
            // `poll` takes an i32 of milliseconds: saturate rather than wrap.
            Some(d) => d.as_millis().min(i32::MAX as u128) as libc::c_int,
        };

        // SAFETY: `poll_fd` is one initialized `pollfd` and the count says so.
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if ready < 0 {
            return Err(FanotifyError::Read(crate::sys::errno()));
        }
        Ok(ready > 0)
    }

    /// Borrow the group's descriptor.
    ///
    /// This is how the group is registered with an event loop, and how it can be
    /// passed to anything else that takes an `AsFd`.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Give up the group and hand back its descriptor.
    ///
    /// The descriptor stays open; whoever receives it now closes it, and until
    /// then the marks stay in place.
    pub fn into_inner(self) -> OwnedFd {
        self.fd
    }
}

impl AsFd for Fanotify {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
