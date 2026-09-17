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

    /// Adopt a group descriptor this process already holds.
    ///
    /// The descriptor-in form of [`init`](Self::init), for a group that was
    /// created elsewhere: inherited across `fork`/`exec`, received over a unix
    /// socket with `SCM_RIGHTS`, or set up before privileges were dropped.  None
    /// of those can be replaced by a call to `fanotify_init`, so without this the
    /// whole API — reading events, placing marks, answering permission events —
    /// is unreachable for a process that did not create its own group.
    ///
    /// Nothing is probed and nothing is stored but the descriptor: it is used as
    /// given, and the kernel's errno is what any later call answers.  The flags
    /// the group was created with are not known here and are not guessed at, so
    /// this is not the place to validate that a group is FID-mode.  A group that
    /// is not FID-mode still answers a read with bytes this crate parses — both
    /// identities share one metadata layout and one version — so the mistake
    /// shows up as events whose fsid and handles are absent rather than as an
    /// error.  [`read_events`](Self::read_events) reports what it can of them.
    ///
    /// The descriptor is owned from here on: dropping the returned value closes
    /// it, which releases the group's marks, so a caller that wants to keep the
    /// descriptor must [`into_inner`](Self::into_inner) it back or duplicate it
    /// first.
    ///
    /// # Safety
    ///
    /// The descriptor must be a fanotify group.  This is the same contract
    /// [`std::os::fd::FromRawFd`] carries and for the same reason: a descriptor
    /// is a bare number, and the kernel answers a `read(2)` on the wrong kind of
    /// object in its own way rather than in a way that can be checked here.  A
    /// duplicate of a group's own descriptor (`try_clone`) is the safe case and
    /// the one this exists for.
    ///
    /// ```rust,no_run
    /// use std::os::fd::OwnedFd;
    /// use fanotify_fid::Fanotify;
    ///
    /// # fn inherited_group() -> OwnedFd { unimplemented!() }
    /// // A group descriptor received over SCM_RIGHTS, say.
    /// let raw: OwnedFd = inherited_group();
    /// let fan = unsafe { Fanotify::from_fd(raw) };
    /// # Ok::<(), fanotify_fid::FanotifyError>(())
    /// ```
    pub unsafe fn from_fd(fd: OwnedFd) -> Self {
        Self { fd }
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
    /// # Reusing storage across reads
    ///
    /// The events `Vec` cannot be reused through *this* call, and that is a
    /// property of the lifetime rather than a missing method:
    /// `Vec<FidEvent<'buf>>` fixes `'buf`, so a `Vec` that outlives one iteration
    /// pins the buffer's borrow for as long as it lives and the next read cannot
    /// have the buffer at all.
    ///
    /// [`EventReader`] is the answer, and it needs nothing of the caller: it owns
    /// the buffer and the event `Vec`, so both are allocated once for the life of
    /// the reader and every read after setup allocates nothing.  Reach for this
    /// call instead when the events are consumed inside one iteration anyway —
    /// both are zero-copy, and only this one lets the buffer live on the stack.
    ///
    /// ```rust,no_run
    /// use fanotify_fid::{EventReader, Fanotify, FanotifyError, consts::*};
    ///
    /// # let fan = Fanotify::new(FAN_CLASS_NOTIF | FAN_REPORT_FID)?;
    /// let mut reader = EventReader::new(&fan, 256 * 1024);
    /// loop {
    ///     match reader.read() {
    ///         Ok(events) => {
    ///             for ev in events.iter() {
    ///                 println!("{:?}", ev.fsid());
    ///             }
    ///         }
    ///         // An empty queue is not a failure: wait for the next event.
    ///         Err(e) if e.is_would_block() => {
    ///             fan.wait_readable(None)?;
    ///         }
    ///         Err(e) => return Err(e),
    ///     }
    /// }
    /// # Ok::<(), FanotifyError>(())
    /// ```
    ///
    /// What that buys is real: without it every read that overflows a freshly
    /// grown buffer pays a `realloc` and a copy of everything already read.  If a
    /// caller would rather own its events outright, `FidEvent::into_owned` on
    /// each one trades that back for a copy per record — which is the trade this
    /// crate's borrowing model exists to refuse.
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
    ///         // An empty queue is not a failure: wait for the next event.
    ///         Err(e) if e.is_would_block() => {
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
        // Nothing to parse: not one byte was written, which on a non-blocking
        // group is the `EAGAIN` retry — the read that must stay free.  The early
        // return is what keeps it free of the walk rather than of an allocation
        // (`Vec::new()` does not allocate, and a parse of an empty buffer would
        // reach the same report); the empty-queue path is also why `read_events`
        // empties the buffer on failure, so a stale length cannot make this look
        // like a batch.
        if buf.is_empty() {
            return Ok((
                Vec::new(),
                ParseReport {
                    bytes_consumed: 0,
                    bytes_left: 0,
                    stop: EventStop::End,
                },
            ));
        }
        // SAFETY-propagation, not a new unsafe block: `sys::read_events`
        // performed the `read(2)` that filled `buf`, so a non-negative pidfd
        // number in it is a descriptor the kernel installed for this process.
        // Each number is adopted at most once, which the adopt helper enforces.
        let mut events = Vec::new();
        let report = fid::parse_fid_events_into(&mut events, buf);
        // A vector of descriptor numbers is scratch space per call rather than
        // per event: it is bounded by the events in one read, and a read that
        // carries pidfds is the rare case.
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

    /// The group's descriptor, for the crate's own syscall wrappers.
    ///
    /// Private on purpose: [`as_fd`](Self::as_fd) is the public form, and the
    /// readers and the response writer take the borrowed descriptor they need
    /// from it.  This exists so a reader can name the descriptor without naming
    /// the field.
    pub(crate) fn fd(&self) -> &OwnedFd {
        &self.fd
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

/// A reader that owns its buffer, so reading allocates nothing after setup.
///
/// [`Fanotify::read_events`] takes the read buffer from the caller, and the
/// events it returns borrow that buffer.  That is what makes parsing free of
/// per-record allocation, but it has a consequence the plain call cannot avoid:
/// `Vec<FidEvent<'buf>>` fixes `'buf`, so a `Vec` that outlives one read pins the
/// buffer's borrow for as long as the `Vec` lives, and the next read cannot have
/// the buffer at all.  The documented workaround was a `'static` buffer obtained
/// with `Box::leak` — trading a permanent leak for a per-read allocation, which
/// is a bad trade to hand a caller.
///
/// This type is the trade done properly.  It owns the buffer and the event
/// `Vec`, so both are allocated once, and hands out a borrow of the events for
/// as long as it is mutably borrowed:
///
/// ```rust,no_run
/// use fanotify_fid::fid::FidEvent;
/// use fanotify_fid::resolve::PathResolver;
/// use fanotify_fid::handle::{HandleCache, Mounts};
/// use fanotify_fid::{EventReader, Fanotify, FanotifyError, consts::*};
///
/// # let fan = Fanotify::new(FAN_CLASS_NOTIF | FAN_REPORT_FID)?;
/// # let store = HandleCache::new();
/// # let mounts = Mounts::new();
/// # let resolver = PathResolver::new(&store, &mounts);
/// let mut reader = EventReader::new(&fan, 256 * 1024);
/// loop {
///     match reader.read() {
///         Ok(events) => {
///             // `&mut`, so a path can be resolved in place: no copy per event.
///             resolver.resolve_events(events);
///             for ev in events.iter() {
///                 println!("{:?}", ev.path());
///             }
///         }
///         // An empty queue is not a failure: wait for the next event.
///         Err(e) if e.is_would_block() => {
///             fan.wait_readable(None)?;
///         }
///         Err(e) => return Err(e),
///     }
/// }
/// # Ok::<(), FanotifyError>(())
/// ```
///
/// # Why this is sound
///
/// The events name bytes inside the reader's own buffer, so storing them as
/// `FidEvent<'static>` is a lifetime erasure — two `unsafe` blocks in
/// `read_reported`, and no others in this type — and these properties make it
/// hold:
///
/// * **The buffer cannot be moved or grown.**  It is a `Box<[u8]>` and its
///   length is a separate field, so there is no capacity to reserve into and no
///   `push` to reallocate: the allocation is made once by [`new`](Self::new) and
///   [`read`](Self::read) only ever changes how many of its bytes are live.  That
///   is a property of the type rather than of a comment — growth is not offered,
///   and a caller that needs a different size makes a different reader — so the
///   safety argument does not depend on the crate's `read_into` continuing to
///   behave.
/// * **`read` takes `&mut self`.**  While the slice it returned is alive the
///   caller cannot call `read` again — or any other `&mut self` method — so the
///   kernel cannot write into the buffer while events borrowing it are in use.
///   The lifetime the caller sees is the borrow of `self`, which is what makes
///   the compiler enforce the order a consumer must have anyway.
/// * **Nothing borrows the buffer once the reader is dropping.**  `Drop` runs
///   the fields in declaration order, so `group`, `buf`, `bytes_read` and
///   `events` are released in that order: the allocation is freed *before* the
///   events that name bytes inside it.  That order is safe only because a
///   `Cow::Borrowed` is a pointer and a length with nothing to run — `Cow` has no
///   `Drop` of its own, and neither does the `&[u8]` inside it, so no destructor
///   reads through the slice.  The invariant a change here has to keep is
///   therefore **not** "`events` outlives `buf`" — declaration order deliberately
///   does not provide that — but "no field of [`FidEvent`] dereferences the
///   buffer when dropped".  A field with a destructor that touched the bytes
///   (`Cow` replaced by a type that reports what it read, say) would make the
///   current order unsound, and moving `events` above `buf` is what that change
///   would have to come with.
/// * **A batch is overwritten, never read back.**  The slice handed out is `&mut`,
///   so a caller may *write* to the events — including storing an event whose
///   `Cow` borrows something shorter-lived than the reader.  That is sound for the
///   same reason the drop order is: the next parse assigns over every live slot
///   (`FidEvent::reset` plus the parsed value), so no stale event is ever read,
///   and dropping the replaced value reaches no buffer because nothing in
///   `FidEvent` reads through a `Cow` on drop.  This is the half of the argument a
///   caller can defeat by keeping one of those `&mut` events alive across a read —
///   which the borrow of `self` already forbids.
///
/// A pidfd record is adopted here exactly as in `read_events`, and on the same
/// grounds: the buffer is the direct result of this call's `read(2)`.
#[derive(Debug)]
pub struct EventReader<'fan> {
    /// Borrowed, not owned: the group outlives every read, and a reader that
    /// owned the descriptor would close the group when it dropped.
    group: &'fan Fanotify,
    /// The read buffer, boxed and fixed: `bytes_read` is how much of it the last
    /// `read(2)` filled.  A `Box<[u8]>` cannot grow, which is the type-level half
    /// of the safety argument above — there is no capacity for a reserve to
    /// consume and no pointer for a growth to invalidate.
    ///
    /// Declared before `events` on purpose, and it does not matter which way
    /// round they are: see the drop-order bullet above for the invariant that
    /// actually has to hold.
    buf: Box<[u8]>,
    /// How many bytes of `buf` the last read produced.
    bytes_read: usize,
    /// The erased form of the events in `buf`.  Never handed out as `'static` —
    /// `read` narrows it to the borrow of `self` before returning.
    events: Vec<FidEvent<'static>>,
}

impl<'fan> EventReader<'fan> {
    /// A reader over `group` with a `capacity`-byte read buffer.
    ///
    /// The capacity is the read size and is fixed for the reader's life: one
    /// `read(2)` returns as many whole events as fit, so a larger buffer means
    /// fewer syscalls on a deep queue, never a partial event.  A buffer too small
    /// for the next event earns `EINVAL` from the kernel rather than a split —
    /// see [`Fanotify::read_events`] — and the only remedy is a larger reader.
    ///
    /// A zero `capacity` is the 64 KiB default below rather than a zero-byte
    /// read, which the kernel would answer `EINVAL` to forever; a caller that
    /// wants a different read size passes one — 256 KiB is a reasonable size for
    /// a filesystem mark.
    pub fn new(group: &'fan Fanotify, capacity: usize) -> Self {
        /// What a `capacity` of zero becomes: the same floor
        /// [`sys::read_events`] applies to a buffer the caller did not size.
        const DEFAULT_BUF_BYTES: usize = 64 * 1024;

        let bytes = if capacity == 0 {
            DEFAULT_BUF_BYTES
        } else {
            capacity
        };
        Self {
            group,
            // Zeroed rather than uninitialized: this is the one allocation the
            // reader makes, and paying one `calloc` for it is what lets every
            // later read be a plain `&mut [u8]` with no `MaybeUninit` anywhere in
            // the API or the safety argument.
            buf: vec![0u8; bytes].into_boxed_slice(),
            bytes_read: 0,
            events: Vec::new(),
        }
    }

    /// Read the next batch and return the events, mutably.
    ///
    /// Mutably because resolving a path writes it onto the event
    /// ([`PathResolver::resolve_events`](crate::resolve::PathResolver::resolve_events)),
    /// and a shared slice would force the caller to copy each event to do that.
    ///
    /// The slice is valid until the next `&mut self` call on this reader; it is
    /// the reader's own storage, so nothing is allocated for it.
    ///
    /// # Errors
    ///
    /// As [`Fanotify::read_events`]: the kernel's errno, with `EAGAIN` for an
    /// empty queue on a non-blocking group — which is not a failure, and costs
    /// nothing here.  An unknown `vers` is [`FanotifyError::UnknownEventVersion`].
    pub fn read(&mut self) -> Result<&mut [FidEvent<'_>]> {
        let (events, report) = self.read_reported()?;
        if let EventStop::UnknownVersion(vers) = report.stop {
            return Err(FanotifyError::UnknownEventVersion(vers));
        }
        Ok(events)
    }

    /// [`read`](Self::read), also reporting how far the parse got.
    ///
    /// The [`ParseReport`] is the same one [`Fanotify::read_events_reported`]
    /// returns, including its treatment of an unknown `vers`: reported rather
    /// than raised, so the events before it are still there.
    ///
    /// # Errors
    ///
    /// The syscall's errno, and nothing else: an error here means no bytes were
    /// read, so the buffer and the events are both empty and
    /// nothing of the previous read is still reachable.  An unknown `vers` in a
    /// *successful* read is not an error here — it is the `EventStop` in the
    /// returned [`ParseReport`], with the events parsed before it still in the
    /// slice.  [`read`](Self::read) is the form that raises it instead, and that
    /// error is the one case where the bytes and the events of the last read stay
    /// reachable.
    pub fn read_reported(&mut self) -> Result<(&mut [FidEvent<'_>], ParseReport)> {
        // Both halves of "what the last read produced" are cleared *before* the
        // read, not after it succeeds.  A failed read — the `EAGAIN` of an empty
        // queue, an `EINVAL` for an oversized event — produced nothing, so
        // the buffer must not go on holding the previous batch and these
        // events must not go on holding its pidfds.  Clearing after the `?` would
        // leave exactly that stale state behind, and a caller that copies
        // a stale buffer on the error path would process the previous batch twice.
        self.bytes_read = 0;
        self.events.clear();

        // `&mut [u8]` out of the box, so the type itself rules out a
        // reallocation: `read_into` has nowhere to grow into.
        let n = sys::read_into(self.group.fd(), &mut self.buf)?;
        self.bytes_read = n;

        // Nothing was written: an empty queue, or the `EAGAIN` this crate's
        // non-blocking examples retry on.  Returning early is what keeps that
        // wake-up free — no parse, no allocation, no syscall beyond the one just
        // made.  The length is zero here, so the erasure below has nothing to
        // get wrong; it is skipped rather than reasoned about.
        let report = if n == 0 {
            ParseReport {
                bytes_consumed: 0,
                bytes_left: 0,
                stop: EventStop::End,
            }
        } else {
            // SAFETY: the erasure's two preconditions are this type's invariants.
            //
            // 1. The bytes live in `self.buf`, a `Box<[u8]>` whose allocation was
            //    made once in `new`: it cannot be reallocated, because there is no
            //    capacity to grow into and no owned `Vec` behind it.  So the bytes
            //    the events name stay where they are for as long as `self` lives —
            //    which is at least as long as the `'static` this claims.
            // 2. No `FidEvent<'static>` is ever exposed as `'static`: the
            //    narrowing below returns the borrow of `&mut self`, so the
            //    compiler will not let a caller hold the events across another
            //    `&mut self` call, and the kernel therefore cannot write into
            //    `self.buf` while an event borrows it.
            //
            // The pidfd adoption is sound for the reason it is in
            // `read_events_reported`: those bytes are the direct result of the
            // `read` just above, so a non-negative number in them is a descriptor
            // the kernel installed for this process.
            let buf: &'static [u8] =
                unsafe { std::slice::from_raw_parts(self.buf.as_ptr(), self.bytes_read) };
            let report = fid::parse_fid_events_into(&mut self.events, buf);
            let mut adopted = Vec::new();
            for event in &mut self.events {
                let Some(raw) = fid::reported_pidfd_number(event.pidfd()) else {
                    continue;
                };
                *event.pidfd_mut() = fid::adopt_reported_pidfd(raw, &mut adopted);
            }
            report
        };

        // The one place the erased lifetime becomes the caller's borrow, and it
        // narrows rather than widens: the events live in `self.events`, which
        // cannot be touched again until this borrow ends.  A shared slice would
        // not do — `FidEvent` is invariant in its lifetime, so `&mut
        // [FidEvent<'static>]` cannot be returned as anything else without this.
        let events = unsafe {
            std::mem::transmute::<&mut [FidEvent<'static>], &mut [FidEvent<'_>]>(&mut self.events)
        };
        Ok((events, report))
    }

    // There is deliberately no `raw_bytes` here.
    //
    // This reader owns its buffer, and the events it hands out borrow that
    // buffer.  Handing out `&[u8]` as well is therefore not a missing accessor
    // but an unsound one: the two borrows cannot both be live, and a method that
    // returned the bytes *without* reborrowing the events would be returning a
    // slice the next read may overwrite while the events still point into it.
    // Rather than document that trap, this type does not offer it — a caller that
    // needs the bytes uses the stateless form, `Fanotify::read_events` or
    // `read_events_reported`, where the buffer is the caller's own `Vec` and the
    // borrow checker can see the whole picture.  See `examples/batch_to_worker.rs`.

    /// The capacity chosen for the read buffer, which is the read size.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// How much storage the event `Vec` has, which a read grows at most once.
    ///
    /// The per-read allocation this type exists to remove is the event `Vec`
    /// growing; after the first read that produced events it is sized for the
    /// batch it saw, and a later read of the same size reuses it.  Exposed for
    /// tests and for a caller that wants to confirm the warm-up happened.
    pub fn event_capacity(&self) -> usize {
        self.events.capacity()
    }
}

/// [`EventReader`] for a group that reports **descriptors** instead of handles.
///
/// The same idea as [`EventReader`], for the other identity: the reader owns the
/// buffer and the event storage, so every read after setup allocates nothing and
/// nothing is left to the caller to arrange.  [`Fanotify::read_fd_events`] is the
/// stateless form, and it is fine when one batch is parsed and dropped; this is
/// the form for a loop, where the event `Vec` is the allocation it removes.
///
/// ```rust,no_run
/// use fanotify_fid::response::FanotifyResponse;
/// use fanotify_fid::{Fanotify, FanotifyError, FdEventReader, consts::*};
///
/// # fn main() -> Result<(), FanotifyError> {
/// // Descriptor identity: the events carry the object, not a handle.
/// let fan = Fanotify::new(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK)?;
/// fan.mark(FAN_MARK_ADD, FAN_OPEN_PERM, "/srv/data")?;
///
/// let mut reader = FdEventReader::new(&fan, 64 * 1024);
/// loop {
///     match reader.read() {
///         Ok(events) => {
///             for ev in events {
///                 let Some(fd) = ev.fd() else { continue };
///                 // The answer must be written before the next read: the next
///                 // read replaces the events, and a replaced event closes its
///                 // descriptor.
///                 fan.send_response(&FanotifyResponse::allow(fd))?;
///             }
///         }
///         // An empty queue is not a failure: wait for the next event.
///         Err(e) if e.is_would_block() => {
///             fan.wait_readable(None)?;
///         }
///         Err(e) => return Err(e),
///     }
/// }
/// # }
/// ```
///
/// # How it differs from the FID reader
///
/// `read` returns `&[FdEvent]` where [`EventReader::read`] returns
/// `&mut [FidEvent<'_>]`, and the difference is a fact about the two formats
/// rather than a choice: an fd-based event **owns** everything it reports, so
/// there is nothing borrowed from the buffer to erase, no lifetime to narrow, and
/// no `unsafe` anywhere in this type.  A caller who needs to change an event has
/// `&mut` through the slice it owns; a caller who wants a path resolved in place
/// has no equivalent here, because a `FdEvent`'s path comes from `/proc` and not
/// from a resolver.
///
/// # The batch stays valid until the next read
///
/// A slot that is rewritten gives up the descriptor it held — dropping an
/// [`OwnedFd`] closes it — so an event's `fd` is live from the read that reported
/// it until the next `read` on the same reader, or until the event is taken out
/// with [`FdEvent::into_fd`].  That is the same rule
/// [`parse_fd_events_into`](crate::fd::parse_fd_events_into) documents, and the
/// same one the stateless call has by construction: what changes here is only
/// that the storage is reused rather than freed.
#[derive(Debug)]
pub struct FdEventReader<'fan> {
    /// Borrowed, as in [`EventReader`]: the reader must not close the group.
    group: &'fan Fanotify,
    /// The read buffer, boxed and fixed: `bytes_read` says how much of it the
    /// last `read(2)` filled.
    buf: Box<[u8]>,
    /// How many bytes of `buf` the last read produced.
    bytes_read: usize,
    /// The events of the last read.  Filled to the largest count the buffer can
    /// hold, so a read reuses slots instead of growing the `Vec`; only the first
    /// events after a read are live, because `read` truncates to the count the
    /// parse produced.
    events: Vec<FdEvent>,
}

impl<'fan> FdEventReader<'fan> {
    /// A reader over `group` with a `capacity`-byte read buffer.
    ///
    /// As [`EventReader::new`]: the capacity is the read size, fixed for the
    /// reader's life, and zero is the 64 KiB default rather than a zero-byte
    /// read.  An fd-based event is [`METADATA_SIZE`](crate::fd::METADATA_SIZE)
    /// bytes with nothing after it, so the buffer also decides how many events
    /// one syscall may return.
    pub fn new(group: &'fan Fanotify, capacity: usize) -> Self {
        /// The same floor [`EventReader::new`] applies.
        const DEFAULT_BUF_BYTES: usize = 64 * 1024;

        let bytes = if capacity == 0 {
            DEFAULT_BUF_BYTES
        } else {
            capacity
        };
        // The most events `bytes` could ever hold, so the event `Vec` is
        // allocated once here and never grown by a read.  A short event is
        // impossible — the kernel writes at least a header — so this is an upper
        // bound rather than a guess that could be exceeded.
        let most_events = bytes.div_ceil(crate::fd::METADATA_SIZE);
        let mut events = Vec::new();
        // Reserved exactly, so the upper bound is the storage's real capacity and
        // cannot be exceeded by a read: `resize_with` alone would leave the `Vec`
        // free to grow past it.
        events.reserve_exact(most_events);
        // `resize_with` rather than `vec![event; n]`: `FdEvent` is deliberately
        // not `Clone` (cloning one would have to duplicate or share a descriptor),
        // and empty slots need no cloning anyway.
        events.resize_with(most_events, || FdEvent::new(0, None, 0));
        Self {
            group,
            buf: vec![0u8; bytes].into_boxed_slice(),
            bytes_read: 0,
            events,
        }
    }

    /// Read the next batch of fd-based events.
    ///
    /// The events are borrowed from the reader, and the borrow is what keeps the
    /// rule above enforceable: the next `read` needs `&mut self`, so the
    /// compiler will not let a caller keep an event's descriptor number or its
    /// place in the batch across one.
    ///
    /// # Errors
    ///
    /// As [`Fanotify::read_fd_events`]: the kernel's errno, with `EAGAIN` for an
    /// empty queue on a non-blocking group — not a failure, and it costs nothing
    /// here.
    pub fn read(&mut self) -> Result<&[FdEvent]> {
        let (events, _) = self.read_reported()?;
        Ok(events)
    }

    /// [`read`](Self::read), also reporting how far the parse got.
    ///
    /// The same [`ParseReport`] as
    /// [`Fanotify::read_fd_events_reported`](crate::Fanotify::read_fd_events_reported):
    /// a kernel `read(2)` returns whole events, so a non-complete report means
    /// the stream, not the caller, and `bytes_left` is the tail that was not
    /// interpreted.
    ///
    /// # Errors
    ///
    /// As [`read`](Self::read).  An error is not a batch: it empties both
    /// [`raw_bytes`](Self::raw_bytes) and the event storage, so the descriptors
    /// the previous batch carried are closed here rather than left held by a
    /// reader whose last read failed.
    pub fn read_reported(&mut self) -> Result<(&[FdEvent], ParseReport)> {
        // Nothing the previous read produced survives into this one — see
        // `EventReader::read_reported` for why this runs before the read rather
        // than after it.  Here it is sharper than a stale `raw_bytes`: the slots
        // still hold the descriptors the previous batch put there, and a read
        // that fails must not leave them owned by a batch that is over.
        self.bytes_read = 0;
        self.events.clear();

        let n = sys::read_into(self.group.fd(), &mut self.buf)?;
        self.bytes_read = n;

        // Every slot is live again: `parse_fd_events_into` writes each one before
        // it is read, and rewrites the `fd` field of a slot it reuses — which is
        // what closes the descriptor the previous read put there.  So a stale
        // descriptor cannot outlive the read that replaced it, and the truncate
        // below is what keeps the returned slice from including slots this read
        // did not fill.
        let report = fd::parse_fd_events_into(&mut self.events, &self.buf[..n]);
        // `bytes_consumed` is the sum of the events' own `event_len` fields, each
        // of which is checked against `METADATA_SIZE` before it is walked, so this
        // division is exact and the result is the number of live slots.
        self.events
            .truncate(report.bytes_consumed / crate::fd::METADATA_SIZE);
        // The same adoption as the stateless read, and on the same grounds: this
        // buffer is what this call's `read(2)` just returned, so a non-negative
        // number in it is a descriptor the kernel installed for this process.
        // The scratch list is per read on purpose: it holds the numbers adopted
        // *in this buffer*, and carrying it across reads would refuse a number
        // the kernel had legitimately reused after the previous batch closed it.
        let mut adopted = Vec::new();
        for event in &mut self.events {
            event.adopt_reported(&mut adopted);
        }
        Ok((&self.events, report))
    }

    /// The bytes the last read produced, marker for marker as the kernel wrote
    /// them.
    ///
    /// For a caller that records raw input, and for the architecture that cannot
    /// keep events across the next read: copy this once and hand the copy to
    /// [`parse_fd_events`](crate::fd::parse_fd_events) wherever you like.
    ///
    /// Empty after a read that returned an error, exactly as in
    /// [`Fanotify::read_events`]: a failed read produced nothing, so the
    /// previous batch does not linger here for a caller to process twice.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.buf[..self.bytes_read]
    }

    /// The read size this reader was built with.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// How many event slots the reader holds, which is its upper bound on events
    /// per read.
    ///
    /// Allocated once, by [`new`](Self::new): this is the storage a read reuses,
    /// exposed so a caller can confirm that no read grows it.
    pub fn event_capacity(&self) -> usize {
        self.events.capacity()
    }
}
