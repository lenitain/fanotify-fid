//! FID identity: the event format that identifies objects by file handle.
//!
//! # The format, byte for byte
//!
//! A FID group's event is a fixed header followed by zero or more info records.
//! Nothing about the records is fixed-size, which is why the header's
//! `event_len` — not a constant stride — is what advances a reader from one
//! event to the next.
//!
//! ```text
//! ┌───────────────────────────────────────────────┐
//! │ struct fanotify_event_metadata      24 bytes  │
//! │   u32 event_len      total size of this event │
//! │   u8  vers           FANOTIFY_METADATA_VERSION│
//! │   u8  reserved                                │
//! │   u16 metadata_len   where records start      │
//! │   u64 mask           which bits fired         │
//! │   i32 fd             FAN_NOFD in a FID group  │
//! │   i32 pid            who caused it            │
//! ├───────────────────────────────────────────────┤
//! │ struct fanotify_event_info_header    4 bytes  │  ┐
//! │   u8  info_type                               │  │ repeated
//! │   u8  pad                                     │  │ event_len −
//! │   u16 len            total size of the record  │  │ metadata_len
//! ├───────────────────────────────────────────────┤  │ bytes
//! │ payload, laid out per info_type:              │  │
//! │   FID / DFID:        fsid(8) + file_handle    │  │
//! │   DFID_NAME:         fsid(8) + file_handle    │  │
//! │                      + name(NUL-terminated)   │  │
//! │                      + padding to 8 bytes     │  │
//! │   PIDFD:             i32                      │  │
//! │   ERROR:             i32 errno + u32 count    │  │
//! │   RANGE:             u64 offset + u64 count   │  │
//! │   MNT:               u64 mount id             │  │
//! └───────────────────────────────────────────────┘  ┘
//! ```
//!
//! The event mask lives in the **header**, not in a record: the records say
//! *which object*, the header says *what happened*.  A mask bit with no record
//! is normal — [`FAN_Q_OVERFLOW`] is the
//! important one, and it names no object at all because it is not about one.
//!
//! # No file descriptor, and no path
//!
//! `metadata.fd` is `FAN_NOFD` for every event of a FID group — that is the
//! whole point of the identity, and it is why FID and the permission classes
//! cannot be combined.  The exception is a
//! [`FAN_NOFD`] value that is not `-1`, which only a
//! [`FAN_REPORT_FD_ERROR`] group produces;
//! see [`FidEvent::fd_error`].
//!
//! There is likewise no path.  The kernel reports an fsid, a handle and a name,
//! and turning that into a path is
//! [`handle::resolve_file_handle`](crate::handle::resolve_file_handle) — a
//! separate call, because it needs a privilege the event itself does not and
//! can fail for reasons that say nothing about the event.
//!
//! # Events borrow the buffer they were parsed from
//!
//! A FID group under a filesystem mark can deliver 10^5–10^6 events a second,
//! and each event names a handle and usually an entry name.  Copying those bytes
//! out of the read buffer would put one heap allocation per record on that path
//! — the parser's whole cost, and paid for bytes that are already in memory and
//! about to be used once.
//!
//! So [`FidEvent<'buf>`](FidEvent) borrows the buffer: its handle and name fields
//! are `Cow<'buf, [u8]>`, borrowed for every event [`parse_fid_events`] produces,
//! and the parser itself allocates nothing beyond growing the event `Vec`.
//! The rules that follow are the whole lifetime model:
//!
//! * **The buffer must outlive the events.**  `parse_fid_events(buf)` returns
//!   `Vec<FidEvent<'_>>` tied to `buf`, so the borrow checker enforces it.
//! * **You cannot read again while events are alive**, because a read needs the
//!   buffer mutably and the events hold it shared.  In the ordinary loop that is
//!   exactly right — parse, resolve, use, drop, read again — and it is why
//!   [`Fanotify::read_events`](crate::Fanotify::read_events) returns borrowed
//!   events rather than copies.
//! * **An event that must outlive the buffer is made owned explicitly**, with
//!   [`FidEvent::into_owned`], which converts every borrowed field to an owned
//!   one.  A hand-built event ([`FidEvent::new`] plus setters) is owned from the
//!   start, because its setters accept anything that becomes a `Cow`.
//!
//! The reports are the other half: [`parse_fid_events_reported`] and
//! [`parse_fid_events_into`] return a [`ParseReport`] saying how far the walk
//! got, because a short buffer and an empty queue must not look alike.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::consts::*;
use crate::error::FanotifyError;
use crate::handle::Fsid;
use crate::parse::{EventStop, ParseReport};

/// `sizeof(struct fanotify_event_metadata)`.
pub const METADATA_SIZE: usize = 24;

/// `sizeof(struct fanotify_event_info_header)`.
pub const INFO_HEADER_SIZE: usize = 4;

/// Size of the `fsid` field at the start of a FID/DFID/DFID_NAME payload.
pub const FSID_SIZE: usize = 8;

/// `struct fanotify_event_metadata` — the fixed header of every event.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

// The parse loop bounds-checks with `METADATA_SIZE` and then reads
// `size_of::<EventMetadata>()` bytes, so if the two ever disagreed the read
// would run past the check that was supposed to cover it.  Pinning the struct to
// the kernel's number here is what makes the bounds check the real one.
const _: () = assert!(std::mem::size_of::<EventMetadata>() == METADATA_SIZE);

/// `struct fanotify_event_info_header` — the type/length header of one record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct InfoHeader {
    info_type: u8,
    pad: u8,
    len: u16,
}

// As above: the record walk checks `INFO_HEADER_SIZE` and reads this.
const _: () = assert!(std::mem::size_of::<InfoHeader>() == INFO_HEADER_SIZE);

/// One side of a `FAN_RENAME` event.
///
/// A rename reports the **parent directory's handle plus the entry name**, on
/// each side the mark matched: the source side arrives as
/// `FAN_EVENT_INFO_TYPE_OLD_DFID_NAME` and the target side as
/// `FAN_EVENT_INFO_TYPE_NEW_DFID_NAME`.  They are independent records, so a
/// rename that moves an entry into or out of the watched object reports only
/// the side that was watched.
/// Each field is a [`Cow`]: borrowed when the side came out of a parse buffer,
/// owned when it was built by hand or converted with
/// [`into_owned`](Self::into_owned).  Parsing therefore copies no bytes, which
/// matters because a rename is exactly the event that names two of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameSide<'buf> {
    /// Handle of the parent directory the entry was, or is, in.
    pub handle: Cow<'buf, [u8]>,
    /// Entry name within that parent, as raw bytes — a Linux filename need not
    /// be UTF-8, so the bytes are the authoritative form.
    pub name: Cow<'buf, [u8]>,
}

impl RenameSide<'_> {
    /// Handle of the parent directory the entry was, or is, in.
    ///
    /// The bytes are the filesystem's, to be used with
    /// [`resolve_file_handle`](crate::handle::resolve_file_handle) and the fsid
    /// the event reported — a handle is only meaningful together with its
    /// filesystem.
    pub fn handle(&self) -> &[u8] {
        &self.handle
    }

    /// The entry name as an [`OsStr`], which accepts any byte sequence.
    pub fn name(&self) -> &OsStr {
        OsStr::from_bytes(&self.name)
    }

    /// The entry name as a `String`, or `None` if it is not valid UTF-8.
    pub fn name_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.name).ok()
    }

    /// The entry name as an owned `OsString`.
    pub fn name_os_string(&self) -> OsString {
        OsString::from_vec(self.name.to_vec())
    }

    /// Take ownership of both fields, so the side outlives the buffer it came
    /// from.
    ///
    /// A side borrowed from a parse buffer is `RenameSide<'buf>`; this is how it
    /// becomes `RenameSide<'static>` — the same bytes, now owned.
    pub fn into_owned(self) -> RenameSide<'static> {
        RenameSide {
            handle: Cow::Owned(self.handle.into_owned()),
            name: Cow::Owned(self.name.into_owned()),
        }
    }
}

/// The pidfd a `FAN_REPORT_PIDFD` group attaches to an event.
///
/// A pidfd is a descriptor, and the record that carries it holds a *number*, so
/// the three cases are kept apart in the type rather than collapsed into an
/// `Option<i32>`: reading `-1` or `-2` as a descriptor number would be reading a
/// sentinel as a descriptor, and adopting it would close an unrelated open file
/// or abort the process.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Pidfd {
    /// No pidfd record: the group was not created with
    /// [`FAN_REPORT_PIDFD`].
    Absent,
    /// A pidfd for the process that caused the event, owned by this event.
    ///
    /// Unlike [`FidEvent::pid`], it cannot be confused by pid reuse.  [`Clone`]
    /// shares the descriptor rather than duplicating it, so a cloned event costs
    /// no syscall; [`Pidfd::into_fd`] takes it out, duplicating it when a clone
    /// still holds it.
    Fd(Arc<OwnedFd>),
    /// A pidfd record that carried a number instead of a descriptor.
    ///
    /// A **negative** value is the kernel's own verdict: [`FAN_NOPIDFD`] when
    /// the target process was already gone, [`FAN_EPIDFD`] when creating the
    /// descriptor failed for another reason, or that failure's errno.
    ///
    /// A **non-negative** value is the descriptor number the record carried,
    /// left unadopted because the bytes it came from prove nothing about
    /// themselves: [`parse_fid_events`] is handed a `&[u8]`, which can come from
    /// anywhere, and adopting a number out of such a buffer is how a descriptor
    /// gets closed by a stranger.  A caller that performed the `read(2)` itself
    /// may adopt it — [`Pidfd::from`] over
    /// `unsafe { OwnedFd::from_raw_fd(n) }`, then [`FidEvent::set_pidfd`] — while
    /// the crate's own read path,
    /// [`Fanotify::read_events`](crate::Fanotify::read_events), already has.
    Unavailable(i32),
}

impl PartialEq for Pidfd {
    /// Compares what the record said about the process, not which descriptor
    /// value holds it.
    ///
    /// Two descriptors naming the same process compare equal, so a cloned event
    /// equals the event it came from, and an event from
    /// [`Fanotify::read_events`](crate::Fanotify::read_events) equals the same
    /// bytes parsed by [`parse_fid_events`] — one holds the descriptor, the
    /// other the number it came from.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Absent, Self::Absent) => true,
            (Self::Fd(a), Self::Fd(b)) => Arc::ptr_eq(a, b) || a.as_raw_fd() == b.as_raw_fd(),
            (Self::Unavailable(a), Self::Unavailable(b)) => a == b,
            (Self::Fd(fd), Self::Unavailable(raw)) | (Self::Unavailable(raw), Self::Fd(fd)) => {
                fd.as_raw_fd() == *raw
            }
            // Absent against anything else: one event named the process and the
            // other said nothing about it.
            _ => false,
        }
    }
}

impl Eq for Pidfd {}

impl From<OwnedFd> for Pidfd {
    /// Attach a descriptor the caller already owns.
    ///
    /// How an event built by hand gets a pidfd: the descriptor is shared, not
    /// duplicated, so the event closes it exactly like one it parsed itself.
    fn from(fd: OwnedFd) -> Self {
        Self::Fd(Arc::new(fd))
    }
}

/// A parsed event of a FID group.
///
/// Every record the kernel defines has a typed accessor here, and a record this
/// crate does not recognise is preserved rather than dropped — verbatim, header
/// included, see [`unknown_info_records`](Self::unknown_info_records).
///
/// The raw identity data is exposed as reported: fsid, handles and name bytes,
/// with no interpretation.  Turning a handle into a path is a separate call
/// ([`resolve_file_handle`](crate::handle::resolve_file_handle)) that needs a
/// privilege the event does not, so the two are not fused.
#[derive(Debug, Clone)]
pub struct FidEvent<'buf> {
    mask: u64,
    pid: i32,
    fsid: Option<Fsid>,
    dfid_name_handle: Option<Cow<'buf, [u8]>>,
    dfid_name_name: Option<Cow<'buf, [u8]>>,
    self_handle: Option<Cow<'buf, [u8]>>,
    pidfd: Pidfd,
    fd_error: Option<i32>,
    fs_error: Option<(i32, u32)>,
    access_range: Option<(u64, u64)>,
    mnt_id: Option<u64>,
    rename_source: Option<RenameSide<'buf>>,
    rename_target: Option<RenameSide<'buf>>,
    unknown_info_records: Vec<(u8, Cow<'buf, [u8]>)>,
    /// Where resolution put the path, or `None` when it was not resolved.
    ///
    /// Empty for every event straight out of
    /// [`parse_fid_events`], because parsing is pure and a path costs a
    /// privileged syscall.  This is the attachment point, not an interpretation:
    /// what lands here is what `/proc` said.
    path: Option<PathBuf>,
}

impl PartialEq for FidEvent<'_> {
    /// Compares every field; the pidfd comparison is [`Pidfd`]'s.
    ///
    /// A cloned event equals the event it was cloned from, and two events whose
    /// pidfd records carried the same number compare equal there — what differs
    /// is which of the two holds the descriptor, which is not a difference in
    /// what the kernel reported.
    fn eq(&self, other: &Self) -> bool {
        self.mask == other.mask
            && self.pid == other.pid
            && self.fsid == other.fsid
            && self.dfid_name_handle == other.dfid_name_handle
            && self.dfid_name_name == other.dfid_name_name
            && self.self_handle == other.self_handle
            && self.pidfd == other.pidfd
            && self.fd_error == other.fd_error
            && self.fs_error == other.fs_error
            && self.access_range == other.access_range
            && self.mnt_id == other.mnt_id
            && self.rename_source == other.rename_source
            && self.rename_target == other.rename_target
            && self.unknown_info_records == other.unknown_info_records
            && self.path == other.path
    }
}

impl Eq for FidEvent<'_> {}

impl Default for FidEvent<'_> {
    /// The same event [`new`](FidEvent::new) makes: one that says nothing.
    fn default() -> Self {
        Self::new()
    }
}

impl<'buf> FidEvent<'buf> {
    /// An event that says nothing, for building one by hand.
    ///
    /// Every field starts empty: no mask, no pid, no handle, no path.  The
    /// setters below put facts on it, and the accessors then report exactly
    /// those facts — which is what makes an event a value a caller can
    /// construct, compare against a parsed one, or synthesise from another.
    ///
    /// The parser does not use this; it fills its events from the buffer, so
    /// nothing here can affect what [`parse_fid_events`] reports.
    ///
    /// ```
    /// use fanotify_fid::consts::FAN_CREATE;
    ///
    /// let mut ev = fanotify_fid::fid::FidEvent::new();
    /// ev.set_mask(FAN_CREATE)
    ///     .set_pid(4242)
    ///     .set_dfid_name(vec![0u8; 12], b"entry".to_vec())
    ///     .set_fd_error(-13);
    /// // `event_names` reports the bit's name without the `FAN_` prefix.
    /// assert!(ev.event_names().any(|n| n == "CREATE"));
    /// assert_eq!(ev.dfid_name_str(), Some("entry"));
    /// assert_eq!(ev.fd_error(), Some(-13));
    /// assert!(ev.path().is_none());
    /// ```
    pub fn new() -> Self {
        Self {
            mask: 0,
            pid: 0,
            fsid: None,
            dfid_name_handle: None,
            dfid_name_name: None,
            self_handle: None,
            pidfd: Pidfd::Absent,
            fd_error: None,
            fs_error: None,
            access_range: None,
            mnt_id: None,
            rename_source: None,
            rename_target: None,
            unknown_info_records: Vec::new(),
            path: None,
        }
    }

    /// Take ownership of every borrowed field, so the event outlives the buffer
    /// it was parsed from.
    ///
    /// A parsed event is [`Cow::Borrowed`] throughout, so it is tied to the
    /// read buffer; this is the explicit conversion to `FidEvent<'static>`,
    /// which copies exactly the fields that were borrowed.  A hand-built event
    /// is already owned and is returned unchanged in content.
    ///
    /// ```
    /// use fanotify_fid::fid::{FidEvent, parse_fid_events};
    ///
    /// # let buf: Vec<u8> = Vec::new();
    /// // Borrowed: tied to `buf`.
    /// let borrowed: Vec<FidEvent<'_>> = parse_fid_events(&buf).unwrap();
    /// // Owned: outlives `buf`, and outlives this call.
    /// let owned: Vec<FidEvent<'static>> =
    ///     borrowed.into_iter().map(FidEvent::into_owned).collect();
    /// # let _ = owned;
    /// ```
    pub fn into_owned(self) -> FidEvent<'static> {
        FidEvent {
            mask: self.mask,
            pid: self.pid,
            fsid: self.fsid,
            dfid_name_handle: self.dfid_name_handle.map(|v| Cow::Owned(v.into_owned())),
            dfid_name_name: self.dfid_name_name.map(|v| Cow::Owned(v.into_owned())),
            self_handle: self.self_handle.map(|v| Cow::Owned(v.into_owned())),
            pidfd: self.pidfd,
            fd_error: self.fd_error,
            fs_error: self.fs_error,
            access_range: self.access_range,
            mnt_id: self.mnt_id,
            rename_source: self.rename_source.map(RenameSide::into_owned),
            rename_target: self.rename_target.map(RenameSide::into_owned),
            unknown_info_records: self
                .unknown_info_records
                .into_iter()
                .map(|(info_type, payload)| (info_type, Cow::Owned(payload.into_owned())))
                .collect(),
            path: self.path,
        }
    }

    /// Return the event to the state [`new`](Self::new) makes, keeping the
    /// capacity of `unknown_info_records` for the next parse.
    ///
    /// The reuse half of [`parse_fid_events_into`]: the outer `Vec` is reused by
    /// clearing it, and each event's record `Vec` by resetting it in place, so a
    /// re-parse of a same-sized buffer allocates nothing at all.  A resolved
    /// path is dropped rather than kept, because reopening a parse does not
    /// un-resolve anything the previous parse produced.
    pub(crate) fn reset(&mut self) {
        self.mask = 0;
        self.pid = 0;
        self.fsid = None;
        self.dfid_name_handle = None;
        self.dfid_name_name = None;
        self.self_handle = None;
        self.pidfd = Pidfd::Absent;
        self.fd_error = None;
        self.fs_error = None;
        self.access_range = None;
        self.mnt_id = None;
        self.rename_source = None;
        self.rename_target = None;
        self.unknown_info_records.clear();
        self.path = None;
    }

    /// Set the event mask.
    pub fn set_mask(&mut self, mask: u64) -> &mut Self {
        self.mask = mask;
        self
    }

    /// Set the pid.
    pub fn set_pid(&mut self, pid: i32) -> &mut Self {
        self.pid = pid;
        self
    }

    /// Set the filesystem id the event's handles belong to.
    pub fn set_fsid(&mut self, fsid: Fsid) -> &mut Self {
        self.fsid = Some(fsid);
        self
    }

    /// The parameters are any [`Cow`] input, so a handle and a name that come
    /// from a parsed buffer are taken as borrowed bytes and a `Vec` built by
    /// hand is taken as owned ones — one setter, no copy either way.
    pub fn set_dfid_name(
        &mut self,
        handle: impl Into<Cow<'buf, [u8]>>,
        name: impl Into<Cow<'buf, [u8]>>,
    ) -> &mut Self {
        self.dfid_name_handle = Some(handle.into());
        self.dfid_name_name = Some(name.into());
        self
    }

    /// Set the object's own handle, as a `FID`/`DFID` record carries it.
    pub fn set_self_handle(&mut self, handle: impl Into<Cow<'buf, [u8]>>) -> &mut Self {
        self.self_handle = Some(handle.into());
        self
    }

    /// Set the mount id, as a `MNT` record carries it.
    pub fn set_mnt_id(&mut self, mnt_id: u64) -> &mut Self {
        self.mnt_id = Some(mnt_id);
        self
    }

    /// Set the access range, as a `RANGE` record carries it.
    pub fn set_access_range(&mut self, offset: u64, count: u64) -> &mut Self {
        self.access_range = Some((offset, count));
        self
    }

    /// Set the filesystem error and merged error count, as an `ERROR` record
    /// carries them.
    pub fn set_fs_error(&mut self, error: i32, error_count: u32) -> &mut Self {
        self.fs_error = Some((error, error_count));
        self
    }

    /// Set the negative errno the kernel put in `metadata.fd`, which only a
    /// [`FAN_REPORT_FD_ERROR`] group produces.
    ///
    /// The parser fills this from the header of such an event; this is the
    /// setter that lets an event synthesised by hand carry the same fact, so a
    /// replayed or recorded event can be reconstructed field for field.
    ///
    /// ```
    /// use fanotify_fid::fid::FidEvent;
    ///
    /// let mut ev = FidEvent::new();
    /// ev.set_fd_error(-libc::EACCES);
    /// assert_eq!(ev.fd_error(), Some(-13));
    /// ```
    pub fn set_fd_error(&mut self, error: i32) -> &mut Self {
        self.fd_error = Some(error);
        self
    }

    /// Set the rename source: the parent handle and the entry's old name.
    pub fn set_rename_source(&mut self, side: RenameSide<'buf>) -> &mut Self {
        self.rename_source = Some(side);
        self
    }

    /// Set the rename target: the parent handle and the entry's new name.
    pub fn set_rename_target(&mut self, side: RenameSide<'buf>) -> &mut Self {
        self.rename_target = Some(side);
        self
    }

    /// Attach a pidfd this crate owns.
    pub fn set_pidfd(&mut self, pidfd: Pidfd) -> &mut Self {
        self.pidfd = pidfd;
        self
    }

    /// Add a record the crate has no typed field for.
    ///
    /// `record` is taken verbatim, **header included**, matching what
    /// [`unknown_info_records`](Self::unknown_info_records) reports: a caller
    /// forwarding a record reads it here with the same bytes it would parse
    /// back.
    pub fn push_unknown_info_record(
        &mut self,
        info_type: u8,
        record: impl Into<Cow<'buf, [u8]>>,
    ) -> &mut Self {
        self.unknown_info_records.push((info_type, record.into()));
        self
    }

    /// The event mask: which bits fired, such as
    /// [`FAN_CREATE`].
    ///
    /// A mask can hold several bits, and it can hold a bit that is not about an
    /// object — [`is_overflow`](Self::is_overflow).
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// The pid of the process that caused the event.
    ///
    /// Zero when the kernel had no answer: an unprivileged group gets `0` for
    /// events caused by *other* processes, and an overflow event carries no pid
    /// at all.  The kernel reports it as a thread id instead when the group was
    /// created with [`FAN_REPORT_TID`].
    ///
    /// For an answer that pid reuse cannot invalidate, use
    /// [`pidfd`](Self::pidfd).
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The filesystem the event's handles belong to, as the record reported it.
    ///
    /// Handle bytes are only unique *within* one filesystem, so this is what
    /// makes them interpretable at all: it is the filter
    /// [`resolve_file_handle`](crate::handle::resolve_file_handle) needs, and
    /// what tells you which of your mount descriptors applies.
    ///
    /// `None` for an event that carries no FID-style record — an overflow, or a
    /// mount event.
    pub fn fsid(&self) -> Option<Fsid> {
        self.fsid
    }

    /// The path this event was resolved to, exactly as `/proc` reported it.
    ///
    /// `None` means no resolution has happened — not that the event has no path.
    /// [`parse_fid_events`] leaves it `None` for every event, because parsing is
    /// pure and producing a path needs `CAP_DAC_READ_SEARCH`;
    /// [`PathResolver`](crate::resolve::PathResolver) is what fills it, and
    /// [`set_path`](Self::set_path) fills it by hand.
    ///
    /// # It is the raw answer, marker included
    ///
    /// For an object that no longer has a name, `/proc` appends `" (deleted)"`
    /// and this returns that string unchanged.  The crate does not remove it,
    /// because a file may legitimately *be* named `foo (deleted)` — see
    /// [`is_deleted`](Self::is_deleted) and
    /// [`without_deleted_suffix`](Self::without_deleted_suffix) for taking that
    /// decision explicitly instead of having it taken here.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Whether resolution has put a path on this event.
    pub fn has_path(&self) -> bool {
        self.path.is_some()
    }

    /// Attach a resolved path.
    ///
    /// What [`PathResolver`](crate::resolve::PathResolver) calls, and the way to
    /// put a path from another source onto an event without the crate being
    /// involved.
    pub fn set_path(&mut self, path: PathBuf) {
        self.path = Some(path);
    }

    /// Drop the resolved path, leaving the event as parsed.
    pub fn clear_path(&mut self) {
        self.path = None;
    }

    /// Whether the resolved path names an object that lost that name.
    ///
    /// True when **any** component ends in `" (deleted)"` — the marker `/proc`
    /// appends to the link target of an unlinked object.  A path whose *parent*
    /// is gone carries the marker in the middle (`/srv/gone (deleted)/child`,
    /// which is what resolving an entry of a deleted directory produces), and
    /// such a path names nothing a caller can open, so it counts here too.
    ///
    /// This is the *conservative* reading: `/proc` reports the same bytes for a
    /// live object whose real name ends that way, so `true` means "do not treat
    /// this as a usable path" rather than "the kernel unlinked this object".
    ///
    /// `false` when nothing was resolved, since nothing is claimed then.
    pub fn is_deleted(&self) -> bool {
        self.path.as_deref().is_some_and(carries_deleted_marker)
    }

    /// The resolved path with one `" (deleted)"` marker removed from every
    /// component that carries one.
    ///
    /// The other half of [`is_deleted`](Self::is_deleted): that one asks, this
    /// one acts.  Each marked component loses **one** marker, so a file really
    /// named `foo (deleted)` becomes `foo`, and a deleted parent's marker in the
    /// middle of the path leaves `/srv/gone (deleted)/child` readable as
    /// `/srv/gone/child`.  Either result may name a different, existing file,
    /// which is why the crate does not do it on its own and why
    /// [`path`](Self::path) keeps the marker: the choice has a wrong answer
    /// available, so it is the caller's to make.
    ///
    /// The path is returned byte for byte when no component carries a marker.
    ///
    /// ```
    /// use std::path::{Path, PathBuf};
    /// # use fanotify_fid::fid::FidEvent;
    /// # fn event_at(path: &Path) -> FidEvent { let mut e = FidEvent::new(); e.set_path(path.to_path_buf()); e }
    /// let ev = event_at(Path::new("/srv/data/report.pdf (deleted)"));
    /// assert!(ev.is_deleted());
    /// assert_eq!(ev.without_deleted_suffix(), Some(PathBuf::from("/srv/data/report.pdf")));
    /// ```
    pub fn without_deleted_suffix(&self) -> Option<PathBuf> {
        let path = self.path.as_deref()?;
        let mut cleaned = PathBuf::new();
        let mut changed = false;
        for component in path.components() {
            match component {
                Component::Normal(name) => match name.as_bytes().strip_suffix(DELETED_MARKER) {
                    Some(stripped) => {
                        cleaned.push(OsStr::from_bytes(stripped));
                        changed = true;
                    }
                    None => cleaned.push(name),
                },
                other => cleaned.push(other.as_os_str()),
            }
        }
        Some(if changed { cleaned } else { path.to_path_buf() })
    }

    /// The parent directory's handle, from a `DFID_NAME` record.
    ///
    /// This is the handle of the directory *containing* the entry the event is
    /// about; the entry's own name is [`dfid_name`](Self::dfid_name).  Present
    /// for directory-entry events of a group created with
    /// [`FAN_REPORT_DIR_FID`].
    pub fn dfid_name_handle(&self) -> Option<&[u8]> {
        self.dfid_name_handle.as_deref()
    }

    /// The entry name, as raw bytes.
    ///
    /// Empty when the event carries no name record.  An empty *name* is also
    /// real — the kernel reports `.` that way — so prefer
    /// [`dfid_name`](Self::dfid_name), whose `Some`/`None` distinguishes "no
    /// record" from "empty name".
    pub fn dfid_name_raw(&self) -> &[u8] {
        self.dfid_name_name.as_deref().unwrap_or(&[])
    }

    /// The entry name as an [`OsStr`], or `None` when there is no name record.
    pub fn dfid_name(&self) -> Option<&OsStr> {
        self.dfid_name_name.as_deref().map(OsStr::from_bytes)
    }

    /// The entry name as a `String`, or `None` when there is no name record
    /// **or** the name is not valid UTF-8.
    pub fn dfid_name_str(&self) -> Option<&str> {
        self.dfid_name_name
            .as_deref()
            .and_then(|name| std::str::from_utf8(name).ok())
    }

    /// The entry name, owned, accepting any bytes.
    pub fn dfid_name_os_string(&self) -> Option<OsString> {
        self.dfid_name_name
            .as_deref()
            .map(|name| OsString::from_vec(name.to_vec()))
    }

    /// The object's own handle, from a `FID` or `DFID` record.
    ///
    /// Present when the group was created with
    /// [`FAN_REPORT_FID`] — the object the event
    /// is about — or with
    /// [`FAN_REPORT_TARGET_FID`], which
    /// adds the child's own handle to directory-entry events.
    pub fn self_handle(&self) -> Option<&[u8]> {
        self.self_handle.as_deref()
    }

    /// How the event names the process that caused it.
    pub fn pidfd(&self) -> &Pidfd {
        &self.pidfd
    }

    /// Take the pidfd out of the event, leaving [`Pidfd::Absent`] behind.
    pub fn take_pidfd(&mut self) -> Pidfd {
        mem::replace(&mut self.pidfd, Pidfd::Absent)
    }

    /// Mutable access to the pidfd, for the read path that adopts it.
    ///
    /// Crate-internal: adoption is only sound where the crate itself performed
    /// the `read(2)` the event came from, and `pidfd` is public precisely so
    /// that a caller cannot be handed a descriptor this crate adopted from
    /// bytes it did not produce.
    pub(crate) fn pidfd_mut(&mut self) -> &mut Pidfd {
        &mut self.pidfd
    }

    /// The negative errno the kernel put in `metadata.fd` instead of a
    /// descriptor, when the group was created with
    /// [`FAN_REPORT_FD_ERROR`].
    ///
    /// Without that flag a negative `fd` can only mean "no descriptor", so this
    /// is `None`.  With it, the value is *why* the kernel could not open one,
    /// which is a different fact from "there was nothing to open".
    ///
    /// [`FAN_NOFD`] is not reported here even then,
    /// because `-1` is both the sentinel and `EPERM`, and the two cannot be told
    /// apart from the value alone.
    pub fn fd_error(&self) -> Option<i32> {
        self.fd_error
    }

    /// The filesystem error code and the number of errors merged into this
    /// event, from an `ERROR` record.
    ///
    /// Only [`FAN_FS_ERROR`] events carry one.
    pub fn fs_error(&self) -> Option<(i32, u32)> {
        self.fs_error
    }

    /// The byte range a [`FAN_PRE_ACCESS`] event
    /// is about, as `(offset, count)`.
    pub fn access_range(&self) -> Option<(u64, u64)> {
        self.access_range
    }

    /// The mount ID of a [`FAN_MNT_ATTACH`] or
    /// [`FAN_MNT_DETACH`] event.
    ///
    /// This is the whole of the mount identity: the event names a mount, not a
    /// file, so no handle and no name accompany it.
    pub fn mnt_id(&self) -> Option<u64> {
        self.mnt_id
    }

    /// The rename source: the parent handle and the entry's **old** name.
    pub fn rename_source(&self) -> Option<&RenameSide<'buf>> {
        self.rename_source.as_ref()
    }

    /// The rename target: the parent handle and the entry's **new** name.
    pub fn rename_target(&self) -> Option<&RenameSide<'buf>> {
        self.rename_target.as_ref()
    }

    /// Records this crate could not turn into a typed field, as
    /// `(info_type, raw_record)`.
    ///
    /// `raw_record` is the record **verbatim, its 4-byte
    /// `fanotify_event_info_header` included**, borrowed from the parse buffer
    /// like every other field.  So the first byte is the `info_type` the tuple
    /// also carries, the next is the header's `pad`, and `raw_record[2..4]` is
    /// the record's own `len` — in the host's byte order, because the kernel
    /// writes these structures into this process's memory rather than into a
    /// byte-order-independent wire format.  That makes the record
    /// self-describing and re-parseable, and is why the header is kept rather
    /// than sliced off.
    ///
    /// Every info type the kernel defines today has a field above, so in
    /// practice this fills for two reasons: a type a newer kernel added, and a
    /// recognised type that could not be interpreted.  Either way the bytes are
    /// kept, so "the parser dropped data" is observable instead of silent.
    ///
    /// # The one entry whose bytes are not a single record
    ///
    /// A record whose `len` fails its bounds check — smaller than a header, or
    /// past the end of the event — cannot be walked past, so the walk stops and
    /// the entry holds the **rest of the event** starting at that record's
    /// header rather than one record.  Nothing is lost and nothing is counted
    /// twice; a caller consuming these bytes should read `len` off the front and
    /// treat only `raw_record[..len]` as the record if it fits.
    pub fn unknown_info_records(&self) -> &[(u8, Cow<'buf, [u8]>)] {
        &self.unknown_info_records
    }

    /// Whether this event says the queue overflowed and events were lost.
    ///
    /// An overflow event is not about an object: it carries no handle, no name
    /// and no pid.  It means an unknown number of events never arrived and
    /// **cannot be recovered from the queue** — a consumer that needs a complete
    /// history has to reconcile by re-scanning, which is the consumer's
    /// decision to make.
    pub fn is_overflow(&self) -> bool {
        self.mask & FAN_Q_OVERFLOW != 0
    }

    /// The names of the event bits set in the mask, for logging and debugging.
    pub fn event_names(&self) -> impl Iterator<Item = &'static str> {
        mask_to_event_names(self.mask)
    }
}

/// Parse a buffer of FID events.
///
/// `buf` is the bytes a `read(2)` on a FID group returned — see
/// [`Fanotify::read_events`](crate::Fanotify::read_events), which is where those
/// bytes normally come from.
///
/// The events **borrow `buf`**, which is what keeps parsing free of per-record
/// allocations; see the module docs for the lifetime model.  A buffer that ends
/// in the middle of an event yields the events before it and no error — the
/// truncation is visible through [`parse_fid_events_reported`], not through the
/// return type, because a short read is a fact about the buffer and not a
/// failure of the parse.
///
/// # This function never takes ownership of a file descriptor
///
/// A pidfd record holds a descriptor *number*, and a `&[u8]` proves nothing
/// about where that number came from: it may have been copied, crafted or
/// parsed twice.  Wrapping it in an [`OwnedFd`] here would close a descriptor
/// this crate does not own — including one the caller is still using — so a
/// pidfd is reported as [`Pidfd::Unavailable`] and never adopted.  Only the
/// crate's read path adopts one, because it knows the buffer came from the
/// kernel's queue for this very call.
///
/// # Malformed input
///
/// The buffer is treated as untrusted, so no input can panic, read out of
/// bounds, or loop forever: an event whose length does not fit the buffer stops
/// the walk, a record whose length does not fit its event stops that event's
/// record walk with the remainder preserved, and a record whose payload is too
/// short is preserved rather than interpreted.  `vers` is the one value that
/// cannot be worked around — every field after it is read according to that
/// version — so a buffer that is not fanotify events at all is rejected with
/// [`FanotifyError::UnknownEventVersion`].
///
/// ```
/// use fanotify_fid::fid::FidEvent;
///
/// # let raw: &[u8] = &[];
/// // Borrowed: nothing is copied out of `raw`, so the events cannot outlive it.
/// let events: Vec<FidEvent<'_>> = fanotify_fid::fid::parse_fid_events(raw).unwrap();
/// # let _ = events;
/// ```
pub fn parse_fid_events(buf: &[u8]) -> Result<Vec<FidEvent<'_>>, FanotifyError> {
    let mut events = Vec::new();
    let report = parse_fid_events_into(&mut events, buf);
    if let EventStop::UnknownVersion(vers) = report.stop {
        return Err(FanotifyError::UnknownEventVersion(vers));
    }
    Ok(events)
}

/// Parse a buffer of FID events and say how far the walk got.
///
/// The same walk as [`parse_fid_events`], except that **nothing is left
/// implicit**: a truncated header, an impossible `event_len`, a `metadata_len`
/// past its event, and an unknown `vers` all land in the [`EventStop`] of the
/// [`ParseReport`] instead of being dropped, and a complete walk is
/// [`EventStop::End`] with `bytes_left == 0`.  This is the entry point to use
/// whenever the bytes are not known to be a whole kernel read — a capture file,
/// a pipe, anything being replayed — because `bytes_left > 0` is exactly the
/// data a caller needs to record or warn about.
///
/// Unlike [`parse_fid_events`] this never fails: an unknown version is
/// [`EventStop::UnknownVersion`], an event in the walk, and the events parsed
/// before it are returned.
///
/// ```
/// use fanotify_fid::fid::parse_fid_events_reported;
///
/// let (events, report) = parse_fid_events_reported(&[]);
/// assert!(events.is_empty());
/// assert!(report.is_complete());
/// ```
pub fn parse_fid_events_reported(buf: &[u8]) -> (Vec<FidEvent<'_>>, ParseReport) {
    let mut events = Vec::new();
    let report = parse_fid_events_into(&mut events, buf);
    (events, report)
}

/// Parse a buffer of FID events into an existing `Vec`, reusing its capacity.
///
/// This is the allocating parser's real body, and the one entry point that
/// **does no allocation at all** on a buffer of already-seen shape: the `Vec`
/// keeps its allocation, and each event's `unknown_info_records` `Vec` is
/// cleared in place rather than freed, so a stream that parses into the same
/// `Vec` sees one allocation when the `Vec` first grows and none afterwards.
/// Parsing itself still borrows `buf`, so no record's bytes are copied.
///
/// The returned [`ParseReport`] is [`parse_fid_events_reported`]'s, including
/// its treatment of an unknown version: reported, not returned as an error.
///
/// # Reuse needs the two lifetimes to agree
///
/// The events borrow `buf`, so `events: &mut Vec<FidEvent<'buf>>` fixes `'buf`:
/// a `Vec` that outlives one parse pins the buffer's borrow for as long as the
/// `Vec` lives, and a read loop therefore cannot hand the same `Vec` back to a
/// fresh borrow of a buffer it still borrows from.  A caller that owns both can
/// still reuse the `Vec` within one buffer's lifetime — parse, work, parse again
/// from the same bytes — which is what makes it worth having; what it cannot do
/// is reuse the `Vec` across two different reads.
///
/// Reading from a group with no per-read allocation at all is
/// [`EventReader`](crate::EventReader)'s job: it owns the buffer and the `Vec`
/// together, so there is no pair of lifetimes left for the caller to reconcile.
///
/// ```
/// use fanotify_fid::fid::{FidEvent, parse_fid_events_into};
///
/// # let raw: &[u8] = &[];
/// let mut events: Vec<FidEvent<'_>> = Vec::with_capacity(64);
/// let report = parse_fid_events_into(&mut events, raw);
/// assert!(report.is_complete());
/// ```
pub fn parse_fid_events_into<'buf>(
    events: &mut Vec<FidEvent<'buf>>,
    buf: &'buf [u8],
) -> ParseReport {
    let mut parsed = 0;
    let mut offset = 0;
    let mut version_checked = false;

    let stop = loop {
        // Fewer than a header's bytes left: either the buffer ended cleanly or
        // it holds the start of an event that a larger read could complete.
        if offset + METADATA_SIZE > buf.len() {
            break if offset == buf.len() {
                EventStop::End
            } else {
                EventStop::ShortHeader
            };
        }
        // SAFETY: the bounds check above guarantees the 24 bytes starting at
        // `offset` are readable; `read_unaligned` because the buffer has no
        // alignment guarantee (the u64 at offset 8 would need 8).
        let meta = unsafe { read_unaligned::<EventMetadata>(buf, offset) };

        // A version this crate does not parse is not recoverable: the layout of
        // every field after it is in question.  One event is enough to say so —
        // the version is a property of the group, not of the event.
        if !version_checked {
            version_checked = true;
            if meta.vers != FANOTIFY_METADATA_VERSION {
                break EventStop::UnknownVersion(meta.vers);
            }
        }

        let event_len = meta.event_len as usize;
        // The kernel writes both of these, so a value outside them means the
        // buffer is not what it claims; stop rather than walk off the end.
        if event_len < METADATA_SIZE || event_len > buf.len() - offset {
            break EventStop::BadEventLen(meta.event_len);
        }
        // `metadata_len` is where the records start.  Clamping it to the header
        // end keeps a malformed value from pointing the record walk back inside
        // the header, where header bytes would be read as a record; a value
        // past the event's own length cannot be clamped anywhere, so the walk
        // stops rather than read the next event's bytes as this one's records.
        let records_start = usize::from(meta.metadata_len).max(METADATA_SIZE);
        if records_start > event_len {
            break EventStop::BadMetadataLen;
        }

        // Reuse the slot if there is one: `reset` keeps the event's
        // `unknown_info_records` allocation.
        if parsed < events.len() {
            events[parsed].reset();
        } else {
            events.push(FidEvent::new());
        }
        let event = &mut events[parsed];
        parse_one_event(event, buf, offset, event_len, records_start, meta);
        parsed += 1;
        offset += event_len;
    };

    // Anything past the parsed prefix is left over from a previous, longer
    // buffer; dropping it frees only what the new buffer does not use.
    events.truncate(parsed);
    ParseReport {
        bytes_consumed: offset,
        bytes_left: buf.len() - offset,
        stop,
    }
}

/// Parse the records of one event into a [`FidEvent`].
fn parse_one_event<'buf>(
    event: &mut FidEvent<'buf>,
    buf: &'buf [u8],
    event_start: usize,
    event_len: usize,
    records_start: usize,
    meta: EventMetadata,
) {
    event.mask = meta.mask;
    event.pid = meta.pid;
    // In a FID group `metadata.fd` is `FAN_NOFD`; a different negative value is
    // the reason a descriptor could not be opened, which only a
    // FAN_REPORT_FD_ERROR group produces.  `-1` is excluded because it is both
    // the sentinel and `EPERM`.
    event.fd_error = (meta.fd < 0 && meta.fd != FAN_NOFD).then_some(meta.fd);

    let event_end = event_start + event_len;
    let mut header_at = event_start + records_start;

    while header_at + INFO_HEADER_SIZE <= event_end {
        // SAFETY: the loop condition guarantees the 4 header bytes are there.
        let header = unsafe { read_unaligned::<InfoHeader>(buf, header_at) };
        let record_len = header.len as usize;

        // A record that does not fit cannot be walked past, so stop and keep the
        // rest as unparsed bytes: that is more useful than skipping a length we
        // have just decided is untrustworthy.  The range has to be the whole
        // tail rather than `len` bytes, because `len` is exactly what failed the
        // check.
        if record_len < INFO_HEADER_SIZE || record_len > event_end - header_at {
            event.preserve(buf, header_at, event_end, header.info_type);
            break;
        }

        // Every other exit from the walk keeps exactly this record: the length
        // passed its bounds check, so `record_end` is the record's own end and
        // no byte of the next record is charged to this one.
        let record_end = header_at + record_len;
        let payload_at = header_at + INFO_HEADER_SIZE;
        let payload_len = record_len - INFO_HEADER_SIZE;

        match header.info_type {
            FAN_EVENT_INFO_TYPE_DFID_NAME => {
                if let Some((fsid, handle, name)) =
                    split_fsid_handle_name(buf, payload_at, payload_len)
                {
                    // A well-formed event has one such record.  A malformed
                    // buffer may hold several; the first with a name wins, and
                    // the rest are preserved rather than silently replacing it.
                    if event.dfid_name_name.is_none() {
                        event.fsid = event.fsid.or(Some(fsid));
                        event.dfid_name_handle = Some(Cow::Borrowed(handle));
                        event.dfid_name_name = Some(Cow::Borrowed(name));
                    } else {
                        event.preserve(buf, header_at, record_end, header.info_type);
                    }
                } else {
                    event.preserve(buf, header_at, record_end, header.info_type);
                }
            }
            FAN_EVENT_INFO_TYPE_FID | FAN_EVENT_INFO_TYPE_DFID => {
                if let Some((fsid, handle)) = split_fsid_handle(buf, payload_at, payload_len) {
                    event.fsid = event.fsid.or(Some(fsid));
                    event.self_handle = Some(Cow::Borrowed(handle));
                } else {
                    event.preserve(buf, header_at, record_end, header.info_type);
                }
            }
            FAN_EVENT_INFO_TYPE_OLD_DFID_NAME => {
                match split_fsid_handle_name(buf, payload_at, payload_len) {
                    Some((fsid, handle, name)) => {
                        event.fsid = event.fsid.or(Some(fsid));
                        event.rename_source = Some(RenameSide {
                            handle: Cow::Borrowed(handle),
                            name: Cow::Borrowed(name),
                        });
                    }
                    None => event.preserve(buf, header_at, record_end, header.info_type),
                }
            }
            FAN_EVENT_INFO_TYPE_NEW_DFID_NAME => {
                match split_fsid_handle_name(buf, payload_at, payload_len) {
                    Some((fsid, handle, name)) => {
                        event.fsid = event.fsid.or(Some(fsid));
                        event.rename_target = Some(RenameSide {
                            handle: Cow::Borrowed(handle),
                            name: Cow::Borrowed(name),
                        });
                    }
                    None => event.preserve(buf, header_at, record_end, header.info_type),
                }
            }
            // A pidfd record is not adopted here: see `parse_fid_events`.  A
            // non-negative value is reported as unavailable so that a caller who
            // *knows* the buffer came from the kernel can adopt it deliberately.
            FAN_EVENT_INFO_TYPE_PIDFD => match read_u32(buf, payload_at, payload_len) {
                Some(raw) => {
                    if event.pidfd_is_absent() {
                        event.pidfd = Pidfd::Unavailable(raw as i32);
                    } else {
                        event.preserve(buf, header_at, record_end, header.info_type);
                    }
                }
                None => event.preserve(buf, header_at, record_end, header.info_type),
            },
            FAN_EVENT_INFO_TYPE_ERROR => {
                match (
                    read_u32(buf, payload_at, payload_len),
                    read_u32(buf, payload_at + 4, payload_len.saturating_sub(4)),
                ) {
                    (Some(error), Some(count)) => event.fs_error = Some((error as i32, count)),
                    _ => event.preserve(buf, header_at, record_end, header.info_type),
                }
            }
            FAN_EVENT_INFO_TYPE_RANGE => {
                match (
                    read_u64(buf, payload_at, payload_len),
                    read_u64(buf, payload_at + 8, payload_len.saturating_sub(8)),
                ) {
                    (Some(offset), Some(count)) => event.access_range = Some((offset, count)),
                    _ => event.preserve(buf, header_at, record_end, header.info_type),
                }
            }
            FAN_EVENT_INFO_TYPE_MNT => match read_u64(buf, payload_at, payload_len) {
                Some(mnt_id) => event.mnt_id = Some(mnt_id),
                None => event.preserve(buf, header_at, record_end, header.info_type),
            },
            // A type this crate does not know.  Kept verbatim — header included,
            // so the record can be re-parsed or forwarded intact — rather than
            // dropped, which is what makes a newer kernel's addition survivable.
            _ => event.preserve(buf, header_at, record_end, header.info_type),
        }

        header_at = record_end;
    }
}

impl<'buf> FidEvent<'buf> {
    /// Present a record verbatim, header included, in `record_at..counted_end`.
    ///
    /// `counted_end` is the end of the record this walk actually accounted for,
    /// which is not always the record's own length: a record whose `len` field
    /// cannot be trusted ends at the end of the event.  Either way the bytes are
    /// borrowed from the parse buffer like every parsed field — only a
    /// hand-built event can hold an owned one here.
    ///
    /// The stored range starts at the record **header**, so the four bytes the
    /// kernel's `fanotify_event_info_header` occupies are part of it and the
    /// entry is self-describing: `len` can be read back off the front of it
    /// rather than assumed from the payload's length.  For a well-formed record
    /// that cannot be walked past for some other reason, `counted_end` is
    /// `record_at + len`, so the range is exactly that one record and no byte of
    /// a following record is charged to it twice.
    fn preserve(&mut self, buf: &'buf [u8], record_at: usize, counted_end: usize, info_type: u8) {
        let record = buf.get(record_at..counted_end).unwrap_or_default();
        self.unknown_info_records
            .push((info_type, Cow::Borrowed(record)));
    }

    /// Whether no pidfd record has been recorded yet.
    fn pidfd_is_absent(&self) -> bool {
        matches!(self.pidfd, Pidfd::Absent)
    }
}

/// Split a `fsid + file_handle` payload.
/// The suffix `/proc/self/fd` appends to the link target of an object that no
/// longer has a name.
const DELETED_MARKER: &[u8] = b" (deleted)";

/// Whether a `/proc` link target carries the unlinked-object marker.
///
/// Matching on bytes rather than on a `String` keeps this correct for a path
/// that is not valid UTF-8, which `/proc` will happily report.
fn ends_with_deleted_marker(path: &OsStr) -> bool {
    path.as_bytes().ends_with(DELETED_MARKER)
}

/// Whether **any** component of a `/proc` link target carries the marker.
///
/// A deleted directory puts the marker in the middle of the paths derived from
/// it (`/srv/gone (deleted)/child`), so looking only at the last component would
/// call a path usable that names nothing.
fn carries_deleted_marker(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => ends_with_deleted_marker(name),
        _ => false,
    })
}

/// Split a `fsid + file_handle` payload.
///
/// The returned handle borrows `buf`, so a parsed event copies nothing.
fn split_fsid_handle(buf: &[u8], at: usize, len: usize) -> Option<(Fsid, &[u8])> {
    let fsid = read_fsid(buf, at, len)?;
    let handle = read_file_handle(buf, at + FSID_SIZE, len.checked_sub(FSID_SIZE)?)?;
    Some((fsid, handle))
}

/// Split a `fsid + file_handle + name` payload, the layout of `DFID_NAME`.
///
/// The name runs to the end of the record, minus the padding the kernel adds to
/// align the record on an 8-byte boundary, and is NUL-terminated.  Both the
/// handle and the name borrow `buf`.
fn split_fsid_handle_name(buf: &[u8], at: usize, len: usize) -> Option<(Fsid, &[u8], &[u8])> {
    let fsid = read_fsid(buf, at, len)?;
    let after_fsid = at + FSID_SIZE;
    let handle = read_file_handle(buf, after_fsid, len.checked_sub(FSID_SIZE)?)?;
    let name_at = after_fsid + handle.len();
    let name_len = len.checked_sub(FSID_SIZE + handle.len())?;
    let raw = buf.get(name_at..name_at + name_len)?;
    // The kernel NUL-terminates the name and pads the record to 8 bytes; the
    // first NUL is where the name ends, and everything after it is padding.
    let name = match raw.iter().position(|&b| b == 0) {
        Some(nul) => &raw[..nul],
        None => raw,
    };
    Some((fsid, handle, name))
}

/// The `fsid` field, as the pair of `int`s a later `statfs` call also reports.
fn read_fsid(buf: &[u8], at: usize, len: usize) -> Option<Fsid> {
    if len < FSID_SIZE {
        return None;
    }
    let first = read_u32(buf, at, len)? as i32;
    let second = read_u32(buf, at + 4, len - 4)? as i32;
    Some((first, second))
}

/// A `struct file_handle`, taken as the exact bytes the filesystem produced.
///
/// On the wire the handle is `u32 handle_bytes | i32 handle_type | bytes[]`,
/// where `handle_bytes` counts only the trailing bytes — not the 8-byte header.
/// The whole thing is returned, because that is what `open_by_handle_at` wants
/// and what [`handle_of_record`] can hand back unchanged.  The slice borrows
/// `buf`, which is what keeps a parsed handle copy-free.
fn read_file_handle(buf: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    let handle_bytes = read_u32(buf, at, len)? as usize;
    if handle_bytes > MAX_HANDLE_SZ {
        return None;
    }
    let total = crate::handle::FILE_HANDLE_HEADER_SIZE.checked_add(handle_bytes)?;
    if total > len {
        return None;
    }
    buf.get(at..at + total)
}

/// Read a little-endian-on-the-wire `u32`, if `len` bytes are available.
fn read_u32(buf: &[u8], at: usize, len: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(at..at + 4).filter(|_| len >= 4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(bytes))
}

/// Read a `u64`, if `len` bytes are available.
fn read_u64(buf: &[u8], at: usize, len: usize) -> Option<u64> {
    let bytes: [u8; 8] = buf.get(at..at + 8).filter(|_| len >= 8)?.try_into().ok()?;
    Some(u64::from_ne_bytes(bytes))
}

/// Read a `#[repr(C)]` struct out of a byte buffer at `offset`.
///
/// # Safety
///
/// The caller must have checked that `offset + size_of::<T>()` bytes are
/// readable from `buf`.  The read is unaligned, so no alignment requirement
/// carries over to the caller.
unsafe fn read_unaligned<T: Copy>(buf: &[u8], offset: usize) -> T {
    // SAFETY: the caller guarantees the bytes are in bounds, and
    // `read_unaligned` imposes no alignment requirement on the source.
    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const T) }
}

/// A pidfd number that was actually reported, or `None`.
///
/// Used only on the crate's own read path, where the buffer is known to be the
/// kernel's answer to this call: there the number really is a descriptor the
/// kernel installed for this process, and the sentinels can be told apart from
/// one because they are negative — which is why a negative value stays
/// [`Pidfd::Unavailable`] rather than being turned into a descriptor.
///
/// `already_adopted` carries the descriptor numbers adopted earlier in the same
/// buffer.  The kernel installs a fresh descriptor per record, so a repeat means
/// the buffer is not what it claims, and adopting it twice would close one
/// descriptor from two owners.  A repeat is therefore left unowned.
pub(crate) fn adopt_reported_pidfd(raw: i32, already_adopted: &mut Vec<i32>) -> Pidfd {
    if raw < 0 || already_adopted.contains(&raw) {
        return Pidfd::Unavailable(raw);
    }
    already_adopted.push(raw);
    // SAFETY: the caller is the read path, which knows the buffer came from
    // `read(2)` on a fanotify group created with FAN_REPORT_PIDFD.  A
    // non-negative descriptor in such a record was installed by the kernel for
    // this process and is owned by it, and the duplicate check above is what
    // makes this the single owner.
    Pidfd::Fd(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
}

impl Pidfd {
    /// Borrow the descriptor, if this is one.
    pub fn as_fd(&self) -> Option<BorrowedFd<'_>> {
        match self {
            Self::Fd(fd) => Some(fd.as_fd()),
            _ => None,
        }
    }

    /// Take the descriptor out, if this is one.
    ///
    /// Solely owned when no clone holds it; otherwise duplicated, so the
    /// returned value is always solely owned.  `None` when the event carries no
    /// descriptor, or when the duplicate could not be made.
    pub fn into_fd(self) -> Option<OwnedFd> {
        match self {
            Self::Fd(fd) => match Arc::try_unwrap(fd) {
                Ok(owned) => Some(owned),
                Err(shared) => shared.try_clone().ok(),
            },
            Self::Absent | Self::Unavailable(_) => None,
        }
    }
}

/// The raw number a pidfd record carried, if the event carries no descriptor.
pub(crate) fn reported_pidfd_number(pidfd: &Pidfd) -> Option<i32> {
    match pidfd {
        Pidfd::Unavailable(raw) => Some(*raw),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `fanotify_event_metadata` with the given length, mask and fd.
    fn metadata(event_len: u32, mask: u64, fd: i32) -> Vec<u8> {
        let mut out = Vec::with_capacity(METADATA_SIZE);
        out.extend_from_slice(&event_len.to_ne_bytes());
        out.push(FANOTIFY_METADATA_VERSION);
        out.push(0);
        out.extend_from_slice(&(METADATA_SIZE as u16).to_ne_bytes());
        out.extend_from_slice(&mask.to_ne_bytes());
        out.extend_from_slice(&fd.to_ne_bytes());
        out.extend_from_slice(&0i32.to_ne_bytes());
        out
    }

    /// An info record with the given type and payload.
    fn record(info_type: u8, payload: &[u8]) -> Vec<u8> {
        let len = (INFO_HEADER_SIZE + payload.len()) as u16;
        let mut out = Vec::with_capacity(len as usize);
        out.push(info_type);
        out.push(0);
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// A `struct file_handle` with `payload_len` bytes of handle.
    fn file_handle(payload_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(crate::handle::FILE_HANDLE_HEADER_SIZE + payload_len);
        out.extend_from_slice(&(payload_len as u32).to_ne_bytes());
        out.extend_from_slice(&1i32.to_ne_bytes());
        out.extend((0..payload_len).map(|i| i as u8));
        out
    }

    /// The body of a `FID`/`DFID` record: an fsid followed by a file handle.
    fn fid_record_payload(fsid: (i32, i32), handle_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&fsid.0.to_ne_bytes());
        out.extend_from_slice(&fsid.1.to_ne_bytes());
        out.extend_from_slice(&file_handle(handle_len));
        out
    }

    fn with_len_prefix(records: &[Vec<u8>], mask: u64, fd: i32) -> Vec<u8> {
        let records_len: usize = records.iter().map(Vec::len).sum();
        let event_len = (METADATA_SIZE + records_len) as u32;
        let mut out = metadata(event_len, mask, fd);
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    #[test]
    fn empty_buffer_yields_no_events() {
        assert!(parse_fid_events(&[]).unwrap().is_empty());
    }

    #[test]
    fn truncated_header_yields_no_events() {
        let buf = vec![0u8; METADATA_SIZE - 1];
        assert!(parse_fid_events(&buf).unwrap().is_empty());
    }

    #[test]
    fn a_foreign_buffer_is_rejected_by_version() {
        // A regular file's first bytes are not events, and 24 bytes of zeros
        // have vers = 0.  Saying so is better than reporting an empty list.
        let buf = vec![0u8; 64];
        assert!(matches!(
            parse_fid_events(&buf),
            Err(FanotifyError::UnknownEventVersion(0))
        ));
    }

    #[test]
    fn a_zero_length_event_stops_the_walk() {
        let mut buf = metadata(0, FAN_CREATE, FAN_NOFD);
        buf.extend_from_slice(&metadata(0, FAN_CREATE, FAN_NOFD));
        assert!(parse_fid_events(&buf).unwrap().is_empty());
    }

    #[test]
    fn dfid_name_record_yields_parent_handle_and_name() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&7i32.to_ne_bytes());
        payload.extend_from_slice(&42i32.to_ne_bytes());
        payload.extend_from_slice(&file_handle(12));
        payload.extend_from_slice(b"hello\0\0\0");

        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_DFID_NAME, &payload)],
            FAN_CREATE,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();

        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.mask(), FAN_CREATE);
        assert_eq!(ev.fsid(), Some((7, 42)));
        assert_eq!(ev.dfid_name_str(), Some("hello"));
        assert_eq!(ev.dfid_name_raw(), b"hello");
        assert_eq!(
            ev.dfid_name_handle().unwrap().len(),
            crate::handle::FILE_HANDLE_HEADER_SIZE + 12
        );
        assert!(ev.unknown_info_records().is_empty());
    }

    #[test]
    fn a_non_utf8_name_survives_intact() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0i32.to_ne_bytes());
        payload.extend_from_slice(&0i32.to_ne_bytes());
        payload.extend_from_slice(&file_handle(8));
        payload.extend_from_slice(&[0xff, 0xfe, 0x00, 0x00]);

        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_DFID_NAME, &payload)],
            FAN_CREATE,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();
        let ev = &events[0];

        assert_eq!(ev.dfid_name_raw(), &[0xff, 0xfe]);
        assert_eq!(ev.dfid_name_str(), None, "not UTF-8, so no &str");
        assert!(ev.dfid_name().is_some(), "but the bytes are still a name");
    }

    #[test]
    fn fid_record_yields_the_object_handle() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1i32.to_ne_bytes());
        payload.extend_from_slice(&2i32.to_ne_bytes());
        payload.extend_from_slice(&file_handle(16));

        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_FID, &payload)],
            FAN_OPEN,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();

        assert_eq!(
            events[0].self_handle().unwrap().len(),
            crate::handle::FILE_HANDLE_HEADER_SIZE + 16
        );
        assert_eq!(events[0].fsid(), Some((1, 2)));
    }

    #[test]
    fn both_rename_sides_are_kept_apart() {
        let side = |name: &[u8]| {
            let mut payload = Vec::new();
            payload.extend_from_slice(&3i32.to_ne_bytes());
            payload.extend_from_slice(&4i32.to_ne_bytes());
            payload.extend_from_slice(&file_handle(8));
            payload.extend_from_slice(name);
            payload
        };
        let buf = with_len_prefix(
            &[
                record(FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, &side(b"before\0\0")),
                record(FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, &side(b"after\0\0\0")),
            ],
            FAN_RENAME,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();
        let ev = &events[0];

        assert_eq!(ev.rename_source().unwrap().name_str(), Some("before"));
        assert_eq!(ev.rename_target().unwrap().name_str(), Some("after"));
        // A rename names parents, not the object, so there is no self handle.
        assert_eq!(ev.self_handle(), None);
    }

    #[test]
    fn mnt_record_yields_a_mount_id_and_no_handle() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&99u64.to_ne_bytes());

        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_MNT, &payload)],
            FAN_MNT_ATTACH,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();

        assert_eq!(events[0].mnt_id(), Some(99));
        assert_eq!(events[0].fsid(), None);
        assert_eq!(events[0].self_handle(), None);
    }

    #[test]
    fn range_and_error_records_are_typed() {
        let mut range = Vec::new();
        range.extend_from_slice(&4096u64.to_ne_bytes());
        range.extend_from_slice(&512u64.to_ne_bytes());
        let mut error = Vec::new();
        error.extend_from_slice(&(-5i32).to_ne_bytes());
        error.extend_from_slice(&3u32.to_ne_bytes());

        let buf = with_len_prefix(
            &[
                record(FAN_EVENT_INFO_TYPE_RANGE, &range),
                record(FAN_EVENT_INFO_TYPE_ERROR, &error),
            ],
            FAN_PRE_ACCESS | FAN_FS_ERROR,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();

        assert_eq!(events[0].access_range(), Some((4096, 512)));
        assert_eq!(events[0].fs_error(), Some((-5, 3)));
    }

    #[test]
    fn an_unknown_record_type_is_preserved_not_dropped() {
        let raw = record(200, b"future payload");
        let buf = with_len_prefix(std::slice::from_ref(&raw), FAN_OPEN, FAN_NOFD);
        let events = parse_fid_events(&buf).unwrap();

        let unknown = events[0].unknown_info_records();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].0, 200);
        assert_eq!(
            unknown[0].1.as_ref(),
            raw.as_slice(),
            "verbatim means header included, so the record can be re-parsed"
        );
        // And it is self-describing: `len` reads back off the front.
        let stored_len = u16::from_ne_bytes([unknown[0].1[2], unknown[0].1[3]]);
        assert_eq!(stored_len as usize, raw.len());
    }

    #[test]
    fn a_following_record_is_not_charged_to_an_unknown_one() {
        // The regression this guards: an unknown record used to be stored as
        // `record_at + 4 .. event_end`, so the whole of the next record was
        // appended to it while that next record was *also* parsed into the
        // event's typed fields — the same bytes in two places, and an entry
        // whose length grew with whatever followed it.
        let unknown = record(200, b"future bytes");
        let fid = record(FAN_EVENT_INFO_TYPE_FID, &fid_record_payload((7, 9), 8));
        let buf = with_len_prefix(&[unknown.clone(), fid.clone()], FAN_OPEN, FAN_NOFD);
        let events = parse_fid_events(&buf).unwrap();

        let kept = events[0].unknown_info_records();
        assert_eq!(
            kept.len(),
            1,
            "the FID record has a typed field, not an entry"
        );
        assert_eq!(
            kept[0].1.as_ref(),
            unknown.as_slice(),
            "the unknown entry is its own record and stops at its own end"
        );
        assert!(
            !kept[0].1.ends_with(&fid),
            "the next record's bytes must not appear inside this entry"
        );

        // The next record is parsed, exactly once.
        assert_eq!(events[0].fsid(), Some((7, 9)));
        assert_eq!(events[0].self_handle().map(<[u8]>::len), Some(16));
    }

    #[test]
    fn a_record_longer_than_its_event_is_preserved_and_stops_the_walk() {
        // Claim 1000 bytes of payload inside an event that has 4.
        let mut record = record(FAN_EVENT_INFO_TYPE_FID, &[]);
        record[2..4].copy_from_slice(&1000u16.to_ne_bytes());

        let buf = with_len_prefix(&[record], FAN_OPEN, FAN_NOFD);
        let events = parse_fid_events(&buf).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].unknown_info_records().len(), 1);
        assert_eq!(
            events[0].unknown_info_records()[0].0,
            FAN_EVENT_INFO_TYPE_FID
        );
    }

    #[test]
    fn a_truncated_payload_is_preserved_rather_than_interpreted() {
        // A FID record with 4 payload bytes cannot hold an 8-byte fsid.
        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_FID, &[0u8; 4])],
            FAN_OPEN,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();

        assert_eq!(events[0].fsid(), None);
        assert_eq!(events[0].self_handle(), None);
        assert_eq!(events[0].unknown_info_records().len(), 1);
    }

    #[test]
    fn a_handle_longer_than_max_handle_sz_is_refused() {
        // handle_bytes = 4096, which no filesystem may produce.
        let mut payload = Vec::new();
        payload.extend_from_slice(&0i32.to_ne_bytes());
        payload.extend_from_slice(&0i32.to_ne_bytes());
        payload.extend_from_slice(&4096u32.to_ne_bytes());
        payload.extend_from_slice(&0i32.to_ne_bytes());
        payload.extend(std::iter::repeat_n(0u8, 16));

        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_FID, &payload)],
            FAN_OPEN,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();

        assert_eq!(events[0].self_handle(), None);
        assert_eq!(events[0].unknown_info_records().len(), 1);
    }

    #[test]
    fn a_pidfd_record_is_never_adopted_from_a_byte_buffer() {
        // A pidfd record whose "descriptor" is 1 — stdout.  Adopting it would
        // close the caller's stdout, which is exactly why the byte-level parser
        // reports instead of owning.
        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_PIDFD, &1i32.to_ne_bytes())],
            FAN_OPEN,
            FAN_NOFD,
        );
        let events = parse_fid_events(&buf).unwrap();

        match events[0].pidfd() {
            Pidfd::Unavailable(1) => {}
            other => panic!("a byte buffer must not yield an owned descriptor, got {other:?}"),
        }
    }

    #[test]
    fn fd_error_is_reported_but_no_fd_is_not() {
        let buf = metadata(METADATA_SIZE as u32, FAN_OPEN, -13); // -EACCES
        let events = parse_fid_events(&buf).unwrap();
        assert_eq!(events[0].fd_error(), Some(-13));

        let buf = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD);
        let events = parse_fid_events(&buf).unwrap();
        assert_eq!(
            events[0].fd_error(),
            None,
            "-1 is the sentinel, not an errno"
        );
    }

    #[test]
    fn several_events_in_one_buffer_are_all_parsed() {
        let first = metadata(METADATA_SIZE as u32, FAN_CREATE, FAN_NOFD);
        let second = metadata(METADATA_SIZE as u32, FAN_DELETE, FAN_NOFD);
        let buf = [first, second].concat();

        let events = parse_fid_events(&buf).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].mask(), FAN_CREATE);
        assert_eq!(events[1].mask(), FAN_DELETE);
    }

    #[test]
    fn a_trailing_partial_event_is_ignored_not_guessed_at() {
        let complete = metadata(METADATA_SIZE as u32, FAN_CREATE, FAN_NOFD);
        let mut buf = complete.clone();
        buf.extend_from_slice(&complete[..METADATA_SIZE - 4]);

        let events = parse_fid_events(&buf).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn overflow_carries_no_identity_at_all() {
        let buf = metadata(METADATA_SIZE as u32, FAN_Q_OVERFLOW, FAN_NOFD);
        let events = parse_fid_events(&buf).unwrap();

        assert!(events[0].is_overflow());
        assert_eq!(events[0].self_handle(), None);
        assert_eq!(events[0].fsid(), None);
        assert_eq!(events[0].event_names().collect::<Vec<_>>(), ["Q_OVERFLOW"]);
    }

    #[test]
    fn a_parsed_event_owns_nothing_and_a_converted_one_owns_everything() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&7i32.to_ne_bytes());
        payload.extend_from_slice(&42i32.to_ne_bytes());
        payload.extend_from_slice(&file_handle(12));
        payload.extend_from_slice(b"hello\0\0\0");
        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_DFID_NAME, &payload)],
            FAN_CREATE,
            FAN_NOFD,
        );

        let owned: Vec<FidEvent<'static>> = parse_fid_events(&buf)
            .unwrap()
            .into_iter()
            .map(FidEvent::into_owned)
            .collect();
        // The buffer can now be dropped or overwritten while the events live.
        drop(buf);

        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].dfid_name_str(), Some("hello"));
        assert_eq!(owned[0].fsid(), Some((7, 42)));
        assert_eq!(owned[0].dfid_name_handle().unwrap().len(), 20);
    }

    // ── What the walk reports ──
    //
    // A parser whose only output is a `Vec` cannot distinguish "the buffer held
    // no events" from "the buffer held the beginning of one", and a consumer of
    // a stream has to distinguish them: one means wait for more, the other means
    // reconcile.  These tests pin both facts down.

    #[test]
    fn a_complete_buffer_reports_complete() {
        let buf = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD);
        let (events, report) = parse_fid_events_reported(&buf);

        assert_eq!(events.len(), 1);
        assert!(report.is_complete());
        assert_eq!(report.bytes_consumed, buf.len());
        assert_eq!(report.bytes_left, 0);
    }

    #[test]
    fn a_truncated_header_is_reported_with_the_bytes_left() {
        let buf = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD);
        let (events, report) = parse_fid_events_reported(&buf[..METADATA_SIZE - 1]);

        assert!(events.is_empty());
        assert_eq!(report.stop, EventStop::ShortHeader);
        assert_eq!(report.bytes_consumed, 0);
        assert_eq!(report.bytes_left, METADATA_SIZE - 1);
    }

    #[test]
    fn a_zero_length_event_is_reported_as_such() {
        let buf = metadata(0, FAN_OPEN, FAN_NOFD);
        let (events, report) = parse_fid_events_reported(&buf);

        assert!(events.is_empty());
        assert_eq!(report.stop, EventStop::BadEventLen(0));
    }

    #[test]
    fn an_event_length_past_the_buffer_is_reported_as_such() {
        let buf = metadata(METADATA_SIZE as u32 + 1, FAN_OPEN, FAN_NOFD);
        let (events, report) = parse_fid_events_reported(&buf);

        assert!(events.is_empty());
        assert_eq!(
            report.stop,
            EventStop::BadEventLen(METADATA_SIZE as u32 + 1)
        );
        assert_eq!(report.bytes_left, METADATA_SIZE);
    }

    #[test]
    fn a_metadata_len_past_the_event_is_reported_as_such() {
        let mut buf = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD);
        buf[6..8].copy_from_slice(&64u16.to_ne_bytes());
        let (events, report) = parse_fid_events_reported(&buf);

        assert!(events.is_empty());
        assert_eq!(report.stop, EventStop::BadMetadataLen);
        assert_eq!(report.bytes_consumed, 0);
        assert_eq!(report.bytes_left, buf.len());
    }

    #[test]
    fn a_metadata_len_below_the_header_is_clamped_rather_than_fatal() {
        // The kernel writes 24 here.  A smaller value cannot point the record
        // walk anywhere but the header, so it is clamped; there is no record
        // layout it could produce that the header end does not already give.
        let mut buf = metadata(METADATA_SIZE as u32, FAN_CREATE, FAN_NOFD);
        buf[6..8].copy_from_slice(&4u16.to_ne_bytes());
        let (events, report) = parse_fid_events_reported(&buf);

        assert!(report.is_complete());
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn an_unknown_version_is_reported_and_a_hard_error_in_the_plain_parser() {
        let mut buf = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD);
        buf[4] = 9;

        let (events, report) = parse_fid_events_reported(&buf);
        assert!(events.is_empty());
        assert_eq!(report.stop, EventStop::UnknownVersion(9));
        assert_eq!(report.bytes_consumed, 0, "nothing after vers is readable");
        assert_eq!(report.bytes_left, buf.len());

        assert!(matches!(
            parse_fid_events(&buf),
            Err(FanotifyError::UnknownEventVersion(9))
        ));
    }

    #[test]
    fn garbage_after_valid_events_is_left_over_not_parsed() {
        let mut buf = metadata(METADATA_SIZE as u32, FAN_CREATE, FAN_NOFD);
        let complete = buf.len();
        buf.extend_from_slice(b"junk");

        let (events, report) = parse_fid_events_reported(&buf);
        assert_eq!(events.len(), 1);
        assert_eq!(report.stop, EventStop::ShortHeader);
        assert_eq!(report.bytes_consumed, complete);
        assert_eq!(report.bytes_left, 4);
    }

    #[test]
    fn a_record_overrunning_its_event_is_consumed_with_the_event() {
        // The event was read whole, so the buffer position is past it; the
        // record-level overrun is preserved on the event, not left in the
        // buffer, because the remainder is only meaningful with that event.
        let mut record = record(FAN_EVENT_INFO_TYPE_FID, &[]);
        record[2..4].copy_from_slice(&1000u16.to_ne_bytes());
        let buf = with_len_prefix(&[record], FAN_OPEN, FAN_NOFD);

        let (events, report) = parse_fid_events_reported(&buf);
        assert_eq!(events.len(), 1);
        assert!(report.is_complete());
        assert_eq!(events[0].unknown_info_records().len(), 1);
    }

    #[test]
    fn a_reused_vec_is_refilled_in_place() {
        let first = metadata(METADATA_SIZE as u32, FAN_CREATE, FAN_NOFD);
        let second = metadata(METADATA_SIZE as u32, FAN_DELETE, FAN_NOFD);

        let mut events: Vec<FidEvent<'_>> = Vec::new();
        assert!(parse_fid_events_into(&mut events, &first).is_complete());
        let capacity = events.capacity();
        assert!(parse_fid_events_into(&mut events, &second).is_complete());

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mask(), FAN_DELETE);
        assert_eq!(events.capacity(), capacity, "the Vec was not reallocated");
    }

    // ── Zero allocations per parsed record ──
    //
    // The claim is that parsing copies nothing and reuses the `Vec`s.  Counting
    // allocations is the only way to make that a test rather than a comment.

    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        // `const` initializers keep the bookkeeping itself allocation-free,
        // which matters when the thing being measured is the absence of them.
        static COUNTING: Cell<bool> = const { Cell::new(false) };
        static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    }

    /// The system allocator, plus a counter that only runs while a test asks.
    struct CountingAllocator;

    // SAFETY: every method forwards to `System` unchanged; the counter is
    // thread-local bookkeeping and does not alter the allocation contract.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            COUNTING.with(|counting| {
                if counting.get() {
                    ALLOCATIONS.with(|n| n.set(n.get() + 1));
                }
            });
            // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which
            // `System` relies on in exactly the same way.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: forwarded unchanged.
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            COUNTING.with(|counting| {
                if counting.get() {
                    ALLOCATIONS.with(|n| n.set(n.get() + 1));
                }
            });
            // SAFETY: forwarded unchanged.
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    /// Run `f`, returning its value and how many allocations it made on this
    /// thread.
    fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
        ALLOCATIONS.with(|n| n.set(0));
        COUNTING.with(|c| c.set(true));
        let result = f();
        COUNTING.with(|c| c.set(false));
        (result, ALLOCATIONS.with(Cell::get))
    }

    #[test]
    fn a_static_buffer_and_its_vec_reuse_both_allocations() {
        // The reuse that a read loop can actually have: when the buffer and the
        // events `Vec` are both `'static`, the borrow a `Vec<FidEvent<'buf>>`
        // pins is the same one every iteration, so one buffer and one `Vec`
        // serve every parse.  Reparsing into the same `Vec` is the half of that
        // this can assert without a kernel; the lifetime half is what the
        // `read_events` doc example compiles.
        let mut payload = Vec::new();
        payload.extend_from_slice(&7i32.to_ne_bytes());
        payload.extend_from_slice(&42i32.to_ne_bytes());
        payload.extend_from_slice(&file_handle(12));
        payload.extend_from_slice(b"hello\0\0\0");
        let buf = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_DFID_NAME, &payload)],
            FAN_CREATE,
            FAN_NOFD,
        );

        let mut events: Vec<FidEvent<'_>> = Vec::new();
        assert!(parse_fid_events_into(&mut events, &buf).is_complete());
        let capacity = events.capacity();
        assert!(capacity > 0);

        for _ in 0..64 {
            let (report, allocations) =
                allocations_during(|| parse_fid_events_into(&mut events, &buf));
            assert!(report.is_complete());
            assert_eq!(events.len(), 1);
            assert_eq!(
                allocations, 0,
                "a warm Vec must not allocate, however many times it is refilled"
            );
            assert_eq!(events.capacity(), capacity, "and must not regrow");
            assert_eq!(events[0].dfid_name_str(), Some("hello"));
        }
    }

    #[test]
    fn parsing_a_known_shape_allocates_nothing() {
        // Two events that each name a parent handle and an entry: the fields
        // that would be the per-record copies in an owning parser.
        let mut payload = Vec::new();
        payload.extend_from_slice(&7i32.to_ne_bytes());
        payload.extend_from_slice(&42i32.to_ne_bytes());
        payload.extend_from_slice(&file_handle(12));
        payload.extend_from_slice(b"hello\0\0\0");
        let one = with_len_prefix(
            &[record(FAN_EVENT_INFO_TYPE_DFID_NAME, &payload)],
            FAN_CREATE,
            FAN_NOFD,
        );
        let buf = [one.clone(), one].concat();

        let mut events: Vec<FidEvent<'_>> = Vec::with_capacity(2);
        // One warm-up parse so that any lazily created state (there should be
        // none) is not charged to the measured call.
        assert!(parse_fid_events_into(&mut events, &buf).is_complete());
        assert_eq!(events.len(), 2);

        let (report, allocations) = allocations_during(|| parse_fid_events_into(&mut events, &buf));
        assert!(report.is_complete());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].dfid_name_str(), Some("hello"));
        assert_eq!(
            allocations, 0,
            "parsing must allocate once for the Vec, never per record"
        );
    }
}
