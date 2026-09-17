//! Descriptor identity: the event format that hands you an open descriptor.
//!
//! This is what fanotify reports when the group was created **without** any FID
//! flag, and it is the original form of the interface.  The kernel opens the
//! object the event is about and puts that descriptor in the event, so the
//! consumer holds the file rather than a name for it.
//!
//! ```text
//! struct fanotify_event_metadata    24 bytes, one per event
//!   u32 event_len      total size of this event (no info records here)
//!   u8  vers           FANOTIFY_METADATA_VERSION
//!   u8  reserved
//!   u16 metadata_len   == 24
//!   u64 mask           which bits fired
//!   i32 fd             an open descriptor, or FAN_NOFD, or -errno
//!   i32 pid            who caused it
//! ```
//!
//! # The stride is not fixed, even though the header is
//!
//! There are no info records in this format, so the header *looks* like a
//! fixed-size stride — and that is a trap: the kernel may extend an event, and
//! `event_len` is what says how long this one is.  Walking by
//! `size_of::<metadata>()` works until it does not, and then it parses garbage.
//! The walk here advances by `event_len`.
//!
//! # The descriptor is owned, and that is a real obligation
//!
//! Each event's `fd` field is a descriptor the **kernel installed for this
//! process** when it queued the event, and it must be closed exactly once.  The
//! adoption has to happen somewhere, and it happens on the crate's read path
//! ([`Fanotify::read_fd_events`](crate::Fanotify::read_fd_events)), because that
//! is the only place that knows the bytes are the kernel's answer to the
//! `read(2)` that just happened.  A descriptor number from any other byte source
//! is just a number: adopting it would close an unrelated open file, or the
//! caller's stdout.
//!
//! [`parse_fd_events`] therefore exists, and **adopts nothing**: it walks the
//! same format for replay, capture analysis and fuzzing, and leaves every event
//! with its raw `fd` field in [`FdEvent::fd_field`] and no descriptor at all.
//! A caller that really means to take the numbers over does so explicitly, with
//! `unsafe` of its own, or by reading through the group.
//!
//! # Reading a live group, and what a batch's storage means
//!
//! [`Fanotify::read_fd_events`](crate::Fanotify::read_fd_events) is the
//! stateless read: one `Vec` of events per call, dropped when the caller is done.
//! [`FdEventReader`](crate::FdEventReader) is the reader for a loop, and it owns
//! its buffer and its event storage so that every read after setup allocates
//! nothing.  Because it reuses that storage, its batches have a lifetime worth
//! stating: **an event's descriptor is open until the next read on that reader
//! replaces it**, or until [`FdEvent::into_fd`] takes it out.  The stateless call
//! has the same rule by construction — the events it returns are dropped together
//! — so nothing about it changes; what changes is that a reused slot gives up the
//! descriptor it held rather than freeing it.
//!
//! # `fd` is not always a descriptor
//!
//! | Value | Meaning |
//! |---|---|
//! | `>= 0` | an open descriptor, owned by the event until it drops |
//! | [`FAN_NOFD`] | no descriptor; see [`FdEvent::no_fd_reason`] for what that does and does not tell you |
//!
//! [`FAN_NOFD`]: crate::consts::FAN_NOFD

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use crate::consts::*;
use crate::error::FanotifyError;
use crate::parse::{EventStop, ParseReport};

/// `sizeof(struct fanotify_event_metadata)` — the size of one fd-based event.
pub const METADATA_SIZE: usize = 24;

/// `struct fanotify_event_metadata`, the whole of an fd-based event.
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

// The walk bounds-checks with `METADATA_SIZE` and then reads
// `size_of::<EventMetadata>()` bytes, so if the two ever disagreed the read
// would run past the check that was supposed to cover it.  Pinning the struct to
// the kernel's number here is what makes the bounds check the real one.
const _: () = assert!(std::mem::size_of::<EventMetadata>() == METADATA_SIZE);

/// One fd-based event: a mask, a pid, and optionally an owned open descriptor.
///
/// The descriptor is closed when the event drops.  Borrow it with
/// [`fd`](Self::fd) — that is what a permission response needs — or take it with
/// [`into_fd`](Self::into_fd).  An event parsed from bytes by
/// [`parse_fd_events`] carries no descriptor and reports the number the buffer
/// held in [`fd_field`](Self::fd_field) instead.
#[derive(Debug)]
pub struct FdEvent {
    mask: u64,
    pid: i32,
    fd: Option<OwnedFd>,
    /// The raw value of the event's `fd` field, kept even when it became an
    /// `OwnedFd` so that the field can be reported as the kernel wrote it.
    fd_field: i32,
}

impl FdEvent {
    /// Build an event by hand: a mask, an optional descriptor the caller
    /// already owns, and a pid.
    ///
    /// The descriptor is adopted by the event — closed when it drops, unless
    /// [`into_fd`](Self::into_fd) takes it out — and the reported `fd` field
    /// becomes its number, so an event built this way reports exactly what the
    /// kernel would have written for the same object.  A hand-built event's pid
    /// is the caller's to choose, because the kernel's rules about blanking it
    /// do not apply to a value that never came from the kernel.
    ///
    /// The constructor **takes an [`OwnedFd`], never a number**: turning a
    /// number into a descriptor is a claim of ownership, and the only place
    /// that claim is sound is the read path that just received the number from
    /// the kernel.  A caller reconstructing an event from a recording passes a
    /// descriptor it opened itself, or leaves the descriptor out and fabricates
    /// only the field with [`set_fd_field`](Self::set_fd_field).
    ///
    /// ```
    /// use fanotify_fid::consts::FAN_OPEN;
    /// use fanotify_fid::fd::FdEvent;
    /// use std::os::fd::AsRawFd;
    ///
    /// let file = std::fs::File::open("/dev/null")?;
    /// let number = file.as_raw_fd();
    /// let event = FdEvent::new(FAN_OPEN, Some(file.into()), 7);
    ///
    /// assert_eq!(event.mask(), FAN_OPEN);
    /// assert_eq!(event.pid(), 7);
    /// assert_eq!(event.fd_field(), number);
    /// assert!(event.fd().is_some());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn new(mask: u64, fd: Option<OwnedFd>, pid: i32) -> Self {
        let fd_field = fd.as_ref().map_or(FAN_NOFD, AsRawFd::as_raw_fd);
        Self {
            mask,
            pid,
            fd,
            fd_field,
        }
    }

    /// Overwrite the reported `fd` field, claiming nothing.
    ///
    /// The field is what the event *says* about a descriptor, and an event built
    /// by hand may want to say [`FAN_NOFD`] or a negative errno without owning a
    /// descriptor at all — which is what replaying a recorded event or comparing
    /// two parses needs.  This method touches only the number: it adopts
    /// nothing, closes nothing, and cannot make [`fd`](Self::fd) return a
    /// descriptor.  Calling it on an event that does own one leaves the
    /// descriptor open and the two facts disagreeing, which is the caller's
    /// explicit choice.
    ///
    /// ```
    /// use fanotify_fid::fd::FdEvent;
    ///
    /// let mut event = FdEvent::new(0, None, 0);
    /// // -EACCES, exactly what a FAN_REPORT_FD_ERROR group writes.
    /// event.set_fd_field(-13);
    /// assert_eq!(event.no_fd_reason(), Some(-13));
    /// assert!(event.fd().is_none());
    /// ```
    pub fn set_fd_field(&mut self, field: i32) -> &mut Self {
        self.fd_field = field;
        self
    }

    /// The event mask: which bits fired.
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// The pid of the process that caused the event.
    ///
    /// Zero when the kernel had no answer, which is the normal case for an
    /// unprivileged group observing other processes.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Borrow the open descriptor the event carries.
    ///
    /// `None` means the event carries no descriptor the crate adopted.  Why is
    /// in [`no_fd_reason`](Self::no_fd_reason) when the field says so, and in
    /// [`fd_field`](Self::fd_field) always: an event from [`parse_fd_events`]
    /// reports a number there and adopts nothing, on purpose.
    pub fn fd(&self) -> Option<BorrowedFd<'_>> {
        self.fd.as_ref().map(AsFd::as_fd)
    }

    /// Take the descriptor out of the event, so it outlives it.
    ///
    /// After this the event no longer closes it; the returned value does, when
    /// it drops.
    pub fn into_fd(self) -> Option<OwnedFd> {
        self.fd
    }

    /// The path of the object, read from `/proc/self/fd`.
    ///
    /// A convenience for the descriptor the event already holds, and
    /// **best-effort** for the usual reasons: it is the path at the moment of
    /// the read, and an unlinked object keeps the `" (deleted)"` marker `/proc`
    /// appends rather than being guessed at.
    ///
    /// `None` when the event carries no descriptor, or when `/proc` cannot
    /// answer.
    pub fn path(&self) -> Option<PathBuf> {
        let fd = self.fd.as_ref()?;
        std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()
    }

    /// The raw value of the event's `fd` field, as the bytes reported it.
    ///
    /// A descriptor number, or [`FAN_NOFD`], or a negative errno.  Most callers
    /// want [`fd`](Self::fd) instead — except after [`parse_fd_events`], where
    /// this is the only place the number appears, because no descriptor was
    /// adopted.
    pub fn fd_field(&self) -> i32 {
        self.fd_field
    }

    /// Why the event carries no descriptor, or `None` when it carries one.
    ///
    /// `Some(FAN_NOFD)` means only "no descriptor": without
    /// [`FAN_REPORT_FD_ERROR`] on the group, the kernel writes that same value
    /// whether or not a descriptor could have been opened.  With that flag, a
    /// *different* negative value is the errno that stopped it — which is what
    /// separates "there was nothing to open" from "opening it failed with
    /// `EACCES`".
    ///
    /// `None` for a **non-negative** field with no descriptor held: a
    /// non-negative number is not a reason for anything, it is a descriptor
    /// number that the event reports without owning (see [`parse_fd_events`]).
    /// The number stays visible through [`fd_field`](Self::fd_field).
    pub fn no_fd_reason(&self) -> Option<i32> {
        if self.fd.is_some() || self.fd_field >= 0 {
            return None;
        }
        Some(self.fd_field)
    }

    /// Whether this event says the queue overflowed and events were lost.
    ///
    /// An overflow event carries no descriptor and no pid, and means an unknown
    /// number of events never arrived.  They cannot be recovered from the queue.
    pub fn is_overflow(&self) -> bool {
        self.mask & FAN_Q_OVERFLOW != 0
    }

    /// The names of the event bits set in the mask, for logging and debugging.
    pub fn event_names(&self) -> impl Iterator<Item = &'static str> {
        mask_to_event_names(self.mask)
    }

    /// Return the event to the state [`new`](Self::new) makes, closing any
    /// descriptor the previous parse adopted.
    fn reset(&mut self) {
        self.mask = 0;
        self.pid = 0;
        self.fd = None;
        self.fd_field = 0;
    }

    /// Turn the reported number into an owned descriptor.
    ///
    /// Called only by the read path, which performed the `read(2)` the bytes came
    /// from: there the number really is a descriptor the kernel installed for
    /// this process.  `already_adopted` carries the numbers adopted earlier in
    /// the same buffer; the kernel installs a fresh descriptor per event, so a
    /// repeat means the buffer is not what it claims, and adopting it twice
    /// would close one descriptor from two owners — a repeat is left unowned.
    pub(crate) fn adopt_reported(&mut self, already_adopted: &mut Vec<i32>) {
        let raw = self.fd_field;
        if self.fd.is_some() || raw < 0 || already_adopted.contains(&raw) {
            return;
        }
        already_adopted.push(raw);
        // SAFETY: the caller is the read path, which knows the buffer came from
        // `read(2)` on a fanotify group.  A non-negative value in such a header
        // was installed by the kernel for this process and is owned by it, and
        // the duplicate check above is what makes this the single owner.
        self.fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
    }
}

/// Walk fd-format events from a byte buffer, **adopting no descriptors**.
///
/// This is the byte-level reader for the format, for the jobs that are not a
/// live group: replaying a capture, diffing two parses, fuzzing the walk.  Each
/// event reports the `fd` field exactly as the bytes carried it through
/// [`FdEvent::fd_field`]; [`FdEvent::fd`] is `None` for all of them, because a
/// `&[u8]` proves nothing about where a number came from and adopting one would
/// close an unrelated descriptor.
///
/// The walk advances by `event_len`, never by a fixed stride, and stops rather
/// than following a length it has decided is untrustworthy — the report says
/// where and why (see [`ParseReport`]), so a caller can keep the unparsed tail
/// instead of losing it.  No input can panic, read out of bounds, or loop
/// forever.
///
/// ```
/// use fanotify_fid::fd::parse_fd_events;
///
/// let (events, report) = parse_fd_events(&[]);
/// assert!(events.is_empty());
/// assert!(report.is_complete(), "an empty buffer is a complete walk");
/// ```
pub fn parse_fd_events(buf: &[u8]) -> (Vec<FdEvent>, ParseReport) {
    let mut events = Vec::new();
    let report = parse_fd_events_into(&mut events, buf);
    (events, report)
}

/// [`parse_fd_events`], reusing an existing `Vec`'s capacity.
///
/// The fd format has no borrowed fields, so the `Vec` itself is the whole
/// allocation, and reusing it across buffers is what the fd-format parser's
/// efficiency knobs come down to.  The old events are dropped — closing any
/// descriptors a read path adopted into them — before the new ones are parsed
/// in their place.  The returned [`ParseReport`] is [`parse_fd_events`]'s.
pub fn parse_fd_events_into(events: &mut Vec<FdEvent>, buf: &[u8]) -> ParseReport {
    let mut parsed = 0;
    let mut offset = 0;
    let mut version_checked = false;

    let stop = loop {
        // Fewer than a header's bytes left: either the buffer ended cleanly or
        // it holds the start of an event a larger read could complete.
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
        let meta =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const EventMetadata) };

        // `vers` is a property of the group, not of the event, so one look is
        // enough — and a different value means every field after it is being
        // read with the wrong layout, which is not recoverable.
        if !version_checked {
            version_checked = true;
            if meta.vers != FANOTIFY_METADATA_VERSION {
                break EventStop::UnknownVersion(meta.vers);
            }
        }

        let event_len = meta.event_len as usize;
        if event_len < METADATA_SIZE || event_len > buf.len() - offset {
            break EventStop::BadEventLen(meta.event_len);
        }
        // The fd format has no records, but the field is still the kernel's and
        // a value past the event means the header cannot be trusted as one.
        let records_start = usize::from(meta.metadata_len).max(METADATA_SIZE);
        if records_start > event_len {
            break EventStop::BadMetadataLen;
        }

        if parsed < events.len() {
            events[parsed].reset();
        } else {
            events.push(FdEvent::new(0, None, 0));
        }
        let event = &mut events[parsed];
        event.mask = meta.mask;
        event.pid = meta.pid;
        event.fd_field = meta.fd;
        parsed += 1;
        offset += event_len;
    };

    events.truncate(parsed);
    ParseReport {
        bytes_consumed: offset,
        bytes_left: buf.len() - offset,
        stop,
    }
}

/// `read(2)` one buffer's worth from an fd-based group and parse it.
///
/// `buf`'s capacity is the read-size knob for this format: a single fd-based
/// event is 24 bytes, plus whatever a future kernel adds to it, so a caller that
/// sizes the buffer deliberately is choosing how many whole events one syscall
/// may return.  The read itself lives in [`sys::read_events`](crate::sys).
///
/// Crate-private on purpose: this is the only place a descriptor number from a
/// buffer is turned into an [`OwnedFd`], and it is sound only because the
/// buffer is the direct result of the `read` just above it.  Everything a
/// caller needs is [`Fanotify::read_fd_events`](crate::Fanotify::read_fd_events),
/// which reaches this through the same guarantee.
pub(crate) fn read_fd_events(
    fanotify_fd: &OwnedFd,
    buf: &mut Vec<u8>,
) -> Result<Vec<FdEvent>, FanotifyError> {
    let (events, report) = read_fd_events_reported(fanotify_fd, buf)?;
    if let EventStop::UnknownVersion(vers) = report.stop {
        return Err(FanotifyError::UnknownEventVersion(vers));
    }
    Ok(events)
}

/// [`read_fd_events`], reporting how far the parse got.
///
/// The adoption is identical; the report is what the convenience form drops.
/// A kernel `read(2)` returns whole events, so a non-complete report is a signal
/// about the stream and `bytes_left` is the tail that was not interpreted.
pub(crate) fn read_fd_events_reported(
    fanotify_fd: &OwnedFd,
    buf: &mut Vec<u8>,
) -> Result<(Vec<FdEvent>, ParseReport), FanotifyError> {
    crate::sys::read_events(fanotify_fd, buf)?;
    // The read above is what makes adoption sound: this buffer is the kernel's
    // answer to this call, so a non-negative number in it is a descriptor the
    // kernel installed for this process.  `adopt_reported` makes each number a
    // single owner even if the buffer names it twice.
    let mut events = Vec::new();
    let report = parse_fd_events_into(&mut events, buf);
    let mut adopted = Vec::new();
    for event in &mut events {
        event.adopt_reported(&mut adopted);
    }
    Ok((events, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(event_len: u32, mask: u64, fd: i32, pid: i32) -> Vec<u8> {
        let mut out = Vec::with_capacity(METADATA_SIZE);
        out.extend_from_slice(&event_len.to_ne_bytes());
        out.push(FANOTIFY_METADATA_VERSION);
        out.push(0);
        out.extend_from_slice(&(METADATA_SIZE as u16).to_ne_bytes());
        out.extend_from_slice(&mask.to_ne_bytes());
        out.extend_from_slice(&fd.to_ne_bytes());
        out.extend_from_slice(&pid.to_ne_bytes());
        out
    }

    #[test]
    fn a_foreign_buffer_is_rejected_by_version() {
        let (events, report) = parse_fd_events(&[0u8; 64]);
        assert!(events.is_empty());
        assert_eq!(report.stop, EventStop::UnknownVersion(0));
        assert_eq!(report.bytes_consumed, 0);
        assert_eq!(report.bytes_left, 64);
    }

    #[test]
    fn an_event_with_no_descriptor_reports_the_sentinel() {
        let buf = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD, 7);
        let (events, report) = parse_fd_events(&buf);

        assert!(report.is_complete());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid(), 7);
        assert_eq!(events[0].fd_field(), FAN_NOFD);
        assert!(events[0].fd().is_none());
        assert_eq!(events[0].no_fd_reason(), Some(FAN_NOFD));
        assert!(!events[0].is_overflow());
    }

    #[test]
    fn a_negative_fd_other_than_the_sentinel_is_the_reason() {
        let buf = metadata(METADATA_SIZE as u32, FAN_OPEN, -13, 7);
        let (events, _) = parse_fd_events(&buf);

        assert_eq!(events[0].no_fd_reason(), Some(-13), "-EACCES");
    }

    #[test]
    fn a_parsed_descriptor_number_is_reported_but_not_adopted() {
        // The number in the bytes is what it is, and adopting it would close
        // whatever descriptor this process happens to hold under that number.
        let buf = metadata(METADATA_SIZE as u32, FAN_OPEN, 1, 7);
        let (events, _) = parse_fd_events(&buf);

        assert_eq!(events[0].fd_field(), 1);
        assert!(events[0].fd().is_none());
        assert_eq!(
            events[0].no_fd_reason(),
            None,
            "a non-negative number is not a reason for a missing descriptor"
        );
    }

    #[test]
    fn a_descriptor_number_is_never_adopted_twice() {
        use std::mem::ManuallyDrop;
        use std::os::fd::AsRawFd;

        // A real descriptor number, put into two headers.  The kernel installs a
        // fresh descriptor per event, so a buffer naming one twice is not what
        // it claims, and adopting both would close it from two owners.
        //
        // `ManuallyDrop` rather than `File` on purpose: a descriptor that
        // appears in a kernel-read buffer belongs to the *event*, and this crate
        // is the one that closes it.  Leaving the `File` alive would claim the
        // same descriptor twice before the parser ever saw it, which is not the
        // situation being tested.
        let kernel_owned = ManuallyDrop::new(std::fs::File::open("/dev/null").unwrap());
        let raw = kernel_owned.as_raw_fd();

        let buf = [
            metadata(METADATA_SIZE as u32, FAN_OPEN, raw, 1),
            metadata(METADATA_SIZE as u32, FAN_OPEN, raw, 2),
        ]
        .concat();
        let (mut events, _) = parse_fd_events(&buf);
        assert_eq!(events.len(), 2);

        let mut adopted = Vec::new();
        events[0].adopt_reported(&mut adopted);
        events[1].adopt_reported(&mut adopted);

        assert!(events[0].fd().is_some(), "the first adopts it");
        assert!(events[1].fd().is_none(), "the repeat stays unowned");
        assert_eq!(events[1].fd_field(), raw, "the field is still reported");

        // Dropping the events closes it exactly once; a second close would be a
        // use-after-close, and the test would abort on std's I/O-safety check.
        drop(events);
        assert!(
            fcntl_getfd(raw) < 0,
            "the descriptor was closed, so the owner really owned it"
        );
    }

    /// `fcntl(fd, F_GETFD)`, for checking a descriptor number is no longer open.
    fn fcntl_getfd(fd: i32) -> i32 {
        // SAFETY: `fcntl` with F_GETFD reads no memory and takes only integers.
        unsafe { libc::fcntl(fd, libc::F_GETFD) }
    }

    #[test]
    fn the_walk_advances_by_event_len_not_by_a_fixed_stride() {
        // The first event is padded to 40 bytes.  Walking by 24 would read the
        // padding as a second event and never see the real one.
        let mut first = metadata(40, FAN_CREATE, FAN_NOFD, 1);
        first.extend_from_slice(&[0u8; 16]);
        let second = metadata(METADATA_SIZE as u32, FAN_DELETE, FAN_NOFD, 2);
        let buf = [first, second].concat();

        let (events, report) = parse_fd_events(&buf);
        assert!(report.is_complete());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].mask(), FAN_CREATE);
        assert_eq!(events[0].pid(), 1);
        assert_eq!(events[1].mask(), FAN_DELETE);
        assert_eq!(events[1].pid(), 2);
    }

    #[test]
    fn a_malformed_length_stops_the_walk_and_is_reported() {
        let good = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD, 1);
        let bad = metadata(9999, FAN_OPEN, FAN_NOFD, 2);
        let buf = [good, bad].concat();

        let (events, report) = parse_fd_events(&buf);
        assert_eq!(events.len(), 1);
        assert_eq!(report.stop, EventStop::BadEventLen(9999));
        assert_eq!(report.bytes_consumed, METADATA_SIZE);
        assert_eq!(report.bytes_left, METADATA_SIZE);
    }

    #[test]
    fn a_zero_length_event_stops_the_walk() {
        let buf = metadata(0, FAN_OPEN, FAN_NOFD, 1);
        let (events, report) = parse_fd_events(&buf);

        assert!(events.is_empty());
        assert_eq!(report.stop, EventStop::BadEventLen(0));
        assert_eq!(report.bytes_left, METADATA_SIZE);
    }

    #[test]
    fn a_metadata_len_past_the_event_stops_the_walk() {
        let mut buf = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD, 1);
        buf[6..8].copy_from_slice(&64u16.to_ne_bytes());

        let (events, report) = parse_fd_events(&buf);
        assert!(events.is_empty());
        assert_eq!(report.stop, EventStop::BadMetadataLen);
    }

    #[test]
    fn an_overflow_event_is_recognised() {
        let buf = metadata(METADATA_SIZE as u32, FAN_Q_OVERFLOW, FAN_NOFD, 0);
        let (events, _) = parse_fd_events(&buf);

        assert!(events[0].is_overflow());
        assert_eq!(events[0].event_names().collect::<Vec<_>>(), ["Q_OVERFLOW"]);
    }

    #[test]
    fn a_truncated_final_event_is_ignored_and_reported() {
        let good = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD, 1);
        let mut buf = good.clone();
        buf.extend_from_slice(&good[..METADATA_SIZE - 8]);

        let (events, report) = parse_fd_events(&buf);
        assert_eq!(events.len(), 1);
        assert_eq!(report.stop, EventStop::ShortHeader);
        assert_eq!(report.bytes_consumed, METADATA_SIZE);
        assert_eq!(report.bytes_left, METADATA_SIZE - 8);
    }

    #[test]
    fn a_reused_vec_parses_the_second_buffer_in_place() {
        let first = metadata(METADATA_SIZE as u32, FAN_OPEN, FAN_NOFD, 1);
        let second = metadata(METADATA_SIZE as u32, FAN_DELETE, FAN_NOFD, 2);

        let mut events = Vec::new();
        assert!(parse_fd_events_into(&mut events, &first).is_complete());
        assert_eq!(events[0].mask(), FAN_OPEN);

        // Same `Vec`, different buffer: the slot is reset, not reallocated.
        let capacity = events.capacity();
        assert!(parse_fd_events_into(&mut events, &second).is_complete());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mask(), FAN_DELETE);
        assert_eq!(events[0].pid(), 2);
        assert_eq!(events.capacity(), capacity);
    }

    #[test]
    fn a_hand_built_event_reports_what_it_was_given() {
        let event = FdEvent::new(FAN_OPEN, None, 7);
        assert_eq!(event.mask(), FAN_OPEN);
        assert_eq!(event.pid(), 7);
        assert_eq!(event.fd_field(), FAN_NOFD);
        assert!(event.fd().is_none());
        assert_eq!(event.no_fd_reason(), Some(FAN_NOFD));

        let file = std::fs::File::open("/dev/null").unwrap();
        let number = file.as_raw_fd();
        let event = FdEvent::new(FAN_OPEN, Some(file.into()), 7);
        assert_eq!(event.fd_field(), number);
        assert!(event.fd().is_some());
        assert_eq!(event.no_fd_reason(), None);
    }

    #[test]
    fn reusing_a_slot_closes_the_descriptor_the_previous_parse_adopted() {
        // The rule `FdEventReader` rests on: it keeps one `Vec` of events and
        // rewrites the slots in place, so a slot that held a descriptor must give
        // it up when the next batch takes it.  That is the difference between
        // reusing storage and leaking a descriptor per batch, and it is a
        // property of the parse rather than of the reader, so it is asserted
        // here, where no group is needed.
        //
        // `ManuallyDrop`, as in the duplicate test above: the descriptor in a
        // read buffer belongs to the *event*, and a `File` that also claimed it
        // would be a second owner rather than the situation under test.
        use std::mem::ManuallyDrop;
        use std::os::fd::AsRawFd;

        let kernel_owned = ManuallyDrop::new(std::fs::File::open("/dev/null").unwrap());
        let raw = kernel_owned.as_raw_fd();

        let first = metadata(METADATA_SIZE as u32, FAN_OPEN, raw, 1);
        let mut events = Vec::new();
        assert!(parse_fd_events_into(&mut events, &first).is_complete());
        let mut adopted = Vec::new();
        events[0].adopt_reported(&mut adopted);
        assert!(events[0].fd().is_some());
        assert!(
            fcntl_getfd(raw) >= 0,
            "the descriptor is open while it is held"
        );

        // A second buffer with no descriptor in the slot the first one used.
        let second = metadata(METADATA_SIZE as u32, FAN_DELETE, FAN_NOFD, 2);
        assert!(parse_fd_events_into(&mut events, &second).is_complete());
        assert_eq!(events[0].mask(), FAN_DELETE, "the slot was rewritten");
        assert!(
            fcntl_getfd(raw) < 0,
            "the replaced slot must have closed the descriptor it held"
        );

        // The slot itself is free again, and the storage is reusable: a later
        // batch fills it and adopts whatever *that* buffer reported.  What must
        // not happen is adopting this number again — the descriptor is closed,
        // and a second `OwnedFd` for a closed number is the double close the
        // adoption guard exists to prevent — so the number is dropped here and
        // the reader's next batch brings fresh ones.
        //
        // Nothing closes the descriptor a second time on the way out of this test:
        // the `ManuallyDrop` wrapping the `File` is exactly what keeps its `Drop`
        // from running, which is the whole reason it is used instead of a `File`
        // that owns the descriptor for real. (`fstat`, not `fstat`-and-close, is
        // what `fcntl_getfd` does, so the checks above never took ownership
        // either.)
    }
}
