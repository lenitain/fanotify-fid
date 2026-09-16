//! Answering a permission event: the decision word and the optional record
//! beside it.
//!
//! A permission event blocks the operation until the group answers, so an
//! unanswered event blocks a file operation rather than merely being lost.  The
//! answer is one `write(2)` to the group, and its wire format is fixed:
//!
//! ```text
//! struct fanotify_response {         8 bytes
//!   s32 fd           the event's descriptor, or FAN_NOFD
//!   u32 response     FAN_ALLOW | FAN_DENY, plus FAN_AUDIT / FAN_INFO / errno
//! }
//! ```
//!
//! # The decision word
//!
//! The kernel matches an answer against a pending event **by descriptor**, so
//! `fd` is the descriptor the event carried
//! ([`FdEvent::fd`](crate::FdEvent::fd)) — the same fact that makes
//! `FID × permission class` an illegal group, because a handle-identified event
//! has no descriptor to match with.
//!
//! On top of the decision, three optional pieces live in the same word:
//!
//! | Bits | Meaning |
//! |---|---|
//! | [`FAN_ALLOW`] / [`FAN_DENY`] | exactly one of them; the decision itself |
//! | [`FAN_AUDIT`] | ask the kernel to log the decision; needs a group created with [`FAN_ENABLE_AUDIT`] |
//! | [`FAN_INFO`] | a response record follows the 8-byte response |
//! | `errno << FAN_ERRNO_SHIFT` | the errno the blocked caller sees, instead of `EPERM` |
//!
//! # The kernel is the authority on all of it
//!
//! Every constraint below is enforced by `fanotify_write`, and none of them is
//! filtered or predicted here — the errno you see is the kernel's:
//!
//! * `response & ~(FAN_ALLOW | FAN_DENY | FAN_AUDIT | FAN_INFO | errno bits)` is
//!   `EINVAL`: the word is a closed set, which is why [`raw`](FanotifyResponse::raw)
//!   exists for sending a word *you* chose and reading the answer.
//! * Including both [`FAN_ALLOW`] and [`FAN_DENY`], or neither, is `EINVAL`.
//! * A packed errno is read only for a [`FAN_CLASS_PRE_CONTENT`] group, and only
//!   from the kernel's short list (`EPERM`, `EIO`, `EBUSY`, `ETXTBSY`, `EAGAIN`,
//!   `ENOSPC`, `EDQUOT`); every other class and value is `EINVAL`.
//! * [`FAN_AUDIT`] without [`FAN_ENABLE_AUDIT`] on the group is `EINVAL` —
//!   that flag needs `CAP_AUDIT_WRITE`, **not** `CAP_SYS_ADMIN`.
//! * [`FAN_INFO`] demands a well-formed record: `pad == 0`, `len` equal to the
//!   record's own length *including* the 4-byte header, and a `type` the kernel
//!   knows.  Today that is exactly one type,
//!   [`FAN_RESPONSE_INFO_AUDIT_RULE`], with `len == 16` and exactly 16 bytes of
//!   record — the kernel rejects any other length with `EINVAL`.
//! * The `fd` must name a pending event, or the write is `ENOENT`.
//!
//! # `FAN_NOFD`: validate a record, answer nothing
//!
//! [`info`](FanotifyResponse::info) and
//! [`audit_rule`](FanotifyResponse::audit_rule) write `FAN_NOFD` in the `fd`
//! field unless [`with_fd`](FanotifyResponse::with_fd) attaches a descriptor.
//! On a kernel that knows the record type, such a write **succeeds and answers
//! no pending event**: the record is validated and then dropped.  That is what
//! makes the form a feature probe for a record type — it succeeds exactly where
//! the type is understood — and it is why a *decision* names the event it is
//! about: attach the descriptor with `with_fd`.
//!
//! # Records that do not exist yet
//!
//! The audit rule is the only record type the kernel defines today, so
//! [`audit_rule`](FanotifyResponse::audit_rule) is the convenient form and the
//! only one a FID-less group needs.  But the record vocabulary is extensible by
//! design, and a crate that could only emit today's type would need a release
//! for every new one.  [`info`](FanotifyResponse::info) therefore takes an
//! arbitrary `type` and payload, and [`raw`](FanotifyResponse::raw) an arbitrary
//! decision word: between them, a caller can send anything the kernel accepts,
//! including a type this crate has never heard of, and see the kernel's verdict
//! rather than this crate's.

use std::borrow::Cow;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use crate::consts::*;
use crate::error::FanotifyError;
use crate::sys::errno;

/// `sizeof(struct fanotify_response_info_header)`: `type`, `pad`, `len`.
const INFO_HEADER_SIZE: usize = 4;

/// The body of one response record: a type the kernel interprets and the bytes
/// that follow its 4-byte header.
#[derive(Debug)]
struct ResponseInfo<'a> {
    info_type: u8,
    payload: Cow<'a, [u8]>,
}

/// A decision about one pending permission event.
///
/// `fd` is the descriptor the kernel matches the answer against, so a response
/// that means to answer an event must carry the [`FdEvent::fd`](crate::FdEvent::fd)
/// of that event: [`raw`](Self::raw) takes it directly, and
/// [`with_fd`](Self::with_fd) attaches it to the record-carrying forms.  A form
/// without one writes [`FAN_NOFD`], which the kernel treats as "validate, do not
/// answer" — see the module docs.
#[derive(Debug)]
pub struct FanotifyResponse<'a> {
    fd: Option<BorrowedFd<'a>>,
    response: u32,
    info: Option<ResponseInfo<'a>>,
}

impl<'a> FanotifyResponse<'a> {
    /// Allow the operation the event asked about.
    ///
    /// The plain `FAN_ALLOW` word, matched against the event's descriptor.
    pub fn allow(fd: BorrowedFd<'a>) -> Self {
        Self::raw(Some(fd), FAN_ALLOW)
    }

    /// Refuse it.  The caller of the blocked operation sees `EPERM`.
    pub fn deny(fd: BorrowedFd<'a>) -> Self {
        Self::raw(Some(fd), FAN_DENY)
    }

    /// Refuse it, reporting `errno` to the blocked caller instead of `EPERM`.
    ///
    /// The kernel reads the errno out of the response's upper
    /// [`FAN_ERRNO_BITS`] bits, so a larger value is truncated to those bits
    /// rather than refused.  **Only a `FAN_CLASS_PRE_CONTENT` group gets this
    /// through**: for any other class the kernel ignores the errno and the
    /// caller still sees `EPERM`.  The errno values the kernel accepts are
    /// limited — see the module docs, and `fanotify(7)` for the list.
    ///
    /// ```
    /// use fanotify_fid::response::FanotifyResponse;
    /// # let file = std::fs::File::open("/dev/null").unwrap();
    /// let fd = std::os::fd::AsFd::as_fd(&file);
    /// let resp = FanotifyResponse::deny_errno(fd, libc::EACCES);
    /// assert_ne!(resp.response(), fanotify_fid::consts::FAN_DENY);
    /// ```
    pub fn deny_errno(fd: BorrowedFd<'a>, errno: i32) -> Self {
        Self::raw(Some(fd), deny_errno_word(errno))
    }

    /// The decision word, exactly as given, plus any record layout implied by
    /// `info`.
    ///
    /// This is the escape hatch in the other direction from
    /// [`info`](Self::info): it sends the `response` word unchanged, so every
    /// combination the kernel understands is reachable, including
    /// [`FAN_AUDIT`] alone, an errno packed into the upper bits, and a
    /// [`FAN_INFO`] bit whose record the caller has arranged separately — or not
    /// arranged, if the point is to read the kernel's `EINVAL`.  The `fd` field
    /// is written from `fd`, or as [`FAN_NOFD`] when there is none.
    ///
    /// Nothing is validated and nothing is added: a word this crate would not
    /// have produced is exactly what the caller asked for.
    ///
    /// ```
    /// use fanotify_fid::consts::{FAN_ALLOW, FAN_AUDIT, FAN_NOFD};
    /// use fanotify_fid::response::FanotifyResponse;
    /// use std::os::fd::AsRawFd;
    ///
    /// let file = std::fs::File::open("/dev/null")?;
    /// let fd = std::os::fd::AsFd::as_fd(&file);
    ///
    /// let resp = FanotifyResponse::raw(Some(fd), FAN_ALLOW | FAN_AUDIT);
    /// assert_eq!(resp.fd().map(|fd| fd.as_raw_fd()), Some(file.as_raw_fd()));
    /// assert_eq!(resp.response(), FAN_ALLOW | FAN_AUDIT);
    ///
    /// let no_fd = FanotifyResponse::raw(None, FAN_ALLOW);
    /// assert!(no_fd.fd().is_none());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn raw(fd: Option<BorrowedFd<'a>>, response: u32) -> Self {
        Self {
            fd,
            response,
            info: None,
        }
    }

    /// A decision with a response record of an arbitrary `type` and `payload`.
    ///
    /// [`FAN_INFO`] is set on the word — the kernel won't look for a record
    /// without it — and the record is written as the kernel reads it: a 4-byte
    /// header (`type`, `pad = 0`, `len`) followed by `payload`, where `len`
    /// counts the header.  `decision` is everything else about the word, so
    /// [`FAN_AUDIT`] is added here if the caller wants an audit record, exactly
    /// as [`raw`](Self::raw) would.
    ///
    /// The `fd` field is [`FAN_NOFD`] unless [`with_fd`](Self::with_fd) attaches
    /// a descriptor: the kernel validates the record and returns **without
    /// answering any event**, which makes this the form to probe whether a
    /// kernel understands a record type.  Attach the event's descriptor to turn
    /// the record into a decision about that event.
    ///
    /// The payload can be borrowed, which is what makes a repeated response cost
    /// no copy, or owned.  A payload that cannot fit `len`'s `u16` is refused
    /// with [`FanotifyError::Write`]`(EINVAL)` when the response is written:
    /// the wire format has no way to say how long it is.
    ///
    /// What the kernel does with the record is the kernel's business: today it
    /// accepts only [`FAN_RESPONSE_INFO_AUDIT_RULE`] and only a 16-byte record,
    /// and answers `EINVAL` for anything else — which is the point of this
    /// constructor.  See the module docs.
    ///
    /// ```
    /// use fanotify_fid::consts::{FAN_DENY, FAN_INFO, FAN_RESPONSE_INFO_NONE};
    /// use fanotify_fid::response::FanotifyResponse;
    ///
    /// let resp = FanotifyResponse::info(FAN_DENY, FAN_RESPONSE_INFO_NONE, b"future payload");
    /// assert_eq!(resp.response(), FAN_DENY | FAN_INFO);
    /// assert_eq!(resp.info_type(), Some(0));
    /// assert_eq!(resp.info_payload(), Some(&b"future payload"[..]));
    /// ```
    pub fn info(decision: u32, info_type: u8, payload: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            fd: None,
            response: decision | FAN_INFO,
            info: Some(ResponseInfo {
                info_type,
                payload: payload.into(),
            }),
        }
    }

    /// The form that carries the audit rule a decision was made under.
    ///
    /// [`FAN_INFO`] says a record follows and [`FAN_AUDIT`] asks the kernel to
    /// log the decision, so the group must have been created with
    /// [`FAN_ENABLE_AUDIT`] (`CAP_AUDIT_WRITE`, not `CAP_SYS_ADMIN`) or the
    /// write is `EINVAL`.  The record is the kernel's
    /// `fanotify_response_info_audit_rule`: the rule number plus the two trust
    /// levels, which this crate writes as the kernel defaults (`0`).
    ///
    /// This is [`info`](Self::info) with the one type the kernel defines today.
    /// Like it, the response carries [`FAN_NOFD`] until
    /// [`with_fd`](Self::with_fd) attaches a descriptor, so on its own it proves
    /// the kernel accepts the record rather than answering anything; attaching
    /// the event's descriptor is what makes the audited decision complete that
    /// event.
    ///
    /// ```
    /// use fanotify_fid::consts::{FAN_DENY, FAN_INFO, FAN_AUDIT};
    /// use fanotify_fid::response::FanotifyResponse;
    ///
    /// let resp = FanotifyResponse::audit_rule(FAN_DENY, 7);
    /// assert_eq!(resp.response(), FAN_DENY | FAN_INFO | FAN_AUDIT);
    /// assert_eq!(resp.info_type(), Some(1));
    /// // rule(4) + subj_trust(4) + obj_trust(4)
    /// assert_eq!(resp.info_payload().map(<[u8]>::len), Some(12));
    /// ```
    pub fn audit_rule(decision: u32, audit_rule: u32) -> Self {
        let mut payload = vec![0u8; 12];
        payload[..4].copy_from_slice(&audit_rule.to_ne_bytes());
        // subj_trust and obj_trust stay at the kernel's default, which is 0.
        Self::info(decision | FAN_AUDIT, FAN_RESPONSE_INFO_AUDIT_RULE, payload)
    }

    /// The decision word as it goes on the wire: [`FAN_ALLOW`] or [`FAN_DENY`],
    /// plus any errno packed into the upper bits, plus [`FAN_AUDIT`] /
    /// [`FAN_INFO`] when the form carries one.
    pub fn response(&self) -> u32 {
        self.response
    }

    /// Attach the descriptor the answer is matched against.
    ///
    /// Every response is matched to a pending event by descriptor, so this is
    /// what makes a record-carrying decision land on the event it is about.
    /// Without it, [`info`](Self::info) and [`audit_rule`](Self::audit_rule)
    /// write [`FAN_NOFD`], which the kernel validates and does not match — see
    /// the module docs for why that is useful and why it is not a decision.
    ///
    /// ```
    /// use fanotify_fid::consts::FAN_ALLOW;
    /// use fanotify_fid::response::FanotifyResponse;
    /// # let file = std::fs::File::open("/dev/null").unwrap();
    /// let fd = std::os::fd::AsFd::as_fd(&file);
    ///
    /// let resp = FanotifyResponse::audit_rule(FAN_ALLOW, 7).with_fd(fd);
    /// assert!(resp.fd().is_some());
    /// ```
    pub fn with_fd(mut self, fd: BorrowedFd<'a>) -> Self {
        self.fd = Some(fd);
        self
    }

    /// The descriptor the answer is matched against, if the form carries one.
    pub fn fd(&self) -> Option<BorrowedFd<'a>> {
        self.fd
    }

    /// The type of the response record, if this form writes one.
    pub fn info_type(&self) -> Option<u8> {
        self.info.as_ref().map(|info| info.info_type)
    }

    /// The record body *after* its 4-byte header, if this form writes one.
    pub fn info_payload(&self) -> Option<&[u8]> {
        self.info.as_ref().map(|info| info.payload.as_ref())
    }
}

/// `FAN_DENY` with `errno` packed where the kernel reads it.
fn deny_errno_word(errno: i32) -> u32 {
    FAN_DENY | (((errno as u32) & FAN_ERRNO_MASK) << FAN_ERRNO_SHIFT)
}

/// The exact bytes [`write_response`] puts on the wire.
///
/// Pure, so the layout is testable without a kernel: one 8-byte
/// `struct fanotify_response`, followed by the record when the form carries
/// one.  A payload whose record cannot be expressed in `len` is refused here,
/// before any syscall.
fn encode_response(response: &FanotifyResponse<'_>) -> Result<Vec<u8>, FanotifyError> {
    let fd_field = response.fd.map_or(FAN_NOFD, |fd| fd.as_raw_fd());
    let record_len = response
        .info
        .as_ref()
        .map_or(0, |info| INFO_HEADER_SIZE + info.payload.len());

    let mut body = Vec::with_capacity(8 + record_len);
    body.extend_from_slice(&fd_field.to_ne_bytes());
    body.extend_from_slice(&response.response.to_ne_bytes());

    if let Some(info) = &response.info {
        let len = u16::try_from(INFO_HEADER_SIZE + info.payload.len()).map_err(|_| {
            // The header's `len` is a `u16`; a longer record has no wire
            // representation, which is a caller error shaped exactly like
            // the kernel's refusal of a malformed record.
            FanotifyError::Write(libc::EINVAL)
        })?;
        body.push(info.info_type);
        body.push(0); // pad, must be zero
        body.extend_from_slice(&len.to_ne_bytes());
        body.extend_from_slice(&info.payload);
    }

    Ok(body)
}

/// Write a decision to the group.
///
/// Takes the decision from [`FanotifyResponse`] and writes exactly
/// [`encode_response`]'s bytes.  Whatever the word and record are, the kernel
/// validates them and its errno is what comes back — see the module docs for
/// the rules.
///
/// # Errors
///
/// [`FanotifyError::Write`] with the kernel's errno: `EINVAL` for a word or
/// record the kernel refuses, `ENOENT` if there is no pending permission event
/// to answer, `EBADF` if the group is not writable.  A *short* write — the
/// kernel consuming fewer bytes than the record — is `EINVAL` too, because a
/// partially consumed record is not a decision.
pub(crate) fn write_response(
    fanotify_fd: impl AsFd,
    response: &FanotifyResponse<'_>,
) -> Result<(), FanotifyError> {
    let body = encode_response(response)?;

    // SAFETY: `body` is an initialized byte buffer and the syscall reads only
    // `body.len()` bytes from it; `fanotify_fd` is borrowed for the call.
    let written = unsafe {
        libc::write(
            fanotify_fd.as_fd().as_raw_fd(),
            body.as_ptr().cast::<libc::c_void>(),
            body.len(),
        )
    };
    if written < 0 {
        return Err(FanotifyError::Write(errno()));
    }
    // The kernel returns the number of bytes it consumed.
    if (written as usize) < body.len() {
        return Err(FanotifyError::Write(libc::EINVAL));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devnull() -> std::fs::File {
        std::fs::File::open("/dev/null").unwrap()
    }

    #[test]
    fn allow_and_deny_are_the_plain_words() {
        let file = devnull();
        let fd = file.as_fd();
        assert_eq!(FanotifyResponse::allow(fd).response(), FAN_ALLOW);
        assert_eq!(FanotifyResponse::deny(fd).response(), FAN_DENY);
    }

    #[test]
    fn deny_errno_packs_the_errno_into_the_upper_byte() {
        let file = devnull();
        let resp = FanotifyResponse::deny_errno(file.as_fd(), libc::EACCES);

        assert_eq!(resp.response() & FAN_DENY, FAN_DENY, "still a deny");
        assert_eq!(
            resp.response() >> FAN_ERRNO_SHIFT,
            libc::EACCES as u32,
            "the errno is where the kernel reads it"
        );
    }

    #[test]
    fn an_errno_wider_than_the_field_is_truncated_not_refused() {
        let file = devnull();
        let resp = FanotifyResponse::deny_errno(file.as_fd(), 0x1_00);
        assert_eq!(resp.response() >> FAN_ERRNO_SHIFT, 0);
        assert_eq!(resp.response(), FAN_DENY);
    }

    #[test]
    fn the_descriptor_form_carries_the_descriptor_it_was_given() {
        let file = devnull();
        let raw = file.as_fd().as_raw_fd();

        let resp = FanotifyResponse::allow(file.as_fd());
        assert_eq!(resp.fd().unwrap().as_raw_fd(), raw);
        assert_eq!(resp.info_type(), None);
        assert_eq!(resp.info_payload(), None);
    }

    #[test]
    fn the_bare_form_is_exactly_8_bytes() {
        let file = devnull();
        let raw = file.as_fd().as_raw_fd();

        for (resp, fd_field) in [
            (FanotifyResponse::allow(file.as_fd()), raw),
            (FanotifyResponse::deny(file.as_fd()), raw),
            (FanotifyResponse::raw(None, FAN_ALLOW | FAN_AUDIT), FAN_NOFD),
        ] {
            let bytes = encode_response(&resp).unwrap();
            assert_eq!(bytes.len(), 8);
            assert_eq!(
                i32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
                fd_field
            );
            assert_eq!(
                u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
                resp.response()
            );
        }
    }

    #[test]
    fn the_audit_rule_form_is_the_exact_24_byte_record() {
        let resp = FanotifyResponse::audit_rule(FAN_DENY, 7);
        let bytes = encode_response(&resp).unwrap();

        assert_eq!(bytes.len(), 24, "8-byte response plus a 16-byte record");
        assert_eq!(
            i32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
            FAN_NOFD
        );
        assert_eq!(
            u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
            FAN_DENY | FAN_INFO | FAN_AUDIT,
        );
        // The record header: type, pad, len — where `len` includes the header.
        assert_eq!(bytes[8], FAN_RESPONSE_INFO_AUDIT_RULE);
        assert_eq!(bytes[9], 0, "pad must be zero");
        assert_eq!(u16::from_ne_bytes(bytes[10..12].try_into().unwrap()), 16);
        // And the payload: rule, subj_trust, obj_trust.
        assert_eq!(u32::from_ne_bytes(bytes[12..16].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(bytes[16..20].try_into().unwrap()), 0);
        assert_eq!(u32::from_ne_bytes(bytes[20..24].try_into().unwrap()), 0);
    }

    #[test]
    fn attaching_a_descriptor_turns_a_record_into_a_matched_response() {
        let file = devnull();
        let raw = file.as_fd().as_raw_fd();

        let resp = FanotifyResponse::audit_rule(FAN_DENY, 7).with_fd(file.as_fd());
        let bytes = encode_response(&resp).unwrap();

        assert_eq!(bytes.len(), 24);
        assert_eq!(
            i32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
            raw,
            "the record is now matched to this event",
        );
        assert_eq!(resp.info_type(), Some(FAN_RESPONSE_INFO_AUDIT_RULE));
    }

    #[test]
    fn an_arbitrary_record_type_and_payload_go_on_the_wire_unchanged() {
        let resp = FanotifyResponse::info(FAN_DENY | FAN_AUDIT, 200, b"future payload");
        let bytes = encode_response(&resp).unwrap();

        assert_eq!(bytes.len(), 8 + 4 + 14);
        assert_eq!(
            u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
            FAN_DENY | FAN_AUDIT | FAN_INFO,
            "the caller's word, plus the bit that makes the record readable",
        );
        assert_eq!(bytes[8], 200);
        assert_eq!(bytes[9], 0);
        assert_eq!(u16::from_ne_bytes(bytes[10..12].try_into().unwrap()), 18);
        assert_eq!(&bytes[12..], b"future payload");

        assert_eq!(resp.info_type(), Some(200));
        assert_eq!(resp.info_payload(), Some(&b"future payload"[..]));
    }

    #[test]
    fn a_record_too_long_for_its_length_field_is_refused_before_the_syscall() {
        // `len` is a u16 and counts the header, so 65532 payload bytes have no
        // wire representation and must be an error rather than a wrapped length.
        let resp = FanotifyResponse::info(FAN_DENY, 1, vec![0u8; 65532]);
        assert!(matches!(
            encode_response(&resp),
            Err(FanotifyError::Write(libc::EINVAL))
        ));

        // One byte less fits exactly.
        let resp = FanotifyResponse::info(FAN_DENY, 1, vec![0u8; 65531]);
        assert_eq!(encode_response(&resp).unwrap().len(), 8 + 4 + 65531);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "miri's pipe shim has no capacity limit, so the partial write cannot happen there"
    )]
    fn a_short_write_is_an_error_not_a_decision() {
        use std::os::fd::{AsFd, FromRawFd, OwnedFd};

        // A pipe holds less than the response and is partly full, so `write(2)`
        // transfers a prefix and returns its length.  The kernel consuming fewer
        // bytes than the record is not a decision, and must be reported.
        let mut fds = [0i32; 2];
        // SAFETY: `pipe2` writes the two descriptors into the array given.
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        assert_eq!(ret, 0, "pipe2 failed");
        // SAFETY: `pipe2` succeeded, so both numbers are descriptors this
        // process owns and no other value refers to.
        let (read_end, write_end) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

        // A 64 KiB pipe (the Linux default), most of it filled: the room left is
        // smaller than the record below, whatever the exact capacity is.
        let filler = vec![0u8; 4096];
        // SAFETY: the pipe descriptor is open for writing and `filler` is a
        // readable buffer of the length given.
        let filled = unsafe {
            libc::write(
                write_end.as_raw_fd(),
                filler.as_ptr().cast::<libc::c_void>(),
                filler.len(),
            )
        };
        assert_eq!(
            filled,
            filler.len() as isize,
            "the pipe must take the filler"
        );

        // 65543 bytes on the wire: larger than any default pipe leaves free.
        let resp = FanotifyResponse::info(FAN_DENY, 1, vec![0u8; 65531]);
        let err = write_response(write_end.as_fd(), &resp)
            .expect_err("a partially consumed record is not a response");
        assert!(
            matches!(err, FanotifyError::Write(libc::EINVAL)),
            "expected EINVAL, got {err:?}"
        );

        drop(read_end);
    }
}
