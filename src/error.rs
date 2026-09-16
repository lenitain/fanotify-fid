//! The one error type this crate returns, and what each errno means.

use std::borrow::Cow;
use std::fmt;

/// Everything that can go wrong, with the **kernel's own errno preserved**.
///
/// This crate does not translate one errno into another and does not decide
/// whether a request was legal — the kernel already did, and replacing its
/// answer with this crate's guess would send a caller looking in the wrong
/// place.  What is added is a description of what that particular errno means
/// *for that particular syscall*, since the same number means different things
/// to `fanotify_init`, `fanotify_mark`, a read of the event queue, and a write
/// of a response.
///
/// The `handle::*` functions are deliberately absent: they call
/// `name_to_handle_at` / `open_by_handle_at` / `statfs` on no fanotify object,
/// and return the `io::Error` those syscalls produce, described on each
/// function.  A variant for them would be one this crate could never produce.
///
/// The variant tells you which operation failed; the payload is the raw
/// `errno`, so `matches!(e, FanotifyError::Init(libc::EPERM))` works and so does
/// matching on `e.errno()`.
///
/// Marked `#[non_exhaustive]` because the set of operations grows with the
/// kernel surface: a new syscall, or a new way to read the event stream, is an
/// addition, and a caller matching exhaustively today should not be broken by
/// one.  A caller that only cares about the errno has [`errno`](Self::errno).
#[non_exhaustive]
#[derive(Debug)]
pub enum FanotifyError {
    /// `fanotify_init` failed.
    Init(i32),
    /// `fanotify_mark` failed.
    Mark(i32),
    /// A `read` on the fanotify descriptor failed.
    Read(i32),
    /// A write of a permission response failed.
    Write(i32),
    /// The bytes read are not fanotify events: `vers` was not
    /// [`FANOTIFY_METADATA_VERSION`](crate::consts::FANOTIFY_METADATA_VERSION).
    ///
    /// Every field after `vers` is read according to that version, so a
    /// different value means this crate would be guessing at the layout.  The
    /// realistic causes are a descriptor that is not a fanotify group, or a
    /// kernel that changed the format.
    UnknownEventVersion(u8),
}

impl FanotifyError {
    /// The raw `errno` this error carries, or `None` for a variant that is not
    /// a syscall failure.
    pub fn errno(&self) -> Option<i32> {
        match *self {
            Self::Init(e) | Self::Mark(e) | Self::Read(e) | Self::Write(e) => Some(e),
            Self::UnknownEventVersion(_) => None,
        }
    }
}

impl fmt::Display for FanotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(code) => write!(
                f,
                "fanotify_init failed (errno={code}): {}",
                describe_init(*code)
            ),
            Self::Mark(code) => write!(
                f,
                "fanotify_mark failed (errno={code}): {}",
                describe_mark(*code)
            ),
            Self::Read(code) => write!(
                f,
                "fanotify read failed (errno={code}): {}",
                describe_read(*code)
            ),
            Self::Write(code) => write!(
                f,
                "fanotify response write failed (errno={code}): {}",
                describe_write(*code)
            ),
            Self::UnknownEventVersion(vers) => write!(
                f,
                "buffer is not a fanotify event: metadata.vers = {vers}, expected {}.  \
                 This usually means the descriptor is not a fanotify group",
                crate::consts::FANOTIFY_METADATA_VERSION
            ),
        }
    }
}

impl std::error::Error for FanotifyError {}

/// `Result` with this crate's error type.
pub type Result<T> = std::result::Result<T, FanotifyError>;

// ── Descriptions, one per syscall ──
//
// The same errno means different things to different syscalls: EINVAL from
// `fanotify_init` is a flag combination, from `fanotify_mark` it is a mark mask,
// and from a response write it is a record that does not match the group's
// flags.  Keeping one function per syscall is what stops a caller from being
// told the wrong thing.

fn describe_init(code: i32) -> Cow<'static, str> {
    match code {
        libc::EINVAL => Cow::Borrowed(
            "The kernel rejected this flag combination.  Its rules: FAN_REPORT_PIDFD excludes \
             FAN_REPORT_TID; FAN_REPORT_MNT excludes every FID flag, FAN_REPORT_FD_ERROR, and \
             any class other than FAN_CLASS_NOTIF; any FID flag excludes FAN_CLASS_CONTENT and \
             FAN_CLASS_PRE_CONTENT; FAN_REPORT_NAME requires FAN_REPORT_DIR_FID; \
             FAN_REPORT_TARGET_FID requires both FAN_REPORT_NAME and FAN_REPORT_FID",
        ),
        libc::EPERM => Cow::Borrowed(
            "Need CAP_SYS_ADMIN for the flags requested.  Without it, a group must be \
             FAN_CLASS_NOTIF and must set a FID flag or FAN_REPORT_MNT — a bare \
             FAN_CLASS_NOTIF group with no report flag is refused too, so pass \
             FAN_REPORT_FID (or FAN_REPORT_DIR_FID) if that was the intent",
        ),
        libc::EMFILE => Cow::Borrowed("Too many fanotify groups (per-user limit is 128)"),
        libc::ENOMEM => Cow::Borrowed("Out of memory"),
        libc::ENOSYS => Cow::Borrowed("This kernel has no fanotify (CONFIG_FANOTIFY is off)"),
        _ => Cow::Owned(format!(
            "Unknown errno {code}.  See fanotify_init(2) for the full list."
        )),
    }
}

fn describe_mark(code: i32) -> Cow<'static, str> {
    match code {
        libc::EINVAL => Cow::Borrowed(
            "The mark mask or anchor flags do not fit this group.  The kernel checks here (not \
             at fanotify_init): a FAN_REPORT_MNT group takes only FAN_MARK_MNTNS with a mask \
             drawn from FAN_MNT_ATTACH/FAN_MNT_DETACH, every other group rejects both of those, \
             an inode mark needs a path, and FAN_RENAME needs a group with FAN_REPORT_NAME",
        ),
        libc::EPERM => Cow::Borrowed(
            "Need CAP_SYS_ADMIN.  An unprivileged group may place FAN_MARK_INODE marks only — \
             and that limit is about the anchor, not the file: marking a root-owned file \
             succeeds",
        ),
        libc::ENOENT => Cow::Borrowed("The path does not exist"),
        libc::EBADF => Cow::Borrowed("The fanotify descriptor, or the dirfd, is not open"),
        libc::ENOTDIR => Cow::Borrowed("FAN_MARK_ONLYDIR was set but the path is not a directory"),
        libc::EOPNOTSUPP => Cow::Borrowed(
            "The filesystem cannot decode the file handles its events would carry, so only \
             FAN_MARK_INODE is allowed on it.  Filesystems that hand out synthetic \
             FILEID_INO64_GEN handles (procfs, sysfs, debugfs, ...) always answer this way",
        ),
        libc::ENOSPC => {
            Cow::Borrowed("Mark limit reached (8192 per group; FAN_UNLIMITED_MARKS lifts it)")
        }
        libc::ENODEV => Cow::Borrowed("The filesystem does not support fsid"),
        libc::EXDEV => Cow::Borrowed("The path crosses into a filesystem with a different fsid"),
        libc::ENOMEM => Cow::Borrowed("Out of memory"),
        libc::ENOSYS => Cow::Borrowed("This kernel does not implement fanotify_mark"),
        _ => Cow::Owned(format!(
            "Unknown errno {code}.  See fanotify_mark(2) for the full list."
        )),
    }
}

fn describe_read(code: i32) -> Cow<'static, str> {
    match code {
        libc::EAGAIN => Cow::Borrowed("No events are queued (non-blocking group)"),
        libc::EINTR => Cow::Borrowed("Interrupted by a signal before any event arrived; retry"),
        libc::EINVAL => Cow::Borrowed(
            "The buffer is too small for the next event.  fanotify never delivers a partial \
             event, so the buffer must hold the largest one — a long entry name is what makes \
             an event big",
        ),
        libc::EBADF => Cow::Borrowed("The fanotify descriptor is not open for reading"),
        libc::ENOMEM => Cow::Borrowed("Out of memory"),
        _ => Cow::Owned(format!(
            "Unknown errno {code}.  See fanotify_read(2) for the full list."
        )),
    }
}

fn describe_write(code: i32) -> Cow<'static, str> {
    match code {
        libc::EINVAL => Cow::Borrowed(
            "The kernel refused the response: the group lacks FAN_ENABLE_AUDIT, the errno in a \
             deny is not one it accepts, or the record layout does not match the flags",
        ),
        libc::ENOENT => Cow::Borrowed(
            "There is no pending permission event to answer, or the descriptor named is not a \
             descriptor the event carried",
        ),
        libc::EBADF => Cow::Borrowed("The fanotify descriptor is not open for writing"),
        _ => Cow::Owned(format!(
            "Unknown errno {code}.  See fanotify_write(2) for the full list."
        )),
    }
}
