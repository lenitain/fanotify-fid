//! Thin, safe wrappers over the syscalls this crate issues itself.
//!
//! Each function is a syscall and nothing else: the arguments are passed
//! through unchanged, the return value becomes an [`OwnedFd`] or a
//! [`FanotifyError`] carrying the kernel's errno, and no combination of
//! arguments is judged here.  A caller who passes something the kernel refuses
//! gets the kernel's own answer — including the distinction between `EPERM`
//! ("legal, but you lack the capability") and `EINVAL` ("not a legal
//! combination").
//!
//! All descriptors are `std` I/O-safety types, in both directions: `AsFd` in,
//! [`OwnedFd`] out.  There is no `RawFd` in this crate's API, so no `Drop` impl
//! and no `close` call is written by hand.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::error::FanotifyError;

/// `fanotify_init(2)`: create a notification group.
///
/// Returns the group's descriptor, which is closed when the returned value
/// drops.  `flags` is a combination of the `FAN_*` init flags — see
/// [`crate::consts`] — and `event_f_flags` is used only by groups that receive
/// event descriptors, where it is the `open(2)` flag set they are opened with.
///
/// # What the kernel decides here
///
/// Flag legality is checked at this call and nowhere else, and the answer is an
/// errno: `EINVAL` for a combination it refuses, `EPERM` when the capability is
/// missing.  **The privilege check runs first**, so a request that is both
/// admin-only and illegal answers `EPERM` to an unprivileged caller and only
/// `EINVAL` to root.  One errno therefore cannot settle legality on its own.
///
/// # Errors
///
/// [`FanotifyError::Init`] with the kernel's errno: `EINVAL`, `EPERM`, `EMFILE`
/// (128 groups per user), `ENOMEM`, or `ENOSYS`.
pub fn fanotify_init(flags: u32, event_f_flags: u32) -> Result<OwnedFd, FanotifyError> {
    // SAFETY: `fanotify_init` takes two integers and returns a descriptor.  It
    // reads no memory from this process, so there is no invariant to uphold
    // beyond the argument types, which the casts make explicit.
    let fd = unsafe { libc::fanotify_init(flags, event_f_flags) };
    if fd < 0 {
        return Err(FanotifyError::Init(errno()));
    }
    // SAFETY: a non-negative return from `fanotify_init` is a descriptor this
    // process owns and no other value refers to, which is exactly the contract
    // `OwnedFd::from_raw_fd` requires.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `fanotify_mark(2)` with a directory descriptor as the anchor.
///
/// `flags` selects the anchor and the action — one of `FAN_MARK_ADD`,
/// `FAN_MARK_REMOVE`, `FAN_MARK_FLUSH` — plus any of `FAN_MARK_MOUNT`,
/// `FAN_MARK_FILESYSTEM`, `FAN_MARK_MNTNS`, `FAN_MARK_DONT_FOLLOW`,
/// `FAN_MARK_ONLYDIR`, `FAN_MARK_EVICTABLE`, `FAN_MARK_IGNORE*`.  `mask` is the
/// set of event bits to act on, or `0` for `FAN_MARK_FLUSH`.
///
/// `dir_fd` anchors the path, which is how a caller that already holds a
/// directory descriptor avoids re-resolving a path it has already resolved.
/// Pass [`AT_FDCWD`](crate::consts::AT_FDCWD) for the working directory.
///
/// # What the kernel decides here
///
/// The rules that depend on the *group* are enforced at this call, not at
/// `fanotify_init`: which anchors the group may use, whether the mask is one its
/// class can carry, and whether the filesystem can decode the handles its events
/// would carry (`EOPNOTSUPP`).
///
/// # Errors
///
/// [`FanotifyError::Mark`] with the kernel's errno: `EINVAL` (mask or anchor
/// does not fit the group), `EPERM` (needs `CAP_SYS_ADMIN`), `ENOENT`,
/// `ENOTDIR`, `EOPNOTSUPP`, `ENOSPC`, `ENODEV`, `EXDEV`.
pub fn fanotify_mark<Fd: AsFd, P: AsRef<OsStr> + ?Sized>(
    fanotify_fd: Fd,
    flags: u32,
    mask: u64,
    dir_fd: i32,
    path: &P,
) -> Result<(), FanotifyError> {
    // A path with an interior NUL cannot be a path, so this is a caller error
    // rather than something to ask the kernel about.
    let c_path = CString::new(path.as_ref().as_encoded_bytes())
        .map_err(|_| FanotifyError::Mark(libc::EINVAL))?;

    // SAFETY: `fanotify_mark` reads one NUL-terminated string, which `c_path`
    // owns for the duration of the call, and takes the two descriptor numbers
    // as integers.  `fanotify_fd` is borrowed for the call by `AsFd`, so the
    // descriptor cannot be closed while the kernel uses it.
    let ret = unsafe {
        libc::fanotify_mark(
            fanotify_fd.as_fd().as_raw_fd(),
            flags,
            mask,
            dir_fd,
            c_path.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(FanotifyError::Mark(errno()));
    }
    Ok(())
}

/// `fanotify_mark(2)` where the object is named by a **descriptor**.
///
/// The kernel's descriptor form is a `NULL` pathname with the object's
/// descriptor as `dirfd`: `fanotify_find_path` takes the path straight from the
/// descriptor, so no path is resolved and no rename can change what is marked.
///
/// # The descriptor must not be `O_PATH`
///
/// The kernel resolves it with `fdget()`, which excludes `O_PATH` files, and
/// answers `EBADF` for one — even though `O_PATH` is the usual way to name an
/// object without opening it, and even though `AT_EMPTY_PATH` (which the kernel
/// does **not** accept here) would suggest otherwise.  Pass a descriptor opened
/// for reading, which is what the kernel's own read-permission check on the
/// object requires anyway.
///
/// `flags` and `mask` are passed through exactly as in [`fanotify_mark`], with
/// one difference that is a property of the form rather than of this function:
/// there is no path for [`FAN_MARK_DONT_FOLLOW`](crate::consts::FAN_MARK_DONT_FOLLOW)
/// to apply to.  [`FAN_MARK_ONLYDIR`](crate::consts::FAN_MARK_ONLYDIR) still
/// means what it says, because the kernel checks the descriptor's mode.
///
/// # Errors
///
/// [`FanotifyError::Mark`] with the kernel's errno: `EBADF` for a closed or
/// `O_PATH` descriptor, `ENOTDIR` under `FAN_MARK_ONLYDIR`, and everything
/// [`fanotify_mark`] lists.
pub(crate) fn fanotify_mark_by_fd(
    fanotify_fd: &OwnedFd,
    flags: u32,
    mask: u64,
    object_fd: BorrowedFd<'_>,
) -> Result<(), FanotifyError> {
    // SAFETY: `fanotify_mark` reads one NUL-terminated path string or, when the
    // pointer is NULL, none at all and uses `dir_fd` as the object.  Here the
    // path is NULL and `dir_fd` is the borrowed descriptor, so the kernel reads
    // no memory from this process.  Both descriptors are borrowed for the call,
    // so neither can be closed while the kernel uses it.
    let ret = unsafe {
        libc::fanotify_mark(
            fanotify_fd.as_raw_fd(),
            flags,
            mask,
            object_fd.as_raw_fd(),
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(FanotifyError::Mark(errno()));
    }
    Ok(())
}

/// `read(2)` on a fanotify group, into a buffer the caller keeps between calls.
///
/// The buffer's **capacity is the read size**: one with no capacity is grown to
/// a default (64 KiB), while one the caller sized is used as it is, so
/// `Vec::with_capacity` is the knob.  On success the buffer's length is what the
/// kernel wrote; on failure it is emptied.
///
/// # Errors
///
/// [`FanotifyError::Read`] with the kernel's errno: `EAGAIN` for an empty queue
/// on a non-blocking group (not a failure), `EINVAL` when the buffer is smaller
/// than the next event — the kernel refuses a partial event rather than
/// splitting one — `EBADF`, `ENOSYS`.
pub(crate) fn read_events(fanotify_fd: &OwnedFd, buf: &mut Vec<u8>) -> Result<(), FanotifyError> {
    /// More than one event fits, whatever the format, so a deep queue costs few
    /// syscalls.  A `read` never returns a partial event regardless, so this is
    /// a throughput floor and not a correctness one.
    const DEFAULT_BUF_BYTES: usize = 64 * 1024;

    // A buffer with no capacity is one the caller did not size; one with
    // capacity is the size they chose, small or large.
    if buf.capacity() == 0 {
        buf.reserve(DEFAULT_BUF_BYTES);
    }

    // SAFETY: `read` writes at most `capacity` bytes into the allocation — which
    // is at least one byte, so no zero-byte read is issued — and the length is
    // advanced only by the value it returns, so no uninitialized byte is ever
    // exposed to safe code.
    let n = unsafe {
        libc::read(
            fanotify_fd.as_raw_fd(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.capacity(),
        )
    };
    if n < 0 {
        buf.clear();
        return Err(FanotifyError::Read(errno()));
    }
    // SAFETY: the successful `read` initialized exactly `n` bytes.
    unsafe { buf.set_len(n as usize) };
    Ok(())
}

/// The current `errno` as an `i32`.
///
/// Every caller has just seen a syscall return a failure, which is when
/// `errno` is meaningful; a `0` here would mean the same thing it does to the
/// kernel (success, i.e. no error), and is kept rather than invented.
pub(crate) fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
