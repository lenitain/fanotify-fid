//! Low-level safe wrappers around fanotify syscalls.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::FanotifyError;

/// Thin safe wrapper around `fanotify_init` (raw syscall).
///
/// Returns an `OwnedFd` that will be automatically closed on drop.
///
/// Requires Linux **≥ 5.1** for FID mode flags (`FAN_REPORT_FID`,
/// `FAN_REPORT_DIR_FID`, `FAN_REPORT_NAME`).  Some flags like
/// `FAN_REPORT_TARGET_FID` require newer kernels (≥ 5.15).
///
/// Provided for convenience when you prefer free functions over the
/// [`Fanotify`](crate::Fanotify) struct.
pub fn fanotify_init(
    flags: u32,
    event_f_flags: u32,
) -> std::result::Result<OwnedFd, FanotifyError> {
    // SAFETY: `fanotify_init` is a pure kernel syscall with no memory-safety
    // requirements beyond passing correctly-typed integer flags.  The kernel
    // validates all flag combinations and returns EINVAL on error.
    let fd = unsafe { libc::fanotify_init(flags as libc::c_uint, event_f_flags as libc::c_uint) };
    if fd < 0 {
        return Err(FanotifyError::Init(
            io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    // SAFETY: `fd` was just returned by a successful `fanotify_init` call and
    // is therefore a valid, owned file descriptor.  `OwnedFd::from_raw_fd`
    // takes ownership; it will be closed on drop.
    Ok(unsafe { <OwnedFd as FromRawFd>::from_raw_fd(fd) })
}

/// Thin safe wrapper around `fanotify_mark` (raw syscall).
///
/// `path` can be a `&Path`, `&str`, or anything `AsRef<OsStr>`.
pub fn fanotify_mark<P: AsRef<OsStr> + ?Sized>(
    fanotify_fd: &OwnedFd,
    flags: u32,
    mask: u64,
    dirfd: i32,
    path: &P,
) -> std::result::Result<(), FanotifyError> {
    // `as_encoded_bytes()` is zero-cost on Linux (OsStr == [u8]).
    // `CString::new` handles null-termination in a single allocation
    // and rejects interior null bytes, which the kernel would also reject.
    let raw = CString::new(path.as_ref().as_encoded_bytes())
        .map_err(|_| FanotifyError::Mark(libc::EINVAL))?;

    // SAFETY: `fanotify_mark` is a pure kernel syscall.  `raw` is a
    // properly null-terminated CString and `fanotify_fd` is a valid
    // `OwnedFd`.  The kernel validates all arguments internally.
    let ret = unsafe {
        libc::fanotify_mark(
            fanotify_fd.as_raw_fd(),
            flags as libc::c_uint,
            mask,
            dirfd,
            raw.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(FanotifyError::Mark(
            io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    Ok(())
}

/// Open a path with `O_PATH` to obtain a mount fd for handle resolution.
///
/// The returned `OwnedFd` is opened with `O_PATH | O_CLOEXEC`, and can be
/// used with [`resolve_file_handle`](crate::handle::resolve_file_handle) and
/// [`read_fid_events`](crate::read::read_fid_events).
///
/// This is equivalent to `open(path, O_PATH | O_CLOEXEC)`.
///
/// # Errors
///
/// Returns `FanotifyError::Io` if the path cannot be opened (permissions,
/// does not exist, etc.).
pub fn open_mount<P: AsRef<OsStr> + ?Sized>(
    path: &P,
) -> std::result::Result<OwnedFd, FanotifyError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .read(true)
        .open(path.as_ref())
        .map_err(FanotifyError::Io)?;
    let fd = file.into();
    Ok(fd)
}
