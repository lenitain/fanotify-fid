//! Safe wrappers around `name_to_handle_at` and `open_by_handle_at`.
//!
//! These two syscalls are needed to convert the file handles received in
//! fanotify FID events back into filesystem paths.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use crate::types::{HandleKey, FH_HDR_SIZE};

/// Look up the file handle for a path.
///
/// Calls `name_to_handle_at(AT_FDCWD, path, ...)` and returns the raw file
/// handle bytes, which can be used as a [`HandleKey`] or passed to
/// [`open_by_handle_at`].
///
/// # Errors
///
/// Returns an `io::Error` if the path does not exist, the process lacks
/// permission, or the kernel does not support `name_to_handle_at` (requires
/// Linux 2.6.39+).
///
/// # Example
///
/// ```rust,no_run
/// use fanotify_fid::handle::name_to_handle_at;
/// use std::path::Path;
///
/// let key = name_to_handle_at(Path::new("/tmp")).unwrap();
/// ```
pub fn name_to_handle_at(path: &Path) -> io::Result<HandleKey> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null byte"))?;

    // First call to determine required size (common case: 128 is plenty).
    let mut buf = vec![0u8; 128];
    let mut mount_id: libc::c_int = 0;

    // Set handle_bytes to available payload space (total buf - 8 byte header).
    // struct file_handle { u32 handle_bytes; i32 handle_type; u8 f_handle[]; };
    let payload_bytes = (buf.len() - 8) as u32;
    buf[0..4].copy_from_slice(&payload_bytes.to_ne_bytes());

    // SAFETY: `name_to_handle_at` is a pure syscall; we pass a valid C string
    // and a buffer large enough to hold the handle.
    let ret = unsafe {
        libc::name_to_handle_at(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            buf.as_mut_ptr() as *mut libc::file_handle,
            &mut mount_id,
            0,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        // If buffer was too small, retry with the size the kernel wrote
        if err.raw_os_error() == Some(libc::EOVERFLOW) {
            let needed = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
            let mut buf = vec![0u8; needed + 64];
            let payload_bytes = (buf.len() - 8) as u32;
            buf[0..4].copy_from_slice(&payload_bytes.to_ne_bytes());
            let ret = unsafe {
                libc::name_to_handle_at(
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::file_handle,
                    &mut mount_id,
                    0,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            let handle_bytes = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
            buf.truncate(8 + handle_bytes);
            return Ok(buf);
        }
        return Err(err);
    }

    let handle_bytes = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    buf.truncate(8 + handle_bytes);
    Ok(buf)
}

/// Open a file by its kernel file handle.
///
/// Calls `open_by_handle_at(mount_fd, fh_data, O_PATH)` and returns an
/// [`OwnedFd`] for the opened file.
///
/// `mount_fd` must be an open file descriptor referencing a mount point on the
/// same filesystem that originally produced the handle.  `fh_data` is the raw
/// handle bytes from a fanotify FID info record or from [`name_to_handle_at`].
///
/// The returned fd is opened with `O_PATH`, so it can be used with
/// `readlink("/proc/self/fd/N")` to recover the path, but not for I/O.
///
/// # Errors
///
/// Returns an `io::Error` if the handle is invalid, the mount fd does not
/// belong to the right filesystem, or the file has been deleted.
pub fn open_by_handle_at(mount_fd: i32, fh_data: &[u8]) -> io::Result<OwnedFd> {
    if fh_data.len() < FH_HDR_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file_handle data too short",
        ));
    }

    // SAFETY: `open_by_handle_at` is a pure syscall; mount_fd must be a valid
    // fd referencing a mount point on the same filesystem as the handle.
    let fd = unsafe {
        libc::open_by_handle_at(
            mount_fd,
            fh_data.as_ptr() as *mut libc::file_handle,
            libc::O_PATH,
        )
    };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: we just successfully opened fd, and OwnedFd takes ownership.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Resolve a file handle to an absolute path by trying each mount fd.
///
/// Iterates through `mount_fds`, attempting [`open_by_handle_at`] on each
/// until one succeeds.  On success, reads the path via
/// `readlink("/proc/self/fd/{fd}")`.
///
/// Returns `None` if no mount fd can resolve the handle (e.g. the file was
/// deleted, or none of the mount fds belong to the right filesystem).
///
/// This is a best-effort function: on a busy system, the file may be deleted
/// between resolution and path read.
pub fn resolve_file_handle(mount_fds: &[OwnedFd], fh_data: &[u8]) -> Option<PathBuf> {
    if fh_data.len() < FH_HDR_SIZE {
        return None;
    }

    for mfd in mount_fds {
        match open_by_handle_at(mfd.as_raw_fd(), fh_data) {
            Ok(fd) => {
                let result = fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()));
                // fd is closed by OwnedFd::drop
                if let Ok(p) = result {
                    return Some(p);
                }
            }
            Err(_) => continue,
        }
    }

    None
}
