//! Safe wrappers around `name_to_handle_at` and `open_by_handle_at`.
//!
//! These two syscalls are needed to convert the file handles received in
//! fanotify FID events back into filesystem paths.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use crate::types::{FH_HDR_SIZE, HandleKey};

/// Shared body of the `name_to_handle_at` wrappers.
///
/// `dfd`/`path`/`flags` are passed through unchanged, so `path` may be empty
/// when `flags` contains `AT_EMPTY_PATH` — that is how the descriptor-based
/// variant names its target.
///
/// Retries once on `EOVERFLOW`, which is the kernel asking for a bigger buffer.
fn name_to_handle_at_raw(
    dfd: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
) -> io::Result<HandleKey> {
    // First call to determine required size (common case: 128 is plenty).
    let mut buf = vec![0u8; 128];
    let mut mount_id: libc::c_int = 0;

    // Set handle_bytes to available payload space (total buf - 8 byte header).
    // struct file_handle { u32 handle_bytes; i32 handle_type; u8 f_handle[]; };
    let payload_bytes = (buf.len() - 8) as u32;
    buf[0..4].copy_from_slice(&payload_bytes.to_ne_bytes());

    // SAFETY: the caller guarantees `path` is a valid C string (or NULL under
    // AT_EMPTY_PATH) and `dfd` a usable dirfd; `buf` is large enough to hold the
    // handle header we advertise in its first 4 bytes.
    let ret = unsafe {
        libc::name_to_handle_at(
            dfd,
            path,
            buf.as_mut_ptr() as *mut libc::file_handle,
            &mut mount_id,
            flags,
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
            // SAFETY: same as above — same path/dfd, buffer sized per the kernel's request.
            let ret = unsafe {
                libc::name_to_handle_at(
                    dfd,
                    path,
                    buf.as_mut_ptr() as *mut libc::file_handle,
                    &mut mount_id,
                    flags,
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

/// Look up the file handle for an **open file descriptor**.
///
/// This is the descriptor-based counterpart of [`name_to_handle_at`]: it calls
/// `name_to_handle_at(fd, "", ..., AT_EMPTY_PATH)` and returns the same handle
/// bytes a fanotify FID event would carry for that object.
///
/// # Why prefer this over the path-based form
///
/// It never re-resolves a path, so it cannot be raced by a concurrent rename or
/// `rmdir`, and it needs no path walk.  A caller that already holds a directory
/// descriptor — a recursive marking walk, for instance — can populate a
/// handle→path cache in the same pass instead of walking the tree a second time
/// by path.
///
/// # Errors
///
/// Returns an `io::Error` if the descriptor is not a directory or file the
/// filesystem can encode a handle for, or if the kernel does not support the
/// syscall (requires Linux 2.6.39+).
///
/// # Example
///
/// ```rust,no_run
/// use fanotify_fid::handle::handle_from_fd;
///
/// let dir = std::fs::File::open("/tmp").unwrap();
/// let key = handle_from_fd(&dir).unwrap();
/// println!("{} handle bytes", key.len());
/// ```
pub fn handle_from_fd<F: AsFd>(fd: F) -> io::Result<HandleKey> {
    // Empty path is only valid in combination with AT_EMPTY_PATH; the kernel
    // then uses `dfd` itself as the target object.
    name_to_handle_at_raw(fd.as_fd().as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH)
}

/// Look up the file handle for a path.
///
/// Calls `name_to_handle_at(AT_FDCWD, path, ...)` and returns the raw file
/// handle bytes, which can be used as a [`HandleKey`] or passed to
/// [`open_by_handle_at`].
///
/// If you already have an open descriptor for the object, prefer
/// [`handle_from_fd`]: it avoids re-resolving the path, so it cannot be raced by
/// a concurrent rename.
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

    name_to_handle_at_raw(libc::AT_FDCWD, c_path.as_ptr(), 0)
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

    // SAFETY: `open_by_handle_at` is a pure kernel syscall.  `mount_fd` must
    // be a valid fd referencing a mount point on the same filesystem as the
    // handle.  The caller guarantees this by providing the mount fd from
    // `open_mount()` or similar.  The kernel validates internally.
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

    // SAFETY: `fd` was just returned by a successful `open_by_handle_at` call
    // and is therefore a valid, owned file descriptor.
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
/// Remove the trailing " (deleted)" marker that `/proc/self/fd` appends to
/// symlinks of unlinked objects.
pub fn strip_deleted_suffix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    match s.strip_suffix(" (deleted)") {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

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
                    // `/proc/self/fd` appends " (deleted)" for unlinked
                    // objects; consumers never want the suffix.
                    return Some(strip_deleted_suffix(p));
                }
            }
            Err(_) => continue,
        }
    }

    None
}
