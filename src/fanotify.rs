//! High-level RAII fanotify file descriptor wrapper.

use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::builder::FanotifyBuilder;
use crate::consts;
use crate::error::FanotifyError;
use crate::sys::fanotify_mark;

/// An RAII fanotify file descriptor with safe `mark` and `read_events`
/// methods.
///
/// The underlying `OwnedFd` is automatically closed on `Drop`.
///
/// `Fanotify` is `Send + Sync` (delegates to `OwnedFd` which is also
/// `Send + Sync`).  You may share it across threads safely.
///
/// Use [`FanotifyBuilder`] (via [`Fanotify::new`]) for ergonomic construction:
///
/// ```rust,no_run
/// use fanotify_fid::prelude::*;
///
/// let fan = Fanotify::new()
///     .report_fid()
///     .report_dir_fid()
///     .report_name()
///     .init()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct Fanotify {
    pub(crate) fd: OwnedFd,
}

impl Fanotify {
    /// Create a [`FanotifyBuilder`] with default settings
    /// (`FAN_CLASS_NOTIF | FAN_CLOEXEC`).
    ///
    /// Call `.init()` on the builder to create the fanotify group.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> FanotifyBuilder {
        FanotifyBuilder::default()
    }

    /// Add or remove a mark on the given path.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use fanotify_fid::prelude::*;
    ///
    /// let fan = Fanotify::new().report_fid().init().unwrap();
    /// fan.mark(FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
    ///          FAN_CREATE | FAN_DELETE, "/").unwrap();
    /// ```
    pub fn mark<P: AsRef<OsStr> + ?Sized>(
        &self,
        flags: u32,
        mask: u64,
        path: &P,
    ) -> std::result::Result<(), FanotifyError> {
        fanotify_mark(&self.fd, flags, mask, consts::AT_FDCWD, path)
    }

    /// Read and parse FID-format events from the fanotify file descriptor.
    ///
    /// Convenience wrapper around [`read_fid_events`](crate::read::read_fid_events) that takes `&self`.
    ///
    /// See [`read_fid_events`](crate::read::read_fid_events) for full documentation.
    pub fn read_events(
        &self,
        mount_fds: &[OwnedFd],
        buf: &mut Vec<u8>,
        cache: Option<&mut crate::types::HandleCache>,
    ) -> std::result::Result<Vec<crate::types::FidEvent>, FanotifyError> {
        crate::read::read_fid_events(&self.fd, mount_fds, buf, cache)
    }

    /// Read fd-based (non-FID) events with default settings.
    ///
    /// The fanotify fd must NOT have been initialized with `FAN_REPORT_FID`.
    /// For custom buffer size, use [`FdReader`](crate::read::FdReader) directly.
    pub fn read_fd_events(&self) -> crate::error::Result<Vec<crate::types::FdEvent>> {
        crate::read::FdReader::new().read(&self.fd)
    }

    /// Read fd-based events with a callback.
    ///
    /// Convenience wrapper around [`FdReader::read_do`](crate::read::FdReader::read_do).
    pub fn read_fd_events_do<F>(&self, callback: F) -> crate::error::Result<()>
    where
        F: FnMut(&crate::types::FdEvent),
    {
        crate::read::FdReader::new().read_do(&self.fd, callback)
    }

    /// Write a permission response.
    ///
    /// Convenience wrapper around [`write_response`](crate::read::write_response).
    pub fn send_response(
        &self,
        response: &crate::types::FanotifyResponse,
    ) -> crate::error::Result<()> {
        crate::read::write_response(&self.fd, response)
    }

    /// Add a mark on a mount point (monitor all files under it).
    pub fn mark_mount<P: AsRef<OsStr> + ?Sized>(
        &self,
        mask: u64,
        path: &P,
    ) -> crate::error::Result<()> {
        fanotify_mark(
            &self.fd,
            consts::FAN_MARK_ADD | consts::FAN_MARK_MOUNT,
            mask,
            consts::AT_FDCWD,
            path,
        )
    }

    /// Get a reference to the underlying `OwnedFd`.
    pub fn as_fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// Consume the wrapper and return the raw file descriptor.
    ///
    /// The fd will be closed when `OwnedFd` is dropped.
    pub fn into_inner(self) -> OwnedFd {
        self.fd
    }
}

impl AsFd for Fanotify {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
