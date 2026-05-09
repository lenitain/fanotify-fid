//! # fanotify-fid
//!
//! Linux fanotify **FID (File Identifier) mode** event parser and file handle utilities.
//!
//! This crate fills the gap left by [`fanotify-rs`](https://crates.io/crates/fanotify-rs),
//! which only supports non-FID (legacy) event reading.  If you pass
//! `FAN_REPORT_FID` / `FAN_REPORT_DIR_FID` / `FAN_REPORT_NAME` to
//! `fanotify_init`, you **must** use this crate (or equivalent code) to
//! correctly parse the variable-length events.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use fanotify_fid::prelude::*;
//!
//! // 1. Create fanotify fd (using fanotify-rs or raw syscall)
//! let fan_fd = fanotify_fid::fanotify_init(
//!     FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK |
//!     FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
//!     0,
//! ).unwrap();
//!
//! // 2. Open mount fd for handle resolution
//! let mount_fd = open_mount_fd("/").unwrap();
//!
//! // 3. Read events
//! let mut buf = Vec::with_capacity(65536);
//! let events = fanotify_fid::read_fid_events(
//!     fan_fd,
//!     &[mount_fd],
//!     &mut buf,
//!     None, // no persistent cache
//! ).unwrap();
//!
//! for ev in &events {
//!     println!("{:?} {:?}", ev.event_names(), ev.path);
//! }
//! ```
//!
//! ## Relationship with `fanotify-rs`
//!
//! This crate is **complementary**, not a replacement.  Use `fanotify-rs` for:
//! - Safe `fanotify_init` / `fanotify_mark` wrappers
//! - Constants if you prefer their re-exports
//!
//! Use `fanotify-fid` for:
//! - FID-mode event reading and parsing (what `fanotify-rs` doesn't support)
//! - `name_to_handle_at` / `open_by_handle_at` safe wrappers
//! - File handle → path resolution

pub mod consts;
pub mod handle;
pub mod parse;
pub mod read;
pub mod types;

/// Convenience re-exports for the most common types and constants.
pub mod prelude {
    pub use crate::consts::*;
    pub use crate::handle::{name_to_handle_at, open_by_handle_at, resolve_file_handle};
    pub use crate::parse::parse_fid_events;
    pub use crate::read::read_fid_events;
    pub use crate::types::{FidEvent, HandleKey, FanMetadata, FanInfoHeader};
}

/// Thin safe wrapper around `fanotify_init` (raw syscall).
///
/// Provided for convenience so you don't need to depend on `fanotify-rs` just
/// for init.  Returns the raw file descriptor on success.
pub fn fanotify_init(flags: u32, event_f_flags: u32) -> std::io::Result<i32> {
    // SAFETY: trivially safe — just passes flags to the kernel.
    let fd = unsafe { libc::fanotify_init(flags as libc::c_uint, event_f_flags as libc::c_uint) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// Thin safe wrapper around `fanotify_mark` (raw syscall).
///
/// `path` can be a `&Path`, `&str`, or anything `AsRef<OsStr>`.
pub fn fanotify_mark<P: AsRef<std::ffi::OsStr>>(
    fanotify_fd: i32,
    flags: u32,
    mask: u64,
    dirfd: i32,
    path: &P,
) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let mut raw = path.as_ref().as_bytes().to_vec();
    raw.push(0); // null-terminate

    // SAFETY: trivially safe — passes validated args to the kernel.
    let ret = unsafe {
        libc::fanotify_mark(
            fanotify_fd,
            flags as libc::c_uint,
            mask,
            dirfd,
            raw.as_ptr() as *const libc::c_char,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
