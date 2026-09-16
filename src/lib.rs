//! # fanotify-fid
//!
//! Linux fanotify **FID (File Identifier) mode** event parser and file handle utilities.
//!
//! This crate fills the gap left by [`fanotify-rs`](https://crates.io/crates/fanotify-rs),
//! which only supports non-FID (fd-based) event reading.  If you pass
//! `FAN_REPORT_FID` / `FAN_REPORT_DIR_FID` / `FAN_REPORT_NAME` to
//! `fanotify_init`, you **must** use this crate (or equivalent code) to
//! correctly parse the variable-length events.
//!
//! **Linux only.** Compilation on non-Linux platforms will fail with a
//! clear error message.
//!
//! ## Requirements
//!
//! - Linux kernel **≥ 5.1** (FID mode), **≥ 5.15** (`FAN_REPORT_TARGET_FID`)
//! - Minimum Rust version: **1.85** (edition 2024)
//!
//! ## Privileges
//!
//! Creating a `FAN_CLASS_NOTIF` group in FID mode needs **no** privilege: an
//! unprivileged process can call `fanotify_init` with
//! `FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME` and receive FID
//! events.  `CAP_SYS_ADMIN` is required for the things around it:
//!
//! | Needs `CAP_SYS_ADMIN` | Why |
//! |---|---|
//! | [`FAN_MARK_MOUNT`], [`FAN_MARK_FILESYSTEM`] | unprivileged groups may only place inode marks |
//! | [`FAN_UNLIMITED_MARKS`], [`FAN_UNLIMITED_QUEUE`] | admin-only init flags |
//! | [`FAN_REPORT_PIDFD`], `FAN_REPORT_TID` | admin-only init flags |
//! | permission-event classes (`FAN_CLASS_CONTENT`, `FAN_CLASS_PRE_CONTENT`) | admin-only classes |
//!
//! An unprivileged group still receives events, but the kernel blanks
//! `metadata.pid` for events caused by *other* processes, so process
//! attribution degrades to `0`.
//!
//! [`FAN_MARK_MOUNT`]: crate::consts::FAN_MARK_MOUNT
//! [`FAN_MARK_FILESYSTEM`]: crate::consts::FAN_MARK_FILESYSTEM
//! [`FAN_UNLIMITED_MARKS`]: crate::consts::FAN_UNLIMITED_MARKS
//! [`FAN_UNLIMITED_QUEUE`]: crate::consts::FAN_UNLIMITED_QUEUE
//! [`FAN_REPORT_PIDFD`]: crate::consts::FAN_REPORT_PIDFD
//!
//! ## Error handling
//!
//! All operations return [`Result<T, FanotifyError>`].  Each error variant
//! includes the raw errno and a **man-page-level description** explaining
//! the cause, common pitfalls, and how to fix it.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use fanotify_fid::prelude::*;
//! use std::os::fd::OwnedFd;
//!
//! # fn open_mount(_: &str) -> OwnedFd { panic!() }
//!
//! // 1. Create fanotify group in FID mode
//! let fan = Fanotify::new()
//!     .nonblock()
//!     .report_fid()
//!     .report_dir_fid()
//!     .report_name()
//!     .init()
//!     .unwrap();
//!
//! // 2. Add marks (whole filesystem)
//! fan.mark(FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
//!          FAN_CREATE | FAN_DELETE | FAN_MODIFY,
//!          "/").unwrap();
//!
//! // 3. Open mount fds for handle resolution
//! let mount_fds = vec![open_mount("/")];
//!
//! // 4. Read events
//! let mut buf = Vec::with_capacity(65536);
//! let events = fan.read_events(&mount_fds, &mut buf, None).unwrap();
//!
//! for ev in &events {
//!     let names: Vec<&str> = ev.event_names().collect();
//!     println!("{:?} {:?}", names, ev.path());
//! }
//! ```
//!
//! # Linux only
//!
//! fanotify-fid is a Linux-only crate.  Compilation on non-Linux platforms
//! will fail with a clear error message.

#[cfg(not(target_os = "linux"))]
compile_error!("fanotify-fid only supports Linux");

mod builder;
mod error;
mod fanotify;
mod sys;

pub mod consts;
pub mod handle;
pub mod parse;
pub mod read;
pub mod types;

pub use builder::FanotifyBuilder;
pub use error::{FanotifyError, Result};
pub use fanotify::Fanotify;
pub use read::FdReader;
pub use sys::{fanotify_init, fanotify_mark, open_mount};

/// Convenience re-exports for the most common types and constants.
pub mod prelude {
    pub use crate::consts::*;
    pub use crate::handle::{
        handle_from_fd, name_to_handle_at, open_by_handle_at, resolve_file_handle,
    };
    pub use crate::parse::parse_fid_events;
    pub use crate::read::{FdReader, read_fid_events, write_response};
    pub use crate::types::{
        FanotifyResponse, FdEvent, FidEvent, HandleCache, HandleKey, PathStore, RenameSide,
    };
    pub use crate::{
        Fanotify, FanotifyBuilder, FanotifyError, fanotify_init, fanotify_mark, open_mount,
    };
}
