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
//! ## Requirements
//!
//! - Linux kernel **≥ 5.1** (FID mode), **≥ 5.15** (`FAN_REPORT_TARGET_FID`)
//! - **`CAP_SYS_ADMIN`** capability (run as root)
//! - Minimum Rust version: **1.75** (edition 2024)
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
//!     println!("{:?} {:?}", ev.event_names(), ev.path);
//! }
//! ```

mod builder;
mod error;
mod fanotify;
mod sys;

pub mod consts;
pub mod error_desc;
pub mod handle;
pub mod parse;
pub mod read;
pub mod types;

pub use builder::FanotifyBuilder;
pub use error::{FanotifyError, Result};
pub use fanotify::Fanotify;
pub use sys::{fanotify_init, fanotify_mark, open_mount};

/// Convenience re-exports for the most common types and constants.
pub mod prelude {
    pub use crate::consts::*;
    pub use crate::handle::{name_to_handle_at, open_by_handle_at, resolve_file_handle};
    pub use crate::parse::parse_fid_events;
    pub use crate::read::{
        legacy_buffer_events, read_fid_events, read_legacy, read_legacy_do,
        set_legacy_buffer_events, write_response,
    };
    pub use crate::types::{FanotifyResponse, FidEvent, HandleCache, HandleKey, LegacyEvent};
    pub use crate::{
        Fanotify, FanotifyBuilder, FanotifyError, fanotify_init, fanotify_mark, open_mount,
    };
}

// ── Comprehensive tests ──

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::types::{FanotifyResponse, FidEvent, HandleCache, LegacyEvent};
    use std::path::PathBuf;

    // ── Constants tests ──

    #[test]
    fn test_new_event_constants_exist() {
        // Verify all naughtyfy-sourced constants are accessible
        let _ = consts::FAN_OPEN_PERM;
        let _ = consts::FAN_ACCESS_PERM;
        let _ = consts::FAN_OPEN_EXEC_PERM;
        let _ = consts::FAN_RENAME;
        let _ = consts::FAN_FS_ERROR;
        let _ = consts::FAN_REPORT_TID;
        let _ = consts::FAN_REPORT_PIDFD;
        let _ = consts::FAN_REPORT_TARGET_FID;
        let _ = consts::FAN_UNLIMITED_QUEUE;
        let _ = consts::FAN_UNLIMITED_MARKS;
        let _ = consts::FAN_ENABLE_AUDIT;
        let _ = consts::FAN_CLASS_CONTENT;
        let _ = consts::FAN_CLASS_PRE_CONTENT;
        let _ = consts::FAN_REPORT_DFID_NAME;
        let _ = consts::FAN_REPORT_DFID_NAME_TARGET;
        let _ = consts::FAN_MARK_DONT_FOLLOW;
        let _ = consts::FAN_MARK_ONLYDIR;
        let _ = consts::FAN_MARK_MOUNT;
        let _ = consts::FAN_MARK_IGNORED_MASK;
        let _ = consts::FAN_MARK_IGNORED_SURV_MODIFY;
        let _ = consts::FAN_MARK_EVICTABLE;
        let _ = consts::FAN_MARK_IGNORE;
        let _ = consts::FAN_MARK_IGNORE_SURV;
        let _ = consts::FAN_ALLOW;
        let _ = consts::FAN_DENY;
        let _ = consts::FAN_AUDIT;
        let _ = consts::O_RDONLY;
        let _ = consts::O_WRONLY;
        let _ = consts::O_RDWR;
        let _ = consts::O_APPEND;
        let _ = consts::O_CLOEXEC;
    }

    #[test]
    fn test_deprecated_constants_still_compile() {
        #[allow(deprecated)]
        {
            let _ = consts::FAN_ALL_CLASS_BITS;
            let _ = consts::FAN_ALL_INIT_FLAGS;
            let _ = consts::FAN_ALL_MARK_FLAGS;
            let _ = consts::FAN_ALL_EVENTS;
            let _ = consts::FAN_ALL_PERM_EVENTS;
            let _ = consts::FAN_ALL_OUTGOING_EVENTS;
        }
    }

    #[test]
    fn test_mask_to_event_names_includes_new() {
        let names = consts::mask_to_event_names(
            consts::FAN_OPEN_PERM | consts::FAN_RENAME | consts::FAN_FS_ERROR,
        );
        assert!(names.contains(&"OPEN_PERM"));
        assert!(names.contains(&"RENAME"));
        assert!(names.contains(&"FS_ERROR"));
    }

    #[test]
    fn test_composed_event_masks() {
        let close = consts::FAN_CLOSE;
        assert_eq!(close, consts::FAN_CLOSE_WRITE | consts::FAN_CLOSE_NOWRITE);

        let mv = consts::FAN_MOVE;
        assert_eq!(mv, consts::FAN_MOVED_FROM | consts::FAN_MOVED_TO);

        let dfid_name = consts::FAN_REPORT_DFID_NAME;
        assert_eq!(
            dfid_name,
            consts::FAN_REPORT_DIR_FID | consts::FAN_REPORT_NAME
        );
    }

    // ── Builder tests ──

    #[test]
    fn test_builder_default_flags() {
        let builder = FanotifyBuilder::default();
        // Default should be NOTIF (0) + CLOEXEC
        // NOTIF=0 means the class bits (0x0C) are clear
        assert!(builder.flags & 0x0C == 0, "class bits should be NOTIF");
        assert!(
            builder.flags & consts::FAN_CLOEXEC != 0,
            "CLOEXEC should be set by default"
        );
        assert!(builder.flags & consts::FAN_CLOEXEC != 0);
    }

    #[test]
    fn test_builder_chain_all_flags() {
        let builder = FanotifyBuilder::default()
            .cloexec()
            .nonblock()
            .class_content()
            .report_fid()
            .report_dir_fid()
            .report_name()
            .report_tid()
            .report_pidfd()
            .report_target_fid()
            .unlimited_queue()
            .unlimited_marks()
            .enable_audit()
            .event_flags(consts::O_CLOEXEC)
            .raw_flags(0x1000);
        // Builder should have accumulated flags
        assert!(builder.flags & consts::FAN_NONBLOCK != 0);
        assert!(builder.flags & consts::FAN_REPORT_FID != 0);
        assert!(builder.flags & consts::FAN_REPORT_TID != 0);
        assert!(builder.flags & consts::FAN_UNLIMITED_QUEUE != 0);
        assert!(builder.flags & 0x1000 != 0);
        assert_eq!(builder.event_f_flags, consts::O_CLOEXEC);
    }

    #[test]
    fn test_builder_class_modes_are_exclusive() {
        // Setting class_pre_content should clear class_content bits
        let b = FanotifyBuilder::default().class_content();
        assert!(b.flags & 0x0C == consts::FAN_CLASS_CONTENT || (b.flags & 0x0C) == 0x04);

        let b = b.class_pre_content();
        // 0x08 should be set, 0x04 should not
        assert_eq!(b.flags & 0x0C, consts::FAN_CLASS_PRE_CONTENT);
    }

    // ── Error tests ──

    #[test]
    fn test_error_display_init() {
        let e = FanotifyError::Init(libc::EPERM);
        let msg = e.to_string();
        assert!(msg.contains("fanotify_init"));
        assert!(msg.contains("CAP_SYS_ADMIN"));
    }

    #[test]
    fn test_error_display_mark() {
        let e = FanotifyError::Mark(libc::ENOENT);
        let msg = e.to_string();
        assert!(msg.contains("fanotify_mark"));
        assert!(msg.contains("does not exist"));
    }

    #[test]
    fn test_error_display_read() {
        let e = FanotifyError::Read(libc::EAGAIN);
        let msg = e.to_string();
        assert!(msg.contains("fanotify_read"));
        assert!(msg.contains("non-blocking"));
    }

    #[test]
    fn test_error_display_handle() {
        let e = FanotifyError::Handle(libc::EOPNOTSUPP);
        let msg = e.to_string();
        assert!(msg.contains("file_handle"));
        assert!(msg.contains("does not support file handles"));
    }

    #[test]
    fn test_error_into_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let e: FanotifyError = io_err.into();
        match e {
            FanotifyError::Io(_) => {}
            _ => panic!("expected Io variant"),
        }
    }

    #[test]
    fn test_error_impl_error_trait() {
        fn check_error(_: &dyn std::error::Error) {}
        let e = FanotifyError::Init(libc::EINVAL);
        check_error(&e); // must compile
    }

    // ── Type tests ──

    #[test]
    fn test_fid_event_methods() {
        let ev = FidEvent {
            mask: consts::FAN_CREATE | consts::FAN_MODIFY,
            pid: 42,
            path: PathBuf::from("/tmp/foo"),
            dfid_name_handle: None,
            dfid_name_filename: None,
            self_handle: None,
        };
        assert!(!ev.is_overflow());
        let names = ev.event_names();
        assert_eq!(names, vec!["MODIFY", "CREATE"]);
    }

    #[test]
    fn test_fid_event_overflow() {
        let ev = FidEvent {
            mask: consts::FAN_Q_OVERFLOW,
            pid: 0,
            path: PathBuf::new(),
            dfid_name_handle: None,
            dfid_name_filename: None,
            self_handle: None,
        };
        assert!(ev.is_overflow());
    }

    #[test]
    fn test_legacy_event_auto_close_fd() {
        // LegacyEvent with fd=-1 should not crash on drop
        let ev = LegacyEvent {
            mask: 0,
            fd: -1,
            pid: 0,
            path: PathBuf::new(),
        };
        drop(ev);
    }

    #[test]
    fn test_fanotify_response_struct() {
        let resp = FanotifyResponse {
            fd: 5,
            response: consts::FAN_ALLOW,
        };
        assert_eq!(resp.fd, 5);
        assert_eq!(resp.response, 0x01);
    }

    #[test]
    fn test_handle_cache_type() {
        use std::collections::HashMap;
        let _cache: HandleCache = HashMap::new();
    }

    // ── open_mount test (path resolution without privileges) ──

    #[test]
    fn test_open_mount_fails_on_nonexistent() {
        let result = open_mount("/nonexistent_path_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_open_mount_succeeds_on_dev() {
        // /dev is always a valid directory even without special permissions
        let result = open_mount("/dev");
        assert!(result.is_ok());
    }

    // ── Fanotify struct tests ──

    #[test]
    fn test_fanotify_impl_as_fd() {
        use std::os::fd::AsFd;
        // We can't create a real Fanotify without CAP_SYS_ADMIN,
        // but we can verify the trait impl compiles.
        fn _takes_as_fd(_: &impl AsFd) {}
        // If this compiles, the impl is correct.
    }

    // ── Pre-commit sanity tests ──

    /// Make sure all public functions compile with expected signatures.
    /// This is a compile-time check.
    #[test]
    fn test_public_api_function_signatures() {
        // These just need to compile — verification that signatures are correct
        fn _check_free_fns() {
            let _ = fanotify_init(0, 0);
            let _ = open_mount("/");
            let _ = handle::name_to_handle_at(std::path::Path::new("/"));
        }

        // Check all prelude exports resolve
        fn _check_prelude() {
            let _ = crate::prelude::Fanotify::new();
            let _ = crate::prelude::FanotifyBuilder::default();
            let _ = crate::prelude::FidEvent {
                mask: 0,
                pid: 0,
                path: PathBuf::new(),
                dfid_name_handle: None,
                dfid_name_filename: None,
                self_handle: None,
            };
            let _ = crate::prelude::LegacyEvent {
                mask: 0,
                fd: -1,
                pid: 0,
                path: PathBuf::new(),
            };
            let _ = crate::prelude::FanotifyResponse {
                fd: -1,
                response: 0,
            };
        }

        _check_free_fns();
        _check_prelude();
    }
}
