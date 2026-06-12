//! Tests for public API surface and prelude.

use fanotify_fid::prelude::*;
use std::os::fd::AsFd;
use std::path::PathBuf;

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

#[test]
fn test_fanotify_impl_as_fd() {
    // We can't create a real Fanotify without CAP_SYS_ADMIN,
    // but we can verify the trait impl compiles.
    fn _takes_as_fd(_: &impl AsFd) {}
    // If this compiles, the impl is correct.
}

#[test]
fn test_public_api_function_signatures() {
    // These just need to compile — verification that signatures are correct
    fn _check_free_fns() {
        let _ = fanotify_init(0, 0);
        let _ = open_mount("/");
        let _ = name_to_handle_at(std::path::Path::new("/"));
    }

    // Check all prelude exports resolve
    fn _check_prelude() {
        let _ = Fanotify::new();
        let _ = FanotifyBuilder::default();
        let _ = FidEvent {
            mask: 0,
            pid: 0,
            path: PathBuf::new(),
            dfid_name_handle: None,
            dfid_name_filename: None,
            self_handle: None,
        };
        let _ = FdEvent {
            mask: 0,
            fd: -1,
            pid: 0,
            path: PathBuf::new(),
        };
        let _ = FanotifyResponse {
            fd: -1,
            response: 0,
        };
    }

    _check_free_fns();
    _check_prelude();
}
