//! Tests for FanotifyError type.

use fanotify_fid::FanotifyError;

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
