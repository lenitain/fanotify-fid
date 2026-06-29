//! FID mode integration tests.
//!
//! These tests verify FAN_REPORT_FID mode functionality.
//! Require `CAP_SYS_ADMIN` (run as root).

mod common;

use common::*;
use fanotify_fid::prelude::*;
use std::fs;
use std::time::Duration;

#[test]
#[ignore]
fn test_fid_event_on_single_file() {
    let dir = tmpdir();
    let f = dir.path().join("t.txt");
    fs::write(&f, b"x").unwrap();

    let fan = Fanotify::new().report_fid().nonblock().init().unwrap();
    fan.mark(FAN_MARK_ADD, FAN_MODIFY, &f).unwrap();
    fs::write(&f, b"y").unwrap();

    let mount_fd = open_mount_fd("/");
    let mnt: &[std::os::fd::OwnedFd] = mount_fd.as_slice();
    let mut buf = Vec::with_capacity(65536);

    let evts = retry(
        || {
            read_fid_events(fan.as_fd(), mnt, &mut buf, None)
                .ok()
                .filter(|e| !e.is_empty())
        },
        Duration::from_secs(2),
    )
    .expect("MODIFY event within 2s");

    assert!(evts.iter().any(|e| e.mask() & FAN_MODIFY != 0));
}
