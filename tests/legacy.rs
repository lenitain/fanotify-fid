//! Legacy mode integration tests.
//!
//! These tests verify non-FID (legacy) fanotify functionality.
//! Require `CAP_SYS_ADMIN` (run as root).

mod common;

use common::*;
use fanotify_fid::prelude::*;
use std::fs;
use std::time::Duration;

#[test]
#[ignore]
fn test_legacy_event_lifecycle() {
    let dir = tmpdir();
    let f = dir.path().join("r.txt");
    fs::write(&f, b"d").unwrap();

    let fan = Fanotify::new().class_content().nonblock().init().unwrap();
    fan.mark(FAN_MARK_ADD, FAN_OPEN, &f).unwrap();
    let _ = fs::read(&f).ok();

    let evts = retry(
        || fan.read_legacy().ok().filter(|e| !e.is_empty()),
        Duration::from_secs(2),
    )
    .expect("OPEN event within 2s");

    assert!(evts[0].mask & FAN_OPEN != 0);
    assert!(evts[0].fd >= 0);
}
