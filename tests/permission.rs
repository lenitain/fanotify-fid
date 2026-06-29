//! Permission event integration tests.
//!
//! These tests verify permission event handling (FAN_OPEN_PERM, etc.).
//! Require `CAP_SYS_ADMIN` (run as root).

mod common;

use common::*;
use fanotify_fid::prelude::*;
use std::fs;
use std::thread;
use std::time::Duration;

#[test]
#[ignore]
fn test_permission_event_response() {
    let dir = tmpdir();
    let f = dir.path().join("p.txt");
    fs::write(&f, b"t").unwrap();

    let fan = Fanotify::new().class_content().init().unwrap();
    // FAN_EVENT_ON_CHILD: without it, marking a directory only catches
    // events on the directory itself, not on files inside it.
    fan.mark(FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, dir.path())
        .unwrap();

    let fc = f.clone();
    let rdr = thread::spawn(move || {
        for _ in 0..100 {
            match fs::read_to_string(&fc) {
                Ok(s) => return s,
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        }
        panic!("reader: timed out");
    });

    // Blocking read — waits until kernel delivers the permission event
    let evts = fan.read_fd_events().expect("read perm event");
    let ev = evts
        .first()
        .filter(|e| e.mask() & FAN_OPEN_PERM != 0)
        .expect("first event should be FAN_OPEN_PERM");
    fan.send_response(&FanotifyResponse::new(ev.fd(), FAN_ALLOW))
        .expect("send FAN_ALLOW");

    assert_eq!(rdr.join().expect("reader"), "t");
}
