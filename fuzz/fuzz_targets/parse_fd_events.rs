//! The fd-format walk, over any bytes.
//!
//! The same totality property as the FID format, plus the one that is specific
//! to this format: **no parse may adopt a descriptor**.  A `&[u8]` proves
//! nothing about where a number came from, and a parser that wrapped one in an
//! `OwnedFd` would eventually close a descriptor its caller still holds — so
//! `fd()` must be `None` for every event the byte-level parser produces, however
//! the buffer is shaped.

#![no_main]

use fanotify_fid::fd::{METADATA_SIZE, parse_fd_events};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (events, report) = parse_fd_events(data);

    assert_eq!(
        report.bytes_consumed + report.bytes_left,
        data.len(),
        "the report must account for every byte exactly once"
    );
    assert!(
        events.len() <= data.len() / METADATA_SIZE + 1,
        "more events than the buffer can hold"
    );

    for event in &events {
        assert!(
            event.fd().is_none(),
            "the byte-level parser must never adopt a descriptor"
        );
        let _ = event.mask();
        let _ = event.pid();
        let _ = event.fd_field();
        let _ = event.no_fd_reason();
        let _ = event.is_overflow();
        let _ = event.event_names();
    }
});
