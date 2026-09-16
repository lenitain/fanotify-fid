//! Any bytes must parse without panicking, reading out of bounds, or looping
//! forever, and the report must account for the buffer exactly.
//!
//! A fanotify read buffer is untrusted by construction — it can be a capture
//! file, a pipe, or a descriptor that is not a fanotify group — so "the parser
//! is a total function over `&[u8]`" is the property that matters, not any one
//! event it might find.  The assertions here are the observable shadow of that
//! property: every byte is either consumed by a whole event or reported as
//! left over, and the number of events is bounded by the header size.

#![no_main]

use fanotify_fid::fid::{METADATA_SIZE, parse_fid_events_reported};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (events, report) = parse_fid_events_reported(data);

    assert_eq!(
        report.bytes_consumed + report.bytes_left,
        data.len(),
        "the report must account for every byte exactly once"
    );
    // Every event is at least one header, so a walk cannot produce more events
    // than that; a number larger than this is an unwritten loop or an
    // over-read.
    assert!(
        events.len() <= data.len() / METADATA_SIZE + 1,
        "more events than the buffer can hold"
    );

    // Touch every accessor: a parser that produced an event is not enough, the
    // event must be readable without a panic.
    for event in &events {
        let _ = event.mask();
        let _ = event.pid();
        let _ = event.fsid();
        let _ = event.dfid_name_handle();
        let _ = event.dfid_name_raw();
        let _ = event.dfid_name_str();
        let _ = event.self_handle();
        let _ = event.pidfd();
        let _ = event.fd_error();
        let _ = event.fs_error();
        let _ = event.access_range();
        let _ = event.mnt_id();
        let _ = event.rename_source().map(|side| side.name_str());
        let _ = event.rename_target().map(|side| side.name_str());
        let _ = event.unknown_info_records();
        let _ = event.is_overflow();
        let _ = event.has_path();
    }

    // And the owned conversion, which is the other way an event is used.
    let _: Vec<_> = events
        .into_iter()
        .map(fanotify_fid::FidEvent::into_owned)
        .collect();
});
