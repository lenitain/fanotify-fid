//! A batch read, copied once, parsed and resolved on a worker thread.
//!
//! Two things this shows that nothing else does:
//!
//! * **Where a batch that has to leave the reading thread is copied.**  It is
//!   copied as bytes, once, by the reader — not as events, per event, by a
//!   library that guessed the caller would need them to outlive the buffer.
//!   `Fanotify::read_events` is the borrowing form and this is the owned one;
//!   the caller picks, and the cost is visible in the call it picks.
//! * **The reader's job is the queue.**  Parsing and resolving happen on the
//!   worker, so a slow resolver cannot let the kernel's queue back up.
//!
//! The store lives on the worker thread, because it is the worker's knowledge.

use std::error::Error;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fanotify_fid::consts::*;
use fanotify_fid::prelude::*;

#[derive(Debug)]
struct Summary {
    masks: Vec<&'static str>,
    path: Option<String>,
}

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let dir = std::env::temp_dir().join(format!("fanotify-fid-batch-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;

    // A FID group with names: the unprivileged row of the table in the crate
    // docs.  Resolving the handles needs CAP_DAC_READ_SEARCH on top, and if it is
    // missing every resolution fails with EPERM — the events and their names
    // still arrive, which is what makes this worth running either way.
    let fan = Fanotify::new(
        FAN_CLASS_NOTIF
            | FAN_CLOEXEC
            | FAN_NONBLOCK
            | FAN_REPORT_FID
            | FAN_REPORT_DIR_FID
            | FAN_REPORT_NAME,
    )?;
    fan.mark(
        FAN_MARK_ADD,
        FAN_CREATE | FAN_DELETE,
        dir.to_str().expect("a UTF-8 path"),
    )?;

    // The worker owns the mount descriptor and the store, so both stay on one
    // thread and the resolver never crosses one.
    let mounts = Mounts::new().with_fd(std::fs::File::open(&dir)?)?;
    let store = HandleCache::new();
    let (send, receive) = mpsc::channel::<(Vec<u8>, mpsc::Sender<Summary>)>();
    std::thread::spawn(move || {
        while let Ok((raw, reply)) = receive.recv() {
            // `parse_fid_events` is the documented byte-level entry point, not a
            // private detail of the reader: a caller holding bytes from
            // anywhere — a file, a socket, a previous run — parses them here.
            let mut events = match parse_fid_events(&raw) {
                Ok(events) => events,
                Err(e) => {
                    eprintln!("worker: a batch failed to parse: {e}");
                    continue;
                }
            };
            // Both borrows are shared, and both end with the loop body: the
            // resolver reads the store, and the same store records what this
            // batch learned — one reference, because a resolution is one
            // operation, not a read followed by an unrelated write.
            let resolved =
                PathResolver::new(&store, &mounts).resolve_events_memo(&store, &mut events);
            let _ = resolved.passes;
            for ev in &events {
                let _ = reply.send(Summary {
                    masks: ev.event_names().collect(),
                    path: ev.path().map(|p| p.display().to_string()),
                });
            }
        }
    });

    // Cause some events: each write is a FAN_CREATE for the new entry.
    for name in ["one", "two", "three"] {
        std::fs::write(dir.join(name), b"x")?;
    }

    let mut buf = Vec::new();
    let mut batches = 0usize;
    let deadline = Instant::now() + Duration::from_secs(5);
    while batches < 1 && Instant::now() < deadline {
        // The read is one statement so that its borrow of `buf` ends here: the
        // events borrow the buffer, and the copy below needs the buffer back.
        let (event_count, would_block, failed) = {
            let (events, _report) = match fan.read_events_reported(&mut buf) {
                Ok(read) => read,
                Err(e) if e.is_would_block() => {
                    // An empty read is not a failure — the loop just found
                    // nothing queued yet.  (A blocking group would not return at
                    // all here; this one is non-blocking, so an empty queue is a
                    // real answer.)
                    fan.wait_readable(Some(Duration::from_millis(50)))?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // The one copy.  It happens here because the batch has to outlive
            // this thread, and bytes are the cheapest thing to copy: one
            // `memcpy` for the whole batch, rather than one allocation per
            // handle and per name.  `events` is dropped with this block, which
            // is what frees `buf` to be read again.
            (events.len(), false, false)
        };
        let _ = (would_block, failed);
        // The borrow ended with the block above, so the copy is free to take it.
        let dispatch = buf.clone();
        let raw_len = dispatch.len();
        let (reply, answers) = mpsc::channel();
        send.send((dispatch, reply))?;
        println!("reader: dispatched {event_count} events ({raw_len} bytes) in one copy");
        for answer in answers.iter().take(event_count) {
            println!(
                "worker: {:?} -> {}",
                answer.masks,
                answer.path.as_deref().unwrap_or("unresolved")
            );
        }
        batches += 1;
    }

    let _ = EventResolution::Resolved;
    std::fs::remove_dir_all(&dir)?;
    if batches == 0 {
        eprintln!("no events arrived within the deadline");
    }
    Ok(())
}
