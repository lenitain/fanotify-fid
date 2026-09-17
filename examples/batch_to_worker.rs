//! Read a batch, copy its bytes once, parse it on another thread.
//!
//! This is the architecture the borrowing model cannot serve directly: the events
//! a read produces point into the reader's buffer, and the next read overwrites
//! that buffer, so an event cannot cross a thread boundary or a queue.  The
//! crate's explicit conversion, [`FidEvent::into_owned`], solves that by copying
//! **per event** — every handle, every name, every preserved record — which is
//! exactly the per-record cost the borrowing model exists to avoid.  So for a
//! read-batch-then-dispatch design the conversion is the wrong tool, and the
//! right one is already on [`EventReader`]:
//!
//! * [`EventReader::raw_bytes`] is the batch the kernel wrote, verbatim;
//! * one `to_vec` copies the **whole batch** — one allocation, one `memcpy`;
//! * [`parse_fid_events`] is public and pure, so the copy can be parsed anywhere,
//!   by anyone, with no borrow of the reader at all.
//!
//! The trade is explicit: one copy per batch instead of one per event, and the
//! worker owns its bytes.  A batch of N events with H handle bytes and M name
//! bytes each costs N small allocations with `into_owned` and one with this —
//! and the second is what a thread pool wants anyway, because handing a worker a
//! `Vec<u8>` is a move rather than a lifetime negotiation.
//!
//! Run it with `cargo run --example batch_to_worker`.

use std::error::Error;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fanotify_fid::handle::Mounts;
use fanotify_fid::resolve::{EventResolution, PathResolver};
use fanotify_fid::{EventReader, Fanotify};

/// What a worker sends back for one event: the masks that fired, and the path if
/// the resolver could produce one.
///
/// Owned strings, because this is the boundary where the bytes stop being the
/// kernel's answer and become this program's data.
struct Summary {
    masks: Vec<&'static str>,
    path: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::temp_dir().join(format!("fanotify-fid-batch-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;

    // A FID group with names: the unprivileged row of the table in the crate
    // docs.  Resolving the handles needs CAP_DAC_READ_SEARCH on top, and if it is
    // missing every resolution fails with EPERM — the events and their names
    // still arrive, which is what makes this worth running either way.
    let fan = Fanotify::new(
        fanotify_fid::consts::FAN_CLASS_NOTIF
            | fanotify_fid::consts::FAN_CLOEXEC
            | fanotify_fid::consts::FAN_NONBLOCK
            | fanotify_fid::consts::FAN_REPORT_FID
            | fanotify_fid::consts::FAN_REPORT_DIR_FID
            | fanotify_fid::consts::FAN_REPORT_NAME,
    )?;
    fan.mark(
        fanotify_fid::consts::FAN_MARK_ADD,
        fanotify_fid::consts::FAN_CREATE | fanotify_fid::consts::FAN_DELETE,
        dir.to_str().expect("a UTF-8 temporary path"),
    )?;

    // The worker: it owns its mount descriptor and its store, so the resolver
    // never leaves this thread and the bytes it parses never leave it either.
    let mounts = Mounts::new().with_fd(std::fs::File::open(&dir)?)?;
    let (send, receive) = mpsc::channel::<(Vec<u8>, std::sync::mpsc::Sender<Summary>)>();
    std::thread::spawn(move || {
        let mut resolver = PathResolver::new(mounts);
        while let Ok((raw, reply)) = receive.recv() {
            // The same call a live read uses, on a buffer that is *this thread's*
            // — which is the whole point: `parse_fid_events` is not a private
            // detail of the reader, it is the documented byte-level entry point.
            let mut events = match fanotify_fid::parse_fid_events(&raw) {
                Ok(events) => events,
                Err(e) => {
                    eprintln!("worker: a batch failed to parse: {e}");
                    continue;
                }
            };
            // Paths are resolved here rather than on the reader thread, so the
            // reader's only job is to keep the kernel's queue empty.
            let resolved = resolver.resolve_events(&mut events);
            let _ = resolved.passes;
            for ev in &events {
                let _ = reply.send(Summary {
                    masks: ev.event_names().collect(),
                    path: ev.path().map(|p| p.display().to_string()),
                });
            }
        }
    });

    let mut reader = EventReader::new(&fan, 256 * 1024);
    let mut batches = 0usize;

    // Cause some events: each write is a FAN_CREATE for the new entry.
    for name in ["one", "two", "three"] {
        std::fs::write(dir.join(name), b"x")?;
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while batches < 1 && Instant::now() < deadline {
        match reader.read() {
            // An empty read is not a failure — the loop just found nothing queued
            // yet.  Nothing was copied and nothing was dispatched.  (A blocking
            // group would not return at all here; this one is non-blocking, so an
            // empty queue is a real answer.)
            Ok([]) => {}
            Ok(events) => {
                let event_count = events.len();
                // The one copy: the whole batch, as the kernel wrote it.  The
                // events' borrow ends here, and nothing else on this thread needs
                // to outlive it.
                let dispatch = reader.raw_bytes().to_vec();
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
            Err(e) if e.is_would_block() => {
                fan.wait_readable(Some(Duration::from_millis(50)))?;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let _ = EventResolution::Resolved;
    std::fs::remove_dir_all(&dir)?;
    if batches == 0 {
        eprintln!("no events arrived within the deadline");
    }
    Ok(())
}
