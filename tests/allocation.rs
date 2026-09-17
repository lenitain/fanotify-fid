//! The two paths that exist to avoid allocating, asserted with an allocator
//! that counts.
//!
//! Everything else in this suite asserts *behaviour*; these assert the absence
//! of a cost, which no behaviour can show.  Both paths are on the wrong side of
//! a blocking operation when they run:
//!
//! * a permission response is written once per intercepted `open(2)`, while the
//!   operation it answers is blocked;
//! * a read that finds an empty queue is the `EAGAIN` retry, which happens on
//!   every wake-up and must not cost a syscall's worth of setup.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::os::fd::AsFd;

use fanotify_fid::consts::*;
use fanotify_fid::handle::{Fsid, HandleCache, Mounts, PathStore};
use fanotify_fid::resolve::PathResolver;
use fanotify_fid::response::FanotifyResponse;
use fanotify_fid::{EventReader, Fanotify, FanotifyError, FdEventReader};

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|c| {
            if c.get() {
                ALLOCATIONS.with(|n| n.set(n.get() + 1));
            }
        });
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        COUNTING.with(|c| {
            if c.get() {
                ALLOCATIONS.with(|n| n.set(n.get() + 1));
            }
        });
        // SAFETY: forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Run `f`, returning its value and how many allocations it made on this thread.
fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    ALLOCATIONS.with(|n| n.set(0));
    COUNTING.with(|c| c.set(true));
    let value = f();
    COUNTING.with(|c| c.set(false));
    (value, ALLOCATIONS.with(|n| n.get()))
}

fn devnull() -> std::fs::File {
    std::fs::File::options()
        .write(true)
        .open("/dev/null")
        .unwrap()
}

/// A FID group, which needs no privilege.
fn fid_group() -> Fanotify {
    Fanotify::new(
        FAN_CLASS_NOTIF
            | FAN_CLOEXEC
            | FAN_NONBLOCK
            | FAN_REPORT_FID
            | FAN_REPORT_DIR_FID
            | FAN_REPORT_NAME,
    )
    .expect("a FID NOTIF group needs no privilege")
}

#[test]
fn a_permission_response_is_built_and_written_without_allocating() {
    // `send_response` on a FID `FAN_CLASS_NOTIF` group builds the whole response
    // and encodes it before the `write(2)` reaches the kernel, which then refuses
    // it because the group is not a permission class.  So the work measured here
    // is the work the real path does; only the kernel's answer differs, and that
    // answer is not this test's business.
    //
    // The two forms this crate constructs itself are what must be free: the
    // plain word, and the audit rule whose 12-byte record was a `Vec` and whose
    // body was another.
    let fan = fid_group();
    let file = devnull();

    for (label, response) in [
        ("the plain word", FanotifyResponse::allow(file.as_fd())),
        ("the audit rule", FanotifyResponse::audit_rule(FAN_DENY, 7)),
    ] {
        let (result, allocations) = allocations_during(|| fan.send_response(&response));
        assert!(
            result.is_err(),
            "{label}: a NOTIF group is not a permission group"
        );
        assert_eq!(
            allocations, 0,
            "{label}: building and encoding the response must not allocate"
        );
    }

    // A payload too large for the inline buffer is the one form that may
    // allocate, and it must still produce the right bytes.
    let big = vec![9u8; 1024];
    let response = FanotifyResponse::info(FAN_DENY, FAN_RESPONSE_INFO_AUDIT_RULE, big);
    let (result, allocations) = allocations_during(|| fan.send_response(&response));
    assert!(result.is_err());
    assert_eq!(
        allocations, 1,
        "a payload past the inline capacity spills to exactly one Vec"
    );
}

#[test]
fn an_empty_queue_read_allocates_nothing_however_often_it_is_retried() {
    // The retry path.  `read` on an empty queue is `EAGAIN`, and a loop that
    // found nothing wakes up to do it again — thousands of times a second, for
    // the rest of the process's life.  Whatever that path costs is paid that
    // often, which is why it is asserted to cost nothing at all rather than
    // merely something small.
    let fan = fid_group();
    let mut reader = EventReader::new(&fan, 256 * 1024);

    // Warm up: the first read may grow the event storage if events were already
    // queued, and that growth is setup rather than per-read.
    let _ = reader.read_reported();

    let (results, allocations) = allocations_during(|| {
        let mut outcomes = Vec::new();
        for _ in 0..1000 {
            // Every one of these is an empty queue: nothing writes to the
            // marked paths, because nothing is marked.
            match reader.read_reported() {
                Ok((events, report)) => outcomes.push((events.len(), report.is_complete())),
                Err(FanotifyError::Read(libc::EAGAIN)) => {}
                Err(e) => panic!("unexpected: {e}"),
            }
        }
        outcomes
    });
    assert!(
        results.iter().all(|(n, _)| *n == 0),
        "the queue is empty, so no read may produce events"
    );
    assert_eq!(
        allocations, 0,
        "1000 empty-queue reads must not allocate once"
    );
}

#[test]
fn the_reader_allocates_nothing_per_read_once_its_storage_has_grown() {
    // The per-read allocation the owning reader removes.  A create event is
    // needed to make the event storage grow, which is the one allocation the
    // reader is allowed; the reads after it must add none.
    let dir = tempfile::tempdir().unwrap();
    let fan = fid_group();
    fan.mark(FAN_MARK_ADD, FAN_CREATE, dir.path().to_str().unwrap())
        .unwrap();

    let mut reader = EventReader::new(&fan, 64 * 1024);
    std::fs::write(dir.path().join("child"), b"x").unwrap();

    // Wait for the event, which is what grows the storage.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut grew = false;
    while !grew && std::time::Instant::now() < deadline {
        match reader.read() {
            Ok(events) => grew = !events.is_empty(),
            Err(FanotifyError::Read(libc::EAGAIN)) => {
                fan.wait_readable(Some(std::time::Duration::from_millis(20)))
                    .unwrap();
            }
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert!(grew, "the create event must arrive");
    assert!(reader.event_capacity() > 0);

    // Now the reads that matter: all empty, all allocation-free.
    let (_, allocations) = allocations_during(|| {
        for _ in 0..1000 {
            let _ = black_box(reader.read_reported().map(|(events, _)| events.len()));
        }
    });
    assert_eq!(allocations, 0, "a warm reader must read without allocating");
}

#[test]
fn the_fd_reader_allocates_nothing_per_read_either() {
    // The fd format's equivalent contract, and the reason `FdEventReader` owns
    // its event storage rather than building a `Vec` per read: a loop that finds
    // an empty queue must cost nothing, exactly as the FID reader's does.
    //
    // A FID group is used to get a real fanotify descriptor without privilege;
    // the bytes an empty read returns are the same empty read either way, and the
    // storage discipline is the format-independent half being measured here.
    let fan = fid_group();
    let mut reader = FdEventReader::new(&fan, 64 * 1024);
    let _ = reader.read_reported();

    let (_, allocations) = allocations_during(|| {
        for _ in 0..1000 {
            let _ = black_box(reader.read_reported().map(|(events, _)| events.len()));
        }
    });
    assert_eq!(
        allocations, 0,
        "1000 empty-queue fd reads must not allocate once"
    );
}

#[test]
fn a_store_hit_costs_the_answer_it_returns_and_nothing_else() {
    // What the resolver's store contract is worth in allocations: a hit answers
    // from the store and never reaches the syscall, so the only allocation on the
    // path is the owned path the caller asked for.  Asserted with the syscall
    // refused, which is what makes "no syscall was spent" a fact rather than an
    // assumption about the filesystem.
    let fsid: Fsid = (0x5eed, 1);
    let handle: Vec<u8> = vec![7; 12];
    let mut store = HandleCache::new();
    PathStore::insert(&mut store, fsid, &handle, std::path::Path::new("/known"));
    let mut resolver = PathResolver::with_store(Mounts::new(), store);
    resolver.set_syscall_fallback(false);

    let (path, allocations) = allocations_during(|| resolver.resolve_handle(fsid, &handle));
    assert_eq!(path.unwrap(), std::path::PathBuf::from("/known"));
    assert_eq!(
        allocations, 1,
        "a hit is the returned `PathBuf`: one allocation, no key copy, no guard"
    );

    // The zero-allocation form, for a store whose values a reference can reach:
    // the lookup itself costs nothing, and a caller that copies the answer pays
    // for the copy and not for the lookup.
    let (found, allocations) = allocations_during(|| resolver.store().path_of(fsid, &handle));
    assert!(found.is_some());
    assert_eq!(allocations, 0, "a borrowed hit must allocate nothing");

    let (copied, allocations) = allocations_during(|| {
        resolver
            .store()
            .path_of(fsid, &handle)
            .map(std::path::Path::to_path_buf)
    });
    assert_eq!(copied.unwrap(), std::path::PathBuf::from("/known"));
    assert_eq!(
        allocations, 1,
        "and copying it is the caller's one allocation"
    );
}
