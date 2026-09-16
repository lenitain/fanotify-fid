//! The resolver's contracts: one handle, one answer; no syscall when the answer
//! is already known; and the decisions a caller makes explicitly rather than
//! having them made here.
//!
//! # Why these are separate from `fid_identity.rs`
//!
//! That file tests what the *kernel* reported.  This one tests what this crate
//! *guarantees* on top of it — the properties that live in the resolver and
//! would be lost if it were deleted, not merely made inconvenient:
//!
//! * knowledge from one call is used by the next (the store is consulted first);
//! * one handle yields one answer for as long as the resolver lives, so two
//!   events about the same directory cannot disagree;
//! * a batch converges, so an event whose parent could only be learned from an
//!   earlier event still resolves;
//! * the `" (deleted)"` marker is reported raw and stripped only when the caller
//!   asks, so a file legitimately named `foo (deleted)` is not silently renamed.
//!
//! The tests that need no privilege stand on their own.  The ones that resolve
//! through the kernel are `#[ignore]`d behind `CAP_DAC_READ_SEARCH` and say so
//! through the shared skip macro, like the rest of this suite.

mod common;

use std::io;
use std::path::{Path, PathBuf};

use common::{Capabilities, mount_fd_of, tmpdir};
use fanotify_fid::consts::*;
use fanotify_fid::fid::FidEvent;
use fanotify_fid::handle::{FileHandle, Fsid, HandleCache, Mounts, PathStore, handle_from_fd};
use fanotify_fid::resolve::{EventResolution, PathResolver};

/// A `FidEvent` naming one entry in a directory, with no path resolved.
///
/// Owned, because a hand-built event's setters accept owned bytes and nothing
/// here borrows a buffer.
fn event_for(dir: &Path, entry: &str) -> FidEvent<'static> {
    let dir_handle = handle_from_fd(std::fs::File::open(dir).unwrap()).unwrap();
    let fsid = fanotify_fid::handle::fsid_of_path(dir).unwrap();
    let mut event = FidEvent::new();
    event.set_mask(FAN_CREATE);
    event.set_fsid(fsid);
    event.set_dfid_name(dir_handle, entry.as_bytes().to_vec());
    event
}

// ── The store is consulted first, and is the only thing consulted when the
//    syscall is refused ──

#[test]
fn a_known_handle_is_answered_without_asking_the_filesystem() {
    let fsid: Fsid = (0x1234, 0x5678);
    let handle: FileHandle = vec![9, 8, 7, 6, 5, 4, 3, 2];

    // Deliberately not a real handle on a real filesystem: if this resolves, it
    // resolved from the store, because nothing else could have answered it.
    // Named as the trait method: `HandleCache` is a `HashMap` alias, so its
    // inherent `insert` would otherwise shadow this one.
    let mut store = HandleCache::new();
    PathStore::insert(
        &mut store,
        fsid,
        &handle,
        PathBuf::from("/learned/elsewhere"),
    );

    let mut resolver = PathResolver::with_store(Mounts::new(), store);
    assert_eq!(
        resolver.resolve_handle(fsid, &handle).unwrap(),
        PathBuf::from("/learned/elsewhere"),
    );
    // A directory plus a name is the same lookup plus a join, so a store hit
    // must answer that too.
    assert_eq!(
        resolver.resolve_dir(fsid, &handle, b"child").unwrap(),
        PathBuf::from("/learned/elsewhere/child"),
    );
}

#[test]
fn with_the_syscall_refused_a_store_miss_is_exdev_rather_than_a_silent_none() {
    let mut resolver = PathResolver::new(Mounts::new());
    resolver.set_syscall_fallback(false);
    let err = resolver
        .resolve_handle((1, 2), &[0u8; 12])
        .expect_err("nothing knows this handle");
    assert_eq!(err.raw_os_error(), Some(libc::EXDEV));
}

#[test]
fn knowledge_survives_across_calls_and_across_events() {
    let fsid: Fsid = (7, 7);
    let handle: FileHandle = vec![1, 1, 1, 1, 1, 1, 1, 1];
    let mut store = HandleCache::new();
    PathStore::insert(&mut store, fsid, &handle, PathBuf::from("/one/answer"));

    let mut resolver = PathResolver::with_store(Mounts::new(), store);
    for _ in 0..3 {
        assert_eq!(
            resolver.resolve_handle(fsid, &handle).unwrap(),
            PathBuf::from("/one/answer"),
        );
    }
    // And a caller can read the store back out, which is what makes pre-seeding
    // and inspection possible.
    assert_eq!(
        PathStore::get(resolver.store(), fsid, &handle),
        Some(PathBuf::from("/one/answer")),
    );
}

// ── Resolving for real, which needs CAP_DAC_READ_SEARCH ──

#[test]
#[ignore = "needs CAP_DAC_READ_SEARCH: open_by_handle_at bypasses path permissions and is never allowed without it"]
fn a_real_directory_handle_resolves_and_then_costs_no_further_syscall() {
    if !Capabilities::probe().has(common::CAP_DAC_READ_SEARCH) {
        skip_without_cap_dac_read_search!("resolving a handle to a path");
    }
    let dir = tmpdir();
    let fsid = fanotify_fid::handle::fsid_of_path(dir.path()).unwrap();
    let handle = handle_from_fd(std::fs::File::open(dir.path()).unwrap()).unwrap();

    let mounts = Mounts::new()
        .with_fd(mount_fd_of(dir.path()).unwrap())
        .unwrap();
    let mut resolver = PathResolver::new(mounts);

    let first = resolver.resolve_handle(fsid, &handle).unwrap();
    assert_eq!(
        std::fs::canonicalize(&first).unwrap(),
        std::fs::canonicalize(dir.path()).unwrap(),
    );

    // The second call must produce the identical answer, and must not need the
    // filesystem to do it: with the syscall refused, only the store is left.
    resolver.set_syscall_fallback(false);
    assert_eq!(resolver.resolve_handle(fsid, &handle).unwrap(), first);
}

#[test]
#[ignore = "needs CAP_DAC_READ_SEARCH: open_by_handle_at bypasses path permissions and is never allowed without it"]
fn a_batch_resolves_every_event_that_names_an_entry_in_a_marked_directory() {
    if !Capabilities::probe().has(common::CAP_DAC_READ_SEARCH) {
        skip_without_cap_dac_read_search!("resolving a whole batch");
    }
    let dir = tmpdir();
    let fan = common::fid_group();
    fan.mark(
        FAN_MARK_ADD,
        FAN_CREATE | FAN_EVENT_ON_CHILD,
        dir.path().to_str().unwrap(),
    )
    .unwrap();

    for name in ["one", "two", "three"] {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    let mut buf = Vec::new();
    let mut events = common::collect_fid_events(&fan, &mut buf);
    assert!(events.len() >= 3, "expected the three creates");

    let mounts = Mounts::new()
        .with_fd(mount_fd_of(dir.path()).unwrap())
        .unwrap();
    let mut resolver = PathResolver::new(mounts);
    let resolved = resolver.resolve_events(&mut events);
    assert_eq!(resolved, events.len(), "every create event should resolve");

    // The point of the store: all three events share one parent handle, and it
    // must be there afterwards, so a later batch about the same directory costs
    // nothing.  Collected before borrowing the store, because the resolver is
    // borrowed mutably by `resolve_events` above.
    let parents: Vec<(Fsid, FileHandle)> = events
        .iter()
        .filter_map(|e| e.fsid().zip(e.dfid_name_handle().map(<[u8]>::to_vec)))
        .collect();
    assert!(!parents.is_empty(), "the events must name a parent");
    let store = resolver.store();
    for (fsid, handle) in parents {
        assert!(
            PathStore::get(store, fsid, &handle).is_some(),
            "the parent handle must be in the store after resolution",
        );
    }
    for name in ["one", "two", "three"] {
        assert!(
            events.iter().any(|e| {
                e.dfid_name() == Some(std::ffi::OsStr::new(name))
                    && e.path().is_some_and(|p| p.ends_with(name))
            }),
            "{name} should carry a path ending in its name",
        );
    }
}

// ── The `(deleted)` decision belongs to the caller ──

#[test]
fn a_deleted_marker_is_reported_raw_and_stripped_only_on_request() {
    let mut event = FidEvent::new();
    event.set_path(PathBuf::from("/srv/data/report.pdf (deleted)"));

    // Raw: the crate does not clean up the kernel's answer behind the caller.
    assert_eq!(
        event.path(),
        Some(Path::new("/srv/data/report.pdf (deleted)")),
    );
    assert!(event.is_deleted());
    assert_eq!(
        event.without_deleted_suffix(),
        Some(PathBuf::from("/srv/data/report.pdf")),
    );
}

#[test]
fn a_name_that_merely_contains_the_marker_is_not_rewritten() {
    // A file legitimately named `notes (deleted)` reports the marker *twice*, so
    // stripping once yields `notes` — a different file.  The crate must not make
    // that substitution on its own; only an explicit call does.
    let mut event = FidEvent::new();
    event.set_path(PathBuf::from("/srv/data/notes (deleted) (deleted)"));
    assert!(event.is_deleted());
    assert_eq!(
        event.without_deleted_suffix(),
        Some(PathBuf::from("/srv/data/notes (deleted)")),
    );
    assert_eq!(
        event.path(),
        Some(Path::new("/srv/data/notes (deleted) (deleted)")),
    );
}

#[test]
fn a_path_without_the_marker_is_left_exactly_as_it_is() {
    let mut event = FidEvent::new();
    event.set_path(PathBuf::from("/srv/data/live.txt"));
    assert!(!event.is_deleted());
    assert_eq!(
        event.without_deleted_suffix(),
        Some(PathBuf::from("/srv/data/live.txt")),
    );
}

#[test]
fn an_unresolved_event_claims_nothing_about_being_deleted() {
    let event = FidEvent::new();
    assert!(!event.has_path());
    assert!(!event.is_deleted());
    assert_eq!(event.without_deleted_suffix(), None);
}

// ── `Mounts` keeps the fsid with the descriptor ──

#[test]
fn a_mount_learns_its_own_filesystem_from_the_kernel() {
    let dir = tmpdir();
    let mounts = Mounts::new()
        .with_fd(mount_fd_of(dir.path()).unwrap())
        .unwrap();
    assert_eq!(mounts.len(), 1);
    assert!(!mounts.is_empty());

    let learned = mounts.fsid_at(0).expect("fstatfs must answer");
    assert_eq!(
        learned,
        fanotify_fid::handle::fsid_of_path(dir.path()).unwrap(),
    );
    // And asking for it selects the descriptor, while another does not.
    assert_eq!(mounts.on_filesystem(learned).len(), 1);
    assert_eq!(mounts.on_filesystem((learned.0 ^ 1, learned.1)).len(), 0);
    assert_eq!(mounts.as_owned_fds().len(), 1);
}

#[test]
fn one_handles_bytes_on_two_filesystems_are_two_entries() {
    // Identical bytes on two filesystems really do occur — every filesystem
    // falling back to the kernel's synthetic `FILEID_INO64_GEN` encoding hands
    // out the same bytes for its root — so a store keyed on bytes alone would
    // answer with another filesystem's path.
    let handle: FileHandle = vec![4, 4, 4, 4, 4, 4, 4, 4];
    let mut store = HandleCache::new();
    PathStore::insert(&mut store, (1, 0), &handle, PathBuf::from("/fs-one/root"));
    PathStore::insert(&mut store, (2, 0), &handle, PathBuf::from("/fs-two/root"));

    assert_eq!(
        PathStore::get(&store, (1, 0), &handle),
        Some(PathBuf::from("/fs-one/root")),
    );
    assert_eq!(
        PathStore::get(&store, (2, 0), &handle),
        Some(PathBuf::from("/fs-two/root")),
    );
}

// ── A resolver refuses to invent an answer ──

#[test]
fn an_event_that_names_no_object_is_not_reported_as_a_failure() {
    let mut resolver = PathResolver::new(Mounts::new());
    // An overflow event: a mask, no identity record, no fsid.
    let mut overflow = FidEvent::new();
    overflow.set_mask(FAN_Q_OVERFLOW);
    assert_eq!(
        resolver.resolve_event(&mut overflow),
        EventResolution::NothingToResolve,
    );
    assert!(!overflow.has_path());

    // A mount event names a mount, not a file, so there is nothing to resolve.
    let mut mount_event = FidEvent::new();
    mount_event.set_mask(FAN_MNT_ATTACH);
    mount_event.set_mnt_id(42);
    assert_eq!(
        resolver.resolve_event(&mut mount_event),
        EventResolution::NothingToResolve,
    );
}

#[test]
fn an_event_whose_answer_is_unavailable_is_distinguishable_from_one_with_nothing_to_ask() {
    let dir = tmpdir();
    let mut event = event_for(dir.path(), "entry");
    // No mounts and no store: the identity is there, the answer is not.
    let mut resolver = PathResolver::new(Mounts::new());
    assert_eq!(
        resolver.resolve_event(&mut event),
        EventResolution::Unresolvable,
    );
    assert!(!event.has_path());
    // The kernel's own facts are untouched by a failed resolution.
    assert!(event.dfid_name_handle().is_some());
    assert_eq!(event.dfid_name(), Some(std::ffi::OsStr::new("entry")));
}

#[test]
fn an_event_that_already_carries_a_path_is_not_resolved_twice() {
    let dir = tmpdir();
    let mut event = event_for(dir.path(), "entry");
    event.set_path(PathBuf::from("/already/known"));

    let mut resolver = PathResolver::new(Mounts::new());
    assert_eq!(
        resolver.resolve_event(&mut event),
        EventResolution::AlreadyResolved,
    );
    assert_eq!(event.path(), Some(Path::new("/already/known")));

    // And clearing it puts the event back to as-parsed, so the resolver will try
    // again rather than believing a stale answer.
    event.clear_path();
    assert!(!event.has_path());
    assert_eq!(
        resolver.resolve_event(&mut event),
        EventResolution::Unresolvable,
    );
}

// ── A failed resolution leaves the kernel's answer intact ──

#[test]
fn a_resolution_failure_is_not_reported_as_an_io_error() {
    // The confusion this guards against: `resolve_handle` fails with EPERM and
    // the caller concludes the *event* was malformed.  It was not.
    let mut resolver = PathResolver::new(Mounts::new());
    let err = resolver
        .resolve_handle((3, 4), &[0u8; 4])
        .expect_err("four bytes is not a file handle");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}
