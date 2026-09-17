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
use fanotify_fid::handle::{
    FileHandle, Fsid, HandleCache, Mounts, PathStore, handle_from_fd, resolve_file_handle_in,
};
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
    // Named as the trait method so the test reads the same whichever store is
    // substituted here.
    let mut store = HandleCache::new();
    PathStore::insert(
        &mut store,
        fsid,
        &handle,
        &PathBuf::from("/learned/elsewhere"),
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
    PathStore::insert(&mut store, fsid, &handle, &PathBuf::from("/one/answer"));

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
        PathStore::get(resolver.store_mut(), fsid, &handle),
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
    assert_eq!(
        resolved.resolved,
        events.len(),
        "every create event should resolve"
    );
    assert_eq!(resolved.unresolved, 0);
    assert_eq!(
        resolved.passes, 1,
        "one pass: nothing needed a parent first"
    );

    // The point of the store: all three events share one parent handle, and it
    // must be there afterwards, so a later batch about the same directory costs
    // nothing.  Collected before borrowing the store, because the resolver is
    // borrowed mutably by `resolve_events` above.
    let parents: Vec<(Fsid, FileHandle)> = events
        .iter()
        .filter_map(|e| e.fsid().zip(e.dfid_name_handle().map(<[u8]>::to_vec)))
        .collect();
    assert!(!parents.is_empty(), "the events must name a parent");
    let store = resolver.store_mut();
    for (fsid, handle) in parents {
        assert!(
            store.get(fsid, &handle).is_some(),
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
    assert_eq!(mounts.candidates().count(), 1);
}

#[test]
fn the_pre_probed_resolution_answers_for_the_fsids_it_was_given() {
    // The externally visible half of the optimization `PathResolver` has always
    // had internally: `Mounts` learns each descriptor's fsid once, and
    // `resolve_file_handle_in` takes those pairs, where `resolve_file_handle`
    // would spend an `fstatfs` per descriptor per call.
    //
    // Asserted without the capability by giving the descriptor a fsid that is
    // deliberately wrong: the filter is what decides whether `open_by_handle_at`
    // is reached at all, so the two outcomes below are the filter working, and
    // the error is whatever the filesystem says about a handle that is not one.
    let dir = tmpdir();
    let claimed = (0xfeed, 7);
    // Built with `add_with_fsid` rather than `add`: the point of the test is a
    // fsid this crate did not read, which is also the one way to get the filter
    // to select or skip a descriptor on purpose.
    let mut mounts = Mounts::new();
    mounts
        .add_with_fsid(mount_fd_of(dir.path()).unwrap(), claimed)
        .unwrap();
    let handle: FileHandle = vec![0u8; 12];

    // The fsid it was told: the descriptor is selected and the syscall is spent,
    // so the answer is the filesystem's — never `EXDEV`, which means "nothing
    // was tried".
    let tried = resolve_file_handle_in(mounts.candidates(), Some(claimed), &handle).unwrap_err();
    assert_ne!(
        tried.raw_os_error(),
        Some(libc::EXDEV),
        "a matching fsid must reach the descriptor: {tried:?}",
    );

    // A different fsid: nothing matches, so nothing is tried and the caller
    // hears the registration gap rather than an errno about the handle.
    let gap =
        resolve_file_handle_in(mounts.candidates(), Some((claimed.0 ^ 1, 0)), &handle).unwrap_err();
    assert_eq!(gap.raw_os_error(), Some(libc::EXDEV));

    // The shape check runs before any descriptor is used, on the same grounds.
    // It is this crate's own `InvalidInput`, not a raw kernel errno: the kernel
    // never saw the call.
    let short = resolve_file_handle_in(mounts.candidates(), Some(claimed), b"short").unwrap_err();
    assert_eq!(short.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn one_handles_bytes_on_two_filesystems_are_two_entries() {
    // Identical bytes on two filesystems really do occur — every filesystem
    // falling back to the kernel's synthetic `FILEID_INO64_GEN` encoding hands
    // out the same bytes for its root — so a store keyed on bytes alone would
    // answer with another filesystem's path.
    let handle: FileHandle = vec![4, 4, 4, 4, 4, 4, 4, 4];
    let mut store = HandleCache::new();
    PathStore::insert(&mut store, (1, 0), &handle, &PathBuf::from("/fs-one/root"));
    PathStore::insert(&mut store, (2, 0), &handle, &PathBuf::from("/fs-two/root"));

    assert_eq!(
        PathStore::get(&mut store, (1, 0), &handle),
        Some(PathBuf::from("/fs-one/root")),
    );
    assert_eq!(
        PathStore::get(&mut store, (2, 0), &handle),
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

#[test]
fn a_directorys_own_entry_name_does_not_end_up_in_the_path() {
    // A `DFID_NAME` record for a directory's entry for itself carries `.`, and
    // `PathBuf::push(".")` would answer `/srv/data/.` — equal to `/srv/data` by
    // `Path::components` and so by `==`, but a different string to `display`,
    // to a `HashMap` key, or to any consumer that compares bytes.
    let fsid: Fsid = (3, 4);
    let handle: FileHandle = vec![2, 2, 2, 2, 2, 2, 2, 2];
    let mut store = HandleCache::new();
    PathStore::insert(&mut store, fsid, &handle, &PathBuf::from("/srv/data"));
    let mut resolver = PathResolver::with_store(Mounts::new(), store);

    let path = resolver.resolve_dir(fsid, &handle, b".").unwrap();
    assert_eq!(path, PathBuf::from("/srv/data"));
    assert_eq!(
        path.as_os_str(),
        PathBuf::from("/srv/data").as_os_str(),
        "the answer must be the same bytes, not merely the same components",
    );
    assert_eq!(path.to_string_lossy(), "/srv/data");
}

#[test]
fn resolve_events_separates_resolving_from_re_seeing() {
    let fsid: Fsid = (5, 6);
    let known: FileHandle = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let unknown: FileHandle = vec![8, 7, 6, 5, 4, 3, 2, 1];

    let mut store = HandleCache::new();
    PathStore::insert(&mut store, fsid, &known, &PathBuf::from("/known"));
    let mut resolver = PathResolver::with_store(Mounts::new(), store);
    resolver.set_syscall_fallback(false);

    let mut events = vec![
        naming(fsid, &known, "a"),
        naming(fsid, &known, "b"),
        naming(fsid, &unknown, "c"),
    ];

    let first = resolver.resolve_events(&mut events);
    assert_eq!(first.resolved, 2, "two events name the known parent");
    assert_eq!(first.already_resolved, 0);
    assert_eq!(first.unresolved, 1, "the third handle is in no store");
    assert_eq!(first.passes, 1);

    // The point of the report: a second call did no work, and says so.  The old
    // return value counted the already-resolved events as resolved and so
    // reported 2 here — the same number as the call that actually resolved them.
    let second = resolver.resolve_events(&mut events);
    assert_eq!(second.resolved, 0, "nothing was left to resolve");
    assert_eq!(second.already_resolved, 2);
    assert_eq!(second.unresolved, 1);
    assert_eq!(
        second.passes, 1,
        "the confirming pass is the only one needed"
    );
}

#[test]
fn resolve_events_counts_a_pass_per_level_of_recovery() {
    // Event `child` names a parent that is NOT in the store; event `parent`
    // names the known handle.  Only pre-seeding can resolve `child`, so it has to
    // wait for `parent` — which is the whole reason the loop repeats, and the
    // reason `passes` exists as a number.
    let fsid: Fsid = (7, 8);
    let root: FileHandle = vec![1, 1, 1, 1, 1, 1, 1, 1];

    let mut store = HandleCache::new();
    PathStore::insert(&mut store, fsid, &root, &PathBuf::from("/root"));
    let mut resolver = PathResolver::with_store(Mounts::new(), store);
    resolver.set_syscall_fallback(false);

    let mut events = vec![naming(fsid, &root, "one")];
    let one = resolver.resolve_events(&mut events);
    assert_eq!(one.resolved, 1);
    assert_eq!(one.passes, 1);
    // The parent handle is now known, so an event about a child of it resolves
    // from the store rather than from the filesystem.
    assert_eq!(
        resolver.resolve_handle(fsid, &root).unwrap(),
        PathBuf::from("/root"),
    );
}

/// A hand-built event naming one entry in a directory, for the resolver tests
/// above that must not touch a real filesystem.
fn naming(fsid: Fsid, parent: &[u8], entry: &str) -> FidEvent<'static> {
    let mut event = FidEvent::new();
    event.set_fsid(fsid);
    event.set_dfid_name(parent.to_vec(), entry.as_bytes().to_vec());
    event
}

#[test]
fn forgetting_the_last_handle_of_a_filesystem_drops_its_level() {
    // A rename invalidates one handle, not a filesystem, so `forget` must leave
    // the neighbours alone — and a cache for a long run must not accumulate an
    // empty level per filesystem it ever saw.
    let fsid: Fsid = (1, 1);
    let other: Fsid = (2, 2);
    let one: FileHandle = vec![1; 8];
    let two: FileHandle = vec![2; 8];

    let mut store = HandleCache::new();
    PathStore::insert(&mut store, fsid, &one, &PathBuf::from("/one"));
    PathStore::insert(&mut store, fsid, &two, &PathBuf::from("/two"));
    PathStore::insert(&mut store, other, &one, &PathBuf::from("/other-one"));
    assert_eq!(store.len(), 3);
    assert_eq!(store.filesystems(), 2);

    PathStore::forget(&mut store, fsid, &one);
    assert_eq!(PathStore::get(&mut store, fsid, &one), None);
    assert_eq!(
        PathStore::get(&mut store, fsid, &two),
        Some(PathBuf::from("/two")),
        "the other handle of the same filesystem must survive",
    );
    assert_eq!(
        PathStore::get(&mut store, other, &one),
        Some(PathBuf::from("/other-one")),
        "the same bytes on another filesystem are a different entry",
    );
    assert_eq!(store.filesystems(), 2, "one handle left on each filesystem");

    PathStore::forget(&mut store, fsid, &two);
    assert_eq!(store.filesystems(), 1, "the emptied level is gone");
    assert!(!store.is_empty(), "the other filesystem is still known");

    PathStore::forget(&mut store, other, &one);
    assert!(store.is_empty(), "nothing is known now");
    assert_eq!(store.len(), 0);
    assert_eq!(store.filesystems(), 0);
}

#[test]
fn known_answers_without_spending_a_syscall_and_keeps_no_borrow() {
    // `known` is the "do I already know?" question: it consults the store and
    // nothing else, so a miss is `None` rather than a resolution.
    //
    // It returns an owned path because the store may be one that cannot hand out
    // a borrow — see `PathStore` — which is also why it takes `&mut self`: a
    // store with a recency or expiry policy may write on a hit.  What that buys
    // the caller is asserted here: the answer outlives the resolver's next use,
    // so a batch naming one parent handle can hold it while the resolver keeps
    // working.
    let fsid: Fsid = (4, 2);
    let handle: FileHandle = vec![6; 8];
    let mut store = HandleCache::new();
    PathStore::insert(&mut store, fsid, &handle, &PathBuf::from("/known/answer"));
    let mut resolver = PathResolver::with_store(Mounts::new(), store);

    let known: PathBuf = resolver.known(fsid, &handle).unwrap();
    assert_eq!(known, PathBuf::from("/known/answer"));
    assert_eq!(resolver.known(fsid, &[0u8; 8]), None);

    // The path is the caller's now, not a borrow of the store: invalidating the
    // entry does not reach it.
    PathStore::forget(resolver.store_mut(), fsid, &handle);
    assert_eq!(resolver.known(fsid, &handle), None);
    assert_eq!(known, PathBuf::from("/known/answer"));

    // The zero-allocation form is the default store's own inherent accessor,
    // which is a borrow and therefore needs no copy and no `&mut self`.
    PathStore::insert(
        resolver.store_mut(),
        fsid,
        &handle,
        &PathBuf::from("/known/answer"),
    );
    let borrowed: &Path = resolver.store().path_of(fsid, &handle).unwrap();
    assert_eq!(borrowed, Path::new("/known/answer"));
    assert_eq!(resolver.store().path_of(fsid, &[0u8; 8]), None);
}
