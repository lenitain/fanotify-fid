//! Properties that must hold for *every* input, searched with a fixed
//! pseudo-random generator so `cargo test` runs them.
//!
//! These are deliberately not examples: no hand-picked path or handle appears in
//! the assertions, because the point is the shape of the answer — a marker is
//! removed from each component and nowhere else, a resolver never changes its
//! mind about an event, a parser is total over arbitrary bytes.  The generator is
//! a few lines of SplitMix64 rather than a dependency, and its seed is fixed, so
//! a failure is reproducible and the search is the same on every machine.
//!
//! The complementary search is `fuzz/`: the same properties with a coverage
//! -guided input generator.  These exist so the properties hold on every
//! `cargo test` run, not only when a fuzzer is pointed at the crate.

use fanotify_fid::consts::*;
use fanotify_fid::fid::FidEvent;
use fanotify_fid::handle::{FileHandle, Fsid, HandleCache, Mounts, PathMemo};
use fanotify_fid::resolve::{EventResolution, PathResolver};
use std::path::{Path, PathBuf};

/// A tiny deterministic generator.
///
/// SplitMix64: property tests want a repeatable walk over many inputs, and a
/// fixture table large enough to matter is worse than a generator small enough
/// to read.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }
}

const DELETED: &str = " (deleted)";

/// A path component and what one marker-strip must turn it into.
///
/// The generated component sometimes *contains* the marker without ending in
/// it, because `/proc` could not produce that from a real unlink and the
/// function's rule is specifically about the suffix.
fn component(rng: &mut Rng, index: usize) -> (String, String) {
    let mut name = format!("c{index}-{}", rng.below(1000));
    match rng.next() % 4 {
        0 => {
            // Marked: exactly one marker comes off.
            name.push_str(DELETED);
            let stripped = name[..name.len() - DELETED.len()].to_owned();
            (name, stripped)
        }
        1 => {
            // Contains but does not end in the marker: untouched.
            let untouched = format!("{name}{DELETED}-tail");
            (untouched.clone(), untouched)
        }
        _ => {
            let untouched = name.clone();
            (name, untouched)
        }
    }
}

/// One path and the answer `without_deleted_suffix` must give for it.
fn random_path(rng: &mut Rng) -> (PathBuf, PathBuf, bool) {
    let components = 1 + rng.below(5);
    let mut path = PathBuf::from("/");
    let mut expected = PathBuf::from("/");
    let mut marked = false;
    for index in 0..components {
        let (name, stripped) = component(rng, index);
        marked |= name.ends_with(DELETED);
        path.push(&name);
        expected.push(&stripped);
    }
    (path, expected, marked)
}

fn event_at(path: &Path) -> FidEvent<'static> {
    let mut event = FidEvent::new();
    event.set_path(path.to_path_buf());
    event
}

#[test]
fn a_path_component_loses_exactly_one_marker_and_unmarked_paths_are_untouched() {
    let mut rng = Rng::new(0x_F00D_5EED);
    for case in 0..2000 {
        let (path, expected, marked) = random_path(&mut rng);
        let event = event_at(&path);

        assert_eq!(event.is_deleted(), marked, "case {case}: {path:?}");
        assert_eq!(
            event.without_deleted_suffix(),
            Some(expected.clone()),
            "case {case}: {path:?}",
        );

        if !marked {
            // Byte for byte, not merely equal after normalisation.
            let answer = event.without_deleted_suffix().unwrap();
            assert_eq!(
                answer.as_os_str().as_encoded_bytes(),
                path.as_os_str().as_encoded_bytes(),
                "case {case}: an unmarked path must be returned verbatim",
            );
        }

        // The removal is exactly one marker per marked component, and it never
        // changes how many components there are.
        assert_eq!(
            expected.components().count(),
            path.components().count(),
            "case {case}: component count must not change",
        );
    }
}

/// An event that names one entry of a parent directory, owned.
fn event_naming(fsid: Fsid, handle: &[u8], name: &str) -> FidEvent<'static> {
    let mut event = FidEvent::new();
    event.set_mask(FAN_CREATE);
    event.set_fsid(fsid);
    event.set_dfid_name(handle.to_vec(), name.as_bytes().to_vec());
    event
}

fn paths_of(events: &[FidEvent<'_>]) -> Vec<Option<PathBuf>> {
    events
        .iter()
        .map(|event| event.path().map(Path::to_path_buf))
        .collect()
}

#[test]
fn resolving_a_batch_converges_and_a_second_pass_changes_nothing() {
    let mut rng = Rng::new(0x_C0FF_EE00);
    let fsid: Fsid = (0x1234, 0x5678);
    let known: FileHandle = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let unknown: FileHandle = vec![9, 9, 9, 9, 9, 9, 9, 9];

    for case in 0..200 {
        let mut events: Vec<FidEvent<'static>> = (0..1 + rng.below(8))
            .map(|index| {
                if rng.next() & 1 == 0 {
                    event_naming(fsid, &known, &format!("known-{index}"))
                } else {
                    event_naming(fsid, &unknown, &format!("unknown-{index}"))
                }
            })
            .collect();

        // Only the one handle is known, and no syscall may be spent, so what
        // resolves is exactly what the store can answer — a deterministic
        // fixture for a property about the resolver's own bookkeeping.
        let store = HandleCache::new();
        PathMemo::remember(&store, fsid, &known, &PathBuf::from("/known"));
        let mounts = Mounts::new();
        let mut resolver = PathResolver::new(&store, &mounts);
        resolver.set_syscall_fallback(false);

        let first = resolver.resolve_events(&mut events);
        let after_first = paths_of(&events);
        let second = resolver.resolve_events(&mut events);

        // A settled batch has nothing left to resolve.  This is the assertion
        // that used to pass for the wrong reason: while `AlreadyResolved` was
        // counted as resolved, both calls reported the same number *because*
        // both were counting "these already had paths" — the second call looked
        // like it had done the first call's work.  What has to drop to zero is
        // `resolved`, and the events have to show up under `already_resolved`.
        assert_eq!(
            second.resolved, 0,
            "case {case}: a settled batch must not resolve anything new"
        );
        assert_eq!(
            second.already_resolved, first.resolved,
            "case {case}: the second call re-sees exactly what the first resolved",
        );
        assert_eq!(
            paths_of(&events),
            after_first,
            "case {case}: the second pass must not change any path",
        );

        // Every event that names the known parent carries a path, every other
        // one does not, and the count is the number of events with paths.
        let resolved: Vec<bool> = events
            .iter()
            .map(|event| event.dfid_name_handle() == Some(known.as_slice()))
            .collect();
        assert_eq!(
            first.resolved,
            events.iter().filter(|event| event.has_path()).count(),
            "case {case}: `resolved` counts the events the call newly resolved",
        );
        for (event, should_resolve) in events.iter().zip(resolved) {
            assert_eq!(event.has_path(), should_resolve, "case {case}");
            if should_resolve {
                assert!(
                    event.path().is_some_and(|path| path.starts_with("/known")),
                    "case {case}: a resolved path must be the store's answer",
                );
            }
        }
    }
}

#[test]
fn resolve_event_says_exactly_whether_the_event_ended_with_a_path() {
    let mut rng = Rng::new(0x_D15C_0BA1);
    let fsid: Fsid = (7, 11);
    let known: FileHandle = vec![4, 4, 4, 4];
    let unknown: FileHandle = vec![5, 5, 5, 5];

    for case in 0..500 {
        let handle = if rng.next() & 1 == 0 {
            &known
        } else {
            &unknown
        };
        let mut event = event_naming(fsid, handle, "entry");

        let store = HandleCache::new();
        PathMemo::remember(&store, fsid, &known, &PathBuf::from("/known"));
        let mounts = Mounts::new();
        let mut resolver = PathResolver::new(&store, &mounts);
        resolver.set_syscall_fallback(false);

        let outcome = resolver.resolve_event(&mut event);
        let claims_a_path = matches!(
            outcome,
            EventResolution::Resolved | EventResolution::AlreadyResolved
        );
        assert_eq!(
            claims_a_path,
            event.has_path(),
            "case {case}: {outcome:?} against has_path()",
        );

        // An event that is already resolved is reported as such, and resolving
        // it again does not change the answer.
        if event.has_path() {
            let before = event.path().map(Path::to_path_buf);
            assert_eq!(
                resolver.resolve_event(&mut event),
                EventResolution::AlreadyResolved,
            );
            assert_eq!(event.path().map(Path::to_path_buf), before);
        }
    }
}

#[test]
fn arbitrary_bytes_never_panic_either_parser_and_are_always_accounted_for() {
    // The deterministic shadow of `fuzz/fuzz_targets`: the same totality
    // property, run in `cargo test` over buffers that are shaped like events
    // often enough to reach the record walk.
    let mut rng = Rng::new(0x_BADC_0DE5);
    for _ in 0..5000 {
        let mut buf = vec![0u8; rng.below(256)];
        for byte in &mut buf {
            *byte = rng.next() as u8;
        }
        if buf.len() >= 24 && rng.next() & 1 == 0 {
            buf[4] = FANOTIFY_METADATA_VERSION;
            let event_len = (24 + rng.below(32)) as u32;
            buf[..4].copy_from_slice(&event_len.to_ne_bytes());
            buf[6..8].copy_from_slice(&24u16.to_ne_bytes());
        }

        let (_, fid) = fanotify_fid::fid::parse_fid_events_reported(&buf);
        assert_eq!(fid.bytes_consumed + fid.bytes_left, buf.len());

        let (events, fd) = fanotify_fid::fd::parse_fd_events(&buf);
        assert_eq!(fd.bytes_consumed + fd.bytes_left, buf.len());
        assert!(
            events.iter().all(|event| event.fd().is_none()),
            "the byte-level fd parser must never adopt a descriptor",
        );
    }
}
