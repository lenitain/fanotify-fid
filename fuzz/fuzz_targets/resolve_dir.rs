//! The name-splicing boundary: no name may move the resolved path out of the
//! directory it was resolved from.
//!
//! `resolve_dir` joins a directory path and one entry name.  The directory half
//! is fixed here by a seeded store, so the only variable is the name — and the
//! property is that the answer is always *inside* the base directory, or the
//! name is refused.  A name carrying `/` or NUL is the obvious way out; `..` is
//! the other one, and is refused for the same reason: the kernel never reports
//! it as an entry name, so joining it could only come from crafted bytes.

#![no_main]

use fanotify_fid::handle::{FileHandle, Fsid, HandleCache, Mounts, PathStore};
use fanotify_fid::resolve::PathResolver;
use libfuzzer_sys::fuzz_target;
use std::path::{Component, PathBuf};

fuzz_target!(|data: &[u8]| {
    const FSID: Fsid = (0x5eed, 2);
    let base = PathBuf::from("/srv/base");
    let handle: FileHandle = vec![0u8; 12];

    // A store hit answers the directory half without a syscall, so the only
    // input that matters is `data`.  The store copies what it keeps, so the base
    // is recorded by reference and stays this closure's to compare against.
    let mut store = HandleCache::new();
    PathStore::insert(&mut store, FSID, &handle, base.as_path());
    let mut resolver = PathResolver::with_store(Mounts::new(), store);

    match resolver.resolve_dir(FSID, &handle, data) {
        Ok(path) => {
            assert!(
                path.starts_with(&base),
                "{path:?} escaped {base:?} for name {data:?}"
            );
            assert!(
                !path.components().any(|c| c == Component::ParentDir),
                "{path:?} contains a parent component for name {data:?}"
            );
        }
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::InvalidInput,
            "a refused name must be refused as invalid input"
        ),
    }
});
