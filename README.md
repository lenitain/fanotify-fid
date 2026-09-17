# fanotify-fid

A Rust library for Linux `fanotify`: it parses what the kernel reports, resolves
file handles to paths, and writes permission decisions.

[![Crates.io](https://img.shields.io/crates/v/fanotify-fid.svg)](https://crates.io/crates/fanotify-fid)
[![Docs.rs](https://docs.rs/fanotify-fid/badge.svg)](https://docs.rs/fanotify-fid)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

`fanotify` watches operations on objects, reports the process, and
in its permission classes holds the operation inside the kernel until you answer.

What it hands you is a byte stream, in one of three identities: an open descriptor
per event, a **file handle plus fsid** (`FID`), or a mount id. The FID form is the
one that scales to a whole filesystem, because the kernel holds no descriptor per
watched object — and it is variable-length records behind a fixed header, so a
fixed-stride reader parses garbage. This crate reads all three, byte for byte.

```rust
use fanotify_fid::{EventReader, Fanotify, consts::*};

let fan = Fanotify::new(
    FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
        | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
)?;
fan.mark(FAN_MARK_ADD, FAN_CREATE | FAN_EVENT_ON_CHILD, "/srv/data")?;

let mut reader = EventReader::new(&fan, 256 * 1024);
loop {
    match reader.read() {
        Ok(events) if !events.is_empty() => {
            for ev in events {
                println!("{:?} {:?}", ev.event_names().collect::<Vec<_>>(), ev.dfid_name());
            }
        }
        Ok(_) => {}
        Err(e) if e.is_would_block() => {
            fan.wait_readable(None)?;
        }
        Err(e) => return Err(e),
    }
}
```

## Features

- All three identities, all nine info record types, and the fields 0.7.x used to
  drop: both sides of a `FAN_RENAME`, the mount id, the access range, filesystem
  errors, and the pidfd.
- `FidEvent<'buf>` borrows the buffer it was parsed from, so a parse copies no
  record's bytes. `EventReader` owns the buffer and the event storage: one
  allocation for the first batch, none after it.
- `PathResolver` turns handles into paths and remembers what it learned, so a
  batch of events about one directory costs one `open_by_handle_at` instead of one
  per event. Plug in your own cache, or none.
- Permission answers in all their forms, including the audit record and any record
  type a newer kernel adds — built without a heap buffer.
- Every errno is the kernel's. Nothing is pre-validated, so a refusal is the
  kernel's own and says which syscall refused it.
- No hidden state: no table of marked paths, no eviction policy, no silent
  re-scan. Marks live in the kernel; caches are yours.

## Install

```toml
[dependencies]
fanotify-fid = "0.8"
```

Rust 1.88 or newer, one dependency (`libc`). A FID group needs no privilege;
resolving its handles needs `CAP_DAC_READ_SEARCH`.

```sh
cargo run --example batch_to_worker
cargo test
sudo -E cargo test -- --ignored --test-threads=1
```

## Testing

The suite runs against a real kernel, not a mock. `tests/baseline.rs` asserts
every legal group configuration and every combination that must not exist, and
reads the capability actually held, because the privilege check runs before the
legality check. `tests/allocation.rs` counts allocations to hold the API to its
zero-copy claims. `tests/properties.rs` asserts the invariants no example can
show. `fuzz/` has three targets for malformed input. The 32 `unsafe` blocks are
syscall calls, unaligned reads of the kernel's records, and two `OwnedFd`
constructions, each with a `SAFETY` comment.

## Documentation

[SPEC.md](SPEC.md) — the behavioural contract, the five legal group
configurations, the privilege and kernel-version tables, and the test gates.

[rustdoc](https://docs.rs/fanotify-fid) — the API, and the authority whenever
anything disagrees with prose.

[examples/](examples) — `batch_to_worker` reads a batch, copies it once and parses
it on a worker thread; `prelude_usage` is the shortest path in.

## License

MIT
