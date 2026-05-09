# fanotify-fid

Linux fanotify **FID (File Identifier) mode** event parser and file handle utilities.

---

## About this crate

Linux fanotify has two event formats:

| Mode | Init flags | Event size | Path resolution |
|------|-----------|-----------|-----------------|
| **Legacy** | default | Fixed (24 bytes) | Via `metadata.fd` |
| **FID** | `FAN_REPORT_FID` / `FAN_REPORT_DIR_FID` / `FAN_REPORT_NAME` | Variable (each event may include extra info records) | Via `file_handle` → `open_by_handle_at()` |

Existing fanotify crates cover the legacy mode. This crate covers FID mode: it reads variable-length events correctly (using each event's `event_len` field rather than fixed-size steps), parses file handles from info records, and resolves them to paths.

It also provides safe wrappers for `name_to_handle_at()` and `open_by_handle_at()`, the syscalls needed to convert file handles back to paths.

---

## Related crates

| Crate | Scope |
|-------|-------|
| [`fanotify-rs`](https://crates.io/crates/fanotify-rs) | Legacy (non-FID) mode: safe `init`/`mark` wrappers, event reading |
| **fanotify-fid** (this crate) | FID mode: event parsing, file handle resolution |
| [`name-to-handle-at`](https://crates.io/crates/name-to-handle-at) | `name_to_handle_at` / `open_by_handle_at` only |

This crate works standalone (it includes its own `fanotify_init`/`fanotify_mark` wrappers) or alongside `fanotify-rs`.

---

## Quick example

```rust,no_run
use fanotify_fid::prelude::*;
use std::os::fd::OwnedFd;

// 1. Create fanotify group in FID mode
let fan = Fanotify::new()
    .nonblock()
    .report_fid()
    .report_dir_fid()
    .report_name()
    .init()
    .unwrap();

// 2. Add marks (whole filesystem)
fan.mark(
    FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
    FAN_CREATE | FAN_DELETE | FAN_MODIFY,
    "/",
).unwrap();

// 3. Open mount fds for handle resolution
let mount_fds: Vec<OwnedFd> = vec![open_mount("/").unwrap()];

// 4. Read events
let mut buf = Vec::with_capacity(65536);
let events = fan.read_events(&mount_fds, &mut buf, None).unwrap();

for ev in &events {
    println!("{:?} {:?}", ev.event_names(), ev.path);
}
```

> **Note**: Alternatively, use the free functions [`fanotify_init`] and
> [`read_fid_events`] directly if you prefer not to use the `Fanotify`
> wrapper.

---

## Modules

| Module | Key items |
|--------|-----------|
| `consts` | All FAN_* constants for FID mode |
| `types` | `FidEvent`, `FanMetadata`, `HandleKey` |
| `handle` | `name_to_handle_at()`, `open_by_handle_at()`, `resolve_file_handle()` |
| `parse` | `parse_fid_events()`, `resolve_with_cache()` |
| `read` | `read_fid_events()` — read + parse + optional cache |

---

## License

MIT
