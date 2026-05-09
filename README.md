# fanotify-fid

Linux fanotify **FID (File Identifier) mode** event parser and file handle utilities.

---

## What this crate does

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

```rust
use fanotify_fid::prelude::*;

let fan_fd = fanotify_init(
    FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK |
    FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
    0,
).unwrap();

let mut buf = Vec::with_capacity(65536);
let mount_fd = /* open a mount fd on the same filesystem */;
let events = read_fid_events(fan_fd, &[mount_fd], &mut buf, None).unwrap();

for ev in &events {
    println!("[{:?}] {}", ev.event_names(), ev.path.display());
}
```

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
