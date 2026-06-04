# fanotify-fid

[![Crates.io](https://img.shields.io/crates/v/fanotify-fid.svg)](https://crates.io/crates/fanotify-fid)
[![Docs.rs](https://docs.rs/fanotify-fid/badge.svg)](https://docs.rs/fanotify-fid)

Linux fanotify **FID (File Identifier) mode** event parser and file handle utilities.

## Installation

```bash
cargo add fanotify-fid
```

Minimum supported Rust version: **1.85** (edition 2024).

## Requirements

- Linux kernel **≥ 5.1** for FID mode (`FAN_REPORT_FID`)
- Linux kernel **≥ 5.15** for `FAN_REPORT_TARGET_FID`
- **`CAP_SYS_ADMIN`** capability (run as root or with `cap_sys_admin+ep`)

The crate compiles on any platform, but all runtime operations require a Linux
kernel with `CONFIG_FANOTIFY` enabled.  Non-Linux platforms will fail at runtime
with `FanotifyError::Init(ENOSYS)`.

## Testing

### Normal tests (no privileges needed)

```bash
cargo test
```

63 unit tests covering all parsing logic, builder flags, error formatting,
cache resolution, and edge cases (empty buffers, truncated data, garbage
input, etc.).  These run without `CAP_SYS_ADMIN`.

### Integration tests (require root)

7 additional tests verify end-to-end behavior against a real Linux kernel.
Tests are organized by functionality in separate modules:

```bash
cargo test --test fid --test legacy --test permission --test handle --no-run
```

```bash
sudo -E ~/.cargo/bin/cargo test --test fid --test legacy --test permission --test handle -- --ignored
```

Coverage:

| Module | Tests | What it checks |
|--------|-------|----------------|
| `tests/fid.rs` | `test_fid_event_on_single_file` | FID init → mark file → modify → read event |
| `tests/legacy.rs` | `test_legacy_event_lifecycle` | Legacy init → mark file → open → read event |
| `tests/permission.rs` | `test_permission_event_response` | Permission event → `FAN_ALLOW` response → file access granted |
| `tests/handle.rs` | `test_name_to_handle_at_real_path` | `name_to_handle_at` on `/tmp` |
| `tests/handle.rs` | `test_open_by_handle_at_resolve` | `open_by_handle_at` (skips if FS doesn't support it) |
| `tests/handle.rs` | `test_resolve_file_handle` | `resolve_file_handle` end-to-end (skips if unsupported) |
| `tests/handle.rs` | `test_cache_recovers_deleted_path` | `HandleCache` recovery for deleted directories |

Handle-dependent tests (`open_by_handle_at`, `resolve_file_handle`, cache)
check for system support at runtime and skip gracefully if the filesystem
doesn't support file handles (e.g., tmpfs, FUSE, containers without
`CAP_DAC_READ_SEARCH`).

---

## About this crate

Linux fanotify has two event formats:

| Mode | Init flags | Event size | Path resolution |
|------|-----------|-----------|-----------------|
| **Legacy** | default | Fixed (24 bytes) | Via `metadata.fd` |
| **FID** | `FAN_REPORT_FID` / `FAN_REPORT_DIR_FID` / `FAN_REPORT_NAME` | Variable (each event may include extra info records) | Via `file_handle` → `open_by_handle_at()` |

This crate covers both Legacy and FID mode: it reads variable-length events correctly (using each event's `event_len` field rather than fixed-size steps), parses file handles from info records, and resolves them to paths.

It also provides safe wrappers for `name_to_handle_at()` and `open_by_handle_at()`, the syscalls needed to convert file handles back to paths.

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

```
src/
├── consts.rs      # FAN_* constants (FAN_REPORT_FID, FAN_CREATE, ...)
├── types.rs       # FidEvent, FanMetadata, HandleKey
├── handle.rs      # name_to_handle_at(), open_by_handle_at(), resolve_file_handle()
├── parse.rs       # parse_fid_events(), resolve_with_cache()
├── read.rs        # read_fid_events() — read + parse + optional cache
├── error_desc.rs  # Error description helpers (errno → diagnostic string)
└── lib.rs         # Fanotify (Builder + top-level API), re-exports
```

## Error handling

All operations return `Result<T, FanotifyError>`.  Each error variant carries the
raw errno and a **concise diagnostic message** explaining the cause:

```rust,no_run
use fanotify_fid::FanotifyError;

let e = FanotifyError::Init(libc::EPERM);
println!("{}", e);
// Prints: fanotify_init failed (errno=1): Need CAP_SYS_ADMIN capability
```

---

## Design notes

### io-uring

io-uring (`IORING_OP_READ`) was evaluated as a replacement for
`libc::read()` in the event reading path.  In theory it can eliminate the
syscall overhead for fd reads.

**Not used** because for a fanotify fd that is driven by epoll / tokio
`AsyncFd`, the `read()` syscall returns immediately (~50–100 ns).  This is
negligible next to the subsequent `open_by_handle_at()` calls (1–5 µs) and
event parsing — well below the noise floor of the overall pipeline.

If a future workload moves the bottleneck to the read path (e.g.
sub‑microsecond event handlers with very high fanotify event rates),
switching to io-uring would be straightforward — `read()` is the only
syscall that needs replacement.

## License

[MIT License](./LICENSE)
