# fanotify-fid

Linux fanotify **FID (File Identifier) mode** event parser and file handle utilities.

## Installation

```bash
cargo add fanotify-fid
```

Minimum supported Rust version: **1.75** (edition 2024).

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
Build as normal user, run the binary under `sudo`:

```bash
cargo test --test integration --no-run
```

```bash
sudo -E ~/.cargo/bin/cargo test --test integration -- --ignored
```

Coverage:

| Test | What it checks |
|------|----------------|
| `test_fid_event_on_single_file` | FID init → mark file → modify → read event |
| `test_legacy_event_lifecycle` | Legacy init → mark file → open → read event |
| `test_permission_event_response` | Permission event → `FAN_ALLOW` response → file access granted |
| `test_name_to_handle_at_real_path` | `name_to_handle_at` on `/tmp` |
| `test_open_by_handle_at_resolve` | `open_by_handle_at` (skips if FS doesn't support it) |
| `test_resolve_file_handle` | `resolve_file_handle` end-to-end (skips if unsupported) |
| `test_cache_recovers_deleted_path` | `HandleCache` recovery for deleted directories |

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

Existing fanotify crates cover the legacy mode. This crate covers FID mode: it reads variable-length events correctly (using each event's `event_len` field rather than fixed-size steps), parses file handles from info records, and resolves them to paths.

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

| Module | Key items |
|--------|-----------|
| `consts` | All FAN_* constants for FID mode |
| `types` | `FidEvent`, `FanMetadata`, `HandleKey` |
| `handle` | `name_to_handle_at()`, `open_by_handle_at()`, `resolve_file_handle()` |
| `parse` | `parse_fid_events()`, `resolve_with_cache()` |
| `read` | `read_fid_events()` — read + parse + optional cache |

## Error handling

All operations return `Result<T, FanotifyError>`.  Each error variant carries the
raw errno and a **man-page-level description** explaining the cause, common
pitfalls, and troubleshooting steps:

```rust,no_run
use fanotify_fid::FanotifyError;

let e = FanotifyError::Init(libc::EPERM);
println!("{}", e);
// Prints: fanotify_init failed (errno=1): ...
//   The operation is not permitted because the caller lacks
//   the CAP_SYS_ADMIN capability...
```

---

## License

MIT
