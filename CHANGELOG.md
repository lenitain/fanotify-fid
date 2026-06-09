# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-09

### Breaking Changes

- **Removed global state**: Deleted `legacy_buffer_events()` and `set_legacy_buffer_events()` functions.
  These were global configuration functions that affected all callers, causing potential issues with:
  - Cross-thread interference
  - Test isolation
  - Unexpected behavior for library users

- **Replaced free functions with `LegacyReader` builder**:
  - Removed: `read_legacy(fan_fd)` → Use `LegacyReader::new().read(fan_fd)`
  - Removed: `read_legacy_do(fan_fd, callback)` → Use `LegacyReader::new().read_do(fan_fd, callback)`

- **Hidden internal types from public API**:
  - `FanMetadata`: `pub` → `pub(crate)` (kernel ABI struct, not for external use)
  - `FanInfoHeader`: `pub` → `pub(crate)` (kernel ABI struct, not for external use)
  - `error_desc` module: merged into `error.rs` (no longer a separate module)

### Added

- `LegacyReader` struct with builder pattern for reading legacy fanotify events:
  ```rust
  // Basic usage
  let events = LegacyReader::new().read(&fan_fd)?;
  
  // Custom buffer size (default: 200 events)
  let events = LegacyReader::new().event_count(500).read(&fan_fd)?;
  
  // Callback mode
  LegacyReader::new().read_do(&fan_fd, |ev| { ... })?;
  ```

### Changed

- **Code organization**: Split `lib.rs` (829 lines) into focused modules:
  - `builder.rs`: `FanotifyBuilder` struct and methods
  - `error.rs`: `FanotifyError` enum, Display impl, and error description helpers (merged from `error_desc.rs`)
  - `fanotify.rs`: `Fanotify` RAII wrapper
  - `sys.rs`: Low-level syscall wrappers (`fanotify_init`, `fanotify_mark`, `open_mount`)
  - `lib.rs`: Now only 85 lines (docs + module declarations + re-exports)

- **Test organization**: Extracted 23 tests from `lib.rs` to `tests/` directory:
  - `tests/consts.rs`: Constant accessibility tests
  - `tests/error.rs`: Error type tests
  - `tests/types.rs`: Event type tests
  - `tests/api.rs`: Public API and prelude tests
  - `tests/common.rs`: Shared test utilities (flat file, not module directory)

- **Internal constants**: Moved size constants (`META_SIZE`, `INFO_HDR_SIZE`, `FSID_SIZE`, `FH_HDR_SIZE`) to `pub(crate)` visibility.

### Migration Guide

```rust
// Before (v0.2.x)
use fanotify_fid::read::{read_legacy, set_legacy_buffer_events};

set_legacy_buffer_events(500);
let events = read_legacy(&fan_fd)?;
read_legacy_do(&fan_fd, |ev| { ... })?;

// After (v0.3.0)
use fanotify_fid::LegacyReader;

let events = LegacyReader::new().event_count(500).read(&fan_fd)?;
LegacyReader::new().read_do(&fan_fd, |ev| { ... })?;
```

## [0.2.5] - 2026-06-05

### Changed

- Extracted error description functions (`errno_desc_init`, `errno_desc_mark`,
  `errno_desc_read`, `errno_desc_handle`) from `lib.rs` into new `error_desc.rs`
  module, reducing `lib.rs` from 1031 to 828 lines.
- Simplified error descriptions from multi-paragraph man-page style to concise
  1-2 line diagnostic messages (e.g., "Invalid flags — check FAN_REPORT_NAME
  requires FAN_REPORT_DIR_FID" instead of 5-10 line explanations).
- Split integration tests into separate modules:
  - `tests/fid.rs`: FID mode tests
  - `tests/legacy.rs`: Legacy mode tests
  - `tests/permission.rs`: Permission event tests
  - `tests/handle.rs`: File handle tests
  - `tests/common/mod.rs`: Shared test utilities

## [0.2.4] - 2026-05-26

### Changed

- `fanotify_mark`: replaced `path.as_bytes().to_vec()` + manual null-termination
  with `CString::new(path.as_encoded_bytes())`, eliminating one heap allocation
  per call. Paths with interior null bytes now return `Err(FanotifyError::Mark(EINVAL))`
  from userspace before any syscall (previously would reach the kernel).
- Removed internal `use std::os::unix::ffi::OsStrExt` import (no longer needed).

## [0.2.3] - 2026-03-28

### Added

- GitHub Actions CI workflow (build + test + fmt + clippy)

- Comprehensive integration tests for `FanotifyBuilder` flag chains and class mode exclusivity.
- Doc-tests for `name_to_handle_at`, `read_fid_events`, `read_legacy`, `write_response`.

### Fixed

- `rust-version` field in `Cargo.toml` set to 1.85 (matching edition 2024 requirements).
- Used named constants instead of magic numbers in internal `read_fid_events_cached`.

### Changed

- Various README improvements: crates.io link, license link, source tree diagram.

## [0.2.2] - 2026-03-20

### Added

- GitHub Actions CI workflow (build + test + fmt + clippy)

- README with source tree diagram, crates.io and license links.

## [0.2.1] - 2026-03-15

### Changed

- Full documentation rewrite with man-page-level error descriptions.
- Each `FanotifyError` variant's `Display` impl now includes detailed guidance
  on common causes, pitfalls, and fixes.
- Integration tests for real fanotify operations (requires root, skipped by default).

### Fixed

- README example fixed to use correct API.

## [0.2.0] - 2026-03-10

### Added

- GitHub Actions CI workflow (build + test + fmt + clippy)

- **Legacy event reading** (`read_legacy`, `read_legacy_do`): support for non-FID
  fanotify events, including callback mode and configurable buffer via `SmallVec`.
- **Permission event handling**: `write_response` and `FanotifyResponse` type for
  responding to permission-type fanotify events.
- **`FanotifyBuilder`**: builder API with `cloexec()`, `nonblock()`, `class_notif()`,
  `class_content()`, `class_pre_content()`, `report_fid()`, `report_dir_fid()`,
  `report_name()`, `report_target_fid()`, `class_notif()`.
- **`mark_mount()`**: mark an entire mount point for monitoring.
- **`LegacyEvent`**: RAII wrapper for legacy event file descriptors.
- **`FanotifyResponse`**: type for permission event responses.
- 26 comprehensive unit tests for the new functionality.
- Missing constants: permission events (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`),
  mark flags (`FAN_MARK_FILESYSTEM`, `FAN_MARK_EVICTABLE`),
  O_* flags for `event_f_flags`.

## [0.1.0] - 2026-02-01

### Added

- GitHub Actions CI workflow (build + test + fmt + clippy)

- Initial release of `fanotify-fid`.
- `fanotify_init` / `fanotify_mark` safe wrappers.
- FID event parsing (`parse_fid_events`) with support for:
  - `FAN_EVENT_INFO_TYPE_FID` (basic file handle events)
  - `FAN_EVENT_INFO_TYPE_DFID` (directory FID events)
  - `FAN_EVENT_INFO_TYPE_DFID_NAME` (directory FID with filename)
- `resolve_file_handle` / `open_by_handle_at` / `name_to_handle_at` for
  resolving `file_handle` to real paths.
- `HandleCache` for caching resolved paths by file handle.
- 30 unit tests for FID event parsing, 6 doc-tests.
- Comprehensive error type with per-variant man-page-level descriptions.
