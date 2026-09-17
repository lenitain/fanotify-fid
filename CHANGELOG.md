# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

0.8.0 is a rewrite rather than a series of additions: the parser became
borrowing, reading and resolving became separate steps, and the items that only
existed to work around the old shape are gone. The version moves for that reason,
and the **Breaking** notes below are the migration path.

### Added

**Reading**

- `EventReader`: a reader that owns its read buffer and its event storage, so a
  loop allocates nothing after the storage has grown and nothing has to be leaked
  to arrange it. `read()` hands out `&mut [FidEvent<'_>]`, so a resolver can
  write a path onto each event in place, and `raw_bytes()` returns the batch
  exactly as the kernel wrote it — the entry point for an architecture that
  cannot keep events across the next read, such as one that copies the batch once
  and parses it on a worker thread (`examples/batch_to_worker.rs`).
- `FdEventReader`: the same reader for descriptor groups. It needs no lifetime
  erasure, because an `FdEvent` owns everything it reports, and its event storage
  is sized for the whole buffer up front (`capacity.div_ceil(24)` slots) so a
  read never grows it. A batch's descriptors stay open until the next read
  replaces the slot or `FdEvent::into_fd` takes one.
- `Fanotify::from_fd()` (`unsafe`): adopt a descriptor that is already a group —
  inherited, received over `SCM_RIGHTS`, or set up before privileges were
  dropped. The caller vouches that it is a fanotify group, the same contract
  `FromRawFd` carries; the returned value owns it, so dropping it closes the
  group and releases its marks. This is what makes the API reachable for a
  process that did not create its own group.
- `FanotifyError::is_would_block()`: whether the error is the `EAGAIN` of an
  empty queue, so a loop does not have to match the raw errno of the right
  variant to tell "nothing queued" from "the read failed".

**Resolving**

- `PathResolver`, `Resolution` and `EventResolution`: resolution is now an
  explicit pass over a batch rather than something that happened inside the read.
  `resolve_events` reports `resolved`, `already_resolved`, `unresolved` and
  `passes` instead of one number that conflated two of them.
- `PathResolver::known()`: the store lookup with no syscall fallback — "do I
  already know this handle?", answered without spending `open_by_handle_at`.
- `PathResolver::store` / `store_mut` / `mounts` / `mounts_mut`: the learning and
  the descriptors are reachable, so a caller can pre-seed, inspect or invalidate
  them.
- `resolve_file_handle_in()`: the other half of `resolve_file_handle`, taking the
  `Candidate` values `Mounts::candidates()` produces instead of a bare
  `&[OwnedFd]`. A bare slice carries no fsid, so `resolve_file_handle` probes
  every descriptor with `fstatfs` on every call; `Mounts` learns each fsid once,
  so this form spends none. It is the call `PathResolver` uses internally.
- `Candidate` and `Mounts::candidates()` are public. `Candidate` pairs a
  descriptor with the fsid known for it, which is what makes the filter sound and
  what a caller needs to drive a resolution itself.
- `HandleCache::path_of()`: a borrowed lookup that allocates nothing. `HandleCache`
  also gained `len`, `is_empty`, `filesystems`, `iter`, `clear` and
  `forget_filesystem`.

**Events**

- `FidEvent::into_owned()`, and the whole borrowed value API built on it: the
  handle, the name, both rename sides and the unknown records are `Cow<'buf,
  [u8]>`, so a parse copies no record's bytes.
- `Pidfd` (`Absent` / `Fd` / `Unavailable`), `FidEvent::{take_pidfd, fd_error,
  access_range, mnt_id}`, and typed `FAN_RENAME` sides. A pidfd record is adopted
  once per buffer and closed on drop.
- `FidEvent::without_deleted_suffix()`, which strips the `" (deleted)"` marker
  from every component rather than the last, and refuses to guess at a path a
  file is legitimately named `foo (deleted)`.
- All the setters a caller needs to build an event by hand (`set_dfid_name`,
  `set_self_handle`, `set_pidfd`, `set_fs_error`, `set_rename_source`,
  `set_rename_target`, `push_unknown_info_record`, …).
- `ParseReport` and `EventStop`, with `parse_fid_events_reported`,
  `parse_fid_events_into`, `parse_fd_events`, `parse_fd_events_into`,
  `read_events_reported` and `read_fd_events_reported`. `bytes_left > 0` now says
  the tail was not interpreted, instead of a short buffer merely yielding fewer
  events.
- `Fanotify::{init, mark_fd, flush_marks, wait_readable}`: `mark_fd` places a
  mark on the object a descriptor names with no path resolution at all.
- 24 new constants, including `FAN_REPORT_MNT`, `FAN_REPORT_FD_ERROR`,
  `FAN_MARK_MNTNS`, `FAN_PRE_ACCESS`, `AT_EMPTY_PATH`, `AT_HANDLE_FID`,
  `FANOTIFY_FID_BITS`, `FANOTIFY_ADMIN_INIT_FLAGS`, `FAN_NOPIDFD`,
  `FAN_EPIDFD`, `MAX_HANDLE_SZ`, `EVENT_F_FLAGS_ALLOWED`, and
  `FANOTIFY_METADATA_VERSION` — which is now enforced rather than assumed.

### Changed

- **Building a group.** `Fanotify::new()` now takes the flags and answers a
  `Result`, and `Fanotify::init()` takes the flags and the `event_f_flags`.
  0.7.1's `Default` added `FAN_CLOEXEC` for you; nothing is added now, so a group
  built without it survives `exec`.
- **Reading events.** `Fanotify::read_events` takes only `&mut Vec<u8>` and
  returns `Result<Vec<FidEvent<'_>>>`: the events borrow the buffer, and their
  `path()` is `None` until a `PathResolver` runs. `read_fd_events` gained the
  same `&mut Vec<u8>` scratch parameter. The buffer's capacity is the read size,
  with a 64 KiB floor.
- **Reading no longer resolves.** 0.7.1's read took the mount descriptors and an
  optional cache and resolved paths inside a fixed 10-pass loop. Resolution is
  now separate, repeatable, and reports what it did.
- **Validation is real.** An unknown `vers` is refused instead of parsed, and a
  `metadata_len` that does not fit its event stops the walk — 0.7.1 read neither
  field.
- **`FidEvent` borrows rather than owns.** Its `path()` is `Option<&Path>`, its
  names are bytes-first (`dfid_name`, `dfid_name_str`, `dfid_name_raw`,
  `dfid_name_os_string`) and a name that is not UTF-8 is no longer dropped, its
  `unknown_info_records()` yields `Cow<'buf, [u8]>`, and it is built with
  `new()` plus setters rather than one six-argument constructor.
- **Preserved records are one record each.** An info record the parser has no
  typed field for is kept verbatim, from its own header to its own end. It used
  to start after the header and run to the end of the event, so the records that
  followed it were stored twice: once inside that entry and once under their own
  typed fields. (`FAN_RENAME`'s two sides and the `RANGE`/`MNT`/`ERROR`/`PIDFD`
  records are typed now, so this only applies to a type the kernel adds next.)
- **Permissions answers.** `FanotifyResponse::{allow, deny, deny_errno,
  audit_rule}` build the common forms, `raw` and `info` cover any decision word
  or record type a newer kernel adds, `with_fd` attaches the descriptor a
  record-carrying answer is matched by, and `info_type`/`info_payload` read one
  back. All of them are built without a heap buffer; `info` with a payload past
  32 bytes spills to exactly one. A response error is a `Write` error, and a
  record that cannot fit is refused before the syscall.
- **Constants.** `FAN_ALL_EVENTS`, `FAN_ALL_PERM_EVENTS` and
  `FAN_ALL_OUTGOING_EVENTS` gained `FAN_ATTRIB`, `FAN_OPEN_EXEC` and
  `FAN_OPEN_EXEC_PERM`; `FAN_ALL_MARK_FLAGS` gained the filesystem, evictable,
  ignore and mount-namespace flags; `FAN_ALL_INIT_FLAGS` gained `FAN_ENABLE_AUDIT`
  and every report flag. The six `FAN_ALL_*` constants are no longer
  `#[deprecated]`. `mask_to_event_names` names the queue-overflow, pre-access,
  mount and child bits it used to skip. The `O_*` constants now come from
  `libc`, which fixes `O_LARGEFILE` on 32-bit targets.
- **Errors.** `FanotifyError` has five variants (`Init`, `Mark`, `Read`,
  `Write`, `UnknownEventVersion`), is `#[non_exhaustive]`, and its messages say
  what the errno means *for that syscall*. Every errno is still the kernel's.
- **A store hit costs one allocation, not two**: the key is no longer copied
  into an owned `Vec` before the lookup. A handle whose filesystem reports
  `f_fsid` zero is still indistinguishable from another such filesystem; the
  docs now say what that costs a store keyed on the pair.
- **`open_by_handle_at` takes any `AsFd`** and opens with `O_PATH | O_CLOEXEC`,
  so it no longer leaks a descriptor across `exec`;
  `name_to_handle_at`/`handle_from_fd` ask for a FID handle and retry without
  `AT_HANDLE_FID` on a kernel that does not know it.
- **MSRV is 1.88** (was 1.85), and the `smallvec` dependency is gone.

### Removed

- `FanotifyBuilder` and its fifteen methods: pass the flags to
  `Fanotify::new`/`init`.
- `FdReader` (`new`, `event_count`, `read`, `read_do`): use
  `Fanotify::read_fd_events(&mut buf)` or `read_fd_events_reported`, or
  `FdEventReader` for a loop.
- `read_fid_events` and `resolve_with_cache`: use `Fanotify::read_events` /
  `parse_fid_events` with a `PathResolver`.
- `write_response` (now internal), `mark_mount`, `read_fd_events_do` and
  `open_mount` (use `Mounts::new().with_fd(...)`).
- `strip_deleted_suffix`: the marker is kept on `path()` and
  `FidEvent::without_deleted_suffix` is the explicit removal.
- `HandleKey`: it is `FileHandle`.
- `FanotifyError::{Handle, Io}` and `impl From<io::Error>`, so `?` on a
  `handle::*` call no longer converts — those functions return `io::Error`.
- `PathStore::lookup` and `Mounts::as_owned_fds`, both added during this release
  and never used by it: the first was a `&self` accessor that no store needing
  `&mut self` or a lock guard can implement, and the second returned a shape
  `iter`/`on_filesystem`/`candidates` already cover.

### Breaking

Read these first; the rest of the entry describes what to migrate *to*.

- `Fanotify::new()` → `Fanotify::new(flags)?`, `Fanotify::init(flags,
  event_f_flags)?`. `FAN_CLOEXEC` is no longer implied.
- `Fanotify::read_events(mount_fds, buf, cache)` →
  `read_events(&mut buf)` plus an explicit `PathResolver` pass. **This one is
  silent:** events no longer carry a path from the read, so code that calls
  `ev.path()` without resolving gets `None` rather than a compile error.
- `FidEvent` carries a lifetime and borrows the buffer; `FidEvent::new` takes no
  arguments and the setters replace the builder-style `with_*` methods;
  `path()` is `Option<&Path>`; `dfid_name_filename()` is `dfid_name_str()`
  (`dfid_name` keeps a non-UTF-8 name instead of dropping it);
  `pidfd()` returns `&Pidfd` and `into_pidfd()` is `take_pidfd()`.
- `unknown_info_records()` yields the record **including its 4-byte header**, so
  a decoder that read the payload must slice `&raw[4..]`; the length is
  `u16::from_ne_bytes([raw[2], raw[3]])` in the host's byte order.
  `push_unknown_info_record` takes that same header-included record.
- `PathStore::get` takes `&mut self` and `PathStore::insert` takes `path: &Path`.
  An implementor changes both receivers. A caller that reached a store through
  `PathResolver::store()` can no longer call `get` on it — use `store_mut()`,
  `known()`, or `HandleCache::path_of`. A raw
  `HashMap<(Fsid, FileHandle), PathBuf>` is no longer a store: `HandleCache` is
  one.
- `PathResolver::resolve_events` returns `Resolution` rather than `usize`. The
  old number counted already-resolved events as resolved, so it reported the
  same count for a settled batch as for the call that had just resolved it; a
  caller that wants that total asks for `resolved + already_resolved`.
- A `DFID_NAME` record naming a directory's own entry (`.`) resolves to the
  directory rather than to `dir/.`: the same path to `Path::components`, a
  different string to `display`, to `==`, or to a `HashMap` key.
- Constants: `FAN_ALL_EVENTS`, `FAN_ALL_PERM_EVENTS`, `FAN_ALL_OUTGOING_EVENTS`,
  `FAN_ALL_MARK_FLAGS` and `FAN_ALL_INIT_FLAGS` have different values.
- `FANOTIFY_METADATA_VERSION` is public, and a buffer whose `vers` differs is
  refused with `UnknownEventVersion` instead of parsed.

### Fixed

- An info record with no typed field no longer absorbs the records that follow
  it — see the note under Changed. `tests/fid_identity.rs` pins it with two
  records, one unknown and one typed.
- A settled batch is no longer reported as newly resolved. `resolve_events`
  counted `AlreadyResolved` towards its result, so a second call on a batch that
  had not changed reported the same number as the call that resolved it, and a
  progress check could not detect the absence of progress.
- A read that fails leaves nothing of the previous batch behind. Both readers
  cleared `bytes_read` and their event storage *after* the read succeeded, so an
  error — `EAGAIN` on an empty queue above all — left `raw_bytes()` answering
  with the previous batch, the fd reader still holding that batch's descriptors,
  and the FID reader still holding its pidfds. A caller that copies `raw_bytes`
  on the error path, which is what `examples/batch_to_worker.rs` demonstrates,
  would process the previous batch twice. `Fanotify::read_events` clears its
  caller's buffer on failure for the same reason: a length left over from a
  successful read must not make an empty queue look like a batch.
- `Mounts::add` no longer leaves a stray fsid behind when duplicating the
  descriptor fails.
- A read interrupted by a signal is retried rather than reported, so no read
  path surfaces `EINTR`. `wait_readable` still reports the `EINTR` of `poll`,
  because retrying there would be a decision about the caller's loop.
- Documentation corrections, each of which described behavior the code does not
  have: `resolve_dir` claimed a borrowed-path fast path that does not exist;
  `Resolution::passes` claimed to count the confirming pass (it describes the
  last productive one); `EventReader`'s safety argument covered neither its
  second `unsafe` block nor drop order, and now states the invariant that keeps
  the lifetime erasure sound — nothing in `FidEvent` may read the buffer when
  dropped, and the next parse overwrites every live slot.

### Tests

- `tests/baseline.rs`: every legal group configuration and every cell that does
  not exist, asserted against the kernel, with the verdict adjusted for the
  capability actually held — because the privilege check runs *before* the
  legality check, so an unprivileged run sees `EPERM` where a privileged one
  sees `EINVAL`.
- `tests/allocation.rs`: the costs the API promises, asserted with a counting
  global allocator — a permission response built and written without allocating,
  1000 empty-queue reads without allocating, a warm reader without allocating, a
  store hit costing exactly the path it returns, and `path_of` costing nothing.
  An absent cost is not something a behavioural test can observe.
- `tests/properties.rs`: convergence, parser totality and the deleted-marker
  rules as properties rather than examples.
- `fuzz/`: three cargo-fuzz targets (`parse_fid_events`, `parse_fd_events`,
  `resolve_dir`).
- `examples/batch_to_worker.rs`: read a batch, copy its bytes once, parse them on
  a worker thread — the architecture the borrowing model cannot serve directly,
  and the one that shows why `raw_bytes` exists.


## [0.7.1] - 2026-09-16

No breaking changes — this release only adds API. `FidEvent::new`'s signature is
unchanged, `FidEvent`'s fields are private, and every item that existed in 0.7.0
still exists with the same name and signature, so an existing caller compiles and
behaves as before. The version moves because the release adds public API, not
because anything stopped working.

### Added

- `handle_from_fd()`: the descriptor-based counterpart of `name_to_handle_at`,
  for an object the caller already has open. It encodes the same handle bytes a
  FID event carries, without re-resolving a path — so it cannot be raced by a
  concurrent rename, needs no privileges, and lets a caller priming a
  handle->path cache do it in the same pass as a tree walk instead of a second
  one by path. `name_to_handle_at` keeps its exact behaviour; both now share one
  implementation of the syscall and its `EOVERFLOW` retry.
- Constants `FAN_EVENT_INFO_TYPE_PIDFD` (4), `_ERROR` (5), `_RANGE` (6),
  `_MNT` (7), `_OLD_DFID_NAME` (10) and `_NEW_DFID_NAME` (12).
- `FAN_RENAME` payloads are parsed: `FidEvent::rename_source()` and
  `FidEvent::rename_target()` each return a `RenameSide { handle, name }`. The
  handle identifies the parent directory and `name` the entry within it, matching
  the kernel's use of `fanotify_event_info_fid` for record types 10 and 12.
  These are deliberately **not** overloaded onto `dfid_name_handle()` /
  `dfid_name_filename()`.
- `FAN_REPORT_PIDFD` payloads are parsed: `FidEvent::pidfd()` returns
  `Option<BorrowedFd<'_>>` and `FidEvent::into_pidfd()` transfers the
  `OwnedFd`. The descriptor is owned by the event and closed on drop, so it no
  longer leaks.
- `FAN_FS_ERROR` payloads are parsed: `FidEvent::fs_error()` returns
  `Option<(i32, u32)>` (negative errno, merged error count).
- `FidEvent::unknown_info_records()` exposes `&[(u8, Vec<u8>)]` — every record
  the parser had no typed field for, as `(info_type, payload)`. This covers
  `RANGE`, `MNT`, any future kernel type, **and** recognised types whose payload
  failed its bounds check, so "data was dropped" is observable rather than
  silent. An empty slice means the event was fully understood.
- `FidEvent::with_pidfd`, `with_fs_error`, `with_rename_source`,
  `with_rename_target` and `push_unknown_info_record` for constructing events
  by hand.
- `FidEvent::set_dfid_name` and `set_self_handle`, so a caller can synthesise
  one event from another while keeping the handle/name pair that path resolution
  relies on.

### Changed

- `FidEvent`'s `PartialEq` is written out by hand instead of derived, because
  `OwnedFd` has no `PartialEq` to derive through. For any event obtainable
  before this release the result is identical: the fields it adds compare equal
  when empty, which is always the case for events built through
  `FidEvent::new`. `Clone` is still derived — with a pidfd present it shares the
  descriptor rather than closing it twice.
- `src/lib.rs` and `README.md` no longer claim a blanket `CAP_SYS_ADMIN`
  requirement. Creating a `FAN_CLASS_NOTIF` FID group needs no privilege; only
  mount/filesystem marks, the unlimited-resource flags, `FAN_REPORT_PIDFD` /
  `FAN_REPORT_TID` and the permission classes do. Both docs now state which is
  which.

### Fixed

- The parser previously recognised three of the eight info record types the
  kernel defines and dropped everything else through `_ => {}` — silently, with
  no return value, counter or log line to tell a caller that data had been
  discarded. `FAN_RENAME` was the worst case: its entire payload lives in two
  records that were dropped, so the event arrived as a bare mask.
- `FAN_RENAME` events no longer resolve to an empty path with no name.
- The pidfd from a `FAN_REPORT_PIDFD` record is no longer leaked.

## [0.7.0] - 2026-08-02

### Added

- `PathStore` trait: plug any handle->path cache (bounded, TTL, ...) into
  `read_fid_events` / `resolve_with_cache` instead of the fixed `HashMap`.

### Changed

- `resolve_with_cache` now takes `mount_fds` and performs a three-tier
  lookup: batch-internal knowledge + persistent cache, then an
  `open_by_handle_at` syscall fallback for deleted objects. Pass `&[]` to
  opt out of the syscall tier.
- `read_fid_events`' cache parameter is generic over `PathStore`.
- `resolve_file_handle` strips the `" (deleted)"` suffix that
  `/proc/self/fd` appends to unlinked objects (consumers never want it).

### Breaking

- `resolve_with_cache` signature changed (added `mount_fds`, generic cache).
- `read_fid_events` cache parameter type changed to `Option<&mut C: PathStore>`.

## [0.6.0] - 2026-07-27

### Breaking Changes

- **`FdEvent` fd field changed from `i32` to `Option<OwnedFd>`**: Constructing an `FdEvent`
  now requires transferring ownership of the file descriptor. Pass `None` for overflow events
  (where `mask` contains `FAN_Q_OVERFLOW`).
- **`FdEvent::fd()` returns `Option<BorrowedFd<'_>>` instead of `i32`**: The returned
  `BorrowedFd` is lifetime-bound to the event, preventing use-after-close.
- **Added `FdEvent::into_fd()`**: Consumes the event and returns `Option<OwnedFd>`,
  transferring fd ownership to the caller.
- **Removed `impl Drop for FdEvent`**: `OwnedFd` handles closing automatically.
- **`FanotifyResponse` now has a lifetime parameter**: `FanotifyResponse<'a>` ties the
  response's lifetime to the event's file descriptor via `BorrowedFd<'a>`, preventing
  use-after-close bugs at compile time.
- **`FanotifyResponse::new()` takes `BorrowedFd<'a>` instead of `i32`**.
- **`FanotifyResponse::fd()` returns `BorrowedFd<'a>` instead of `i32`**.
- **Removed `Clone` from `FanotifyResponse`**: `BorrowedFd` is not cloneable, and responses
  are consumed by `write_response` anyway.
- **`write_response()` and `Fanotify::send_response()` now take `&FanotifyResponse<'_>`**.

### Migration Guide

```rust
// BEFORE (0.5.x)
let ev = FdEvent::new(mask, raw_fd, pid, path);
let fd = ev.fd(); // i32
let resp = FanotifyResponse::new(fd, FAN_ALLOW);

// AFTER (0.6.0)
let ev = FdEvent::new(mask, Some(owned_fd), pid, path);
let fd = ev.fd(); // Option<BorrowedFd<'_>>
let resp = FanotifyResponse::new(fd.unwrap(), FAN_ALLOW);

// For overflow events:
let ev = FdEvent::new(FAN_Q_OVERFLOW, None, 0, PathBuf::new());
assert!(ev.fd().is_none());
```

## [0.5.0] - 2026-06-29

### Fixed

- **ZFS compatibility**: `open_mount()` now uses `O_DIRECTORY` instead of `O_PATH` to
  resolve path resolution failures on ZFS file systems. ZFS's `open_by_handle_at`
  implementation requires a directory file descriptor to correctly identify mount points.

### Changed

- **Event struct fields are now private** ([C-STRUCT-PRIVATE](https://rust-lang.github.io/api-guidelines/interoperability.html#types-are-send-and-sync-where-possible-c-send-sync)):
  - `FidEvent`: fields `mask`, `pid`, `path`, `dfid_name_handle`, `dfid_name_filename`, `self_handle` are now private
  - `FdEvent`: fields `mask`, `fd`, `pid`, `path` are now private
  - `FanotifyResponse`: fields `fd`, `response` are now private
  - Added constructors: `FidEvent::new()`, `FdEvent::new()`, `FanotifyResponse::new()`
  - Added getter methods for all fields

- **`FidEvent` implements `PartialEq` and `Eq`** ([C-COMMON-TRAITS](https://rust-lang.github.io/api-guidelines/interoperability.html#commonly-used-types-should-be-the-same-c-common-traits))

### Migration Guide

**Struct field access** (breaking):

```rust
// Before (0.4.x)
let ev: FidEvent = ...;
println!("pid={} path={}", ev.pid, ev.path.display());

// After (0.5.0)
let ev: FidEvent = ...;
println!("pid={} path={}", ev.pid(), ev.path().display());
```

**Struct construction** (breaking):

```rust
// Before (0.4.x)
let resp = FanotifyResponse { fd: 5, response: FAN_ALLOW };

// After (0.5.0)
let resp = FanotifyResponse::new(5, FAN_ALLOW);
```

## [0.4.1] - 2026-06-22

### Added

- **`mark_at()` method for TOCTOU-safe fd-based marking**: New method on `Fanotify` that
  accepts a directory fd as anchor instead of using `AT_FDCWD`.
  Combined with `O_NOFOLLOW | O_DIRECTORY` when opening the `dir_fd`,
  this eliminates TOCTOU race conditions between path resolution and
  `fanotify_mark()` calls.

  ```rust
  use fanotify_fid::prelude::*;
  use std::fs::OpenOptions;
  use std::os::unix::fs::OpenOptionsExt;
  use std::path::Path;

  let fan = Fanotify::new().report_fid().init().unwrap();
  let dir_fd = OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
      .open("/some/dir")
      .unwrap();

  fan.mark_at(&dir_fd, FAN_MARK_ADD, FAN_CREATE | FAN_DELETE, Path::new(".")).unwrap();
  ```

## [0.4.0] - 2026-06-14

### Breaking Changes

- **`mask_to_event_names` returns iterator instead of `Vec`**: Eliminates heap allocation on every call.
  - `mask_to_event_names(mask)` now returns `impl Iterator<Item = &'static str>` instead of `Vec<&'static str>`
  - `FidEvent::event_names()` and `FdEvent::event_names()` also return iterators
  - Callers that need a `Vec` should use `.collect()`: `let names: Vec<&str> = ev.event_names().collect();`
  - Callers that only iterate can now do so without allocation: `for name in ev.event_names() { ... }`

### Removed

- Dead code: removed unused `_fake_handle` variable in test

## [0.3.1] - 2026-06-12

### Breaking Changes

- **Renamed `Legacy*` to `Fd*`**: The "legacy" naming was misleading — fd-based and FID-based
  fanotify modes are both actively maintained, parallel interfaces in the Linux kernel.
  - `LegacyEvent` → `FdEvent`
  - `LegacyReader` → `FdReader`
  - `read_legacy()` → `read_fd_events()`
  - `read_legacy_do()` → `read_fd_events_do()`
  - `tests/legacy.rs` → `tests/fd.rs`

## [0.3.0] - 2026-06-09

### Breaking Changes

- **Removed global state**: Deleted `legacy_buffer_events()` and `set_legacy_buffer_events()` functions.
  These were global configuration functions that affected all callers, causing potential issues with:
  - Cross-thread interference
  - Test isolation
  - Unexpected behavior for library users

- **Replaced free functions with `FdReader` builder**:
  - Removed: `read_legacy(fan_fd)` → Use `FdReader::new().read(fan_fd)`
  - Removed: `read_legacy_do(fan_fd, callback)` → Use `FdReader::new().read_do(fan_fd, callback)`

- **Hidden internal types from public API**:
  - `FanMetadata`: `pub` → `pub(crate)` (kernel ABI struct, not for external use)
  - `FanInfoHeader`: `pub` → `pub(crate)` (kernel ABI struct, not for external use)
  - `error_desc` module: merged into `error.rs` (no longer a separate module)

### Added

- `FdReader` struct with builder pattern for reading fd-based fanotify events:
  ```rust
  // Basic usage
  let events = FdReader::new().read(&fan_fd)?;

  // Custom buffer size (default: 200 events)
  let events = FdReader::new().event_count(500).read(&fan_fd)?;

  // Callback mode
  FdReader::new().read_do(&fan_fd, |ev| { ... })?;
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
use fanotify_fid::FdReader;

let events = FdReader::new().event_count(500).read(&fan_fd)?;
FdReader::new().read_do(&fan_fd, |ev| { ... })?;
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
  - `tests/fd.rs`: fd-based mode tests
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
- Doc-tests for `name_to_handle_at`, `read_fid_events`, `FdReader::read`, `write_response`.

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

- **fd-based event reading** (`FdReader`): support for non-FID
  fanotify events, including callback mode and configurable buffer via `SmallVec`.
- **Permission event handling**: `write_response` and `FanotifyResponse` type for
  responding to permission-type fanotify events.
- **`FanotifyBuilder`**: builder API with `cloexec()`, `nonblock()`, `class_notif()`,
  `class_content()`, `class_pre_content()`, `report_fid()`, `report_dir_fid()`,
  `report_name()`, `report_target_fid()`, `class_notif()`.
- **`mark_mount()`**: mark an entire mount point for monitoring.
- **`FdEvent`**: RAII wrapper for fd-based event file descriptors.
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
