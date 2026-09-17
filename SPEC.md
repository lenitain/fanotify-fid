# fanotify-fid — specification

Complete reference for `fanotify-fid` 0.8.0: installation, the data model, the behavioral contract, privileges, kernel feature floors, design refusals, and a map of the public API. The crate parses Linux fanotify events and manipulates file handles, handing out what the kernel reports and deciding as little as possible. `rustdoc` is the authority for details; this file states the contracts.

## 1. Installation

```toml
[dependencies]
fanotify-fid = "0.8"
```

* **Linux only.** On any other target the crate fails to compile with `fanotify-fid only supports Linux` (`compile_error!` in `src/lib.rs`); there is no non-Linux stub.
* **Rust 1.88 or newer.** `Cargo.toml` sets `rust-version = "1.88"` and `edition = "2024"`.
* **One dependency:** `libc` (0.2), for the syscalls. `tempfile` is a dev-dependency of the integration tests and is not in a downstream build.
* **Library name** for `use` statements: `fanotify_fid`.

### Examples

```sh
cargo run --example batch_to_worker   # read a batch, copy it once, parse it on another thread
cargo run --example prelude_usage     # the shortest path: one import
```

`batch_to_worker` creates a FID notification group, which needs no privilege, so it runs as any user; resolving the handles it reports needs `CAP_DAC_READ_SEARCH`, and without it every resolution fails with `EPERM` while the events and their names still arrive.

### Tests

```sh
cargo test                                          # unprivileged gate
sudo -E cargo test -- --ignored --test-threads=1    # privileged gate
```

**The unprivileged gate** covers what needs no capability: both byte-level parsers and the `ParseReport` vocabulary, the property searches over arbitrary bytes and generated paths, the constants checked against the running kernel, the allocation guarantees, the reader storage rules, the error vocabulary, and the FID × NOTIF row end to end.

**The privileged gate** runs the `#[ignore]`d tests: the admin-gated descriptor-identity rows in all three classes, every anchor including `FAN_MARK_MOUNT`, `FAN_MARK_FILESYSTEM` and `FAN_MARK_MNTNS`, permission events and both response forms, `open_by_handle_at` through `CAP_DAC_READ_SEARCH`, and a real mount attach event. `--test-threads=1` serialises them, because they place real marks on real filesystems and read real event queues, and serial execution keeps event attribution unambiguous.

**The `SKIPPED:` rule.** A test that finds it cannot run where it is running prints a line beginning `SKIPPED:` to standard error, naming the capability it needs, and returns; such a test still exits 0. A skip is therefore never a pass: the privileged CI job runs the ignored tests with `--nocapture`, captures the output, and fails if `SKIPPED:` appears anywhere in it.

## 2. The data model

### The three identities

An event names its object in one of three ways, each a different wire format:

| Identity | Type | What the event carries |
|---|---|---|
| descriptor | `FdEvent` | an open descriptor the kernel installed for this process, in `metadata.fd` |
| file handle (FID) | `FidEvent` | an fsid plus an opaque filesystem handle, as info records |
| mount | `FidEvent` | a mount ID (`FidEvent::mnt_id`), read by the same reader as FID |

For a FID group, `metadata.fd` is `FAN_NOFD`; the one exception is a `FAN_REPORT_FD_ERROR` group, whose `fd` field may hold a negative errno instead (`FidEvent::fd_error`). A mount event is a FID-format event whose identity record is the mount ID: no handle, no name, no fsid. A FID event never carries a path; turning an fsid and a handle into one is a separate, privileged call (section 3.3).

### The three axes

Two dimensions are chosen at `fanotify_init`, the third at `fanotify_mark`:

| Axis | Chosen at | Values |
|---|---|---|
| **Identity** | `fanotify_init` | descriptor · file handle + fsid (FID) · mount ID |
| **Class** | `fanotify_init` | `FAN_CLASS_NOTIF` · `FAN_CLASS_CONTENT` · `FAN_CLASS_PRE_CONTENT` |
| **Anchor** | `fanotify_mark` | `FAN_MARK_INODE` · `FAN_MARK_MOUNT` · `FAN_MARK_FILESYSTEM` · `FAN_MARK_MNTNS` |

`FAN_CLASS_NOTIF` and `FAN_MARK_INODE` are encoded as **zero**, so "absent" and "chosen" are the same bit pattern; pass them explicitly when you mean them.

### The five legal configurations

| # | Identity | Class | Anchors | Privilege |
|---|---|---|---|---|
| 1 | descriptor | `NOTIF` | inode · mount · filesystem | `CAP_SYS_ADMIN` |
| 2 | descriptor | `CONTENT` | inode · mount · filesystem | `CAP_SYS_ADMIN` |
| 3 | descriptor | `PRE_CONTENT` | inode · mount · filesystem | `CAP_SYS_ADMIN` |
| 4 | FID | `NOTIF` | inode · mount · filesystem | inode anchors need none |
| 5 | mount | `NOTIF` | **`MNTNS` only** | `CAP_SYS_ADMIN` |

The crate can express all five: a group's flags are its `fanotify_init` argument and its marks are `fanotify_mark` arguments, and neither call is filtered, rewritten or judged.

### Where each rule is enforced

| Rule | Checked at |
|---|---|
| identity × class | `fanotify_init` |
| the FID flag dependencies, and `PIDFD` × `TID` | `fanotify_init` |
| mount identity's anchor and mask | `fanotify_mark` |
| `FAN_RENAME`'s need for `FAN_REPORT_NAME` | `fanotify_mark` |
| which anchors the capability allows | `fanotify_mark` |
| whether the filesystem can decode the handles its events carry (`EOPNOTSUPP`) | `fanotify_mark` |

The split matters: a configuration can be legal at `fanotify_init` and refused at `fanotify_mark`, which is the difference between "the flags are wrong" and "the mark is wrong".

### Combinations that do not exist

1. **FID × a permission class.** A permission event must hand the process a descriptor for the object being decided about, and the kernel must hold it until the answer arrives; file-handle identity exists precisely so that the kernel holds *no* descriptor. The kernel refuses the pair with `EINVAL`.
2. **Mount identity × any anchor but `MNTNS`.** A mount event is scoped to a mount namespace, not to an inode, so the anchor is pinned to `FAN_MARK_MNTNS` and the mask to `FAN_MNT_ATTACH` / `FAN_MNT_DETACH`. This is checked at `fanotify_mark`, not at `fanotify_init`: a group can be created for mount events and then be unusable if it is marked wrongly.
3. **`FAN_REPORT_TARGET_FID` without `FAN_REPORT_NAME` and `FAN_REPORT_FID`.** The child's own handle is reported *in addition to* the parent handle and name, so the flags that describe the pair are prerequisites; `FAN_REPORT_NAME` in turn requires `FAN_REPORT_DIR_FID`.

These are not gaps to be filled. The kernel is the authority on them, and the crate checks none of them (section 6).

## 3. Guarantees

### 3.1 Parsing and the borrowing model

1. **A parsed event borrows the buffer it was parsed from.** `FidEvent<'buf>`'s handle and name fields are `Cow<'buf, [u8]>` and are `Cow::Borrowed` for every event `parse_fid_events` produces. *Consequence:* the buffer must outlive the events, the borrow checker enforces it, and the buffer cannot be read into again while events from it are alive.
2. **Parsing copies no record bytes and allocates nothing per record.** The only allocation is the outer event `Vec`, plus the `unknown_info_records` `Vec` of an event that had a record preserved; `parse_fid_events_into` reuses both, so on a buffer of already-seen shape it does no allocation at all. *Consequence:* a whole-filesystem event rate costs no per-event heap traffic.
3. **An event that must outlive the buffer is made owned explicitly.** `FidEvent::into_owned` returns `FidEvent<'static>`, copying exactly the fields that were borrowed; `RenameSide::into_owned` does the same for one side of a rename. An event built by hand (`FidEvent::new` plus setters) is owned from the start.
4. **A `Vec<FidEvent<'buf>>` cannot be reused across two different reads.** The events borrow `buf`, so the `Vec` pins that borrow for as long as it lives, and a read needs the buffer mutably. Reuse within one buffer's lifetime is supported; reuse across reads is `EventReader`'s job, because it owns the buffer and the `Vec` together. *Consequence:* a batch that has to outlive the buffer is either made owned per event (`FidEvent::into_owned`) or copied as **bytes** once, by the caller, through the stateless `Fanotify::read_events*` forms — the crate never guesses which, and `EventReader` deliberately exposes no `raw_bytes` to make the second choice look free when the events still borrow it.
5. **Truncation and malformation are reported, not silent.** `parse_fid_events_reported` and `parse_fid_events_into` return a `ParseReport` whose `bytes_consumed`, `bytes_left` and `EventStop` say how far the walk got and why it stopped; `is_complete()` is true only for `EventStop::End` with `bytes_left == 0`. `parse_fid_events` (and `read_events`) returns an error only for `EventStop::UnknownVersion`, the one condition nothing can be recovered from. *Consequence:* an empty queue and a short buffer cannot be confused.
6. **No input can panic, read out of bounds, or loop forever.** An event whose `event_len` does not fit the buffer stops the walk; a record whose `len` does not fit its event stops that event's record walk with the remainder preserved; a record whose payload is too short is preserved rather than interpreted. Property tests assert this over arbitrary bytes on every `cargo test` run.
7. **A record the crate does not recognise is preserved verbatim, header included**, in `FidEvent::unknown_info_records`, borrowed like every other field, so a type a newer kernel adds survives the parser. The one entry whose bytes are not a single record is a record whose `len` failed its bounds check: that entry holds the rest of the event from that record's header, because the length it claims cannot be walked past.

### 3.2 Reading

1. **A reader owns its storage.** `EventReader` and `FdEventReader` own their read buffer and their event storage, both allocated by `new` and reused by every read after it.
2. **After setup, a read allocates nothing.** The read path only moves the buffer's length; it never grows it. `EventReader`'s event `Vec` grows on the first read that produces events (setup); `FdEventReader` reserves its upper bound (`capacity / 24` slots) in `new`. *Consequence:* an empty-queue read — the `EAGAIN` retry a non-blocking loop makes on every wake-up — costs no allocation, asserted over a thousand reads.
3. **The buffer capacity is the read size and is fixed for a reader's life.** `new(group, capacity)` treats a capacity of zero as 64 KiB. For the stateless `read_events(&self, buf)` forms, the caller's `Vec` capacity is the read size and a zero-capacity `Vec` is grown to 64 KiB; the buffer's contents are otherwise ignored.
4. **The kernel never delivers a partial event.** A buffer too small for the next event earns `EINVAL`; the remedy is a larger buffer, and `capacity()` reports the size in use.
5. **`FdEventReader::raw_bytes()` is the bytes of the last successful read**, exactly as the kernel wrote them, for recording or for replay through the public pure parsers. `EventReader` has no such accessor: its events borrow the same buffer, so the two borrows cannot both be live.
6. **A read that fails leaves nothing behind.** Both readers clear the byte count and the event storage *before* the read, so a failure — `EAGAIN` on an empty queue, `EINVAL` for an oversized event, any other errno — yields no events, and (for `FdEventReader`) empty `raw_bytes` and the previous batch's descriptors closed. *Consequence:* a loop that copies the batch on the error path cannot dispatch the previous one twice.
7. **A signal is retried, not reported.** The crate's own `read` retries `EINTR` internally, so a caller never sees it and no read error means "a signal arrived". `wait_readable` reports `EINTR` instead of retrying, because retrying there would be a decision about the caller's loop.
8. **An empty queue on a non-blocking group is `EAGAIN`, not an empty list.** `FanotifyError::is_would_block()` is true for exactly that case (`Read(EAGAIN)`) and false for the same errno from any other operation. `Fanotify::wait_readable(timeout)` waits for readability (`None` waits indefinitely) and returns whether there is something to read.
9. **Only the read path adopts descriptors.** `Fanotify::read_events` and `EventReader` turn a non-negative pidfd number into `Pidfd::Fd`; a repeated number within one buffer is left unowned, so one descriptor is never closed from two owners. `parse_fid_events` — handed a `&[u8]`, which proves nothing about where its bytes came from — reports `Pidfd::Unavailable(n)` and adopts nothing; `parse_fd_events` reports the `fd` field in `FdEvent::fd_field` and leaves `FdEvent::fd()` as `None`.
10. **An fd-based batch's descriptors are live until the next read replaces them**, or until `FdEvent::into_fd` takes one out. `FdEventReader::read` returns `&[FdEvent]` and `EventReader::read` returns `&mut [FidEvent<'_>]`, so a resolver can write paths in place and no copy per event is needed.
11. **`FdEventReader::raw_bytes` exists and `EventReader`'s does not.** An `FdEvent` owns what it reports, so the bytes of the last read are an independent fact; a `FidEvent` borrows the buffer, so handing out the same bytes would be handing out a second borrow the first one forbids. `FdEventReader::raw_bytes()` is the bytes of the last successful read, empty after a failure.

### 3.3 Path resolution

1. **`PathResolver` is where learned knowledge lives between calls.** `PathResolver<C: PathStore>` holds a store (default `HandleCache`), the `Mounts` it may resolve against, and a syscall-fallback switch. Its reason to exist is the guarantee "one handle resolves to one answer, consistently": while the store holds an answer, every caller of that handle gets it.
2. **A store hit spends no syscall, and reading one costs no copy.** `PathStore` is one operation for reading — `with_path(&self, fsid, handle, f: impl FnOnce(&Path) -> R) -> Option<R>` — and `PathMemo: PathStore` is the separate capability for writing: `remember(&self, fsid, handle, &Path)` and `forget(&self, fsid, handle)`. The closure is what lets a store behind a lock answer without copying and without leaking a guard, while a store whose values are owned in place answers from a plain borrow; both take `&self`, because a resolver holds **one** reference to the store and cannot hold a mutable one for writing beside it. `HandleCache` is an unbounded two-level map behind a `RwLock` (so one `&HandleCache` reads and records) and adds `path_of` for an owned answer; `NoCache` keeps nothing, so every resolution asks the filesystem.
3. **A resolution writes nothing unless a `PathMemo` is passed.** With one, a `DFID_NAME` resolution records the entry's own handle (so a later `FID` record about the same object resolves from the store) and `resolve_dir` records the parent directory it decoded by syscall. Without one, the store is only ever read, which is why the read-only form takes `&self` and can run while the caller holds any number of shared borrows of it.
4. **The fsid filter decides which descriptors may answer.** Only candidates whose fsid matches the event's are tried; an unknown fsid on either side matches, because no evidence is not evidence against. *Consequence:* a descriptor whose fsid could not be read is tried rather than skipped, and the filter's cost is at most one descriptor too many tried, never a wrong path.
4. **`EXDEV` means no candidate was on that filesystem at all** — a registration gap, not a property of the handle. With `set_syscall_fallback(false)` the resolver answers only from its store and never calls `open_by_handle_at`, so an unprivileged process gets `EXDEV` instead of `EPERM` whenever the store has not been taught the answer. Otherwise the error is the last errno of the attempts on a matching filesystem: `EPERM` without `CAP_DAC_READ_SEARCH`, `ESTALE` for a handle the filesystem cannot decode, `EINVAL` for a malformed handle.
5. **`resolve_dir` appends one path component and validates it.** An empty name or `.` returns the directory itself, byte for byte. A name containing `/` or NUL, or equal to `..`, is `InvalidInput` rather than something spliced into the path. The directory half is resolved before the name is validated.
6. **`resolve_event` tries three shapes in order** and lands the first that answers on the event as `FidEvent::path`: the parent handle plus entry name of a `DFID_NAME` record; the source side of a `FAN_RENAME` event; the object's own handle from a `FID`/`DFID` record. It returns an `EventResolution` (`Resolved`, `AlreadyResolved`, `NothingToResolve`, `Unresolvable`) rather than an errno, so "nothing to resolve" and "the answer was unavailable" stay apart. It takes `&self` and never records; `resolve_event_memo` is the same call with a `PathMemo` to teach. A rename's target side is resolved by the separate `resolve_rename_target`, because it names a different parent and costs a syscall the event itself does not imply.
7. **`resolve_events` makes one pass; `resolve_events_memo` repeats until no further event can be resolved.** Repeating is only meaningful when the batch records what it learned — without a memo the second pass would ask the filesystem the same questions again — so the loop belongs to the memo form. The `Resolution` both return describes the last pass that resolved something — `resolved`, `already_resolved`, `unresolved`, and `passes` as that pass's own number, so a batch settled on the first pass reports `passes == 1`. *Consequence:* a second call on a settled batch reports `resolved == 0`, which is what makes the number usable as a progress check.
8. **`resolve_file_handle` and `resolve_file_handle_in` are the same resolution over different inputs.** The first takes a bare `&[OwnedFd]`, which carries no fsid, so it asks the kernel once per descriptor **per call**; the second takes `Candidate`s whose fsids were learned when the descriptors were added (`Mounts::candidates()`), so the filter costs nothing. Prefer the second whenever the descriptors outlive the call.
9. **`Mounts::add` learns each descriptor's fsid from the kernel** (`fsid_of_fd`), records it as unknown if the probe fails, and duplicates the descriptor (`F_DUPFD_CLOEXEC`). `add` is the safe form; `add_with_fsid` exists for a caller that already probed, and a wrong fsid passed there is the one way to get a silent mismatch — the handle opens, the `readlink` succeeds, and the path names a *different, existing* file on another filesystem.
10. **Paths are best-effort and cannot be otherwise.** The only way back from an open handle is `open_by_handle_at` followed by `readlink("/proc/self/fd/N")`, so the answer is the path at that moment; a concurrent rename between the open and the readlink makes it a description of a moment, not an invariant. An unlinked object keeps its `" (deleted)"` marker (section 3.4).
11. **The zero-fsid limitation is the interface's, not a choice.** No `Fsid` value is reserved: `(0, 0)` is a filesystem that reports zero, not a missing one, and it matches like any other value. Some filesystems do report zero — `fanotify(7)` names `fuse(4)` — and the kernel offers no field that separates two such instances, so a filter over the event's own fields cannot either. *Consequence:* two zero-fsid filesystems watched through one group share a slot in the fsid-keyed store; a caller in that position keeps one `Mounts` and one store per filesystem. Everywhere else the fsid is what stops one filesystem's handle bytes from resolving to another's path — several pseudo-filesystems hand out identical bytes for their roots.

### 3.4 The deleted-marker contract

`/proc` appends `" (deleted)"` to the link target of an object that no longer has a name. The crate never removes it on its own, because a file may legitimately *be* named `foo (deleted)`, and no string distinguishes the two cases.

1. **`FidEvent::path()` returns the raw `/proc` answer, marker included.** `None` means no resolution happened, not that the event has no path.
2. **`is_deleted()` reports whether any component ends in `" (deleted)"`**, reading every path component rather than only the last. It is the conservative reading: `true` means "do not treat this as a usable path", not "the kernel unlinked this object". It is `false` when nothing was resolved.
3. **`without_deleted_suffix()` removes one marker from every marked component** and returns the path byte for byte when no component carries one. *Consequence:* a file really named `foo (deleted)` becomes `foo`, and either result may name a different, possibly existing file — which is why the choice is the caller's and not this crate's.
4. **A deleted parent puts the marker in the middle of a path.** Resolving an entry of a deleted directory yields `/srv/gone (deleted)/child`: the entry existed, and this says where. `is_deleted` is true for it, and `without_deleted_suffix` yields `/srv/gone/child`.
5. **An fd-based event has the same raw answer and no marker helpers.** `FdEvent::path()` is the `readlink` result for the descriptor the event holds, marker included; the decision about what the marker means is the caller's there too.

### 3.5 Permission responses

1. **Five constructors cover the wire format.** `allow(fd)`, `deny(fd)` and `deny_errno(fd, errno)` are the 8-byte word; `raw(fd, word)` sends a word the caller chose; `info(decision, info_type, payload)` and `audit_rule(decision, rule)` add a response record. `with_fd(fd)` attaches the descriptor; without it the record-carrying forms write `FAN_NOFD`.
2. **The kernel matches an answer to a pending event by descriptor.** A response that means to answer an event must carry that event's `FdEvent::fd`; a descriptor that names no pending event is `ENOENT`. A form carrying `FAN_NOFD` is validated and then dropped — it answers nothing, which makes it a feature probe for a record type rather than a decision.
3. **The kernel validates every part of the response; the crate filters nothing.** `EINVAL` covers: the response word is a closed set (`FAN_ALLOW | FAN_DENY | FAN_AUDIT | FAN_INFO | errno bits`); exactly one of `FAN_ALLOW`/`FAN_DENY` must be set; a `FAN_INFO` record must have `pad == 0`, a `len` counting the 4-byte header, and a `type` the kernel knows. Today the only record type is `FAN_RESPONSE_INFO_AUDIT_RULE`, whose record is 16 bytes including the header.
4. **`deny_errno` packs the errno into the upper `FAN_ERRNO_BITS` (8) bits** of the word; a wider value is truncated to those bits rather than refused. **The errno channel is meaningful only for a `FAN_CLASS_PRE_CONTENT` group:** every other class converts `FAN_DENY` to `EPERM` without reading those bits, so a `FAN_CLASS_CONTENT` group reaches the blocked caller as `EPERM` whatever was encoded. Which class wants `deny_errno` rather than `deny` is therefore a property of the group, not of the response.
5. **`FAN_AUDIT` needs `FAN_ENABLE_AUDIT` on the group, which needs `CAP_AUDIT_WRITE`** — not `CAP_SYS_ADMIN`. An audited response from a group without the flag is `EINVAL`. `audit_rule` sets `FAN_AUDIT | FAN_INFO` and writes the audit-rule record: the rule number, then the two trust levels the crate writes as the kernel defaults (0).
6. **Building the responses this crate constructs itself allocates nothing.** The plain word and the audit rule are encoded on the stack; a payload handed to `info` that exceeds the inline capacity spills to exactly one `Vec`, and a record whose length does not fit the header's `u16` is refused with `Write(EINVAL)` before the syscall. *Consequence:* answering a blocked operation adds no allocator latency to somebody else's syscall.
7. **An unanswered permission event blocks the file operation** rather than being lost, which is why the answer must be written before the next read replaces the events that carry its descriptor.

### 3.6 Errors and errno pass-through

1. **Every syscall failure carries the kernel's own errno**, in the variant that names the operation: `FanotifyError::Init(i32)`, `Mark(i32)`, `Read(i32)`, `Write(i32)`. `errno()` returns `Option<i32>`, and `matches!(e, FanotifyError::Init(libc::EPERM))` works.
2. **The crate never translates one errno into another**, and never turns a failed syscall into a different kind of answer. What it adds is a description of what that errno means *for that particular syscall*, because the same number means different things to `fanotify_init`, `fanotify_mark`, a read of the queue and a write of a response. That description lives in `Display`; the payload stays the raw number. *Consequence:* `EINVAL` from `init` is about flags, from `mark` about the mask or anchor, and from a response write about a word or record the kernel refused.
3. **Two errnos are the crate's own, and only these two:** `Mark(EINVAL)` for a path containing an interior NUL (a caller error, refused before the syscall), and `Write(EINVAL)` for a short response write. Malformed handle bytes are reported as `io::ErrorKind::InvalidInput` by the `handle` functions, which return `io::Error` rather than `FanotifyError` because they call `name_to_handle_at` / `open_by_handle_at` / `statfs` on no fanotify object.
4. **`FanotifyError::UnknownEventVersion(u8)` is the one variant that is not a syscall failure.** It means `metadata.vers` was not `FANOTIFY_METADATA_VERSION`, so every field after it would be read with the wrong layout; the realistic causes are a descriptor that is not a fanotify group or a kernel that changed the format. `errno()` returns `None` for it.
5. **`is_would_block()` is the one predicate to match on an empty queue**, true only for `Read(EAGAIN)`; the same `EAGAIN` from a response write means something else, and matching the raw errno of the wrong variant is a silent mistake.
6. **`FanotifyError` is `#[non_exhaustive]`**, because the set of operations grows with the kernel surface; a caller matching exhaustively today should not be broken by an addition, and a caller that only cares about the errno uses `errno()`. `Result<T>` is this crate's alias for `std::result::Result<T, FanotifyError>`.

## 4. Privileges

| Needs `CAP_SYS_ADMIN` | Why |
|---|---|
| a `FAN_CLASS_NOTIF` group with no report flag at all | *omitting* a report flag is not the unprivileged choice |
| `FAN_CLASS_CONTENT` / `FAN_CLASS_PRE_CONTENT` | admin-only classes |
| `FAN_MARK_MOUNT` / `FAN_MARK_FILESYSTEM` / `FAN_MARK_MNTNS` | an unprivileged group may place inode marks only — and that limit is about the **anchor**, not the file: marking a root-owned object succeeds |
| `FAN_REPORT_PIDFD`, `FAN_REPORT_TID`, `FAN_REPORT_FD_ERROR` | admin-only init flags |
| `FAN_UNLIMITED_QUEUE`, `FAN_UNLIMITED_MARKS` | admin-only init flags |
| `FAN_FS_ERROR` events | inherited from the filesystem mark they need |
| `FAN_REPORT_MNT` **marks** | creating the group needs nothing — `FAN_REPORT_MNT` is outside the kernel's admin-only init set — while the only anchor such a group accepts, `FAN_MARK_MNTNS`, needs the capability at `fanotify_mark` |

Two capabilities outside that table are separate questions with separate answers:

* **`CAP_DAC_READ_SEARCH`** for `open_by_handle_at`, and therefore for turning a handle into a path (`resolve_file_handle`, `PathResolver`). Receiving events needs nothing; *resolving* them needs the capability that bypasses path permissions. Ownership, file mode and `CAP_DAC_OVERRIDE` are not substitutes. An unprivileged consumer works from the handles and names the events carry, or from `handle_from_fd` on directories it can already open, and needs no privileged syscall at all.
* **`CAP_AUDIT_WRITE`** for `FAN_ENABLE_AUDIT`, without which an audited response (`FAN_AUDIT`, and therefore `FanotifyResponse::audit_rule`) is refused.

An unprivileged group still receives events, but the kernel blanks `metadata.pid` for events caused by *other* processes, so `FidEvent::pid()` and `FdEvent::pid()` degrade to `0` there; `FAN_REPORT_PIDFD` answers the same question without that blanking, and it is admin-only.

A user namespace is not a privileged environment: `CapEff` inside a nested user namespace can be full while fanotify still checks the **initial** user namespace, so `unshare -Ur` earns `EPERM` from `fanotify_init`.

## 5. Kernel feature floors

| Feature | Floor |
|---|---|
| fanotify itself (`fanotify_init`, `fanotify_mark`) | 2.6.36 |
| `name_to_handle_at`, `open_by_handle_at` | 2.6.39 (`ENOSYS` before) |
| FID identity (`FAN_REPORT_FID`) | 5.1 |
| `FAN_REPORT_DIR_FID`, `FAN_REPORT_NAME` | 5.9 |
| an unprivileged FID group (inode marks) | 5.13 |
| `FAN_REPORT_TARGET_FID` | 5.17 |
| `FAN_PRE_ACCESS` | 6.13 |
| `AT_HANDLE_FID` | 6.13 |
| `FAN_REPORT_MNT`, `FAN_MARK_MNTNS` | 6.14 |

**There is no feature detection in this crate, and there should not be.** The way to find out whether a kernel supports something is to ask it and read the errno: `EINVAL` for a flag it does not know, `ENOSYS` for a call it does not have. A version number is a second source of truth, and a wrong one on a distribution kernel that backported the feature. The one adaptation the crate performs is local and specific: `name_to_handle_at` asks for `AT_HANDLE_FID` and, if the kernel answers `EINVAL` for a flag it does not know, retries without it.

**The EPERM-before-EINVAL trap.** A successful call means legal and permitted; a failure means one of two different things, and they are not distinguishable from a single errno:

* `EPERM` — legal, but the caller lacks the capability. **The privilege check runs first**, so an unprivileged caller sees this even for combinations that are also illegal.
* `EINVAL` — the kernel refuses the combination. Only a privileged caller gets to see this for a combination that is both.

*Consequence:* "run it as root" is the only way to settle legality for the admin-only rows of section 2, and a test that expects `EINVAL` for an admin-gated combination must first know the capability is held.

## 6. What this crate deliberately does not do

* **It does not judge legality.** The kernel is the authority. A validation layer here would eventually disagree with it about an errno or a rule, and the cost of that disagreement is a caller sent looking in the wrong place — this crate's check reporting `EINVAL` where the kernel would have said `EPERM`, or refusing something a newer kernel allows. Call the kernel and read its answer.
* **It does not keep state for you.** No record of which paths are marked, no handle→path cache of its own, no eviction policy, no re-scan after an overflow. A mark lives in the kernel and dies with the inode or the group; a cache is a policy about memory and staleness that only the caller can choose. There is no `Mark` type and no way to ask the crate what is marked. (`PathResolver` keeps state, but only what the caller puts in its `PathStore`, and the store is the caller's to choose and bound.)
* **It does not walk trees.** An anchor does not recurse: a mark covers its own object and, for events that can be about a child, that object's immediate children. "Watch this tree" is a strategy — one mark per directory, one mount or filesystem mark, or an index the caller already keeps — and which one is right is a property of what is being built.
* **It does not attribute processes.** The pid and pidfd the kernel reports are handed over as reported. `Pidfd` keeps the three cases (no record, descriptor, sentinel number) apart rather than collapsing them into an `Option<i32>`, because reading `-1` or `-2` as a descriptor number would close an unrelated file; what a pid or pidfd *means* about a process is not this crate's to decide.
* **It does not wrap what is already expressible.** No builder hides which flags were passed, no adapter saves a few lines by inventing its own semantics, no wrapper renames a kernel concept. Every anchor, mask, action and response bit is a constant passed through, and every syscall answer is the kernel's.

## 7. Public API reference

`rustdoc` is the authority for details; this is a map. Items marked *prelude* are also reachable through `use fanotify_fid::prelude::*;`.

### Crate root

| Item | Purpose |
|---|---|
| `Fanotify`, `EventReader`, `FdEventReader` *prelude* | the group and its two readers (module `group`) |
| `FidEvent`, `Pidfd`, `RenameSide`, `parse_fid_events`, `parse_fid_events_into`, `parse_fid_events_reported` *prelude* | FID-format events and their parsers |
| `FdEvent`, `parse_fd_events` *prelude* | fd-format events and the non-adopting byte walk |
| `parse::EventStop`, `parse::ParseReport` *prelude* | how far an event walk got, and why it stopped |
| `handle::{Fsid, FileHandle, Candidate, HandleCache, Mounts, NoCache, PathStore, PathMemo, resolve_file_handle, resolve_file_handle_in}` *prelude* | handle identity, where paths are kept, and the syscalls around it |
| `resolve::{PathResolver, Resolution, EventResolution}` *prelude* | batch resolution over a store |
| `response::FanotifyResponse` *prelude* | a permission decision |
| `FanotifyError`, `Result` *prelude* | the error type and the crate's `Result` alias |

### `consts` — the UAPI header, transcribed

Every value is the numeric literal `/usr/include/linux/fanotify.h` gives it, so the file can be compared against the header line by line. No constant carries behaviour and none is validated here; `prelude::*` brings the whole module in.

* **init:** `FAN_CLOEXEC`, `FAN_NONBLOCK`, `FAN_CLASS_NOTIF`, `FAN_CLASS_CONTENT`, `FAN_CLASS_PRE_CONTENT`, `FAN_ALL_CLASS_BITS`, `FAN_UNLIMITED_QUEUE`, `FAN_UNLIMITED_MARKS`, `FAN_ENABLE_AUDIT`, `FAN_REPORT_PIDFD`, `FAN_REPORT_TID`, `FAN_REPORT_FID`, `FAN_REPORT_DIR_FID`, `FAN_REPORT_NAME`, `FAN_REPORT_TARGET_FID`, `FAN_REPORT_FD_ERROR`, `FAN_REPORT_MNT`, `FAN_REPORT_DFID_NAME`, `FAN_REPORT_DFID_NAME_TARGET`, `FANOTIFY_FID_BITS`, `FANOTIFY_ADMIN_INIT_FLAGS`, `FAN_ALL_INIT_FLAGS`
* **mark:** `FAN_MARK_ADD`, `FAN_MARK_REMOVE`, `FAN_MARK_DONT_FOLLOW`, `FAN_MARK_ONLYDIR`, `FAN_MARK_MOUNT`, `FAN_MARK_IGNORED_MASK`, `FAN_MARK_IGNORED_SURV_MODIFY`, `FAN_MARK_FLUSH`, `FAN_MARK_FILESYSTEM`, `FAN_MARK_EVICTABLE`, `FAN_MARK_IGNORE`, `FAN_MARK_INODE`, `FAN_MARK_MNTNS`, `FAN_MARK_IGNORE_SURV`, `FAN_ALL_MARK_FLAGS`
* **paths and handles:** `AT_FDCWD`, `AT_EMPTY_PATH`, `AT_HANDLE_FID`, `MAX_HANDLE_SZ`
* **`event_f_flags`:** `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_APPEND`, `O_NONBLOCK`, `O_DSYNC`, `O_SYNC`, `O_LARGEFILE`, `O_NOATIME`, `O_CLOEXEC`, `EVENT_F_FLAGS_ALLOWED`
* **event mask bits:** `FAN_ACCESS`, `FAN_MODIFY`, `FAN_ATTRIB`, `FAN_CLOSE_WRITE`, `FAN_CLOSE_NOWRITE`, `FAN_OPEN`, `FAN_OPEN_EXEC`, `FAN_MOVED_FROM`, `FAN_MOVED_TO`, `FAN_CREATE`, `FAN_DELETE`, `FAN_DELETE_SELF`, `FAN_MOVE_SELF`, `FAN_Q_OVERFLOW`, `FAN_FS_ERROR`, `FAN_OPEN_PERM`, `FAN_ACCESS_PERM`, `FAN_OPEN_EXEC_PERM`, `FAN_PRE_ACCESS`, `FAN_MNT_ATTACH`, `FAN_MNT_DETACH`, `FAN_EVENT_ON_CHILD`, `FAN_RENAME`, `FAN_ONDIR`, `FAN_CLOSE`, `FAN_MOVE`, `FANOTIFY_MOUNT_EVENTS`, `FAN_ALL_EVENTS`, `FAN_ALL_PERM_EVENTS`, `FAN_ALL_OUTGOING_EVENTS`
* **info record types:** `FAN_EVENT_INFO_TYPE_FID`, `_DFID_NAME`, `_DFID`, `_PIDFD`, `_ERROR`, `_RANGE`, `_MNT`, `_OLD_DFID_NAME`, `_NEW_DFID_NAME`
* **metadata, responses and sentinels:** `FANOTIFY_METADATA_VERSION`, `FAN_ALLOW`, `FAN_DENY`, `FAN_AUDIT`, `FAN_INFO`, `FAN_ERRNO_BITS`, `FAN_ERRNO_SHIFT`, `FAN_ERRNO_MASK`, `FAN_RESPONSE_INFO_NONE`, `FAN_RESPONSE_INFO_AUDIT_RULE`, `FAN_NOFD`, `FAN_NOPIDFD`, `FAN_EPIDFD`
* **display helper:** `EVENT_NAMES`, `mask_to_event_names(mask: u64) -> impl Iterator<Item = &'static str>`

Two traps the module documents: `FAN_CLASS_NOTIF` and `FAN_MARK_INODE` are zero, and `FAN_MARK_MNTNS` is `0x110`, which is `FAN_MARK_FILESYSTEM | FAN_MARK_MOUNT` rather than a fresh bit — treat it as one opaque constant.

### `group`

```rust
impl Fanotify {
    pub fn new(flags: u32) -> Result<Self>;                       // event_f_flags = 0
    pub fn init(flags: u32, event_f_flags: u32) -> Result<Self>;  // the syscall, unfiltered
    pub unsafe fn from_fd(fd: OwnedFd) -> Self;                   // adopt a group created elsewhere
    pub fn mark<P: AsRef<OsStr> + ?Sized>(&self, flags: u32, mask: u64, path: &P) -> Result<()>;
    pub fn mark_at<Fd: AsFd, P: AsRef<OsStr> + ?Sized>(&self, dir_fd: Fd, flags: u32, mask: u64, path: &P) -> Result<()>;
    pub fn mark_fd<Fd: AsFd>(&self, fd: Fd, flags: u32, mask: u64) -> Result<()>;
    pub fn flush_marks(&self) -> Result<()>;
    pub fn read_events<'buf>(&self, buf: &'buf mut Vec<u8>) -> Result<Vec<FidEvent<'buf>>>;
    pub fn read_events_reported<'buf>(&self, buf: &'buf mut Vec<u8>) -> Result<(Vec<FidEvent<'buf>>, ParseReport)>;
    pub fn read_fd_events(&self, buf: &mut Vec<u8>) -> Result<Vec<FdEvent>>;
    pub fn read_fd_events_reported(&self, buf: &mut Vec<u8>) -> Result<(Vec<FdEvent>, ParseReport)>;
    pub fn send_response(&self, response: &FanotifyResponse<'_>) -> Result<()>;
    pub fn wait_readable(&self, timeout: Option<Duration>) -> Result<bool>;
    pub fn as_fd(&self) -> BorrowedFd<'_>;
    pub fn into_inner(self) -> OwnedFd;
}
impl AsFd for Fanotify
```

`mark` anchors the path at `AT_FDCWD`, `mark_at` at a directory descriptor, and `mark_fd` at the object a descriptor names (the kernel's `NULL`-pathname form, which needs a real open — an `O_PATH` descriptor is `EBADF`). `flush_marks` removes every mark of every anchor and leaves the group usable.

```rust
impl<'fan> EventReader<'fan> {
    pub fn new(group: &'fan Fanotify, capacity: usize) -> Self;
    pub fn read(&mut self) -> Result<&mut [FidEvent<'_>]>;
    pub fn read_reported(&mut self) -> Result<(&mut [FidEvent<'_>], ParseReport)>;
    pub fn capacity(&self) -> usize;       pub fn event_capacity(&self) -> usize;
}
impl<'fan> FdEventReader<'fan> {
    pub fn new(group: &'fan Fanotify, capacity: usize) -> Self;
    pub fn read(&mut self) -> Result<&[FdEvent]>;
    pub fn read_reported(&mut self) -> Result<(&[FdEvent], ParseReport)>;
    pub fn raw_bytes(&self) -> &[u8];      pub fn capacity(&self) -> usize;
    pub fn event_capacity(&self) -> usize;
}
```

### `fid`

`fid::METADATA_SIZE` (24), `fid::INFO_HEADER_SIZE` (4) and `fid::FSID_SIZE` (8) are the wire sizes the module documents byte for byte. They are module items, not crate-root re-exports.

```rust
pub fn parse_fid_events(buf: &[u8]) -> Result<Vec<FidEvent<'_>>, FanotifyError>;
pub fn parse_fid_events_reported(buf: &[u8]) -> (Vec<FidEvent<'_>>, ParseReport);
pub fn parse_fid_events_into<'buf>(events: &mut Vec<FidEvent<'buf>>, buf: &'buf [u8]) -> ParseReport;
```

`FidEvent` accessors, one per fact the kernel can report: `mask`, `pid`, `fsid`, `path`, `has_path`, `is_deleted`, `without_deleted_suffix`, `dfid_name_handle`, `dfid_name_raw`, `dfid_name`, `dfid_name_str`, `dfid_name_os_string`, `self_handle`, `pidfd`, `take_pidfd`, `fd_error`, `fs_error`, `access_range`, `mnt_id`, `rename_source`, `rename_target`, `unknown_info_records`, `is_overflow`, `event_names`. Construction and ownership: `new`, `into_owned`, `set_path`, `clear_path`, and a setter per field (`set_mask`, `set_pid`, `set_fsid`, `set_dfid_name`, `set_self_handle`, `set_mnt_id`, `set_access_range`, `set_fs_error`, `set_fd_error`, `set_rename_source`, `set_rename_target`, `set_pidfd`, `push_unknown_info_record`). `FidEvent` and `RenameSide` implement `PartialEq`/`Eq`; `Pidfd` compares what the record said about the process, not which descriptor value holds it. `Pidfd` is `Absent | Fd(Arc<OwnedFd>) | Unavailable(i32)`, with `as_fd`, `into_fd` and `From<OwnedFd>`.

### `fd`

`fd::METADATA_SIZE` (24). `fd::parse_fd_events(buf) -> (Vec<FdEvent>, ParseReport)` and `fd::parse_fd_events_into(&mut Vec<FdEvent>, buf) -> ParseReport` are the non-adopting byte walks. `FdEvent::new(mask, Option<OwnedFd>, pid)`, `set_fd_field`, `mask`, `pid`, `fd`, `into_fd`, `path`, `fd_field`, `no_fd_reason`, `is_overflow`, `event_names`. An event that owns a descriptor closes it when it drops.

### `handle`

```rust
pub type Fsid = (i32, i32);
pub type FileHandle = Vec<u8>;
pub const FILE_HANDLE_HEADER_SIZE: usize = 8;
pub const MAX_FILE_HANDLE_SIZE: usize = FILE_HANDLE_HEADER_SIZE + MAX_HANDLE_SZ;

pub fn handle_from_fd<Fd: AsFd>(fd: Fd) -> io::Result<FileHandle>;
pub fn name_to_handle_at<P: AsRef<Path> + ?Sized>(path: &P) -> io::Result<FileHandle>;
pub fn open_by_handle_at<Fd: AsFd>(mount_fd: Fd, handle: &[u8]) -> io::Result<OwnedFd>;
pub fn fsid_of_path<P: AsRef<Path> + ?Sized>(path: &P) -> io::Result<Fsid>;
pub fn fsid_of_fd<Fd: AsFd>(fd: Fd) -> io::Result<Fsid>;
pub fn resolve_file_handle(mount_fds: &[OwnedFd], fsid: Option<Fsid>, handle: &[u8]) -> io::Result<PathBuf>;
pub fn resolve_file_handle_in<'a, I: IntoIterator<Item = Candidate<'a>>>(
    candidates: I, fsid: Option<Fsid>, handle: &[u8]) -> io::Result<PathBuf>;
```

`handle_from_fd` and `name_to_handle_at` ask for a FID rather than an openable handle, so they work on filesystems with no `fh_to_dentry`; on a pre-6.13 kernel `AT_HANDLE_FID` is retried without. `open_by_handle_at` opens `O_PATH`, so the result names the object and can be `readlink`ed but not read or written.

```rust
pub trait PathStore {
    // Read.  The closure receives the path for the duration of the call, which is
    // what lets a store behind a lock answer without copying and without leaking.
    fn with_path<R>(&self, fsid: Fsid, handle: &[u8], f: impl FnOnce(&Path) -> R) -> Option<R>;
}
impl<T: PathStore + ?Sized> PathStore for &T;   // so `&store` and `store` are one call

pub trait PathMemo: PathStore {
    fn remember(&self, fsid: Fsid, handle: &[u8], path: &Path);   // default: nothing
    fn forget(&self, fsid: Fsid, handle: &[u8]);                  // default: nothing
}
pub struct Candidate<'a> { pub fd: BorrowedFd<'a>, pub fsid: Option<Fsid> }

impl HandleCache {   // Default, Debug; the PathStore default
    pub fn new() -> Self;
    pub fn len(&self) -> usize;                    pub fn is_empty(&self) -> bool;
    pub fn filesystems(&self) -> usize;            pub fn clear(&self);
    pub fn forget_filesystem(&self, fsid: Fsid);
    pub fn entries(&self) -> Vec<(Fsid, FileHandle, PathBuf)>;   // copied out, for inspection
    pub fn with_path<R>(&self, fsid: Fsid, handle: &[u8], f: impl FnOnce(&Path) -> R) -> Option<R>;
    pub fn path_of(&self, fsid: Fsid, handle: &[u8]) -> Option<PathBuf>;  // owned, for a keeper
}
impl Clone for HandleCache;   // a copy of the entries, not a shared handle
pub struct NoCache;  // keeps nothing, implements PathStore only

impl Mounts {
    pub fn new() -> Self;
    pub fn add<Fd: AsFd>(&mut self, fd: Fd) -> io::Result<&mut Self>;
    pub fn with_fd<Fd: AsFd>(mut self, fd: Fd) -> io::Result<Self>;
    pub fn add_with_fsid<Fd: AsFd>(&mut self, fd: Fd, fsid: Fsid) -> io::Result<&mut Self>;
    pub fn on_filesystem(&self, fsid: Fsid) -> Vec<BorrowedFd<'_>>;
    pub fn matching(&self, fsid: Fsid) -> Vec<&OwnedFd>;
    pub fn candidates(&self) -> impl Iterator<Item = Candidate<'_>> + use<'_>;
    pub fn iter(&self) -> impl Iterator<Item = BorrowedFd<'_>>;
    pub fn len(&self) -> usize;                    pub fn is_empty(&self) -> bool;
    pub fn fsid_at(&self, index: usize) -> Option<Fsid>;
}
impl Index<usize> for Mounts { type Output = OwnedFd; }
```

### `resolve`

```rust
// Borrows, not ownership: the store and the mounts live with the caller.
pub struct PathResolver<'a, C: ?Sized = HandleCache> { /* &store, &mounts, syscall_fallback */ }

impl<'a, C: PathStore + ?Sized> PathResolver<'a, C> {
    pub fn new(store: &'a C, mounts: &'a Mounts) -> Self;
    pub fn set_syscall_fallback(&mut self, enabled: bool) -> &mut Self;
    pub fn store(&self) -> &C;                     pub fn mounts(&self) -> &Mounts;

    // Reading: never records, takes `&self`, so the store can be borrowed freely.
    pub fn resolve_handle(&self, fsid: Fsid, handle: &[u8]) -> io::Result<PathBuf>;
    pub fn resolve_dir(&self, fsid: Fsid, handle: &[u8], name: &[u8]) -> io::Result<PathBuf>;
    pub fn resolve_event(&self, event: &mut FidEvent<'_>) -> EventResolution;
    pub fn resolve_rename_target(&self, event: &FidEvent<'_>) -> Option<io::Result<PathBuf>>;
    pub fn known(&self, fsid: Fsid, handle: &[u8]) -> Option<PathBuf>;
    pub fn resolve_events(&self, events: &mut [FidEvent<'_>]) -> Resolution;

    // Recording: the same calls with a memo to teach, and one pass more.
    pub fn resolve_handle_memo<M: PathMemo + ?Sized>(&self, memo: &M, fsid: Fsid, handle: &[u8]) -> io::Result<PathBuf>;
    pub fn resolve_event_memo<M: PathMemo + ?Sized>(&self, memo: &M, event: &mut FidEvent<'_>) -> EventResolution;
    pub fn resolve_events_memo<M: PathMemo + ?Sized>(&self, memo: &M, events: &mut [FidEvent<'_>]) -> Resolution;
}

pub struct Resolution { pub resolved: usize, pub already_resolved: usize,
                        pub unresolved: usize, pub passes: usize }   // Default, Copy
pub enum EventResolution { Resolved, AlreadyResolved, NothingToResolve, Unresolvable } // non_exhaustive
```

### `response`

```rust
impl<'a> FanotifyResponse<'a> {
    pub fn allow(fd: BorrowedFd<'a>) -> Self;
    pub fn deny(fd: BorrowedFd<'a>) -> Self;
    pub fn deny_errno(fd: BorrowedFd<'a>, errno: i32) -> Self;
    pub fn raw(fd: Option<BorrowedFd<'a>>, response: u32) -> Self;
    pub fn info(decision: u32, info_type: u8, payload: impl Into<Cow<'a, [u8]>>) -> Self;
    pub fn audit_rule(decision: u32, audit_rule: u32) -> Self;
    pub fn with_fd(self, fd: BorrowedFd<'a>) -> Self;   pub fn fd(&self) -> Option<BorrowedFd<'a>>;
    pub fn response(&self) -> u32;
    pub fn info_type(&self) -> Option<u8>;              pub fn info_payload(&self) -> Option<&[u8]>;
}
```

### `parse`, `error`, `sys`

`EventStop` is `End | ShortHeader | BadEventLen(u32) | BadMetadataLen | UnknownVersion(u8)`, `#[non_exhaustive]`. `ParseReport { pub bytes_consumed: usize, pub bytes_left: usize, pub stop: EventStop }` with `is_complete()`. `FanotifyError` is `Init(i32) | Mark(i32) | Read(i32) | Write(i32) | UnknownEventVersion(u8)`, `#[non_exhaustive]`, with `errno()`, `is_would_block()`, `Display` and `std::error::Error`.

```rust
pub fn fanotify_init(flags: u32, event_f_flags: u32) -> Result<OwnedFd, FanotifyError>;
pub fn fanotify_mark<Fd: AsFd, P: AsRef<OsStr> + ?Sized>(
    fanotify_fd: Fd, flags: u32, mask: u64, dir_fd: i32, path: &P) -> Result<(), FanotifyError>;
```

Each is the syscall and nothing else: arguments unchanged, return value an `OwnedFd` or the kernel's errno. The crate's other syscall wrappers (`read`, `read_into`, `fanotify_mark_by_fd`) are crate-internal, so the descriptors the crate adopts can only come from a read it performed itself.

### `prelude`

`prelude::*` re-exports `consts::*`; `Candidate`, `FileHandle`, `Fsid`, `HandleCache`, `Mounts`, `NoCache`, `PathMemo`, `PathStore`, `fsid_of_fd`, `fsid_of_path`, `handle_from_fd`, `name_to_handle_at`, `open_by_handle_at`, `resolve_file_handle`, `resolve_file_handle_in`; `EventResolution`, `PathResolver`, `Resolution`; `fanotify_init`, `fanotify_mark`; and `EventReader`, `EventStop`, `Fanotify`, `FanotifyError`, `FanotifyResponse`, `FdEvent`, `FdEventReader`, `FidEvent`, `ParseReport`, `Pidfd`, `RenameSide`, `Result`, `parse_fd_events`, `parse_fid_events`, `parse_fid_events_into`, `parse_fid_events_reported`.

It is curated rather than `pub use crate::*`: the modules `fd`, `fid`, `handle`, `resolve` and `response` stay unglobbed, so a caller that wants an item outside the list names its module.

## 8. Specification vs. implementation

**Contracts.** A caller may rely on these, and a change to one is a breaking change:

* the API in section 7 — item names, signatures, types and trait implementations;
* the behavioral statements in section 3: the borrowing model and the reported parse vocabulary, the readers' ownership and per-read allocation behavior, the raw-bytes rule (fd reader only) and the failed-read rule, the deleted-marker rules, the response forms and descriptor matching, and the errno pass-through with `is_would_block`;
* the privilege and enforcement tables in sections 2 and 4 as descriptions of the kernel's rules: the crate does not enforce them, so what a caller relies on is that the crate does not get in their way;
* the `prelude` contents;
* the wire formats, which are the kernel's: `struct fanotify_event_metadata`, `fanotify_event_info_header`, `fanotify_response`, the info record payloads, and `struct file_handle`.

**Implementation details.** These are current behavior and may change without a breaking release, provided the contracts above still hold:

* the default read size (64 KiB for a zero-capacity buffer or reader) and the number of event slots a reader pre-allocates (`capacity / 24` for `FdEventReader`);
* that `HandleCache` is an unbounded two-level map behind an `RwLock`, that `EventReader` stores its buffer with a lifetime erasure, and that `parse_fid_events_into` reuses an existing event `Vec`;
* the exact `Display` text and errno-description wording;
* that `resolve_file_handle` probes each descriptor's fsid once per call, and that a failure whose errno the platform did not report surfaces as `EIO` from `resolve_file_handle_in`;
* that `name_to_handle_at` retries without `AT_HANDLE_FID` on `EINVAL`;
* the internal response encoding buffer (a 32-byte inline array with a `Vec` spill), as long as the forms that exist today still write their bytes without allocating.
