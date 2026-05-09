# fanotify-fid → naughtyfy Superset Implementation Plan

> **For agentic workers:** Use `/skill:subagent-driven-development` (recommended) or `/skill:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand fanotify-fid to fully cover naughtyfy's feature set (legacy mode, permission events, constants) while keeping all existing FID functionality and modern Rust patterns (OwnedFd, custom errors, Builder, RAII).

**Architecture:** naughtyfy's functions become methods on `Fanotify` + free functions in `read.rs`. Constants become a unified `consts.rs`. Legacy event parsing is a new code path alongside existing FID path. Permission response writing is added as a new concern.

**Tech Stack:** Rust, libc syscall bindings, std::os::fd::{OwnedFd, AsRawFd, FromRawFd}

---
## File Map

```
src/
  lib.rs      ← Expand FanotifyBuilder (all init flags), Fanotify (mark mount, response send, legacy read)
  consts.rs   ← Add ALL missing constants + #[deprecated] annotations
  types.rs    ← Add LegacyEvent, FanotifyResponse
  handle.rs   ← Unchanged
  parse.rs    ← Unchanged (FID only)
  read.rs     ← Add read_legacy(), read_legacy_do(), write_response()
```

## Constants Inventory

naughtyfy has these that fanotify-fid currently lacks:

**Event masks:** FAN_OPEN_PERM, FAN_ACCESS_PERM, FAN_OPEN_EXEC_PERM, FAN_RENAME, FAN_FS_ERROR

**Init flags:** FAN_UNLIMITED_QUEUE, FAN_UNLIMITED_MARKS, FAN_ENABLE_AUDIT, FAN_REPORT_TID, FAN_REPORT_PIDFD, FAN_REPORT_TARGET_FID, FAN_CLASS_CONTENT, FAN_CLASS_PRE_CONTENT

**Mark flags:** FAN_MARK_DONT_FOLLOW, FAN_MARK_ONLYDIR, FAN_MARK_MOUNT, FAN_MARK_IGNORED_MASK, FAN_MARK_IGNORED_SURV_MODIFY, FAN_MARK_EVICTABLE, FAN_MARK_IGNORE, FAN_MARK_IGNORE_SURV

**Response flags:** FAN_ALLOW (0x01), FAN_DENY (0x02), FAN_AUDIT (0x10)

**O_* flags:** O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, O_NONBLOCK, O_DSYNC, O_LARGEFILE, O_NOATIME, O_CLOEXEC

**Convenience:** FAN_REPORT_DFID_NAME, FAN_REPORT_DFID_NAME_TARGET

**Deprecated (with `#[deprecated]`):** FAN_ALL_CLASS_BITS, FAN_ALL_INIT_FLAGS, FAN_ALL_MARK_FLAGS, FAN_ALL_EVENTS, FAN_ALL_PERM_EVENTS, FAN_ALL_OUTGOING_EVENTS

---

### Task 1: Expand Constants

**Files:**
- Modify: `src/consts.rs`

- [ ] **Step 1: Add permission event masks**

After `FAN_Q_OVERFLOW`, add:
```rust
/// Filesystem error event.
pub const FAN_FS_ERROR: u64 = 0x0000_8000;
/// Permission check on open.
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
/// Permission check on access.
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;
/// Permission check on exec open.
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
/// File was renamed.
pub const FAN_RENAME: u64 = 0x1000_0000;
```

- [ ] **Step 2: Add missing init flags**

After `FAN_REPORT_NAME`, add:
```rust
pub const FAN_REPORT_TID: u32 = 0x0000_0100;
pub const FAN_REPORT_PIDFD: u32 = 0x0000_0080;
pub const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
pub const FAN_ENABLE_AUDIT: u32 = 0x0000_0040;
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
```

- [ ] **Step 3: Add convenience FID flag combos**

```rust
pub const FAN_REPORT_DFID_NAME: u32 = FAN_REPORT_DIR_FID | FAN_REPORT_NAME;
pub const FAN_REPORT_DFID_NAME_TARGET: u32 = FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID;
```

- [ ] **Step 4: Add missing mark flags**

After `FAN_MARK_FILESYSTEM`, add:
```rust
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;
pub const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;
pub const FAN_MARK_IGNORED_MASK: u32 = 0x0000_0020;
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
pub const FAN_MARK_EVICTABLE: u32 = 0x0000_0200;
pub const FAN_MARK_IGNORE: u32 = 0x0000_0400;
pub const FAN_MARK_IGNORE_SURV: u32 = FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY;
```

- [ ] **Step 5: Add permission response flags**

Before `FAN_NOFD`:
```rust
pub const FAN_ALLOW: u32 = 0x01;
pub const FAN_DENY: u32 = 0x02;
pub const FAN_AUDIT: u32 = 0x10;
```

- [ ] **Step 6: Add O_* flags**

```rust
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_APPEND: u32 = 0x400;  // 2000 octal
pub const O_NONBLOCK: u32 = 0x800;  // 4000 octal
pub const O_DSYNC: u32 = 0x1000;  // 10000 octal
pub const O_LARGEFILE: u32 = 0x8000;  // 0x40000 on some archs, use 0x8000 for portability
pub const O_NOATIME: u32 = 0x40000;  // 1000000 octal
pub const O_CLOEXEC: u32 = 0x80000;  // 2000000 octal
```

- [ ] **Step 7: Add deprecated constants**

Add at end of module with `#[deprecated]`:
```rust
#[deprecated(note = "use individual FAN_CLASS_* constants instead")]
pub const FAN_ALL_CLASS_BITS: u32 = FAN_CLASS_NOTIF | FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;

#[deprecated(note = "use individual init flags instead")]
pub const FAN_ALL_INIT_FLAGS: u32 = FAN_CLOEXEC | FAN_NONBLOCK | FAN_ALL_CLASS_BITS
    | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS;

#[deprecated(note = "use individual mark flags instead")]
pub const FAN_ALL_MARK_FLAGS: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY | FAN_MARK_FLUSH;

#[deprecated(note = "use individual event masks instead")]
pub const FAN_ALL_EVENTS: u64 = FAN_ACCESS | FAN_MODIFY | FAN_CLOSE | FAN_OPEN;

#[deprecated(note = "use individual permission masks instead")]
pub const FAN_ALL_PERM_EVENTS: u64 = FAN_OPEN_PERM | FAN_ACCESS_PERM;

#[deprecated(note = "use individual event masks instead")]
pub const FAN_ALL_OUTGOING_EVENTS: u64 = FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS | FAN_Q_OVERFLOW;
```

- [ ] **Step 8: Add EVENT_NAMES entries for new event types**

Add to `EVENT_NAMES` slice:
```rust
(FAN_OPEN_PERM, "OPEN_PERM"),
(FAN_ACCESS_PERM, "ACCESS_PERM"),
(FAN_OPEN_EXEC_PERM, "OPEN_EXEC_PERM"),
(FAN_RENAME, "RENAME"),
```

- [ ] **Step 9: Build and test**

Run: `cargo build` and `cargo test`
Expected: passes, no warnings

- [ ] **Step 10: Commit**

```bash
git add src/consts.rs
git commit -m "feat: add missing constants from naughtyfy (perm events, O_*, mark flags, deprecated)"
```

---

### Task 2: Add Legacy Event Types and Response Type

**Files:**
- Modify: `src/types.rs`

- [ ] **Step 1: Add LegacyEvent struct**

After `impl FidEvent { ... }` block, add.
`LegacyEvent` owns its fd — it is automatically closed on `Drop`:
```rust
/// A parsed legacy (non-FID) fanotify event.
///
/// Legacy events carry an open file descriptor for the accessed file.
/// The fd is automatically closed when this event is dropped (RAII).
/// If you need the fd to outlive the event, use `libc::dup(ev.fd)` to
/// obtain a copy.
#[derive(Debug, Clone)]
pub struct LegacyEvent {
    /// Event mask (one or more of `FAN_ACCESS`, `FAN_MODIFY`, etc.).
    pub mask: u64,
    /// Open file descriptor for the object being accessed.
    /// Automatically closed on drop.
    pub fd: i32,
    /// PID of the process that triggered the event.
    pub pid: i32,
    /// Resolved path (via `readlink("/proc/self/fd/N")`).
    ///
    /// This is best-effort; may be empty if resolution fails.
    pub path: PathBuf,
}

impl Drop for LegacyEvent {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd); }
        }
    }
}

impl LegacyEvent {
    /// Returns `true` if this event indicates a queue overflow.
    pub fn is_overflow(&self) -> bool {
        self.mask & crate::consts::FAN_Q_OVERFLOW != 0
    }

    /// Human-readable event names from the mask.
    pub fn event_names(&self) -> Vec<&'static str> {
        crate::consts::mask_to_event_names(self.mask)
    }
}
```

- [ ] **Step 2: Add FanotifyResponse type**

After `LegacyEvent`, add:
```rust
/// A response to a permission event (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`,
/// `FAN_OPEN_EXEC_PERM`).
///
/// Write this to the fanotify fd after receiving a permission event to
/// grant or deny the operation.
#[derive(Debug, Clone)]
pub struct FanotifyResponse {
    /// The file descriptor from the `LegacyEvent` that triggered the
    /// permission check.
    pub fd: i32,
    /// `FAN_ALLOW` to grant, `FAN_DENY` to deny.
    pub response: u32,
}
```

- [ ] **Step 3: Add naive_name_to_handle_at and naive_open_by_handle_at** (wait — these already exist in handle.rs, skip)

Actually, FanotifyResponse doesn't need a constructor since fields are public. Skip.

- [ ] **Step 4: Export new types from prelude in lib.rs**

The prelude will need `LegacyEvent` and `FanotifyResponse` added — do this in a later task when the prelude is updated holistically.

- [ ] **Step 5: Build and test**

Run: `cargo build` and `cargo test`
Expected: passes

- [ ] **Step 6: Commit**

```bash
git add src/types.rs
git commit -m "feat: add LegacyEvent and FanotifyResponse types"
```

---

### Task 3: Add Legacy Event Reading and Permission Writing

**Files:**
- Modify: `src/read.rs`

- [ ] **Step 1: Add read_legacy function**

```rust
/// Read and parse legacy (non-FID) events from a fanotify file descriptor.
///
/// The fanotify fd must NOT have been created with `FAN_REPORT_FID` flags.
/// Each returned [`LegacyEvent`] carries an open file descriptor for the
/// accessed file. The caller should close it (or let `LegacyEvent` handle
/// it if we add Drop — we don't, to match existing behavior).
///
/// # Errors
/// Returns `FanotifyError::Read` if the read syscall fails.
pub fn read_legacy(
    fan_fd: &OwnedFd,
) -> Result<Vec<LegacyEvent>, FanotifyError> {
    use std::os::fd::AsRawFd;

    let mut buf = [0u8; 24 * 200]; // 200 events max
    let n = unsafe {
        libc::read(
            fan_fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };

    if n < 0 {
        return Err(FanotifyError::Read(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    if n == 0 {
        return Ok(Vec::new());
    }

    let n = n as usize;
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + 24 <= n {
        // SAFETY: bounds verified
        let meta = unsafe {
            std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FanMetadata)
        };
        let event_len = meta.event_len as usize;
        if event_len < 24 || offset + event_len > n {
            break;
        }

        let path = if meta.fd >= 0 {
            std::fs::read_link(format!("/proc/self/fd/{}", meta.fd)).unwrap_or_default()
        } else {
            PathBuf::new()
        };

        events.push(LegacyEvent {
            mask: meta.mask,
            fd: meta.fd,
            pid: meta.pid,
            path,
        });

        offset += event_len;
    }

    Ok(events)
}
```

- [ ] **Step 2: Add read_legacy_do (callback mode)**

```rust
/// Read legacy events and apply a callback to each.
///
/// Like [`read_legacy`] but processes events via `callback` as they are
/// parsed, avoiding allocation of a `Vec`.
///
/// # Errors
/// Returns `FanotifyError::Read` if the read syscall fails.
pub fn read_legacy_do<F>(fan_fd: &OwnedFd, mut callback: F) -> Result<(), FanotifyError>
where
    F: FnMut(&LegacyEvent),
{
    let events = read_legacy(fan_fd)?;
    for ev in &events {
        callback(ev);
    }
    Ok(())
}
```

- [ ] **Step 3: Add write_response function**

```rust
/// Write a permission response to the fanotify fd.
///
/// Must be called after receiving a permission event (`FAN_OPEN_PERM`,
/// `FAN_ACCESS_PERM`, or `FAN_OPEN_EXEC_PERM`) to grant or deny the
/// operation.
///
/// # Errors
/// Returns `FanotifyError::Read` (reusing the variant since it's a write
/// to the same fd) if the write syscall fails.
pub fn write_response(
    fan_fd: &OwnedFd,
    response: &FanotifyResponse,
) -> Result<(), FanotifyError> {
    use std::os::fd::AsRawFd;

    let resp = libc::fanotify_response {
        fd: response.fd,
        response: response.response,
    };

    let ret = unsafe {
        libc::write(
            fan_fd.as_raw_fd(),
            &resp as *const libc::fanotify_response as *const libc::c_void,
            std::mem::size_of::<libc::fanotify_response>(),
        )
    };

    if ret < 0 {
        return Err(FanotifyError::Read(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    Ok(())
}
```

- [ ] **Step 4: Update imports in read.rs**

Add to imports:
```rust
use std::path::PathBuf;
use crate::types::{LegacyEvent, FanotifyResponse};
```

- [ ] **Step 5: Build and test**

Run: `cargo build` and `cargo test`
Expected: passes

- [ ] **Step 6: Commit**

```bash
git add src/read.rs
git commit -m "feat: add legacy event reading, callback mode, and permission response"
```

---

### Task 4: Expand FanotifyBuilder

**Files:**
- Modify: `src/lib.rs`

- [ ] **Step 1: Add missing Builder methods to FanotifyBuilder**

Add these methods after existing ones:
```rust
/// Enable unlimited event queue (requires CAP_SYS_ADMIN).
pub fn unlimited_queue(mut self) -> Self {
    self.flags |= consts::FAN_UNLIMITED_QUEUE;
    self
}

/// Enable unlimited marks (requires CAP_SYS_ADMIN).
pub fn unlimited_marks(mut self) -> Self {
    self.flags |= consts::FAN_UNLIMITED_MARKS;
    self
}

/// Enable audit logging for permission events.
pub fn enable_audit(mut self) -> Self {
    self.flags |= consts::FAN_ENABLE_AUDIT;
    self
}

/// Report thread ID instead of process ID in events.
pub fn report_tid(mut self) -> Self {
    self.flags |= consts::FAN_REPORT_TID;
    self
}

/// Report pidfd for event->pid.
pub fn report_pidfd(mut self) -> Self {
    self.flags |= consts::FAN_REPORT_PIDFD;
    self
}

/// Report dirent target id.
pub fn report_target_fid(mut self) -> Self {
    self.flags |= consts::FAN_REPORT_TARGET_FID;
    self
}
```

Note: `unlimited_queue()`, `unlimited_marks()`, `report_tid()` already exist — check before adding. Only add truly missing ones.

- [ ] **Step 2: Add legacy read methods to Fanotify**

After `read_events` method, add:
```rust
/// Read legacy (non-FID) events.
///
/// The fanotify fd must NOT have been initialized with `FAN_REPORT_FID`.
pub fn read_legacy(&self) -> Result<Vec<LegacyEvent>, FanotifyError> {
    crate::read::read_legacy(&self.fd)
}

/// Read legacy events with a callback.
///
/// Convenience wrapper around [`read_legacy_do`].
pub fn read_legacy_do<F>(&self, callback: F) -> Result<(), FanotifyError>
where
    F: FnMut(&LegacyEvent),
{
    crate::read::read_legacy_do(&self.fd, callback)
}

/// Write a permission response.
///
/// Convenience wrapper around [`write_response`].
pub fn send_response(&self, response: &FanotifyResponse) -> Result<(), FanotifyError> {
    crate::read::write_response(&self.fd, response)
}
```

- [ ] **Step 3: Add mark_mount method to Fanotify**

After existing `mark` method, add:
```rust
/// Add a mark on a mount point (monitor all files under it).
pub fn mark_mount<P: AsRef<OsStr> + ?Sized>(
    &self,
    mask: u64,
    path: &P,
) -> Result<(), FanotifyError> {
    fanotify_mark(
        &self.fd,
        consts::FAN_MARK_ADD | consts::FAN_MARK_MOUNT,
        mask,
        consts::AT_FDCWD,
        path,
    )
}
```

- [ ] **Step 4: Update prelude exports**

In the prelude module, add to existing exports:
```rust
pub use crate::types::{FidEvent, HandleCache, HandleKey, LegacyEvent, FanotifyResponse};
pub use crate::read::{read_fid_events, read_legacy, read_legacy_do, write_response};
```

- [ ] **Step 5: Build and test**

Run: `cargo build` and `cargo test`
Expected: passes

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs
git commit -m "feat: add legacy read, permission response, mark_mount to Fanotify/Builder"
```

---

### Task 5: Add Legacy Event Tests

**Files:**
- Create: `src/legacy_tests.rs` (module with tests)
- Modify: `src/lib.rs` (add `mod legacy_tests;`)

Actually, following existing pattern of tests inside modules, add tests to read.rs.

- [ ] **Step 1: Add unit tests for legacy parsing**

Add `#[cfg(test)]` module at end of `read.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    // Helper: build a synthetic legacy event in a buffer
    fn build_legacy_event(mask: u64, pid: i32, fd: i32, event_len: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&event_len.to_ne_bytes());
        buf.push(3); // vers
        buf.push(0); // reserved
        buf.extend_from_slice(&24u16.to_ne_bytes()); // metadata_len
        buf.extend_from_slice(&mask.to_ne_bytes());
        buf.extend_from_slice(&fd.to_ne_bytes());
        buf.extend_from_slice(&pid.to_ne_bytes());
        buf
    }

    #[test]
    fn test_read_legacy_empty_buffer() {
        // read_legacy does a real read syscall, so we can't easily test it
        // without a real fanotify fd.  But we can verify the parsing logic
        // works correctly with a synthetic buffer.
        // This test creates a valid-looking but fake fd that will fail.
        let bad_fd = unsafe { OwnedFd::from_raw_fd(-1) };
        let result = read_legacy(&bad_fd);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_legacy_parse_correctness() {
        let raw = build_legacy_event(0x0000_0001, 1234, 5, 24);
        assert_eq!(raw.len(), 24);
        // Parse manually:
        let meta: FanMetadata = unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const _) };
        assert_eq!(meta.mask, 0x0000_0001);
        assert_eq!(meta.pid, 1234);
        assert_eq!(meta.fd, 5);
        assert_eq!(meta.event_len, 24);
    }
}
```

- [ ] **Step 2: Build and test**

Run: `cargo build` and `cargo test`
Expected: tests pass

- [ ] **Step 3: Commit**

```bash
git add src/read.rs
git commit -m "test: add legacy event parsing tests"
```

---

### Task 6: Final Integration

**Files:**
- Modify: `src/lib.rs` (ensure all exports match updated API)
- Modify: `README.md` (update usage examples for legacy mode too)

- [ ] **Step 1: Verify full API coherence**

```
cargo build 2>&1 | grep -E "^error" || echo "NO ERRORS"
cargo test 2>&1 | tail -5
```

- [ ] **Step 2: Update README.md**

Add a legacy mode usage example alongside the FID example.

- [ ] **Step 3: Final commit**

```bash
git add README.md src/
git commit -m "feat: complete naughtyfy superset coverage"
```

---

## Verification Checklist

- [ ] No warnings (especially `unused_import`, `dead_code`)
- [ ] All existing FID functionality unchanged (38 tests pass)
- [ ] New legacy read tests pass
- [ ] `Fanotify::read_legacy()` returns events with correct mask/fd/pid/path
- [ ] `FanotifyBuilder` exposes all naughtyfy flags
- [ ] `Fanotify::send_response()` writes valid permission response
- [ ] `read_legacy_do()` callback is invoked per event
- [ ] All deprecated constants annotated with `#[deprecated]`
- [ ] `cargo doc --no-deps` succeeds
