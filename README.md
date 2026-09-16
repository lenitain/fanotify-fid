# fanotify-fid

Linux fanotify, with the kernel's answers passed through instead of second-guessed.

[![Crates.io](https://img.shields.io/crates/v/fanotify-fid.svg)](https://crates.io/crates/fanotify-fid)
[![Docs.rs](https://docs.rs/fanotify-fid/badge.svg)](https://docs.rs/fanotify-fid)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What this crate is for

fanotify reports events in three different **identities**, and the one that makes
whole-filesystem monitoring practical is the one most wrappers do not implement:
a **file handle plus fsid** instead of an open descriptor per watched object.
That format is variable-length — a fixed header followed by variable-length info
records — so reading it with a fixed stride parses garbage sooner or later.

This crate handles all three identities and the bytes they actually arrive in:

* **descriptor** — `FdEvent`, an owned open descriptor per event;
* **file handle** (`FID`) — `FidEvent`, with the fsid, the parent handle, the
  entry name, both sides of a rename, the mount ID, the access range, the
  filesystem error and the pidfd;
* **mount** — `FAN_REPORT_MNT` events, read by the same FID reader, identified by
  mount ID.

Plus the two ways to answer a permission event, the file-handle syscalls a FID
event is unusable without, and the UAPI constants as themselves.

## What it deliberately does not do

> Whatever you cannot get right **without understanding fanotify** is here.
> Whatever is **your own decision** is yours.

* **It does not judge legality.** The kernel is the authority, and it reports
  `EINVAL` for a combination it refuses and `EPERM` for a capability it wants.
  A validation layer in the crate would eventually disagree with the kernel
  about one of those — and the cost of that disagreement is a bug report
  pointing in the wrong direction. Every errno you see here is the kernel's.
* **It does not keep state for you.** No record of marked paths, no
  handle→path cache, no eviction policy, no re-scan after an overflow. A mark
  lives in the kernel; a cache is a policy about memory and staleness that only
  you can choose.
* **It does not walk trees.** An anchor does not recurse, so "watch this tree"
  is a strategy — one mark per directory, or one mount/filesystem mark, or your
  own index.
* **It does not attribute processes.** The pid and pidfd are handed over as
  reported.
* **It does not wrap what is already expressible.** No builder that hides which
  flags you passed, no adapter that saves three lines and invents its own
  semantics.

## The combinations that exist

Every group is a point on three axes: **identity** (chosen at `fanotify_init`),
**class** (also at init), and **anchor** (chosen at `fanotify_mark`). Not every
point exists, and the missing ones are ruled out by what the objects are:

* **FID × a permission class does not exist.** A permission event must hand over
  a descriptor for the object being decided about, and the kernel holds it until
  the answer arrives; file-handle identity exists precisely so that no
  descriptor is held. The kernel refuses the pair with `EINVAL`.
* **Mount identity × any anchor but `FAN_MARK_MNTNS` does not exist.** A mount
  event is scoped to a mount namespace, not to an inode, so the anchor is pinned
  and the mask is limited to `FAN_MNT_ATTACH | FAN_MNT_DETACH`. This is checked
  at `fanotify_mark`, **not** at init.
* **`FAN_REPORT_TARGET_FID` needs `FAN_REPORT_NAME` and `FAN_REPORT_FID`** —
  the child's handle is reported *in addition to* the parent handle and name.

So there are **five** legal group configurations, and the crate can express all
of them:

| # | Identity | Class | Anchors | Privilege |
|---|---|---|---|---|
| 1 | descriptor | `NOTIF` | inode · mount · filesystem | `CAP_SYS_ADMIN` |
| 2 | descriptor | `CONTENT` | inode · mount · filesystem | `CAP_SYS_ADMIN` |
| 3 | descriptor | `PRE_CONTENT` | inode · mount · filesystem | `CAP_SYS_ADMIN` |
| 4 | FID | `NOTIF` | inode · mount · filesystem | inode anchors need none |
| 5 | mount | `NOTIF` | **MNTNS only** | `CAP_SYS_ADMIN` |

Row 4 is the useful one: no privilege for inode marks, and no descriptor held
per watched object.

`tests/baseline.rs` asserts every row and every non-existent cell against the
kernel. It also records **where** each rule is enforced, because that is the
difference between "my flags are wrong" and "my mark is wrong":

| Rule | Checked at |
|---|---|
| identity × class | `fanotify_init` |
| the FID flag dependencies, and `PIDFD × TID` | `fanotify_init` |
| mount identity's anchor and mask | `fanotify_mark` |
| `FAN_RENAME`'s need for `FAN_REPORT_NAME` | `fanotify_mark` |
| which anchors the capability allows | `fanotify_mark` |
| whether the filesystem can decode handles | `fanotify_mark` |

## Privileges

| Needs `CAP_SYS_ADMIN` | Why |
|---|---|
| a bare `FAN_CLASS_NOTIF` with **no** report flag | omitting a report flag is not the unprivileged choice |
| `FAN_CLASS_CONTENT` / `FAN_CLASS_PRE_CONTENT` | admin-only classes |
| `FAN_MARK_MOUNT` / `FAN_MARK_FILESYSTEM` / `FAN_MARK_MNTNS` | an unprivileged group may place inode marks only — and that limit is about the **anchor**, not the file: marking a root-owned object succeeds |
| `FAN_REPORT_PIDFD`, `FAN_REPORT_TID`, `FAN_REPORT_FD_ERROR` | admin-only init flags |
| `FAN_UNLIMITED_QUEUE`, `FAN_UNLIMITED_MARKS` | admin-only init flags |
| `FAN_REPORT_MNT` **marks** | creating the group needs nothing; marking it does |
| `FAN_FS_ERROR` events | inherited from the filesystem mark they need |

Two more capabilities matter, and they are separate questions from the above:

* **`CAP_DAC_READ_SEARCH`** for `open_by_handle_at`, and therefore for turning a
  handle into a path. Receiving events needs nothing; *resolving* them needs the
  capability that bypasses path permissions. An unprivileged consumer works from
  the handles and names the events already carry and needs no syscall at all.
* **`CAP_AUDIT_WRITE`** for `FAN_ENABLE_AUDIT`, without which an audited
  response (`FAN_AUDIT`, and therefore `FanotifyResponse::audit_rule`) is
  refused.

An unprivileged group still receives events, but the kernel blanks
`metadata.pid` for events caused by *other* processes, so `FidEvent::pid()`
degrades to `0` there.

## Usage

```toml
[dependencies]
fanotify-fid = "0.8"
```

The examples below name each item individually. `use fanotify_fid::prelude::*;`
brings in the same set — the constants, the types and the free functions — when
you would rather not list them.

### Reading a FID group

```rust,no_run
use fanotify_fid::{Fanotify, FanotifyError, consts::*};
use fanotify_fid::handle::resolve_file_handle;
use std::os::fd::OwnedFd;

// 1. A group that identifies objects by handle.  No privilege needed.
let fan = Fanotify::new(
    FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
        | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
)?;

// 2. Mark an object.  A mark covers that object, and — with
//    FAN_EVENT_ON_CHILD — its immediate children.  Never a subtree.
fan.mark(FAN_MARK_ADD, FAN_CREATE | FAN_DELETE, "/srv/data")?;

// 3. A mount descriptor says which filesystem a handle belongs to.  Resolving
//    through it needs CAP_DAC_READ_SEARCH; without it, use the handles and
//    names the events carry.
let mount_fds: Vec<OwnedFd> = vec![std::fs::File::open("/srv/data")?.into()];

// 4. Read.
let mut buf = Vec::new();
loop {
    match fan.read_events(&mut buf) {
        Ok(events) => {
            for ev in &events {
                if ev.is_overflow() {
                    // An unknown number of events were dropped and cannot be
                    // recovered from the queue: reconcile by re-scanning.
                    eprintln!("queue overflow");
                    continue;
                }
                println!("{:?} fsid={:?} name={:?}",
                    ev.event_names().collect::<Vec<_>>(),
                    ev.fsid(),
                    ev.dfid_name_str());

                if let (Some(fsid), Some(handle)) = (ev.fsid(), ev.dfid_name_handle()) {
                    println!("parent: {:?}", resolve_file_handle(&mount_fds, Some(fsid), handle));
                }
            }
        }
        // An empty queue on a non-blocking group is EAGAIN, not an empty list.
        Err(FanotifyError::Read(libc::EAGAIN)) => {
            fan.wait_readable(None)?;
        }
        Err(e) => return Err(e.into()),
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Nothing in that loop resolves a path for you, and that is deliberate: the fsid,
the handles and the name bytes are what the kernel reported, and what to do with
them is your decision. `resolve_file_handle` is there when you want a path, and
`FidEvent::dfid_name()` gives you the name as an `OsStr` when you would rather
consult your own index.

### Events borrow the read buffer

At a whole-filesystem event rate, copying each event's handle and name out of
the read buffer would be the parser's entire cost. So it does not: `FidEvent`
carries a lifetime — `FidEvent<'buf>` — and its bytes point into the buffer
`read_events` filled. The rules that follow are the whole model:

* the buffer must outlive the events, and the events must be dropped before the
  next read into that buffer — which is what the loop above already does;
* `FidEvent::into_owned()` is the explicit conversion for an event that has to
  outlive the buffer, and an event built by hand is owned from the start;
* nothing is hidden: `parse_fid_events` and `read_events` return borrowed
events, `read_events_reported` and `parse_fid_events_reported` return the same
events plus a `ParseReport` — `bytes_consumed`, `bytes_left` and an `EventStop` —
so a short buffer or a malformed header is visible instead of silently yielding
fewer events. The reported form of the fd reader is `read_fd_events_reported`.

The fd format has no borrowed fields — its events own their descriptors — so
`parse_fd_events` there is the byte-level walk for captures and replay, and it
**adopts no descriptor**: a number from a `&[u8]` is reported, never claimed.

### Resolving events to paths

A path needs `open_by_handle_at`, and that has a cost beyond the syscall: it is
privileged (`CAP_DAC_READ_SEARCH`), and one directory handle is named by *every*
event about its children, so asking per event asks the same question hundreds of
times.

`PathResolver` is where that knowledge lives between calls. It holds a
`PathStore`, holds the mount descriptors **with their fsids** so the right one is
used for each handle, and resolves a whole batch in as many passes as the
nesting requires:

```rust,no_run
use fanotify_fid::{FanotifyError, consts::*};
use fanotify_fid::handle::Mounts;
use fanotify_fid::resolve::PathResolver;

let fan = fanotify_fid::Fanotify::new(
    FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
        | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
)?;
fan.mark(FAN_MARK_ADD, FAN_CREATE | FAN_EVENT_ON_CHILD, "/srv/data")?;

// One descriptor per filesystem you want paths on.  Each is probed for its
// fsid, so a handle can never be opened against the wrong filesystem.
let mounts = Mounts::new().with_fd(std::fs::File::open("/srv/data")?)?;
let mut resolver = PathResolver::new(mounts);

let mut buf = Vec::new();
loop {
    let mut events = match fan.read_events(&mut buf) {
        Ok(events) => events,
        Err(FanotifyError::Read(libc::EAGAIN)) => {
            fan.wait_readable(None)?;
            continue;
        }
        Err(e) => return Err(e.into()),
    };
    resolver.resolve_events(&mut events);
    for ev in &events {
        match ev.path() {
            // Exactly what /proc reported, marker included — see below.
            Some(path) if ev.is_deleted() => {
                println!("gone: {:?}", ev.without_deleted_suffix().unwrap_or_default())
            }
            Some(path) => println!("{}", path.display()),
            // No capability, or no descriptor on that filesystem.  The handle
            // and the name are still exactly what the kernel said.
            None => println!("unresolved: {:?}", ev.dfid_name()),
        }
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Three things are yours to choose, which is why they are setters and parameters
rather than defaults buried in the type:

* **where knowledge lives** — `PathResolver<C>` is generic over `PathStore`; the
  default is an unbounded `HandleCache`, and an LRU or a TTL map drops in
  unchanged. Pre-seed it with `store_mut()` to skip syscalls entirely, drop one
  handle's answer with `forget()` so the next call asks the filesystem again, or
  pass `NoCache` to keep nothing at all and get the path as of every call.
* **whether a syscall may be spent at all** — `set_syscall_fallback(false)` makes
  the resolver answer only from its store, so an unprivileged process gets
  `EXDEV` instead of `EPERM` and can never accidentally resolve behind its own
  back.
* **what to do about a deleted object** — `path()` returns the raw `/proc`
  answer, `" (deleted)"` marker included, because a file may legitimately *be*
  named `foo (deleted)`. `is_deleted()` asks, `without_deleted_suffix()` acts,
  and both read every component: a deleted parent leaves the marker in the middle
  of the paths derived from it (`/srv/gone (deleted)/child`), which is not a path
  anyone can open either. Stripping is never done for you, because the
  substitution has a wrong answer available.

### Answering a permission event

Permission events need `FAN_CLASS_CONTENT` or `FAN_CLASS_PRE_CONTENT` — which
are admin-only, and **mutually exclusive with every FID flag**, so a
handle-reporting group never receives one.

```rust,no_run
use fanotify_fid::{Fanotify, consts::*};
use fanotify_fid::response::FanotifyResponse;

let fan = Fanotify::new(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK)?;
fan.mark(FAN_MARK_ADD, FAN_OPEN_PERM, "/srv/data")?;

let mut buf = Vec::new();
loop {
    for ev in fan.read_fd_events(&mut buf)? {
        let Some(fd) = ev.fd() else { continue };
        // The event's own descriptor is what the kernel matches the answer on.
        let decision = if ev.mask() & FAN_OPEN_PERM != 0 {
            FanotifyResponse::allow(fd)
        } else {
            FanotifyResponse::deny_errno(fd, libc::EACCES)
        };
        fan.send_response(&decision)?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`FanotifyResponse::audit_rule` is the form that also writes a
`FAN_RESPONSE_INFO_AUDIT_RULE` record beside the decision, for the audit log.
The kernel matches every response by descriptor, so attach the event's own with
`.with_fd(fd)` — without it the record is validated and answers nothing. The
`FAN_AUDIT` flag it sets needs `FAN_ENABLE_AUDIT` (`CAP_AUDIT_WRITE`), and
`FanotifyResponse::info` is the same form for a record type this crate has never
heard of.

### Watching a directory tree

A mark never covers a subtree. Whether an event needs `FAN_EVENT_ON_CHILD` to be
reported for a *child* depends on what that event is about:

| Mask bits | Needs `FAN_EVENT_ON_CHILD`? |
|---|---|
| `FAN_OPEN`, `FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_WRITE`, the `_PERM` events | **yes** — without it they are reported for the marked object only |
| `FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_FROM`, `FAN_MOVED_TO`, `FAN_RENAME` | no — a directory-entry event is only ever about a child |

`tests/group.rs` asserts both halves against the kernel. Covering a tree is then
your loop: mark each directory, or use one `FAN_MARK_MOUNT` /
`FAN_MARK_FILESYSTEM` mark where the privilege allows.

### Checking a flag combination against your kernel

Ask the kernel, and read the errno — there is no feature detection here, because
a version number is a second source of truth that is wrong on any kernel with a
backport.

```rust,no_run
use fanotify_fid::{Fanotify, consts::*};

// Legal and permitted: a FID group needs no capability.
assert!(Fanotify::new(FAN_CLASS_NOTIF | FAN_REPORT_FID).is_ok());
```

Three outcomes, and one trap:

* success — legal and permitted;
* `EINVAL` — the kernel refuses this combination;
* `EPERM` — legal, but the capability is missing. **The privilege check runs
  first**, so an unprivileged process sees `EPERM` even for combinations that are
  also illegal, and never sees the `EINVAL` that would settle the question. Only
  a privileged run can settle legality for the admin-only rows.

## Requirements

* Linux only — the crate fails to compile elsewhere with that message.
* Rust **1.85** or newer (edition 2024).
* One dependency: `libc`.

Feature floors, if you need them: fanotify itself 2.6.36; FID identity 5.1;
`FAN_REPORT_DIR_FID` / `FAN_REPORT_NAME` 5.9; an unprivileged FID group 5.13;
`FAN_REPORT_TARGET_FID` 5.17; `FAN_PRE_ACCESS` 6.13; `FAN_REPORT_MNT` and
`FAN_MARK_MNTNS` 6.14; `AT_HANDLE_FID` 6.13.

## Testing

```sh
cargo test                          # unprivileged: parsing, row 4, constants
sudo -E cargo test -- --ignored --test-threads=1
```

The second command covers what an unprivileged run cannot: permission events,
every anchor, the mount row, and `open_by_handle_at`. Those tests report
`SKIPPED:` and the CI job fails if that marker appears, so a skip can never be
counted as a pass.
