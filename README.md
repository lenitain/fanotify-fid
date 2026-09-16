# fanotify-fid

Linux fanotify FID (File Identifier) mode event parser and file handle utilities.

[![Crates.io](https://img.shields.io/crates/v/fanotify-fid.svg)](https://crates.io/crates/fanotify-fid)
[![Docs.rs](https://docs.rs/fanotify-fid/badge.svg)](https://docs.rs/fanotify-fid)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/lenitain/fanotify-fid/actions/workflows/ci.yml/badge.svg)](https://github.com/lenitain/fanotify-fid/actions/workflows/ci.yml)

## Overview

**fanotify-fid** is a comprehensive Rust library for Linux fanotify, supporting both fd-based and FID mode event parsing. It reads variable-length events correctly using each event's `event_len` field, parses file handles from info records, and resolves them to paths. The crate also provides safe wrappers for `name_to_handle_at()` and `open_by_handle_at()` syscalls needed to convert file handles back to paths.

### Why fanotify-fid?

Unlike basic fanotify wrappers that only handle fd-based events, **fanotify-fid** provides complete support for FID mode — the modern, variable-length event format that includes file handle information. This enables more efficient filesystem monitoring without needing to maintain separate file descriptors for each watched file. For system tools that need to track filesystem changes with minimal overhead, fanotify-fid offers the most complete and ergonomic Rust interface to Linux's fanotify subsystem.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
fanotify-fid = "0.7"
```

### Requirements

- Linux kernel **≥ 5.1** for FID mode (`FAN_REPORT_FID`)
- Linux kernel **≥ 5.15** for `FAN_REPORT_TARGET_FID`

No privilege is needed to *create* a `FAN_CLASS_NOTIF` FID group and receive
events — an unprivileged process can pass `FAN_REPORT_FID |
FAN_REPORT_DIR_FID | FAN_REPORT_NAME` to `fanotify_init`.  `CAP_SYS_ADMIN`
(run as root or with `cap_sys_admin+ep`) is needed for the surrounding features:

| Needs `CAP_SYS_ADMIN` | Why |
|---|---|
| `FAN_MARK_MOUNT`, `FAN_MARK_FILESYSTEM` | unprivileged groups may only place inode marks |
| `FAN_UNLIMITED_MARKS`, `FAN_UNLIMITED_QUEUE` | admin-only init flags |
| `FAN_REPORT_PIDFD`, `FAN_REPORT_TID` | admin-only init flags |
| `FAN_CLASS_CONTENT`, `FAN_CLASS_PRE_CONTENT` | admin-only classes |

The example below uses `FAN_MARK_FILESYSTEM`, which is why it must run as root.
Without privilege the kernel also blanks `metadata.pid` for events caused by
other processes, so `pid` attribution degrades to `0`.

This crate is Linux-only and will fail to compile on other platforms.

### Quick start

```rust
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
    let names: Vec<&str> = ev.event_names().collect();
    println!("{:?} {:?}", names, ev.path());
}
```
