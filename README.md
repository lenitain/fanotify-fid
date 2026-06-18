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
fanotify-fid = "0.4.0"
```

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
    println!("{:?} {:?}", ev.event_names(), ev.path);
}
```

## Building from Source

Requires Rust toolchain (tested with `rustc 1.85.0`).

```bash
git clone https://github.com/lenitain/fanotify-fid.git
cd fanotify-fid
cargo build --release
```

### Requirements

- Linux kernel **≥ 5.1** for FID mode (`FAN_REPORT_FID`)
- Linux kernel **≥ 5.15** for `FAN_REPORT_TARGET_FID`
- **`CAP_SYS_ADMIN`** capability (run as root or with `cap_sys_admin+ep`)

The crate compiles on any platform, but all runtime operations require a Linux
kernel with `CONFIG_FANOTIFY` enabled.  Non-Linux platforms will fail at runtime
with `FanotifyError::Init(ENOSYS)`.

## License

[MIT License](./LICENSE)