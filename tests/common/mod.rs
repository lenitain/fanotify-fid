//! Shared helpers for integration tests.
//!
//! Three rules this file exists to enforce:
//!
//! * **a test that cannot run must say so**, not pass quietly — see
//!   [`skip_without_cap_sys_admin`];
//! * **a test asserting on a failure must know which capabilities this process
//!   holds**, because the privilege check runs before the legality check and
//!   therefore masks it — see [`Capabilities`];
//! * **a capability probe reads `CapEff`, not the uid and not a syscall.**  The
//!   uid is wrong in both directions (a non-root process can hold a capability,
//!   root can drop one), and a syscall is wrong because a failure has more than
//!   one possible cause — `fanotify_mark` refusing `FAN_MARK_MNTNS` with `EPERM`
//!   says nothing about whether an unrelated `fanotify_init` would be allowed.

#![allow(dead_code)]

use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

use fanotify_fid::consts::*;
use fanotify_fid::{Fanotify, FanotifyError, FidEvent};

/// Retry until the closure returns `Some`, or give up after `timeout`.
///
/// Kernel event delivery is asynchronous: a mark can be in place before an
/// event is queued, and the write that causes it returns before the event is
/// readable.
pub fn retry<T, F: FnMut() -> Option<T>>(mut f: F, timeout: Duration) -> Option<T> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(value) = f() {
            return Some(value);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    f()
}

/// A temporary directory, removed when it drops.
pub fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create a temporary directory")
}

/// A mount descriptor for `path`: an ordinary directory open, which is what
/// `open_by_handle_at` accepts.
pub fn mount_fd_of(path: &Path) -> std::io::Result<OwnedFd> {
    Ok(std::fs::File::open(path)?.into())
}

/// `CAP_SYS_ADMIN`.
pub const CAP_SYS_ADMIN: u32 = 21;
/// `CAP_DAC_READ_SEARCH` — what `open_by_handle_at` needs.
pub const CAP_DAC_READ_SEARCH: u32 = 2;
/// `CAP_AUDIT_WRITE` — what `FAN_ENABLE_AUDIT` needs.
pub const CAP_AUDIT_WRITE: u32 = 29;

/// The capabilities this process actually holds.
///
/// # A user namespace is not enough, and the reason is worth knowing
///
/// `CapEff` reports the capabilities of the *current user namespace*, and
/// fanotify checks them against the **initial** one.  So `unshare -Ur` gives a
/// process a full `CapEff` and still earns `EPERM` from `fanotify_init`: the
/// probe below would call it admin, the tests would run, and every
/// admin-gated test would fail on a capability the namespace cannot confer.
///
/// That is a deliberate kernel boundary — fanotify grants authority over the
/// whole system's files, so it is not delegable to a nested namespace — and the
/// only environment where these tests can run is a real privileged one.  A
/// failure that looks like a bug in the crate on a `unshare -Ur` run is this,
/// which is why every privileged test names the capability it needs.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    effective: u64,
}

impl Capabilities {
    /// Read `CapEff` from `/proc/self/status`.
    ///
    /// That file is the process's own view of its capability sets, so it is
    /// exact where a syscall probe can only be suggestive.
    pub fn probe() -> Self {
        let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
        let line = status
            .lines()
            .find(|l| l.starts_with("CapEff:"))
            .expect("/proc/self/status has no CapEff line");
        let hex = line
            .split_whitespace()
            .nth(1)
            .expect("CapEff has no value")
            .trim();
        Self {
            effective: u64::from_str_radix(hex, 16).expect("CapEff is a hex mask"),
        }
    }

    /// Whether capability number `cap` is held.
    pub fn has(self, cap: u32) -> bool {
        self.effective & (1u64 << cap) != 0
    }

    /// Whether this process may create and mark admin-only groups.
    pub fn is_admin(self) -> bool {
        self.has(CAP_SYS_ADMIN)
    }

    /// The errno a call is expected to produce when it needs `CAP_SYS_ADMIN`:
    /// `EPERM` without it, and `verdict_if_admin` with it.
    ///
    /// This is the shape every admin-gated assertion takes, because the kernel
    /// checks the capability **before** it checks legality: an unprivileged
    /// process never sees the `EINVAL` that settles a legal question, so an
    /// assertion expecting it would only pass by accident.
    pub fn admin_gated(self, verdict_if_admin: i32) -> i32 {
        if self.is_admin() {
            verdict_if_admin
        } else {
            libc::EPERM
        }
    }
}

/// Announce that a test needs `CAP_SYS_ADMIN` and cannot run here, then return
/// from it.
///
/// Used with `#[ignore]`, so `cargo test` does not run the test at all and
/// `cargo test -- --ignored` reports this instead of a pass for work that never
/// happened.  The CI job that runs as root greps for the marker and fails if it
/// appears, so a skip can never be mistaken for a pass.
#[macro_export]
macro_rules! skip_without_cap_sys_admin {
    ($what:expr) => {{
        eprintln!();
        eprintln!("SKIPPED: {} — needs CAP_SYS_ADMIN", $what);
        eprintln!("  run with: sudo -E cargo test -- --ignored --test-threads=1");
        eprintln!();
        return;
    }};
}

/// Announce that a test needs `CAP_DAC_READ_SEARCH` and cannot run here.
///
/// The capability `open_by_handle_at` requires, and the one that separates
/// "receives events" from "can resolve them to paths": it is a deliberate
/// anti-escalation rule, since the call bypasses path permissions entirely.
#[macro_export]
macro_rules! skip_without_cap_dac_read_search {
    ($what:expr) => {{
        eprintln!();
        eprintln!("SKIPPED: {} — needs CAP_DAC_READ_SEARCH", $what);
        eprintln!("  run with: sudo -E cargo test -- --ignored --test-threads=1");
        eprintln!();
        return;
    }};
}

/// `CLONE_NEWUSER` and friends: whether this process is in a nested user
/// namespace, where `CapEff` is full but fanotify still refuses.
pub fn in_a_nested_user_namespace() -> bool {
    // A process in the initial user namespace has uid 0 outside it; one in a
    // child namespace has a mapped uid and a namespace whose parent is not
    // itself.  `getuid() != 0` with `CapEff` full is the signature of the trap.
    // SAFETY: reading this process's own credentials, which cannot fail.
    let uid = unsafe { libc::getuid() };
    // SAFETY: `geteuid` takes no arguments and cannot fail either.
    let euid = unsafe { libc::geteuid() };
    uid != 0 && euid != 0 && Capabilities::probe().is_admin()
}

/// The FID flags a group needs to report an object, its parent and the name.
pub const FID_WITH_NAME: u32 = FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME;

/// A FID group that needs no privilege, non-blocking.
pub fn fid_group() -> Fanotify {
    Fanotify::init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FID_WITH_NAME,
        0,
    )
    .expect("a FID NOTIF group needs no privilege")
}

/// Drain a FID group, retrying until at least one event arrives.
///
/// Returns **owned** events: the borrowed form is what a real consumer wants,
/// but a retry loop cannot return values borrowing its own scratch buffer, and a
/// test that hands events back to its body does not need the zero-copy path.
/// [`FidEvent::into_owned`] is exercised by every caller of this helper.
pub fn collect_fid_events(fan: &Fanotify, buf: &mut Vec<u8>) -> Vec<FidEvent<'static>> {
    retry(
        || match fan.read_events(buf) {
            Ok(events) if !events.is_empty() => Some(
                events
                    .into_iter()
                    .map(FidEvent::into_owned)
                    .collect::<Vec<_>>(),
            ),
            Ok(_) => None,
            Err(FanotifyError::Read(libc::EAGAIN)) => None,
            Err(e) => panic!("read_events failed: {e}"),
        },
        Duration::from_secs(5),
    )
    .expect("no event arrived within 5 seconds; is the mark in place?")
}
