//! What a downstream caller writes: one import, then the ordinary path.
//!
//! This is an example rather than a doctest so it is compiled by
//! `cargo test --all-targets`, which is what keeps the shortest path from
//! quietly getting longer.

// The whole point: one import, no crate-root or `consts` line.
use fanotify_fid::prelude::*;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // The common case: flags only.  `event_f_flags` is not in the way.
    let fan = Fanotify::new(
        FAN_CLASS_NOTIF
            | FAN_CLOEXEC
            | FAN_NONBLOCK
            | FAN_REPORT_FID
            | FAN_REPORT_DIR_FID
            | FAN_REPORT_NAME,
    )?;
    fan.mark(FAN_MARK_ADD, FAN_CREATE, "/tmp")?;

    // The rare case is still reachable, and the legal set is discoverable.
    let _with_event_f_flags =
        Fanotify::init(FAN_CLASS_NOTIF | FAN_REPORT_FID, O_NOATIME | O_CLOEXEC)?;
    let _allowed: u32 = EVENT_F_FLAGS_ALLOWED;

    // Resolving: the mount descriptor carries its own fsid, the resolver keeps
    // what it learns.
    let mounts = Mounts::new().with_fd(std::fs::File::open("/tmp")?)?;
    let mut resolver = PathResolver::new(mounts);
    let _ = resolver.store_mut();
    let _ = EventResolution::Resolved;

    // And the free functions are in scope too.
    let _ = handle_from_fd(std::fs::File::open("/tmp")?)?;
    let _ = fsid_of_path("/tmp")?;
    Ok(())
}
