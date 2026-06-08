//! Builder for creating fanotify groups.

use crate::consts;
use crate::error::FanotifyError;
use crate::fanotify::Fanotify;
use crate::sys::fanotify_init;

/// Builder for [`Fanotify`].
///
/// Created via [`Fanotify::new()`](crate::Fanotify::new).
#[derive(Debug, Clone)]
pub struct FanotifyBuilder {
    pub(crate) flags: u32,
    pub(crate) event_f_flags: u32,
}

impl FanotifyBuilder {
    /// Enable close-on-exec (always on by default).
    pub fn cloexec(mut self) -> Self {
        self.flags |= consts::FAN_CLOEXEC;
        self
    }

    /// Make the fanotify fd non-blocking.
    pub fn nonblock(mut self) -> Self {
        self.flags |= consts::FAN_NONBLOCK;
        self
    }

    /// Set notification class to `FAN_CLASS_NOTIF` (default).
    pub fn class_notif(mut self) -> Self {
        self.flags = (self.flags & !0x0C) | consts::FAN_CLASS_NOTIF;
        self
    }

    /// Set notification class to `FAN_CLASS_CONTENT` (for permission events).
    pub fn class_content(mut self) -> Self {
        self.flags = (self.flags & !0x0C) | consts::FAN_CLASS_CONTENT;
        self
    }

    /// Set notification class to `FAN_CLASS_PRE_CONTENT`.
    pub fn class_pre_content(mut self) -> Self {
        self.flags = (self.flags & !0x0C) | consts::FAN_CLASS_PRE_CONTENT;
        self
    }

    /// Report file identifiers (file handles) instead of file descriptors.
    pub fn report_fid(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_FID;
        self
    }

    /// Report parent directory identifiers.
    pub fn report_dir_fid(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_DIR_FID;
        self
    }

    /// Report entry names in parent directory events.
    pub fn report_name(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_NAME;
        self
    }

    /// Report thread ID instead of process ID.
    pub fn report_tid(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_TID;
        self
    }

    /// Remove event queue size limit (needs `CAP_SYS_ADMIN`).
    pub fn unlimited_queue(mut self) -> Self {
        self.flags |= consts::FAN_UNLIMITED_QUEUE;
        self
    }

    /// Remove mark count limit (needs `CAP_SYS_ADMIN`).
    pub fn unlimited_marks(mut self) -> Self {
        self.flags |= consts::FAN_UNLIMITED_MARKS;
        self
    }

    /// Set event_f_flags (flags for opened event fds).
    ///
    /// In FID mode, the fanotify fd doesn't produce event fds, so this
    /// is typically 0.
    pub fn event_flags(mut self, flags: u32) -> Self {
        self.event_f_flags = flags;
        self
    }

    /// Enable audit logging for permission events.
    pub fn enable_audit(mut self) -> Self {
        self.flags |= consts::FAN_ENABLE_AUDIT;
        self
    }

    /// Report pidfd for event->pid.
    pub fn report_pidfd(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_PIDFD;
        self
    }

    /// Report dirent target id (requires Linux ≥ 5.15).
    ///
    /// Requires both `FAN_REPORT_DFID_NAME` and `FAN_REPORT_FID`.
    pub fn report_target_fid(mut self) -> Self {
        self.flags |= consts::FAN_REPORT_TARGET_FID;
        self
    }

    /// Add arbitrary raw flags.
    pub fn raw_flags(mut self, flags: u32) -> Self {
        self.flags |= flags;
        self
    }

    /// Create the fanotify group.  Returns a [`Fanotify`] handle on success.
    ///
    /// See [`fanotify_init`] for error details.
    pub fn init(self) -> std::result::Result<Fanotify, FanotifyError> {
        let fd = fanotify_init(self.flags, self.event_f_flags)?;
        Ok(Fanotify { fd })
    }
}

impl Default for FanotifyBuilder {
    fn default() -> Self {
        FanotifyBuilder {
            flags: consts::FAN_CLASS_NOTIF | consts::FAN_CLOEXEC,
            event_f_flags: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default_flags() {
        let builder = FanotifyBuilder::default();
        // Default should be NOTIF (0) + CLOEXEC
        // NOTIF=0 means the class bits (0x0C) are clear
        assert!(builder.flags & 0x0C == 0, "class bits should be NOTIF");
        assert!(
            builder.flags & consts::FAN_CLOEXEC != 0,
            "CLOEXEC should be set by default"
        );
        assert!(builder.flags & consts::FAN_CLOEXEC != 0);
    }

    #[test]
    fn test_builder_chain_all_flags() {
        let builder = FanotifyBuilder::default()
            .cloexec()
            .nonblock()
            .class_content()
            .report_fid()
            .report_dir_fid()
            .report_name()
            .report_tid()
            .report_pidfd()
            .report_target_fid()
            .unlimited_queue()
            .unlimited_marks()
            .enable_audit()
            .event_flags(consts::O_CLOEXEC)
            .raw_flags(0x1000);
        // Builder should have accumulated flags
        assert!(builder.flags & consts::FAN_NONBLOCK != 0);
        assert!(builder.flags & consts::FAN_REPORT_FID != 0);
        assert!(builder.flags & consts::FAN_REPORT_TID != 0);
        assert!(builder.flags & consts::FAN_UNLIMITED_QUEUE != 0);
        assert!(builder.flags & 0x1000 != 0);
        assert_eq!(builder.event_f_flags, consts::O_CLOEXEC);
    }

    #[test]
    fn test_builder_class_modes_are_exclusive() {
        // Setting class_pre_content should clear class_content bits
        let b = FanotifyBuilder::default().class_content();
        assert!(b.flags & 0x0C == consts::FAN_CLASS_CONTENT || (b.flags & 0x0C) == 0x04);

        let b = b.class_pre_content();
        // 0x08 should be set, 0x04 should not
        assert_eq!(b.flags & 0x0C, consts::FAN_CLASS_PRE_CONTENT);
    }
}
