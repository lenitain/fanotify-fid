//! What an event walk did: how much of a buffer became events, and where it
//! stopped.
//!
//! A buffer of fanotify events is walked by `event_len`, one event at a time,
//! and the walk can stop without reaching the end.  "The buffer ended" is only
//! one of the reasons, and a parser that reports only events cannot distinguish
//! `Ok(vec![])` for a short buffer from an empty queue — which is the same
//! mistake as dropping events silently, just one level up.
//!
//! This module is the vocabulary for saying which happened.  [`ParseReport`]
//! carries the two facts a caller needs to act:
//!
//! * **how many bytes were consumed**, which is where the last complete event
//!   ended;
//! * **where the walk stopped** ([`EventStop`]), which is what makes the bytes
//!   after that point intelligible: a partial header is a short read to be
//!   completed, an impossible `event_len` is a buffer that is not events, and
//!   an unknown version is a header this crate does not parse.
//!
//! `bytes_left` is `buf.len() - bytes_consumed` as the parser saw it, kept as a
//! field rather than derived so a report is self-contained: bytes that are left
//! over can be logged, written to disk, or replayed, which is the whole point of
//! reporting them.
//!
//! # This is not an error type
//!
//! A report is produced even when the walk succeeded, and a caller that only
//! wants events can ignore it.  The hard-failing parsers
//! ([`parse_fid_events`](crate::fid::parse_fid_events),
//! [`parse_fd_events`](crate::fd::parse_fd_events)) return an error for the one
//! case that cannot be recovered from — an unknown `vers` — while the reported
//! entry points put it in [`EventStop::UnknownVersion`] instead, so a caller
//! that is recording raw bytes can keep them alongside the reason.

/// Where an event walk stopped.
///
/// The variants are the ways a buffer of events can end early, and they are
/// deliberately not collapsed into "truncated": a short header is a buffer that
/// may be completed and re-parsed, while an impossible `event_len` is a buffer
/// that will never be events — the caller's response to the two is different.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStop {
    /// The buffer ended exactly on an event boundary: `bytes_left == 0`.
    End,
    /// Fewer than one header's worth of bytes were left, so there is a partial
    /// event at the end.  A larger read may complete it; the bytes at
    /// `bytes_consumed` are the start of it.
    ShortHeader,
    /// The event at `bytes_consumed` declared a length that cannot be a whole
    /// event: below the header size, or past the end of the buffer.
    ///
    /// The value is the `event_len` the header carried, unchanged, because the
    /// number the buffer claims is the evidence — a caller diagnosing a stream
    /// wants to see it, not a re-derived equivalent.
    BadEventLen(u32),
    /// The event at `bytes_consumed` declared a `metadata_len` past its own
    /// `event_len`, so records cannot be located without reading the next
    /// event's bytes as this one's.  The walk stops instead of guessing.
    BadMetadataLen,
    /// The first header's `vers` was not
    /// [`FANOTIFY_METADATA_VERSION`](crate::consts::FANOTIFY_METADATA_VERSION),
    /// so every field after it would be read with the wrong layout.  The value
    /// is the version the buffer carried.
    ///
    /// This is a property of the group, not of the event, so it is decided from
    /// the first header and cannot be recovered from by skipping.
    UnknownVersion(u8),
}

/// How far a parse walk got, and why it stopped.
///
/// Returned by the `*_reported` and `*_into` parsers; the plain parsers drop it.
/// A complete walk is [`EventStop::End`] with `bytes_left == 0`, which
/// [`is_complete`](Self::is_complete) reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseReport {
    /// How many bytes of the buffer became events — or, more precisely, where
    /// the walk stopped: everything before this offset was parsed or skipped
    /// over as a whole event, and the bytes from here on were not.
    pub bytes_consumed: usize,
    /// How many bytes were left when the walk stopped, `buf.len() -
    /// bytes_consumed`.
    pub bytes_left: usize,
    /// The reason the walk stopped.
    pub stop: EventStop,
}

impl ParseReport {
    /// Whether the whole buffer was walked and ended on an event boundary.
    ///
    /// `false` after any [`EventStop`] other than [`EventStop::End`], including
    /// [`UnknownVersion`](EventStop::UnknownVersion): a header this crate cannot
    /// read is not a complete parse, even if it filled the buffer.
    pub fn is_complete(&self) -> bool {
        matches!(self.stop, EventStop::End)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_walk_is_the_only_complete_report() {
        let complete = ParseReport {
            bytes_consumed: 24,
            bytes_left: 0,
            stop: EventStop::End,
        };
        assert!(complete.is_complete());

        for stop in [
            EventStop::ShortHeader,
            EventStop::BadEventLen(0),
            EventStop::BadMetadataLen,
            EventStop::UnknownVersion(0),
        ] {
            let report = ParseReport {
                bytes_consumed: 0,
                bytes_left: 24,
                stop,
            };
            assert!(!report.is_complete(), "{stop:?} must not read as complete");
        }
    }
}
