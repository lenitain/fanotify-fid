//! Turning the handles an event carries into paths, consistently.
//!
//! # Why this is a type and not a function
//!
//! [`resolve_file_handle`](crate::handle::resolve_file_handle) answers one
//! question about one handle: given these descriptors, what path is this?  It is
//! pure, and that is what makes it predictable.
//!
//! A stream of events asks a question it cannot answer: *what is this handle,
//! given what I have already learned?*  Two events about children of one
//! directory carry the **same** parent handle, and a handle costs a privileged
//! `open_by_handle_at` plus a `readlink` every time it is asked.  Worse, an
//! answer that changes between two calls about one handle is not a slower answer
//! — it is a wrong one, because a caller that saw `/srv/a` for a handle and then
//! `/srv/b` for the same handle has no way to tell which call the object it is
//! reasoning about belongs to.
//!
//! So the knowledge has to live somewhere between calls, and that somewhere is
//! this type.  It is not caching for speed, although it is that too: it is the
//! only place the guarantee *"one handle resolves to one answer"* can be held.
//! A caller who writes it themselves gets their own version of that guarantee,
//! which is to say the crate no longer has one.
//!
//! # What is here, and what is deliberately not
//!
//! | Question | Answer |
//! |---|---|
//! | Where does learned knowledge live? | The [`PathStore`] you pass, or [`HandleCache`] if you name none |
//! | Which descriptors may answer? | The [`Mounts`] you add, each probed for its fsid |
//! | May a syscall be spent at all? | [`PathResolver::set_syscall_fallback`] |
//! | What if the answer is a deleted object? | Reported, not cleaned up — see [`FidEvent::is_deleted`] |
//!
//! The first three are policy, which is why they are parameters and setters.
//! They are not decisions this crate can make for you: a bound on the store is a
//! policy about memory, and whether to spend a privileged syscall is a policy
//! about privilege.  The fourth is a fact, and facts are reported.
//!
//! ```rust,no_run
//! use fanotify_fid::consts::*;
//! use fanotify_fid::handle::{HandleCache, Mounts};
//! use fanotify_fid::resolve::PathResolver;
//! use fanotify_fid::{Fanotify, FanotifyError};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let fan = Fanotify::new(
//!     FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
//! )?;
//! fan.mark(FAN_MARK_ADD, FAN_CREATE | FAN_EVENT_ON_CHILD, "/srv/data")?;
//!
//! // One descriptor per filesystem you want paths on.  Resolving needs
//! // CAP_DAC_READ_SEARCH; without it every call answers EPERM, and the handles
//! // and names the events carry still need no privilege at all.
//! let mounts = Mounts::new().with_fd(std::fs::File::open("/srv/data")?)?;
//! let store = HandleCache::new();
//! let resolver = PathResolver::new(&store, &mounts);
//!
//! let mut buf = Vec::new();
//! loop {
//!     let mut events = match fan.read_events(&mut buf) {
//!         Ok(events) => events,
//!         // An empty queue is not a failure: wait for the next event.
//!         Err(e) if e.is_would_block() => {
//!             fan.wait_readable(None)?;
//!             continue;
//!         }
//!         Err(e) => return Err(e.into()),
//!     };
//!     // Resolves what it can, and says how many it managed.  The learning form
//!     // keeps what it decoded, so the next batch about these directories is
//!     // answered from the store.
//!     let resolved = resolver.resolve_events_memo(&store, &mut events);
//!     for ev in &events {
//!         if ev.has_path() {
//!             println!("{:?}{}", ev.path(), if ev.is_deleted() { " (gone)" } else { "" });
//!         } else {
//!             // No privilege, or a filesystem with no descriptor here.  The
//!             // handle and name are still exactly what the kernel reported.
//!             println!("unresolved: {:?}", ev.dfid_name());
//!         }
//!     }
//!     let _ = resolved;
//! }
//! # Ok(())
//! # }
//! ```

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::fid::FidEvent;
use crate::handle::{Fsid, HandleCache, Mounts, PathMemo, PathStore, resolve_file_handle_in};

/// Resolves the handles of FID events against a store the caller owns.
///
/// The resolver holds **borrows** — of the store to read, of the mounts to try —
/// and no state of its own beyond the syscall switch.  That is not a style
/// choice: the store is shared, so a caller keeps it in one place and resolves
/// from anywhere, and every read of it is a `&self` lookup handing the borrowed
/// path to a closure ([`PathStore::with_path`]) rather than a copy.
///
/// Recording is a different call on that same reference: the methods that learn
/// take `&M where M: PathMemo`, so a reader that only reads never asks for the
/// right to write.
///
/// See the [module docs](self) for why the knowledge belongs to the store rather
/// than to this type.
#[derive(Debug)]
pub struct PathResolver<'a, C: ?Sized = HandleCache> {
    store: &'a C,
    mounts: &'a Mounts,
    syscall_fallback: bool,
}

impl<'a, C: PathStore + ?Sized> PathResolver<'a, C> {
    /// A resolver that reads from `store` and may spend `open_by_handle_at` to
    /// learn more.
    pub fn new(store: &'a C, mounts: &'a Mounts) -> Self {
        Self {
            store,
            mounts,
            // On by default: a resolver that cannot consult the filesystem
            // answers only from what it has already seen, which is useful but
            // cannot resolve the first event of a run — and that is a worse
            // default than spending a syscall the caller can refuse.
            syscall_fallback: true,
        }
    }

    /// Allow or forbid spending `open_by_handle_at`.
    ///
    /// With it off, this resolver answers only from its [`PathStore`] and the
    /// mounts' [`fsid_of_fd`](crate::handle::fsid_of_fd) probes: no privileged
    /// call is made, so an unprivileged process gets `EPERM` never and
    /// [`EXDEV`](libc::EXDEV) whenever the store has not been taught the answer.
    ///
    /// That makes this the knob for a caller who fills the store some other way
    /// — from a tree walk of its own, from a previous run, from
    /// [`handle_from_fd`](crate::handle::handle_from_fd) on directories it can
    /// already open — and who wants to be sure the crate is not quietly
    /// resolving behind its back.
    pub fn set_syscall_fallback(&mut self, enabled: bool) -> &mut Self {
        self.syscall_fallback = enabled;
        self
    }

    /// The store this resolver reads.
    pub fn store(&self) -> &C {
        self.store
    }

    /// The mount descriptors this resolver may use.
    pub fn mounts(&self) -> &Mounts {
        self.mounts
    }

    /// Resolve one handle, using the store first and the syscall only if needed.
    ///
    /// Never returns the `None`-means-five-things answer: `EPERM` is the missing
    /// capability, `ESTALE` a handle the filesystem cannot decode (`ENOENT` and
    /// `EOPNOTSUPP` are not in this call's vocabulary), `EXDEV` no descriptor on
    /// that filesystem, `EINVAL` a malformed handle.  A descriptor whose fsid
    /// could not be learned is tried rather than skipped, since not knowing is
    /// not evidence of a mismatch.
    ///
    /// **A hit is borrowed and no syscall is spent**: the store answers from what
    /// it holds, which is the whole point of [`PathStore::with_path`] taking
    /// `&self` and handing the borrow to your closure.  Drop the entry with
    /// [`PathMemo::forget`] to ask the filesystem again.
    ///
    /// A hit still costs the returned `PathBuf` — the answer has to be owned to
    /// leave the store — while a miss builds one from a `readlink`.  Neither is a
    /// copy of what the store already held on top of that, which is what an owned
    /// store lookup made it.
    pub fn resolve_handle(&self, fsid: Fsid, handle: &[u8]) -> io::Result<PathBuf> {
        if let Some(path) = self.store.with_path(fsid, handle, Path::to_path_buf) {
            return Ok(path);
        }
        if !self.syscall_fallback {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }

        // The candidates are walked in place: no `Vec` per miss, which is what
        // `resolve_file_handle_in` taking an iterator buys — and the fsids were
        // learned when the mounts were added, so this spends no `fstatfs`.
        resolve_file_handle_in(self.mounts.candidates(), Some(fsid), handle)
    }

    /// Resolve one handle and record the answer, for a caller that is willing to
    /// spend the write.
    ///
    /// [`resolve_handle`](Self::resolve_handle) plus [`PathMemo::remember`], and
    /// the reason the two are separate: a caller that only reads never asks a
    /// store to record anything, so it can resolve from a store it only has a
    /// shared reference to.
    pub fn resolve_handle_memo<M: PathMemo + ?Sized>(
        &self,
        memo: &M,
        fsid: Fsid,
        handle: &[u8],
    ) -> io::Result<PathBuf> {
        let path = self.resolve_handle(fsid, handle)?;
        memo.remember(fsid, handle, &path);
        Ok(path)
    }

    /// Resolve a parent directory handle plus an entry name into a full path.
    ///
    /// The directory half is resolved first — from the store when it is there,
    /// which is what makes a batch of events about one directory cost one
    /// syscall rather than one per event — and then `name` is appended.  An
    /// empty `name` means the path *is* the directory, which is how a `FID`
    /// record resolves.
    ///
    /// A directory that is itself deleted yields the marker in the parent
    /// component, e.g. `/srv/gone (deleted)/child`: the entry named `child`
    /// existed, and this says where.  Such a path names nothing a caller can
    /// open, which [`FidEvent::is_deleted`] reports — it reads every component,
    /// not only the last — and one marker per marked component is what
    /// [`FidEvent::without_deleted_suffix`] removes.
    ///
    /// `name` is a single path component, as a Linux filename is.  A name
    /// containing `/` or NUL is `EINVAL` rather than something spliced into the
    /// path — with `push`, an absolute name would replace the directory instead
    /// of naming a child of it — and `..` is refused too: `base/..` is not a
    /// child of `base`, and the kernel never reports it, so joining it could only
    /// come from crafted bytes and could only produce an escaped path.
    ///
    /// `.` is the one name that changes nothing, and it is returned as the
    /// directory itself rather than pushed: a directory's entry for itself is
    /// reported as `.` by a `DFID_NAME` record, and `PathBuf::push(".")` would
    /// answer `/srv/data/.` — the same path to `Path::components`, and so the
    /// same path to `==`, but not the same string to `display`, to a `HashMap`
    /// key, or to anything else that compares bytes.
    ///
    /// The answer is owned, and the join is why: a hit with no name to append is
    /// the store's own bytes copied once, while a name to append needs a buffer to
    /// be joined into.  Appending is the one allocation this resolution cannot
    /// avoid — a path *is* the join of its parts — and it is one, not the store's
    /// copy plus the join, which is what an owned store lookup would have made it.
    ///
    /// The name is validated before the directory half is resolved, so a rejected
    /// name never causes a syscall.
    pub fn resolve_dir(&self, fsid: Fsid, handle: &[u8], name: &[u8]) -> io::Result<PathBuf> {
        // Validate before anything is resolved, so a name that cannot be a name
        // never causes a syscall.
        if !name.is_empty() && name != b"." {
            if name.contains(&b'/') || name.contains(&0) || name == b".." {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "entry name must be one path component",
                ));
            }
            // A Linux filename is bytes, not text; `PathBuf::push` is what keeps
            // a name that is not UTF-8 intact while joining the way a path joins
            // — including at `/`, where a separator written by hand gives
            // `//name`.  The directory half is joined *inside* the store's
            // closure, so a hit costs this one allocation and no copy of the
            // directory on top of it.
            if let Some(path) = self.store.with_path(fsid, handle, |dir| {
                let mut path = dir.to_path_buf();
                path.push(OsStr::from_bytes(name));
                path
            }) {
                return Ok(path);
            }
        } else if let Some(path) = self.store.with_path(fsid, handle, Path::to_path_buf) {
            // The path *is* the directory: no join, and the only cost is the copy
            // the answer has to be made of.
            return Ok(path);
        }

        if !self.syscall_fallback {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        let dir = resolve_file_handle_in(self.mounts.candidates(), Some(fsid), handle)?;
        if name.is_empty() || name == b"." {
            return Ok(dir);
        }
        let mut path = dir;
        path.push(OsStr::from_bytes(name));
        Ok(path)
    }

    /// Resolve an event, if the records it carries name something resolvable.
    ///
    /// Three shapes are tried in order, and the first that answers lands on the
    /// event as its [`path`](FidEvent::path):
    ///
    /// * the parent handle and entry name of a `DFID_NAME` record — the best
    ///   answer, since it needs no syscall for the *entry* half;
    /// * the **source side** of a `FAN_RENAME` event, which is a parent handle
    ///   and the entry's old name.  The kernel names a rename's parents and
    ///   never the object itself, so this side is the one this call can speak
    ///   for;
    /// * the object's own handle, from a `FID`/`DFID` record.
    ///
    /// A rename's **target** side is
    /// [`resolve_rename_target`](Self::resolve_rename_target): it names a
    /// different parent, and resolving it is the caller's call because it costs
    /// a syscall for an answer the event itself does not carry.
    ///
    /// Returns what it did — [`EventResolution`], not an errno — so that
    /// "nothing to resolve" and "the answer was unavailable" stay apart.  Ask
    /// [`resolve_handle`](Self::resolve_handle) or
    /// [`resolve_dir`](Self::resolve_dir) directly when the errno matters.
    ///
    /// # This call does not write
    ///
    /// It takes `&self`: nothing it does modifies the store, because a reader
    /// resolving a batch has no business asking for the right to write.  A
    /// resolution that succeeds does spend a syscall and does learn something
    /// worth keeping — use [`resolve_event_memo`](Self::resolve_event_memo), or
    /// [`resolve_events_memo`](Self::resolve_events_memo), to hand that knowledge
    /// to a [`PathMemo`].
    pub fn resolve_event(&self, event: &mut FidEvent<'_>) -> EventResolution {
        if event.has_path() {
            return EventResolution::AlreadyResolved;
        }
        let Some(fsid) = event.fsid() else {
            return EventResolution::NothingToResolve;
        };

        // The handles and names are borrowed from the event, so nothing here
        // copies them: the parse that produced them was allocation-free and the
        // resolution does not undo that.  The path a record yields is put on the
        // event, which does own it — that is the one copy resolution makes, and
        // a caller that would rather not make it reads the handle and name and
        // resolves lazily.
        if let Some(handle) = event.dfid_name_handle()
            && let Ok(path) = self.resolve_dir(fsid, handle, event.dfid_name_raw())
        {
            event.set_path(path);
            return EventResolution::Resolved;
        }

        if let Some(side) = event.rename_source() {
            // A rename names parents, not the object, so the source side is the
            // only thing this event can carry a path for.
            if let Ok(path) = self.resolve_dir(fsid, side.handle(), side.name().as_bytes()) {
                event.set_path(path);
                return EventResolution::Resolved;
            }
        }

        if let Some(handle) = event.self_handle()
            && let Ok(path) = self.resolve_handle(fsid, handle)
        {
            event.set_path(path);
            return EventResolution::Resolved;
        }

        EventResolution::Unresolvable
    }

    /// [`resolve_event`](Self::resolve_event), recording what it learns.
    ///
    /// The same resolution with the one thing the read-only form cannot do:
    /// teach the store the handles it decoded, so an event about the same
    /// directory — arriving later, or later in the same batch — resolves from
    /// the store instead of spending `open_by_handle_at` again.
    pub fn resolve_event_memo<M: PathMemo + ?Sized>(
        &self,
        memo: &M,
        event: &mut FidEvent<'_>,
    ) -> EventResolution {
        if event.has_path() {
            return EventResolution::AlreadyResolved;
        }
        let Some(fsid) = event.fsid() else {
            return EventResolution::NothingToResolve;
        };

        if let Some(handle) = event.dfid_name_handle()
            && let Ok(path) = self.resolve_dir(fsid, handle, event.dfid_name_raw())
        {
            // The parent is now in the store.  So is the entry itself when the
            // record named one: an event about that same object arriving later
            // carries `FID`/`DFID` — no name — and the path just derived is
            // byte-identical to what resolving that handle alone would produce,
            // so storing it cannot contradict the parent.
            if let Some(self_handle) = event.self_handle() {
                memo.remember(fsid, self_handle, &path);
            }
            event.set_path(path);
            return EventResolution::Resolved;
        }

        if let Some(side) = event.rename_source()
            && let Ok(path) = self.resolve_dir(fsid, side.handle(), side.name().as_bytes())
        {
            event.set_path(path);
            return EventResolution::Resolved;
        }

        if let Some(handle) = event.self_handle()
            && let Ok(path) = self.resolve_handle(fsid, handle)
        {
            memo.remember(fsid, handle, &path);
            event.set_path(path);
            return EventResolution::Resolved;
        }

        EventResolution::Unresolvable
    }

    /// Resolve the target side of a rename event, which
    /// [`resolve_event`](Self::resolve_event) leaves alone — it names a
    /// different parent, and this is the call that decides to spend a syscall on
    /// it.
    ///
    /// The answer is owned, and it is worth taking: a rename target whose parent
    /// the store already knows costs no syscall and no store copy.
    pub fn resolve_rename_target(&self, event: &FidEvent<'_>) -> Option<io::Result<PathBuf>> {
        let (Some(fsid), Some(side)) = (event.fsid(), event.rename_target()) else {
            return None;
        };
        Some(self.resolve_dir(fsid, side.handle(), side.name().as_bytes()))
    }

    /// The path this resolver already knows for a handle, borrowed.
    ///
    /// No syscall and no copy: the answer is read straight out of the
    /// [`PathStore`].  It is [`resolve_handle`](Self::resolve_handle) without the
    /// fallback — the way to ask "do I already know?" without asking the
    /// filesystem and without paying for an answer.
    ///
    /// ```
    /// use fanotify_fid::handle::{Fsid, HandleCache, Mounts, PathMemo};
    /// use fanotify_fid::resolve::PathResolver;
    ///
    /// let fsid: Fsid = (0x5eed, 1);
    /// let store = HandleCache::new();
    /// PathMemo::remember(&store, fsid, &[7; 12], std::path::Path::new("/srv/data"));
    /// let mounts = Mounts::new();
    /// let resolver = PathResolver::new(&store, &mounts);
    ///
    /// // Owned: the caller asked to be told the path, so it keeps the copy.
    /// let known: std::path::PathBuf = resolver.known(fsid, &[7; 12]).unwrap();
    /// assert_eq!(known, std::path::Path::new("/srv/data"));
    /// assert!(resolver.known(fsid, &[0; 8]).is_none());
    ///
    /// // And the form resolution reads through copies nothing at all.
    /// let same = resolver
    ///     .store()
    ///     .with_path(fsid, &[7; 12], |p| p == std::path::Path::new("/srv/data"));
    /// assert_eq!(same, Some(true));
    /// ```
    ///
    /// A batch of events about children of one directory names that directory's
    /// handle repeatedly: resolve the parent once, then look it up here for the
    /// rest of the batch.  An entry a caller wants to *invalidate* is
    /// [`PathMemo::forget`].
    pub fn known(&self, fsid: Fsid, handle: &[u8]) -> Option<PathBuf> {
        self.store.with_path(fsid, handle, Path::to_path_buf)
    }

    /// Resolve a batch, repeating until no further event can be resolved.
    ///
    /// # Why more than one pass
    ///
    /// One pass is not enough, and the case is ordinary rather than exotic.
    /// Event A is about a child of directory `D` and resolves `D` from the
    /// filesystem.  Event B is about a child of a directory *inside* `D` — but
    /// the record B carries names its own parent, not `D`, and no syscall can
    /// decode it if that parent has meanwhile been deleted.  What resolves B is
    /// knowing `D`, and A is what taught it.  A later pass, with A's knowledge in
    /// the store, reaches B.
    ///
    /// That recovery only exists when the batch *recorded* what it learned, so
    /// it is [`resolve_events_memo`](Self::resolve_events_memo) that repeats
    /// passes.  The read-only form makes exactly one pass, because without a
    /// memo a second pass would ask the filesystem the same questions again and
    /// get the same answers.
    ///
    /// # Returns
    ///
    /// A [`Resolution`] saying how much work that took and what is still
    /// outstanding.  A batch whose handles cannot be resolved costs one pass and
    /// no spinning; a chain of nested recoveries costs one pass per level.
    ///
    /// The distinction the count keeps is between resolving and re-seeing: an
    /// event that already carried a path is not counted as resolved, so a second
    /// call on a settled batch reports [`resolved == 0`](Resolution::resolved)
    /// rather than reporting the batch again.  See [`Resolution`].
    pub fn resolve_events(&self, events: &mut [FidEvent<'_>]) -> Resolution {
        let mut newly = 0;
        let mut already = 0;
        let mut unresolved = 0;
        for event in events.iter_mut() {
            match self.resolve_event(event) {
                EventResolution::Resolved => newly += 1,
                EventResolution::AlreadyResolved => already += 1,
                EventResolution::NothingToResolve | EventResolution::Unresolvable => {
                    unresolved += 1;
                }
            }
        }
        Resolution {
            resolved: newly,
            already_resolved: already,
            unresolved,
            passes: 1,
        }
    }

    /// [`resolve_events`](Self::resolve_events), recording what it learns and
    /// repeating until a pass resolves nothing new.
    ///
    /// The fixed-point loop is what makes a nested recovery work: a pass that
    /// resolves a parent teaches the memo, and the next pass reaches children
    /// whose own parents are gone.  Each pass that makes progress resolves at
    /// least one handle that was not known before, so the loop cannot run more
    /// times than there are events.
    pub fn resolve_events_memo<M: PathMemo + ?Sized>(
        &self,
        memo: &M,
        events: &mut [FidEvent<'_>],
    ) -> Resolution {
        let mut passes = 0;
        let mut best = Resolution::default();
        loop {
            let mut newly = 0;
            let mut already = 0;
            let mut unresolved = 0;
            for event in events.iter_mut() {
                match self.resolve_event_memo(memo, event) {
                    EventResolution::Resolved => newly += 1,
                    EventResolution::AlreadyResolved => already += 1,
                    EventResolution::NothingToResolve | EventResolution::Unresolvable => {
                        unresolved += 1;
                    }
                }
            }
            passes += 1;
            let this = Resolution {
                resolved: newly,
                already_resolved: already,
                unresolved,
                passes,
            };
            // The pass that resolves nothing new is the one that proves the
            // fixed point was reached, and it is not work: it re-sees what is
            // already there, so its `resolved` is zero by definition.  Reporting
            // it would say "this call resolved nothing" about a call that just
            // resolved a batch.  So the last pass that *did* work is the one
            // kept, and a batch that never resolved anything reports its first
            // pass.
            if newly == 0 {
                if passes == 1 {
                    return this;
                }
                return best;
            }
            best = this;
        }
    }
}

/// What [`PathResolver::resolve_events`] did to a batch.
///
/// A count on its own cannot say the interesting things about a batch — how many
/// events were already settled, how many still need attention, or how much work
/// the resolution took — and the one number it can say must not be the sum of
/// "I resolved this" and "this was already resolved", because those mean opposite
/// things to a caller deciding whether to try again.
///
/// The counts describe **the last pass that resolved something**, not the pass
/// that ended the loop: a fixed-point loop always ends with a pass that resolves
/// nothing, which would make every number here zero.  So all four fields are that
/// pass's own account — `passes` included, which is why it is 1 for a batch that
/// was settled on the first pass rather than 2.  A batch that never resolved
/// anything has no productive pass to describe, so the first pass's account is
/// what is returned: `passes == 1` with `resolved == 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Resolution {
    /// Events this call **newly** resolved.
    ///
    /// Zero means this call changed no event's path: the batch was already as
    /// resolved as this resolver can make it.  A second call on a settled batch
    /// reports zero, which is what makes the number usable as a progress check —
    /// the old return value could not distinguish "resolved 8 events" from
    /// "re-examined 8 events that were resolved last time".
    pub resolved: usize,
    /// Events that already carried a path when that pass reached them.
    ///
    /// A large number here with `resolved == 0` is the "already settled" case;
    /// the same number with `resolved > 0` says the batch was part settled and
    /// part new.
    pub already_resolved: usize,
    /// Events left without a path: [`EventResolution::NothingToResolve`] and
    /// [`EventResolution::Unresolvable`] together.
    ///
    /// Their handles and names are still on the events; which of the two it was
    /// is per-event, from [`PathResolver::resolve_event`].
    pub unresolved: usize,
    /// Passes the fixed point took, at least one.
    ///
    /// One for a batch that needed no nested recovery; more than one says the
    /// resolution made progress in rounds — an event's parent was learned only
    /// after another event resolved it.  Useful as a health signal: a number that
    /// keeps climbing with batch size means the store is not retaining what it
    /// learns.
    pub passes: usize,
}

/// What [`PathResolver::resolve_event`] did, so a caller can tell "nothing to
/// resolve" from "tried and failed".
///
/// Marked `#[non_exhaustive]` because the set is about the resolver's
/// vocabulary and not about fanotify's: a later way to end — a source that is
/// known to be gone, a resolution deliberately skipped — is an addition, and a
/// caller matching exhaustively today should not be broken by one.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventResolution {
    /// The event now carries a path.
    Resolved,
    /// It already carried one, so nothing was done.
    AlreadyResolved,
    /// Its records name no object with a filesystem — an overflow, or a mount
    /// event, which names a mount rather than a file.
    NothingToResolve,
    /// It names an object, and the answer was not available: no capability, no
    /// descriptor on that filesystem, or an object the filesystem cannot decode.
    /// The handles and names are still on the event.
    Unresolvable,
}
