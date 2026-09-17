//! File handles: the syscalls that produce and consume the identity a FID event
//! carries.
//!
//! A FID event does not name a file by path or by descriptor.  It carries an
//! **fsid** and a **file handle** — an opaque byte string the filesystem
//! produced — and that pair is all the kernel reports.  Four syscalls make the
//! pair usable:
//!
//! | Call | Direction |
//! |---|---|
//! | [`name_to_handle_at`] | path → handle |
//! | [`handle_from_fd`] | open descriptor → handle |
//! | [`open_by_handle_at`] | handle + mount descriptor → open descriptor |
//! | [`fsid_of_path`] / [`fsid_of_fd`] | path or descriptor → fsid |
//!
//! # Two facts that decide how you use these
//!
//! **A handle is only meaningful together with its filesystem.**  The bytes
//! carry no filesystem identity of their own, and unrelated filesystems really
//! do produce identical bytes for different objects: every filesystem that falls
//! back to the kernel's synthetic `FILEID_INO64_GEN` encoding (procfs, sysfs,
//! debugfs, tracefs, bpf, devpts) hands out the same bytes for its root.
//! [`resolve_file_handle`] therefore takes the fsid as an optional filter —
//! `Some(fsid)` from the event is the correct answer, and `None` means "try
//! every mount descriptor", which is what you want only when you have one
//! filesystem.  [`Mounts`] carries that pairing, and [`PathStore`] is where an
//! answer, once learned, can be kept — see
//! [`PathResolver`](crate::resolve::PathResolver) for the two used together.
//!
//! **Opening by handle needs `CAP_DAC_READ_SEARCH`**, which an unprivileged
//! process can never hold: the call bypasses path permissions by design, so the
//! kernel does not let it be used without them, and it is not a permission a
//! caller can otherwise arrange — ownership, file mode and `CAP_DAC_OVERRIDE`
//! are not substitutes.  This is not a gap in the crate.  The events themselves
//! carry the handle, the parent handle and the entry name, and those need no
//! privilege at all — a consumer that keeps its own index, or asks
//! [`handle_from_fd`] about directories it can already open, never has to call
//! [`open_by_handle_at`].
//!
//! # Paths from handles are best-effort, and cannot be otherwise
//!
//! The only way to turn an open descriptor back into a path is
//! `readlink("/proc/self/fd/N")`, which is what [`resolve_file_handle`] does.
//! Two consequences follow, and neither has a workaround:
//!
//! * On a busy filesystem the object may be renamed between the open and the
//!   `readlink`, so the answer describes a moment, not an invariant.
//! * `/proc` appends `" (deleted)"` to the link target of an unlinked object —
//!   and a file may legitimately *be* named `foo (deleted)`, in which case the
//!   marker is doubled and stripping it once names a different, possibly
//!   existing, file.  Nothing in the string distinguishes the two, so this
//!   module does not guess: it returns exactly what `/proc` reported.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use crate::consts::{AT_EMPTY_PATH, AT_HANDLE_FID, MAX_HANDLE_SZ};
use crate::sys::errno;

/// A filesystem id, as a FID info record reports it: the two `int`s of
/// `statfs(2)`'s `f_fsid`.
///
/// It is the crate's answer to "which filesystem is this handle's", and it is
/// what [`PathStore`] keys on and what [`Mounts`] filters by.  **No value is
/// reserved**: `(0, 0)` is a filesystem that reports zero, not a missing one.
/// Some filesystems do report zero — `fanotify(7)` names `fuse(4)` — and for
/// those the kernel itself offers no way to tell two instances apart, so a store
/// keyed on this pair cannot either.  The rule that decides whether a descriptor
/// may be tried for a handle is the one [`resolve_file_handle_in`] documents; its
/// cost is one descriptor too many tried, never a wrong path.  See
/// [`PathStore`] for the consequence to a cache.
pub type Fsid = (i32, i32);

/// A raw file handle: the bytes of `struct file_handle`, header included.
///
/// This is exactly what [`open_by_handle_at`] takes and exactly what a FID info
/// record carries, with no wrapper and no normalisation — the bytes are the
/// filesystem's, and reinterpreting them here would only add a way to be wrong.
pub type FileHandle = Vec<u8>;

/// Size of `struct file_handle`'s fixed part: `handle_bytes` (u32) +
/// `handle_type` (i32).
pub const FILE_HANDLE_HEADER_SIZE: usize = 8;

/// The largest buffer `name_to_handle_at` accepts: the header plus
/// [`MAX_HANDLE_SZ`] bytes of payload.
pub const MAX_FILE_HANDLE_SIZE: usize = FILE_HANDLE_HEADER_SIZE + MAX_HANDLE_SZ;

/// What a caller already knows about handles, kept across calls.
///
/// A handle costs a privileged `open_by_handle_at` plus a `readlink` to become a
/// path, and an event stream asks about the *same* directory handle again and
/// again — every event about a child of one directory names that directory.  The
/// store is where that knowledge lives between calls, which makes it the thing
/// that turns "one syscall per event" into "one syscall per directory".
///
/// # It holds what the kernel said, and nothing else
///
/// A stored path is the raw `readlink` result, so an unlinked object is stored
/// with the `" (deleted)"` marker `/proc` appends.  The store does not clean
/// that up, and must not: see [`crate::fid::FidEvent::without_deleted_suffix`]
/// for why the decision belongs to the caller, and
/// [`PathResolver`](crate::resolve::PathResolver) for how it is kept consistent.
///
/// # Implementing it
///
/// Three operations are required: record ([`insert`](Self::insert)), answer
/// ([`get`](Self::get)) and drop ([`forget`](Self::forget)).  Implement them to
/// bound the cache (an LRU that drops the oldest entries), to share it (a handle
/// behind a lock), to persist it, to forget on demand, or to keep nothing at all
/// ([`NoCache`]) — none of which this crate can choose for you, because each is a
/// policy about memory, staleness or concurrency.
///
/// A hit is used as the answer and no syscall is spent; a miss means "ask the
/// filesystem".  So a store that expires, forgets or declines to answer costs a
/// privileged call rather than producing a wrong path, while a store that *does*
/// answer is what keeps two events about one handle from contradicting each
/// other.
///
/// # Why a hit hands over an owned path
///
/// [`get`](Self::get) returns `Option<PathBuf>` rather than a borrow, and that
/// is the shape the policies above actually need.  A borrow would rule out the
/// two stores most worth having:
///
/// * **a handle behind a lock.**  A reference into a `Mutex<HashMap>` cannot
///   outlive the guard that produced it, and no signature taking `&self` and
///   returning `Option<&Path>` can express "the guard travels with the
///   answer".  A store in that shape can only answer by copying.
/// * **an LRU, or any store with a recency or expiry policy.**  A hit is what
///   *updates* the policy, so a lookup is a write — `lru::LruCache::get` takes
///   `&mut self` — and a `&self` method cannot call it.
///
/// So the trait asks for the copy, and the copy is cheap next to what it buys:
/// a hit still skips `open_by_handle_at` and a `readlink`, which is the whole
/// reason the store exists.  A store that *can* hand out a reference — one whose
/// values are already owned in place, with no policy to update — should say so
/// with an **inherent** method, and only that way: [`HandleCache::path_of`] is
/// this crate's own example, and it is what
/// [`PathResolver::known`](crate::resolve::PathResolver::known) sends a caller to
/// for the zero-allocation look.  A `&self` method on this trait could not serve
/// that purpose, because the stores that need the copy are exactly the ones that
/// need `&mut self` or a guard — so a trait-level borrow would either exclude
/// them or be silently useless for them.  What a store must not do is pretend a
/// `&self` borrow covers a store that needs `&mut self` or a guard.
///
/// The key is the **pair** of fsid and handle, not the handle alone: handle
/// bytes are only meaningful together with their filesystem.  Two filesystems
/// that both fall back to the kernel's synthetic `FILEID_INO64_GEN` encoding
/// (procfs, sysfs, tracefs, …) hand out identical bytes for their roots, so a
/// store keyed on bytes alone answers with another filesystem's path.
///
/// # The pair is only as good as the fsid
///
/// The split above is what makes one handle resolve to one answer **across
/// filesystems**, and it holds except where the kernel's fsid stops
/// distinguishing them: a filesystem that reports `f_fsid` zero — `fuse(4)` is
/// the documented case — is one `(0, 0)` to this key no matter how many instances
/// are mounted.  Two such filesystems watched through one group then share a
/// slot, so a stored path can be handed back for the other one's handle.  The
/// kernel reports no field that separates them, so a store cannot either; a
/// caller in that position keeps one store per filesystem, the same way it keeps
/// one [`Mounts`] per filesystem.
pub trait PathStore {
    /// The path already known for this handle, if any.
    ///
    /// Owned, because the stores this trait exists for cannot hand out a
    /// reference: see the type-level docs on why.  A store that can — an
    /// in-place map — is free to add an inherent borrowing accessor alongside
    /// this method, and should, because that accessor is the only zero-allocation
    /// way to ask.
    ///
    /// Takes `&mut self`: a hit is what updates a recency, an expiry or a
    /// counter, so a lookup may legitimately write.  A store with no policy to
    /// update ignores the mutability.
    fn get(&mut self, fsid: Fsid, handle: &[u8]) -> Option<PathBuf>;

    /// Record a path for this handle.
    ///
    /// Called with what the filesystem reported, including any `" (deleted)"`
    /// marker.  While the entry is there, later lookups of the same handle
    /// return what was recorded, so that every reader of one handle sees one
    /// answer; [`forget`](Self::forget) is how a caller replaces it.
    ///
    /// Borrowed rather than owned so that a store which cannot take ownership —
    /// a persisted log, a shared structure, anything that has to copy anyway —
    /// is not forced to allocate first.  A store that can keep the path must copy
    /// it, because the caller keeps its own copy: the answer goes on the event as
    /// well as into the store.
    fn insert(&mut self, fsid: Fsid, handle: &[u8], path: &Path);

    /// Drop what is known about this handle, so the next lookup asks the
    /// filesystem again.
    ///
    /// The way to answer *where is it now*: a handle's path can change — a
    /// rename is exactly that — and this store holds the answer from when it
    /// was learned.  Forgetting before the next resolution makes the resolver
    /// spend the syscall, which is what a caller that has just seen a rename
    /// event wants.
    fn forget(&mut self, fsid: Fsid, handle: &[u8]);
}

/// The store this crate uses when the caller has no reason to choose one.
///
/// Two levels of [`HashMap`](std::collections::HashMap) — the outer keyed by
/// fsid, the inner by handle bytes — which is what makes a lookup take the
/// caller's `&[u8]` **without copying it**.  A single map over an
/// `(Fsid, FileHandle)` key cannot do that: `HashMap::get` needs one borrowed
/// form of the key, and no tuple of `(Fsid, &[u8])` hashes like
/// `(Fsid, Vec<u8>)` does, so the lookup would have to build the owned key first
/// — an allocation and a `memcpy` per hit.  Splitting the levels is what lets the
/// inner map borrow: `Vec<u8>: Borrow<[u8]>` is exactly the relation
/// `HashMap::get` is written for.  That is also why this store can offer
/// [`path_of`](Self::path_of), the zero-allocation hit, which the [`PathStore`]
/// trait cannot ask of every store.
///
/// Unbounded is a real property and not an oversight: this crate cannot know how
/// many handles a long-running process will see, so a bound would be a guess
/// that silently discards knowledge.  A caller that needs one implements
/// [`PathStore`] over an LRU or a TTL map and passes that instead — which the
/// trait's `&mut self` lookup is shaped to allow, since a hit in such a store
/// updates the policy that makes it bounded.
#[derive(Debug, Clone, Default)]
pub struct HandleCache {
    /// Handles are only meaningful within their filesystem, so the split by
    /// fsid is the same fact the key was expressing — as a level instead of as a
    /// tuple.
    by_filesystem: std::collections::HashMap<Fsid, std::collections::HashMap<FileHandle, PathBuf>>,
}

impl HandleCache {
    /// A cache that knows nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many handles are known, across every filesystem.
    pub fn len(&self) -> usize {
        self.by_filesystem
            .values()
            .map(std::collections::HashMap::len)
            .sum()
    }

    /// Whether nothing is known.
    pub fn is_empty(&self) -> bool {
        // Cheaper than `len() == 0`: the first non-empty level decides.
        self.by_filesystem
            .values()
            .all(std::collections::HashMap::is_empty)
    }

    /// How many filesystems have at least one handle recorded.
    pub fn filesystems(&self) -> usize {
        self.by_filesystem.len()
    }

    /// Forget every handle of one filesystem, the way
    /// [`forget`](PathStore::forget) forgets one.
    ///
    /// What a caller does after unmounting: the level goes away whole, which
    /// takes its handles' allocations with it.
    pub fn forget_filesystem(&mut self, fsid: Fsid) {
        self.by_filesystem.remove(&fsid);
    }

    /// Drop everything, keeping the outer level's allocation for reuse.
    pub fn clear(&mut self) {
        self.by_filesystem.clear();
    }

    /// Every entry, for inspection or persistence.
    pub fn iter(&self) -> impl Iterator<Item = (Fsid, &[u8], &Path)> {
        self.by_filesystem.iter().flat_map(|(fsid, handles)| {
            handles
                .iter()
                .map(move |(h, p)| (*fsid, h.as_slice(), p.as_path()))
        })
    }

    /// The path known for this handle, **borrowed**: a hit allocates nothing.
    ///
    /// This store has nothing to update on a hit — no recency, no expiry, no
    /// counter — and its values are owned in place inside the map, so it is one
    /// of the stores that really can hand out a reference.  It says so with an
    /// inherent method because [`PathStore::get`] cannot: the trait's shape has
    /// to cover stores that answer from behind a lock or with a policy to update
    /// (see its docs), and those can only answer by copying.
    ///
    /// Reach for this when the caller wants to *look* rather than to resolve:
    /// something that formats a path, compares it, or hands the borrow to
    /// another call.  Anything that has to keep the path needs an owned one
    /// anyway, and [`PathStore::get`] is that form.
    pub fn path_of(&self, fsid: Fsid, handle: &[u8]) -> Option<&Path> {
        self.by_filesystem
            .get(&fsid)?
            .get(handle)
            .map(PathBuf::as_path)
    }
}

impl PathStore for HandleCache {
    fn get(&mut self, fsid: Fsid, handle: &[u8]) -> Option<PathBuf> {
        // The one copy a hit costs, and the reason `path_of` exists alongside it:
        // a caller that can work from a borrow does not have to pay this.
        self.path_of(fsid, handle).map(Path::to_path_buf)
    }

    fn insert(&mut self, fsid: Fsid, handle: &[u8], path: &Path) {
        // The store owns its path, so this is where the copy happens: one
        // allocation per miss, which is the miss's whole cost on top of the
        // syscall it just spent.
        self.by_filesystem
            .entry(fsid)
            .or_default()
            .insert(handle.to_vec(), path.to_path_buf());
    }

    fn forget(&mut self, fsid: Fsid, handle: &[u8]) {
        if let Some(handles) = self.by_filesystem.get_mut(&fsid) {
            handles.remove(handle);
            // A filesystem with no handles left is a level with nothing in it;
            // dropping it here keeps a long run's outer level proportional to
            // the filesystems still in use rather than to every one ever seen.
            if handles.is_empty() {
                self.by_filesystem.remove(&fsid);
            }
        }
    }
}

/// A store that remembers nothing, so every resolution asks the filesystem.
///
/// The answer is then the path as of the call rather than as of the first event
/// about that handle: what a caller watching for renames wants, and what a
/// caller that needs no consistency across events pays for with one
/// [`open_by_handle_at`] per handle.  [`HandleCache`] is the opposite choice,
/// and [`PathStore::forget`] is the middle one — keep the cache, drop what a
/// rename invalidated.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCache;

impl PathStore for NoCache {
    /// The borrowed form of a known path is [`HandleCache::path_of`], which is
    /// inherent rather than part of this trait: a `&self` method here could not
    /// serve the stores that need `&mut self` or a lock guard, which is why
    /// [`get`](Self::get) copies.  Nothing is ever known.
    fn get(&mut self, _fsid: Fsid, _handle: &[u8]) -> Option<PathBuf> {
        None
    }

    /// Nothing is recorded: keeping it is the one thing this store does not do.
    fn insert(&mut self, _fsid: Fsid, _handle: &[u8], _path: &Path) {}

    /// Nothing to forget.
    fn forget(&mut self, _fsid: Fsid, _handle: &[u8]) {}
}

/// Look up the file handle of an **open descriptor**.
///
/// The descriptor-based form of [`name_to_handle_at`]: it resolves no path, so
/// it cannot be raced by a concurrent rename, and it reaches objects a path
/// cannot — a file in a directory the caller may not read, or one with no
/// remaining name at all.
///
/// The bytes returned are the ones a FID event reports for the same object, so
/// this is how a caller learns the handle of something it can already open: a
/// directory it is watching, a file it just created.
///
/// # Errors
///
/// `EOPNOTSUPP` if the filesystem cannot encode handles at all (a pipe, a
/// socket, or some pseudo-filesystems), `ENOTDIR`/`EBADF` if the descriptor is
/// not usable, `ENOSYS` on a kernel without the call (pre-2.6.39).
///
/// ```rust,no_run
/// use fanotify_fid::handle::handle_from_fd;
///
/// let dir = std::fs::File::open("/tmp")?;
/// let handle = handle_from_fd(&dir)?;
/// println!("{} bytes of handle", handle.len());
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn handle_from_fd<Fd: AsFd>(fd: Fd) -> io::Result<FileHandle> {
    // An empty path is only valid together with `AT_EMPTY_PATH`; the kernel
    // then uses the descriptor itself as the object to encode.
    name_to_handle_at_raw(fd.as_fd().as_raw_fd(), c"".as_ptr(), AT_EMPTY_PATH)
}

/// Look up the file handle of a **path**.
///
/// Asks for a FID rather than an openable handle, because a FID is what fanotify
/// reports: on filesystems with no `fh_to_dentry` operation a plain request
/// fails with `EOPNOTSUPP` while a FID request succeeds.  On filesystems that
/// support both, the two requests produce identical bytes, so there is nothing
/// to choose between them and this picks the one that always works.
///
/// Prefer [`handle_from_fd`] when you hold a descriptor: this call resolves the
/// path again, and that resolution can be raced.
///
/// # Errors
///
/// Any `name_to_handle_at` errno — `ENOENT`, `EACCES`, `EOPNOTSUPP`, `EPERM`
/// for a path that requires `CAP_DAC_READ_SEARCH` to walk.
///
/// ```rust,no_run
/// use fanotify_fid::handle::name_to_handle_at;
///
/// let handle = name_to_handle_at(std::path::Path::new("/tmp"))?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn name_to_handle_at<P: AsRef<Path> + ?Sized>(path: &P) -> io::Result<FileHandle> {
    let c_path = c_path(path.as_ref())?;
    name_to_handle_at_raw(libc::AT_FDCWD, c_path.as_ptr(), 0)
}

/// `name_to_handle_at` with an explicit anchor, asking for a FID.
///
/// `AT_HANDLE_FID` is only understood from Linux 6.13; older kernels report
/// `EINVAL` for a flag they do not know, so that specific error is retried
/// without it.  The retry cannot mask a real `EINVAL`: the only other thing
/// `EINVAL` means here is a capacity problem, and the capacity is fixed at the
/// maximum the kernel accepts.
fn name_to_handle_at_raw(
    dir_fd: i32,
    path: *const libc::c_char,
    flags: i32,
) -> io::Result<FileHandle> {
    match name_to_handle_at_flags(dir_fd, path, flags | AT_HANDLE_FID) {
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
            name_to_handle_at_flags(dir_fd, path, flags)
        }
        other => other,
    }
}

/// One `name_to_handle_at` attempt with exactly the given flags.
fn name_to_handle_at_flags(
    dir_fd: i32,
    path: *const libc::c_char,
    flags: i32,
) -> io::Result<FileHandle> {
    // Advertise the largest capacity the kernel accepts, so a filesystem whose
    // handle does not fit is refusing the request rather than being asked twice.
    let mut buf = vec![0u8; MAX_FILE_HANDLE_SIZE];
    let mut mount_id: libc::c_int = 0;
    // `struct file_handle { u32 handle_bytes; i32 handle_type; u8 f_handle[]; }`
    // — on the way in, `handle_bytes` is the *capacity* of `f_handle`.
    buf[0..4].copy_from_slice(&(MAX_HANDLE_SZ as u32).to_ne_bytes());

    // SAFETY: `path` is a NUL-terminated string owned by the caller (or an
    // empty one under `AT_EMPTY_PATH`, where the kernel does not read it), and
    // `buf` is at least as large as the capacity its first four bytes
    // advertise, which is what the kernel writes the handle into.
    let ret = unsafe {
        libc::name_to_handle_at(
            dir_fd,
            path,
            buf.as_mut_ptr() as *mut libc::file_handle,
            &mut mount_id,
            flags,
        )
    };
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(errno()));
    }

    // On success the kernel writes back the *used* length.  Clamp it to the
    // capacity offered so a bogus reply cannot produce a longer slice than the
    // buffer holds.
    let used = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    buf.truncate(FILE_HANDLE_HEADER_SIZE + used.min(MAX_HANDLE_SZ));
    Ok(buf)
}

/// Open a file from its handle, against a mount descriptor on its filesystem.
///
/// `mount_fd` must be a directory descriptor on the filesystem that produced
/// the handle — any directory on it, not necessarily its mount point.
///
/// The returned descriptor is opened `O_PATH`, so it names the object and can
/// be `readlink`ed through `/proc/self/fd`, but cannot be read or written.
///
/// # Errors
///
/// `EPERM` without `CAP_DAC_READ_SEARCH` — the expected answer for an
/// unprivileged caller, and not a defect to work around.
///
/// `ESTALE` is how the kernel reports **every** way this can fail to decode: the
/// object was deleted, the handle belongs to a different filesystem, or this
/// filesystem has no `fh_to_dentry` operation at all.  All three arrive as the
/// same errno, so they cannot be told apart from it — `ENOENT` and
/// `EOPNOTSUPP` are not in this call's vocabulary, even though
/// [`name_to_handle_at`] does use the second.
///
/// `EINVAL` for malformed bytes.  `EXDEV` when the mount descriptor is on a
/// different filesystem.  `ENOSYS` on a kernel without the call.
pub fn open_by_handle_at<Fd: AsFd>(mount_fd: Fd, handle: &[u8]) -> io::Result<OwnedFd> {
    if handle.len() < FILE_HANDLE_HEADER_SIZE || handle.len() > MAX_FILE_HANDLE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handle must be a struct file_handle: an 8-byte header plus at most MAX_HANDLE_SZ bytes",
        ));
    }

    // SAFETY: `handle` is a byte slice of at least the header size and at most
    // the maximum the kernel accepts, which is exactly what the kernel reads
    // through the `*mut file_handle`; `mount_fd` is borrowed for the call.
    // The kernel does not write through the pointer despite the non-const type.
    let fd = unsafe {
        libc::open_by_handle_at(
            mount_fd.as_fd().as_raw_fd(),
            handle.as_ptr() as *mut libc::file_handle,
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(errno()));
    }
    // SAFETY: a non-negative return from `open_by_handle_at` is a descriptor
    // this process owns and nothing else refers to.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The filesystem id of a path, as a FID record would report it.
///
/// This is `statfs(path).f_fsid`.  Use it to recognise which of your mount
/// descriptors belongs to an event, since that is what decides whether a handle
/// may be opened against it.
///
/// # Errors
///
/// `ENOENT` if the path does not exist, `EACCES` if it cannot be reached.
pub fn fsid_of_path<P: AsRef<Path> + ?Sized>(path: &P) -> io::Result<Fsid> {
    let c_path = c_path(path.as_ref())?;
    // SAFETY: `statfs` fills a struct this process owns, and `c_path` is a
    // NUL-terminated string alive for the call.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above; the return value is checked before `st` is read.
    let ret = unsafe { libc::statfs(c_path.as_ptr(), &mut st) };
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(errno()));
    }
    Ok(fsid_of_statfs(&st))
}

/// The filesystem id of an open descriptor.
///
/// Cheaper than [`fsid_of_path`] when a descriptor is already held, and it
/// cannot be raced by a path change.
pub fn fsid_of_fd<Fd: AsFd>(fd: Fd) -> io::Result<Fsid> {
    // SAFETY: `fstatfs` fills a struct this process owns.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above; the return value is checked before `st` is read.
    let ret = unsafe { libc::fstatfs(fd.as_fd().as_raw_fd(), &mut st) };
    if ret != 0 {
        return Err(io::Error::from_raw_os_error(errno()));
    }
    Ok(fsid_of_statfs(&st))
}

/// `f_fsid` as the `(i32, i32)` pair a FID record carries.
///
/// `libc` keeps `fsid_t`'s only field private, so the two words are read by
/// representation.  `__kernel_fsid_t` is defined as exactly two `int`s and the
/// size assertion fails the build if that ever stops being true.
fn fsid_of_statfs(st: &libc::statfs) -> Fsid {
    const _: () = assert!(std::mem::size_of::<libc::fsid_t>() == 8);
    // SAFETY: `fsid_t` is two `c_int`s with no padding, read by value.
    let words: [i32; 2] = unsafe { std::mem::transmute_copy(&st.f_fsid) };
    (words[0], words[1])
}

/// Turn a handle into a path, by opening it and reading `/proc/self/fd`.
///
/// `fsid` filters the candidate mount descriptors: only those on that
/// filesystem are tried.  Pass the fsid the event reported.  `None` means "this
/// handle may be on any filesystem you gave me a descriptor for", which is only
/// sound when every descriptor belongs to one filesystem — otherwise the same
/// bytes can resolve to a *different, existing* file on another one.
///
/// Which filesystem each descriptor is on has to be **asked of the kernel**
/// ([`fsid_of_fd`]) — a descriptor the caller supplies carries no such fact — and
/// a descriptor whose fsid cannot be read is tried anyway: not knowing is not
/// evidence of a mismatch.  That probe runs **once per descriptor per call**,
/// because a bare `&[OwnedFd]` carries no fsid to remember.  [`Mounts`] exists to
/// learn each fsid once instead, and [`Mounts::candidates`] hands the pair to
/// [`resolve_file_handle_in`], which is this function without the repeated
/// `fstatfs`.  Use this one when the descriptors are a local slice built for one
/// call; use that one for anything that resolves more than one handle.
///
/// # Errors
///
/// The errno of the last attempt on a matching filesystem: `EPERM` without
/// `CAP_DAC_READ_SEARCH`, `ESTALE` if the object is gone.  `EXDEV` when no
/// descriptor was on `fsid` at all — a caller mistake, not a property of the
/// handle.  `EINVAL` if `mount_fds` is empty or the handle is malformed.
///
/// # The path is best-effort
///
/// See the module docs: the answer comes from `/proc/self/fd` after the open, so
/// it is the path *at that moment*, and an unlinked object keeps its
/// `" (deleted)"` marker rather than being guessed at.
pub fn resolve_file_handle(
    mount_fds: &[OwnedFd],
    fsid: Option<Fsid>,
    handle: &[u8],
) -> io::Result<PathBuf> {
    if mount_fds.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // Probed here because a bare `&[OwnedFd]` carries no fsid — the kernel has
    // to be asked, once per descriptor per call.  No collection: the candidates
    // are taken as an iterator, so the probe is consumed as it is walked.
    resolve_file_handle_in(
        mount_fds.iter().map(|fd| Candidate {
            fd: fd.as_fd(),
            fsid: fsid_of_fd(fd).ok(),
        }),
        fsid,
        handle,
    )
}

/// One descriptor a handle may be opened against, with what is known about the
/// filesystem it is on.
///
/// What [`resolve_file_handle_in`] walks, and what [`Mounts::candidates`]
/// produces: a descriptor paired with the fsid learned for it once, which is what
/// keeps a resolution from spending an `fstatfs` per call.
///
/// The fsid is what makes the filter sound: `open_by_handle_at` on a descriptor
/// from another filesystem can open the same bytes as a *different, existing*
/// file, and nothing in the answer says so.  `None` is "not known", which is not
/// the same as "does not match" — an unknown fsid on either side matches, and
/// [`resolve_file_handle_in`] states the rule.
///
/// The fields are public so a caller can assemble candidates a [`Mounts`] did not
/// produce — a descriptor whose fsid it read itself with [`fsid_of_fd`], or a
/// synthetic one.  A wrong `fsid` is the one way to get the silent mismatch
/// [`Mounts::add`] exists to prevent, so prefer [`Mounts::add_with_fsid`] unless
/// the value came from this crate.
#[derive(Clone, Copy)]
pub struct Candidate<'a> {
    /// The mount descriptor that may answer.
    pub fd: BorrowedFd<'a>,
    /// The filesystem that descriptor is on, when the kernel would say.
    pub fsid: Option<Fsid>,
}

/// Whether a descriptor on `known` may be tried for a handle reported on
/// `wanted`.
///
/// An unknown fsid on either side matches: no evidence is not evidence against,
/// and refusing to try would turn a descriptor whose filesystem could not be
/// queried into a resolution that never happened.  This is the rule
/// [`Mounts`] pre-filters by, so the selection it hands over is exactly the
/// selection this tries.
///
/// # Zero is not an unimplemented fsid
///
/// No value of [`Fsid`] is reserved, so `(0, 0)` is matched like any other: it
/// means "the filesystem that reports zero", not "no filesystem".  That matters
/// because filesystems do report zero — `fanotify(7)` says so of `fuse(4)`
/// explicitly, and adds that when two of them report zero under one group,
/// **the kernel gives no way to tell them apart**.  Two such mounts therefore
/// select each other here, which is the one case where the fsid filter cannot do
/// what it exists for.  It is not a gap in this rule but a limit of the
/// interface: nothing in the event distinguishes the two, so no rule over the
/// event's own fields could either.  A caller watching two zero-fsid filesystems
/// through one group has to keep one [`Mounts`] per filesystem and pass the
/// right one to the right events.
fn wanted_filesystem(known: Option<Fsid>, wanted: Option<Fsid>) -> bool {
    match (wanted, known) {
        (Some(want), Some(on)) => want == on,
        _ => true,
    }
}

/// [`resolve_file_handle`]'s implementation, over descriptors whose filesystems
/// are already known.
///
/// `resolve_file_handle` accepts a bare `&[OwnedFd]`, which carries no fsid, so
/// it has to ask the kernel ([`fsid_of_fd`]) for each one **on every call** — one
/// `fstatfs` per descriptor per resolution.  That probe is a property of the
/// descriptor, not of any one call, which is exactly the fact [`Mounts`] exists
/// to learn once.  This is that function's other half: call it with
/// [`Mounts::candidates`] and the filter costs nothing, because the fsids were
/// read when the descriptors were added.
///
/// Prefer it over [`resolve_file_handle`] whenever the descriptors outlive the
/// call — an event loop, a worker thread, anything resolving more than one
/// handle.  Reach for `resolve_file_handle` when the descriptors really are a
/// local `&[OwnedFd]` built for one call.
///
/// # Errors
///
/// As [`resolve_file_handle`]: the errno of the last attempt on a matching
/// filesystem (`EPERM` without `CAP_DAC_READ_SEARCH`, `ESTALE` if the object is
/// gone), `EINVAL` for a malformed handle, and `EXDEV` when nothing was tried —
/// an empty selection, or one whose descriptors are all on other filesystems.
/// `EXDEV` is about the selection rather than the handle: it says the caller
/// registered no descriptor that could answer, which is why it is not folded
/// into the last attempt's errno.
///
/// # The path is best-effort
///
/// As [`resolve_file_handle`]: it comes from `/proc/self/fd` after the open, so
/// it is the path *at that moment*, and an unlinked object keeps its
/// `" (deleted)"` marker rather than being guessed at.
///
/// ```
/// use fanotify_fid::handle::{Mounts, resolve_file_handle_in};
///
/// let dir = std::fs::File::open("/tmp")?;
/// let mounts = Mounts::new().with_fd(&dir)?;
///
/// // A byte string that is not a handle: the shape is checked before any
/// // descriptor is used, so this answers without touching the filesystem.
/// let err = resolve_file_handle_in(mounts.candidates(), None, b"short").unwrap_err();
/// assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
///
/// // No descriptor was added for the fsid the caller names, so nothing is
/// // tried — which is a registration gap, not a property of the handle.
/// let err = resolve_file_handle_in(mounts.candidates(), Some((0xdead, 1)), &[0u8; 12])
///     .unwrap_err();
/// assert_eq!(err.raw_os_error(), Some(libc::EXDEV));
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn resolve_file_handle_in<'a, I>(
    candidates: I,
    fsid: Option<Fsid>,
    handle: &[u8],
) -> io::Result<PathBuf>
where
    I: IntoIterator<Item = Candidate<'a>>,
{
    if handle.len() < FILE_HANDLE_HEADER_SIZE || handle.len() > MAX_FILE_HANDLE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handle must be a struct file_handle: an 8-byte header plus at most MAX_HANDLE_SZ bytes",
        ));
    }

    let mut attempted = false;
    let mut last = libc::EXDEV;
    for candidate in candidates {
        if !wanted_filesystem(candidate.fsid, fsid) {
            continue;
        }
        attempted = true;
        match open_by_handle_at(candidate.fd, handle) {
            Ok(fd) => match fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
                Ok(path) => return Ok(path),
                Err(e) => last = e.raw_os_error().unwrap_or(libc::EIO),
            },
            Err(e) => last = e.raw_os_error().unwrap_or(libc::EIO),
        }
    }

    if !attempted {
        // Nothing was tried — no descriptor on the wanted filesystem, or none at
        // all.  Reporting the last errno would blame the handle for a descriptor
        // that never got used.
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Err(io::Error::from_raw_os_error(last))
}

/// A path as a C string, rejecting an interior NUL byte.
fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a null byte"))
}

/// The mount descriptors a caller can resolve handles against, each paired with
/// the filesystem it is on.
///
/// [`open_by_handle_at`] takes a descriptor on the handle's own filesystem, and
/// [`resolve_file_handle`] filters by fsid so it does not open the same bytes
/// against the wrong one.  Both need the same fact — *which filesystem is this
/// descriptor on* — and that fact is a property of the descriptor, not of any
/// one call.  Keeping the pair here is what stops every caller from maintaining
/// a parallel array of fsids and getting it out of step.
///
/// # The fsid is learned once, from the descriptor itself
///
/// [`add`](Self::add) asks the kernel ([`fsid_of_fd`]) instead of taking the
/// caller's word for it, because a mismatch is silent: the handle opens, the
/// `readlink` succeeds, and the path names a **different existing file** on
/// another filesystem.  Probing costs one `fstatfs` per descriptor, once.
///
/// # An open descriptor, not a path
///
/// `add` takes anything [`AsFd`], so a caller can pass a directory it already
/// has open, or open one at the mount point.  No path is stored, so a mount that
/// moves does not leave this collection pointing somewhere stale.
///
/// ```
/// use fanotify_fid::handle::Mounts;
///
/// let dir = std::fs::File::open("/tmp")?;
/// let mounts = Mounts::new().with_fd(&dir)?;
/// assert_eq!(mounts.len(), 1);
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct Mounts {
    /// Each descriptor with the fsid learned for it, in one vector.
    ///
    /// Paired rather than zipped from two vectors because resolution asks
    /// "which of these may answer for this fsid" once per cache miss, and one
    /// contiguous run of `(descriptor, fsid)` is both a single pass and the
    /// iterator [`candidates`](Self::candidates) yields with no collection step.
    entries: Vec<(OwnedFd, Option<Fsid>)>,
}

impl Mounts {
    /// An empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a descriptor, learning its fsid from the kernel.
    ///
    /// The fsid is recorded as unknown if `fstatfs` fails, which costs only the
    /// pre-filter below — resolution still tries the descriptor.
    ///
    /// # Errors
    ///
    /// The descriptor is duplicated (`F_DUPFD_CLOEXEC`), so this fails with
    /// `EMFILE`/`ENFILE` when the process is out of descriptors.
    pub fn add<Fd: AsFd>(&mut self, fd: Fd) -> io::Result<&mut Self> {
        // The fsid probe runs first so that a `try_clone` failure does not leave
        // an entry with a descriptor and no fsid.
        let known = fsid_of_fd(&fd).ok();
        self.entries.push((fd.as_fd().try_clone_to_owned()?, known));
        Ok(self)
    }

    /// [`add`](Self::add), for building a collection in one expression.
    pub fn with_fd<Fd: AsFd>(mut self, fd: Fd) -> io::Result<Self> {
        self.add(fd)?;
        Ok(self)
    }

    /// Add a descriptor whose filesystem is already known.
    ///
    /// For a caller that has just called [`fsid_of_fd`] or
    /// [`fsid_of_path`] itself and would rather not spend a second `fstatfs`.
    /// Passing the wrong fsid here is the one way to get the silent mismatch
    /// [`add`](Self::add) exists to prevent, so prefer `add` unless the value
    /// came from this crate.
    ///
    /// # Errors
    ///
    /// As [`add`](Self::add): the descriptor is duplicated.
    pub fn add_with_fsid<Fd: AsFd>(&mut self, fd: Fd, fsid: Fsid) -> io::Result<&mut Self> {
        self.entries
            .push((fd.as_fd().try_clone_to_owned()?, Some(fsid)));
        Ok(self)
    }

    /// The descriptors on this filesystem, in the order they were added.
    ///
    /// A descriptor whose fsid could not be learned is included: its filesystem
    /// cannot be shown to differ, and skipping it would refuse a resolution this
    /// crate has no evidence is wrong.  An empty result therefore means "none
    /// known to match", not "none can match" — the caller decides what to do
    /// with that.
    pub fn on_filesystem(&self, fsid: Fsid) -> Vec<BorrowedFd<'_>> {
        // Filtered here rather than through `matching`: that returns borrowed
        // descriptors tied to a temporary `Vec`, which cannot be handed out.
        self.entries
            .iter()
            .filter(|(_, known)| wanted_filesystem(*known, Some(fsid)))
            .map(|(fd, _)| fd.as_fd())
            .collect()
    }

    /// The descriptors on this filesystem, as references for a resolution call.
    ///
    /// [`on_filesystem`](Self::on_filesystem) returns borrowed descriptors,
    /// which is what an event loop wants; this returns the owned ones in a plain
    /// `Vec`, which is what asking the filesystem wants.  Both select the same
    /// descriptors.
    pub fn matching(&self, fsid: Fsid) -> Vec<&OwnedFd> {
        self.entries
            .iter()
            .filter(|(_, known)| wanted_filesystem(*known, Some(fsid)))
            .map(|(fd, _)| fd)
            .collect()
    }

    /// Every descriptor with what is known about each one's filesystem.
    ///
    /// The fsid carried alongside each descriptor is what stops
    /// [`resolve_file_handle_in`] from spending an `fstatfs` per candidate: a
    /// descriptor whose fsid was learned by [`add`](Self::add) is already known
    /// to be on the filesystem or not.  An iterator rather than a slice or a
    /// `Vec`, so resolution walks the descriptors in place instead of copying
    /// them somewhere first.  A caller that wants the descriptors alone has
    /// [`on_filesystem`](Self::on_filesystem) and [`iter`](Self::iter).
    pub fn candidates(&self) -> impl Iterator<Item = Candidate<'_>> + use<'_> {
        self.entries.iter().map(|(fd, known)| Candidate {
            fd: fd.as_fd(),
            fsid: *known,
        })
    }

    /// Every descriptor, for iteration when the fsid is not in question.
    pub fn iter(&self) -> impl Iterator<Item = BorrowedFd<'_>> {
        self.entries.iter().map(|(fd, _)| fd.as_fd())
    }

    /// How many descriptors were added.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none were added.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The fsid learned for the descriptor at `index`, if it was learned.
    pub fn fsid_at(&self, index: usize) -> Option<Fsid> {
        self.entries.get(index).and_then(|(_, known)| *known)
    }
}

impl std::ops::Index<usize> for Mounts {
    type Output = OwnedFd;

    fn index(&self, index: usize) -> &OwnedFd {
        &self.entries[index].0
    }
}
