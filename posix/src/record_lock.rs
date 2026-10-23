//! Process-owned advisory record locks. No descriptor, pathname or untrusted
//! request identity is accepted here. The eventual IPC adapter must obtain a
//! file key and access mode from the explicitly delegated FileHandle.
use super::*;

pub const MAX_LOCKS: usize = 4096;
pub const MAX_LOCKS_PER_PROCESS: usize = 128;
const END: u64 = i64::MAX as u64 + 1;

/// Identity supplied by the trusted filesystem observation, never wire data.
/// Different descriptions, hard links and renamed paths may share this key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileKey {
    pub device: u64,
    pub inode: u64,
}

pub use protocol::record_lock::Kind;

/// Half-open interval within the signed off_t domain. END also represents
/// locking through all future file growth, rather than today's file length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    start: u64,
    end: u64,
}

impl Range {
    /// `base` is a validated SEEK_SET/CUR/END snapshot. Negative lengths are
    /// supported without signed overflow or reducing zero length to empty.
    pub fn normalize(base: i64, offset: i64, length: i64) -> Result<Self, Error> {
        if base < 0 {
            return Err(Error::InvalidRange);
        }
        let anchor = i128::from(base) + i128::from(offset);
        if anchor < 0 {
            return Err(Error::InvalidRange);
        }
        if anchor > i128::from(i64::MAX) {
            return Err(Error::Overflow);
        }
        let (start, end) = if length < 0 {
            (anchor + i128::from(length), anchor)
        } else if length == 0 {
            (anchor, i128::from(END))
        } else {
            (anchor, anchor + i128::from(length))
        };
        if start < 0 || end <= start {
            return Err(Error::InvalidRange);
        }
        if end > i128::from(END) {
            return Err(Error::Overflow);
        }
        Ok(Self {
            start: start as u64,
            end: end as u64,
        })
    }
    /// Canonical SEEK_SET offset/length. Zero length retains growth coverage.
    pub fn offset_length(self) -> (i64, i64) {
        (
            self.start as i64,
            if self.end == END {
                0
            } else {
                (self.end - self.start) as i64
            },
        )
    }
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub owner: u64,
    pub kind: Kind,
    pub range: Range,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRange,
    Overflow,
    WouldBlock(Conflict),
    NoLocks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Lock {
    file: FileKey,
    owner: u64,
    kind: Kind,
    range: Range,
}

#[derive(Debug)]
pub(super) struct Registry {
    entries: Vec<Lock>,
}
impl Registry {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub(super) fn has_owner(&self, owner: u64) -> bool {
        self.entries.iter().any(|lock| lock.owner == owner)
    }
    pub(super) fn has_file(&self, file: FileKey) -> bool {
        self.entries.iter().any(|lock| lock.file == file)
    }
    pub(super) fn owns_file(&self, owner: u64, file: FileKey) -> bool {
        self.entries
            .iter()
            .any(|lock| lock.owner == owner && lock.file == file)
    }
    pub(super) fn release_file(&mut self, owner: u64, file: FileKey) {
        self.entries
            .retain(|lock| lock.owner != owner || lock.file != file);
    }
    pub(super) fn retire_owner(&mut self, owner: u64) {
        self.entries.retain(|lock| lock.owner != owner);
    }

    fn conflict(&self, owner: u64, file: FileKey, kind: Kind, range: Range) -> Option<Conflict> {
        self.entries
            .iter()
            .filter(|lock| {
                lock.file == file
                    && lock.owner != owner
                    && range.overlaps(lock.range)
                    && (kind == Kind::Write || lock.kind == Kind::Write)
            })
            .min_by_key(|lock| (lock.range.start, lock.owner))
            .map(|lock| Conflict {
                owner: lock.owner,
                kind: lock.kind,
                range: lock.range,
            })
    }

    fn replace(
        &mut self,
        owner: u64,
        file: FileKey,
        range: Range,
        kind: Option<Kind>,
    ) -> Result<(), Error> {
        if let Some(kind) = kind {
            if let Some(conflict) = self.conflict(owner, file, kind, range) {
                return Err(Error::WouldBlock(conflict));
            }
        }
        if kind.is_none()
            && !self.entries.iter().any(|lock| {
                lock.owner == owner
                    && lock.file == file
                    && lock.range.start < range.start
                    && range.end < lock.range.end
            })
        {
            // Whole removal, no-op and edge trimming need no new record.
            // These releases must work without allocating temporary storage.
            self.entries.retain_mut(|lock| {
                if lock.owner != owner || lock.file != file || !lock.range.overlaps(range) {
                    return true;
                }
                if lock.range.start < range.start {
                    lock.range.end = range.start;
                    true
                } else if range.end < lock.range.end {
                    lock.range.start = range.end;
                    true
                } else {
                    false
                }
            });
            return Ok(());
        }
        // Build before mutation. Splitting, merging and quota failure leave
        // all prior locks intact, including a failed read-to-write upgrade.
        let mut next = Vec::new();
        next.try_reserve(self.entries.len() * 2 + usize::from(kind.is_some()))
            .map_err(|_| Error::NoLocks)?;
        for &lock in &self.entries {
            if lock.owner != owner || lock.file != file || !lock.range.overlaps(range) {
                next.push(lock);
                continue;
            }
            if lock.range.start < range.start {
                next.push(Lock {
                    range: Range {
                        start: lock.range.start,
                        end: range.start,
                    },
                    ..lock
                });
            }
            if range.end < lock.range.end {
                next.push(Lock {
                    range: Range {
                        start: range.end,
                        end: lock.range.end,
                    },
                    ..lock
                });
            }
        }
        if let Some(kind) = kind {
            next.push(Lock {
                file,
                owner,
                kind,
                range,
            });
        }
        next.sort_unstable_by_key(|lock| (lock.file, lock.owner, lock.range.start));
        let mut used = 0;
        for index in 0..next.len() {
            let lock = next[index];
            if used != 0
                && next[used - 1].file == lock.file
                && next[used - 1].owner == lock.owner
                && next[used - 1].kind == lock.kind
                && next[used - 1].range.end >= lock.range.start
            {
                next[used - 1].range.end = next[used - 1].range.end.max(lock.range.end);
            } else {
                next[used] = lock;
                used += 1;
            }
        }
        next.truncate(used);
        if used > MAX_LOCKS
            || next.iter().filter(|lock| lock.owner == owner).count() > MAX_LOCKS_PER_PROCESS
        {
            return Err(Error::NoLocks);
        }
        self.entries = next;
        Ok(())
    }
}

/// Borrow tied to one service-admitted process, independent of its UID.
pub struct OwnedLocks<'a, H: Copy = u32> {
    owner: u64,
    registry: &'a mut Registry,
    publication: Option<&'a dyn resource_policy::Published<H>>,
}
impl<H: Copy> OwnedLocks<'_, H> {
    fn publish(&self) {
        if let Some(page) = self.publication {
            page.publish_record_locks(self.registry.has_owner(self.owner));
        }
    }
    /// Apply a decoded request after Handle, access-mode and image admission.
    /// The adapter must keep the file alive and obtain position/size from that
    /// same attached description, outside the service state lock. Neither
    /// value, nor `file`, may be accepted as authority from request bytes.
    pub fn apply(
        &mut self,
        file: FileKey,
        request: protocol::record_lock::Request,
        current_position: i64,
        file_size: i64,
    ) -> Result<protocol::record_lock::Reply, i32> {
        use protocol::record_lock::{Operation, Origin, Reply};
        if request.operation == Operation::ReleaseFile {
            // Preserve the wire invariant for internal callers too.
            if request.origin != Origin::Start || request.start != 0 || request.length != 0 {
                return Err(STATUS_EINVAL);
            }
            self.release_file(file);
            return Ok(Reply::Done);
        }
        let base = match request.origin {
            Origin::Start => 0,
            Origin::Current => current_position,
            Origin::End => file_size,
        };
        let range = Range::normalize(base, request.start, request.length).map_err(lock_status)?;
        match request.operation {
            Operation::Query(kind) => Ok(match self.conflict(file, kind, range) {
                Some(conflict) => {
                    let (start, length) = conflict.range.offset_length();
                    Reply::Conflict {
                        owner: conflict.owner,
                        kind: conflict.kind,
                        start,
                        length,
                    }
                }
                None => Reply::Unlocked,
            }),
            Operation::Set(kind) => self
                .set(file, kind, range)
                .map(|()| Reply::Done)
                .map_err(lock_status),
            Operation::Unlock => self
                .unlock(file, range)
                .map(|()| Reply::Done)
                .map_err(lock_status),
            Operation::ReleaseFile => unreachable!(),
        }
    }

    pub fn conflict(&self, file: FileKey, kind: Kind, range: Range) -> Option<Conflict> {
        self.registry.conflict(self.owner, file, kind, range)
    }
    pub fn set(&mut self, file: FileKey, kind: Kind, range: Range) -> Result<(), Error> {
        let result = self.registry.replace(self.owner, file, range, Some(kind));
        self.publish();
        result
    }
    pub fn unlock(&mut self, file: FileKey, range: Range) -> Result<(), Error> {
        let result = self.registry.replace(self.owner, file, range, None);
        self.publish();
        result
    }
    /// Closing ANY description of this file releases this process's locks.
    /// The FD/IPC adapter must call this, including dup2 replacement/exec close.
    pub fn release_file(&mut self, file: FileKey) {
        self.registry.release_file(self.owner, file);
        self.publish();
    }
}

fn lock_status(error: Error) -> i32 {
    match error {
        Error::InvalidRange => STATUS_EINVAL,
        Error::Overflow => STATUS_EOVERFLOW,
        Error::WouldBlock(_) => -11, // EAGAIN, nonblocking F_SETLK
        Error::NoLocks => -37,       // ENOLCK
    }
}

impl<H: Copy> PosixService<H> {
    /// Internal API after native image/Handle admission, not a wire request.
    pub fn record_locks(&mut self, peer: PeerIdentity) -> Result<OwnedLocks<'_, H>, i32> {
        if !self.sessions.contains_key(&peer.process_id)
            || !self.processes.contains_key(&peer.process_id)
            || self
                .process_wait_states
                .get(&peer.process_id)
                .is_none_or(|state| state.exit_observed)
        {
            return Err(protocol::STATUS_ESRCH);
        }
        Ok(OwnedLocks {
            owner: peer.process_id,
            registry: &mut self.record_locks,
            publication: self
                .resource_policies
                .iter()
                .find(|(owner, _)| *owner == peer.process_id)
                .map(|(_, page)| page.as_ref()),
        })
    }
}
