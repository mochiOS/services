//! Blocking record-lock policy. A pending request owns no lock and stores no
//! FD, pathname or client-supplied identity. Native IPC admission must authenticate its
//! owner/image and retain a reference to the observed file before calling here.
//! Sleeping, signal interruption and reply delivery belong to the IPC adapter.
use super::*;
use record_lock::{Error, FileKey, Kind, Range};

pub const MAX_WAITERS: usize = 1024;
pub const MAX_WAITERS_PER_PROCESS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token(u64);

impl Token {
    pub fn from_raw(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }
    pub fn as_raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Acquired,
    Pending(Token),
}

#[derive(Clone, Copy, Debug)]
struct Request {
    owner: u64,
    revision: u64,
    file: FileKey,
    kind: Kind,
    range: Range,
    token: Token,
}

#[derive(Debug)]
pub(super) struct Waits {
    entries: Vec<Request>,
    next: u64,
}

impl Waits {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next: 1,
        }
    }
    pub(super) fn has_owner(&self, owner: u64) -> bool {
        self.entries.iter().any(|entry| entry.owner == owner)
    }
    pub(super) fn has_file(&self, file: FileKey) -> bool {
        self.entries.iter().any(|entry| entry.file == file)
    }
    pub(super) fn retire_owner(&mut self, owner: u64) {
        self.entries.retain(|entry| entry.owner != owner);
    }

    /// Recompute edges from current held ranges, never cached first-blocker
    /// PIDs: one write request may be blocked by multiple independent readers.
    /// Bounded scratch needs no allocation while inspecting policy. Owners
    /// without pending calls have no outgoing edges and need not be visited.
    fn deadlocks(&self, candidate: Request, locks: &record_lock::Registry) -> bool {
        let mut owners = [0u64; MAX_WAITERS + 1];
        for (slot, entry) in owners.iter_mut().zip(&self.entries) {
            *slot = entry.owner;
        }
        owners[self.entries.len()] = candidate.owner;
        let mut count = self.entries.len() + 1;
        owners[..count].sort_unstable();
        let mut unique = 0;
        for index in 0..count {
            if unique == 0 || owners[unique - 1] != owners[index] {
                owners[unique] = owners[index];
                unique += 1;
            }
        }
        count = unique;
        let owners = &owners[..count];
        let mut seen = [false; MAX_WAITERS + 1];
        let mut queue = [0usize; MAX_WAITERS + 1];
        let root = owners.binary_search(&candidate.owner).unwrap();
        queue[0] = root;
        seen[root] = true;
        let (mut head, mut tail) = (0, 1);
        while head < tail {
            let owner = owners[queue[head]];
            head += 1;
            let mut cycle = false;
            let mut inspect = |request: &Request| {
                locks.for_each_blocker(
                    request.owner,
                    request.file,
                    request.kind,
                    request.range,
                    |blocker| {
                        if blocker == candidate.owner {
                            cycle = true;
                        } else if let Ok(index) = owners.binary_search(&blocker) {
                            if !seen[index] {
                                seen[index] = true;
                                queue[tail] = index;
                                tail += 1;
                            }
                        }
                    },
                );
            };
            if owner == candidate.owner {
                inspect(&candidate);
            }
            for entry in self.entries.iter().filter(|entry| entry.owner == owner) {
                inspect(entry);
            }
            if cycle {
                return true;
            }
        }
        false
    }

    fn enqueue(
        &mut self,
        mut request: Request,
        locks: &record_lock::Registry,
    ) -> Result<Token, i32> {
        if self.entries.len() >= MAX_WAITERS
            || self
                .entries
                .iter()
                .filter(|entry| entry.owner == request.owner)
                .count()
                >= MAX_WAITERS_PER_PROCESS
            || self.next == u64::MAX
        {
            return Err(-37); // ENOLCK; never wrap a token into an ABA match.
        }
        if self.deadlocks(request, locks) {
            return Err(-35); // EDEADLK
        }
        self.entries.try_reserve(1).map_err(|_| -37)?;
        request.token = Token(self.next);
        self.next += 1;
        self.entries.push(request);
        Ok(request.token)
    }
}

impl<H: Copy> PosixService<H> {
    /// Internal after native image and FileHandle validation. Range is fixed
    /// at initial admission, including a SEEK_CUR/END observation. Register
    /// and retry under the same service state lock as ordinary lock mutation.
    pub fn begin_record_lock_wait(
        &mut self,
        peer: PeerIdentity,
        file: FileKey,
        kind: Kind,
        range: Range,
    ) -> Result<Outcome, i32> {
        match self.record_locks(peer)?.set(file, kind, range) {
            Ok(()) => return Ok(Outcome::Acquired),
            Err(Error::WouldBlock(_)) => {}
            Err(error) => return Err(status(error)),
        }
        let revision = self.process_wait_states[&peer.process_id].observed_image_revision;
        self.record_lock_waits
            .enqueue(
                Request {
                    owner: peer.process_id,
                    revision,
                    file,
                    kind,
                    range,
                    token: Token(0),
                },
                &self.record_locks,
            )
            .map(Outcome::Pending)
    }

    /// No speculative grant: a wake is only a reason to retry. Revalidation
    /// and acquisition are atomic with competing lock changes. On terminal
    /// failure the request is consumed; a continuing conflict stays pending.
    pub fn retry_record_lock_wait(
        &mut self,
        peer: PeerIdentity,
        token: Token,
    ) -> Result<Outcome, i32> {
        let index = self.record_lock_wait_index(peer, token)?;
        let entry = self.record_lock_waits.entries[index];
        match self
            .record_locks(peer)?
            .set(entry.file, entry.kind, entry.range)
        {
            Err(Error::WouldBlock(_)) => Ok(Outcome::Pending(token)),
            result => {
                self.record_lock_waits.entries.remove(index);
                result.map(|()| Outcome::Acquired).map_err(status)
            }
        }
    }

    /// Called for interruption, cancellation or abandoned IPC. Never releases
    /// an acquired lock; acquisition already consumed the pending token.
    pub fn cancel_record_lock_wait(&mut self, peer: PeerIdentity, token: Token) -> Result<(), i32> {
        let index = self.record_lock_wait_index(peer, token)?;
        self.record_lock_waits.entries.remove(index);
        Ok(())
    }

    fn record_lock_wait_index(&mut self, peer: PeerIdentity, token: Token) -> Result<usize, i32> {
        self.record_locks(peer)?;
        let revision = self.process_wait_states[&peer.process_id].observed_image_revision;
        self.record_lock_waits
            .entries
            .iter()
            .position(|entry| {
                entry.owner == peer.process_id && entry.revision == revision && entry.token == token
            })
            .ok_or(protocol::STATUS_ESRCH)
    }
}

fn status(error: Error) -> i32 {
    match error {
        Error::InvalidRange => STATUS_EINVAL,
        Error::Overflow => STATUS_EOVERFLOW,
        Error::WouldBlock(_) => -11,
        Error::NoLocks => -37,
    }
}
