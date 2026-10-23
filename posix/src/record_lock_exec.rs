//! Prepare close-on-exec lock retirement without changing a single lock until
//! a trusted native image observation proves successful replacement. This is
//! internal policy state; no FD, pathname or client-supplied image generation
//! is authority. A FileHandle IPC adapter must identify the files first.
use super::*;
use record_lock::FileKey;

pub const MAX_PREPARATIONS: usize = 1024;

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

#[derive(Debug)]
struct Preparation {
    owner: u64,
    revision: u64,
    token: Token,
    files: Vec<FileKey>,
}

#[derive(Debug)]
pub(super) struct Preparations {
    entries: Vec<Preparation>,
    next_token: u64,
}

impl Preparations {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_token: 1,
        }
    }

    pub(super) fn retire_owner(&mut self, owner: u64) {
        self.entries.retain(|entry| entry.owner != owner);
    }

    pub(super) fn has_owner(&self, owner: u64) -> bool {
        self.entries.iter().any(|entry| entry.owner == owner)
    }

    /// Infallible after the native image and process state have been checked.
    /// One preparation is consumed once, even if observation skips generations.
    pub(super) fn commit_observed(
        &mut self,
        owner: u64,
        revision: u64,
        locks: &mut record_lock::Registry,
    ) {
        self.entries.retain(|entry| {
            if entry.owner != owner || revision <= entry.revision {
                return true;
            }
            for &file in &entry.files {
                locks.release_file(owner, file);
            }
            false
        });
    }
}

impl<H: Copy> PosixService<H> {
    pub fn has_record_lock_execs(&self) -> bool {
        !self.record_lock_execs.entries.is_empty()
    }

    /// Called periodically and immediately before a lock operation on `file`.
    /// A different process must not see stale conflicts after completed exec.
    /// Metadata failures do not prevent observing independent owners.
    pub fn refresh_record_lock_execs<P: ProcessBackend<H>>(
        &mut self,
        processes: &mut P,
        file: Option<FileKey>,
    ) -> Result<usize, i32> {
        let mut owners = Vec::new();
        owners
            .try_reserve(self.record_lock_execs.entries.len())
            .map_err(|_| -12)?;
        owners.extend(
            self.record_lock_execs
                .entries
                .iter()
                .filter(|entry| file.is_none_or(|file| entry.files.contains(&file)))
                .map(|entry| entry.owner),
        );
        let mut completed = 0;
        let mut failure = None;
        for owner in owners {
            let result = self
                .registered_peer(owner)
                .ok_or(protocol::STATUS_ESRCH)
                .and_then(|peer| self.refresh_image_state(peer, processes));
            match result {
                Ok(()) => completed += usize::from(!self.record_lock_execs.has_owner(owner)),
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(completed), Err)
    }

    /// Atomically append observations from another bounded Handle IPC batch.
    pub fn extend_record_lock_exec(
        &mut self,
        peer: PeerIdentity,
        token: Token,
        files: &[FileKey],
    ) -> Result<(), i32> {
        self.record_locks(peer)?;
        let entry = self
            .record_lock_execs
            .entries
            .iter_mut()
            .find(|entry| entry.owner == peer.process_id && entry.token == token)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut added = Vec::new();
        for &file in files {
            if self.record_locks.owns_file(peer.process_id, file)
                && !entry.files.contains(&file)
                && !added.contains(&file)
            {
                if entry.files.len() + added.len() >= record_lock::MAX_LOCKS_PER_PROCESS {
                    return Err(-37);
                }
                added.try_reserve(1).map_err(|_| -37)?;
                added.push(file);
            }
        }
        entry.files.try_reserve(added.len()).map_err(|_| -37)?;
        entry.files.extend(added);
        Ok(())
    }

    /// Internal API after native request admission and FileHandle observation.
    /// `files` is the trusted set of files closed by the proposed image's FD
    /// snapshot. The eventual runtime must serialize lock/FD mutations and
    /// concurrent exec attempts, cancel on failure and never call this from
    /// raw client-supplied device/inode bytes. No startup claim commits it.
    pub fn prepare_record_lock_exec(
        &mut self,
        peer: PeerIdentity,
        files: &[FileKey],
    ) -> Result<Option<Token>, i32> {
        self.record_locks(peer)?;
        let owner = peer.process_id;
        if self
            .record_lock_execs
            .entries
            .iter()
            .any(|entry| entry.owner == owner)
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        let mut selected = Vec::new();
        for &file in files {
            if self.record_locks.owns_file(owner, file) && !selected.contains(&file) {
                selected.try_reserve(1).map_err(|_| -37)?;
                selected.push(file);
            }
        }
        if selected.is_empty() {
            return Ok(None);
        }
        if self.record_lock_execs.entries.len() >= MAX_PREPARATIONS {
            return Err(protocol::STATUS_EAGAIN);
        }
        let next_token = self
            .record_lock_execs
            .next_token
            .checked_add(1)
            .ok_or(STATUS_EOVERFLOW)?;
        self.record_lock_execs
            .entries
            .try_reserve(1)
            .map_err(|_| -37)?;
        let token = Token(self.record_lock_execs.next_token);
        self.record_lock_execs.entries.push(Preparation {
            owner,
            revision: self.process_wait_states[&owner].observed_image_revision,
            token,
            files: selected,
        });
        self.record_lock_execs.next_token = next_token;
        Ok(Some(token))
    }

    /// Cancel only this process's exact preparation. A late cancellation can
    /// neither erase another process's plan nor a newer plan after exec.
    pub fn cancel_record_lock_exec(&mut self, peer: PeerIdentity, token: Token) -> Result<(), i32> {
        self.record_locks(peer)?;
        let index = self
            .record_lock_execs
            .entries
            .iter()
            .position(|entry| entry.owner == peer.process_id && entry.token == token)
            .ok_or(protocol::STATUS_ESRCH)?;
        self.record_lock_execs.entries.swap_remove(index);
        Ok(())
    }
}
