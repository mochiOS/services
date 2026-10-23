//! Prepare close-on-exec lock retirement without changing a single lock until
//! a trusted native image observation proves successful replacement. This is
//! internal policy state; no FD, pathname or client-supplied image generation
//! is authority. A FileHandle IPC adapter must identify the files first.
use super::*;
use record_lock::FileKey;

pub const MAX_PREPARATIONS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token(u64);

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
