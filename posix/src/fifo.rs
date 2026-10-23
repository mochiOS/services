//! Owner-side state for one retained FIFO inode. No pathname, PID or FD is an
//! authority here: the future filesystem/provider adapter must authenticate the
//! inode and own a native provider reference before registering an opening.
//!
//! Calls are serialized by the owner. Blocking is expressed as pending/would
//! block, so the service dispatcher never sleeps while holding this state.

use std::collections::VecDeque;

pub const BUFFER_CAPACITY: usize = 64 * 1024;
pub const MAX_OPEN_DESCRIPTIONS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// Owner-local description token; never an authentication token or an FD.
/// Duplicated/transferred native references share it. Release it only when the
/// native provider reports the last reference, not on each dup/fork FD close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptionId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadDescription,
    WrongAccess,
    OpenPending,
    WouldBlock,
    NoReaders,
    ResourceLimit,
    NoMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub open_ready: bool,
    pub buffered_bytes: usize,
    pub readers: usize,
    pub writers: usize,
}

struct Description {
    id: DescriptionId,
    access: Access,
    ready: bool,
}

#[derive(Default)]
pub struct Channel {
    data: VecDeque<u8>,
    descriptions: Vec<Description>,
    last_id: u64,
}

impl Channel {
    /// Register an owner-held reference. A blocking opening joins the rendezvous
    /// immediately but cannot do I/O until its opposite side has registered.
    /// Admission/allocation failures leave all existing openings unchanged.
    /// O_RDWR is intentionally absent: its FIFO behavior is not portable POSIX.
    pub fn open(&mut self, access: Access, nonblocking: bool) -> Result<DescriptionId, Error> {
        let opposite_present = self.descriptions.iter().any(|entry| entry.access != access);
        if access == Access::Write && nonblocking && !opposite_present {
            return Err(Error::NoReaders);
        }
        if self.descriptions.len() == MAX_OPEN_DESCRIPTIONS {
            return Err(Error::ResourceLimit);
        }
        let next = self.last_id.checked_add(1).ok_or(Error::ResourceLimit)?;
        self.descriptions
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        let id = DescriptionId(next);
        self.descriptions.push(Description {
            id,
            access,
            ready: nonblocking || opposite_present,
        });
        self.last_id = next;
        for entry in &mut self.descriptions {
            if entry.access != access {
                entry.ready = true;
            }
        }
        Ok(id)
    }

    pub fn observe(&self, id: DescriptionId) -> Result<Observation, Error> {
        let entry = self.description(id)?;
        let readers = self
            .descriptions
            .iter()
            .filter(|entry| entry.access == Access::Read)
            .count();
        Ok(Observation {
            open_ready: entry.ready,
            buffered_bytes: self.data.len(),
            readers,
            writers: self.descriptions.len() - readers,
        })
    }

    pub fn read(&mut self, id: DescriptionId, output: &mut [u8]) -> Result<usize, Error> {
        self.require_ready(id, Access::Read)?;
        if output.is_empty() {
            return Ok(0);
        }
        if self.data.is_empty()
            && self
                .descriptions
                .iter()
                .any(|entry| entry.access == Access::Write)
        {
            return Err(Error::WouldBlock);
        }
        let count = output.len().min(self.data.len());
        for byte in &mut output[..count] {
            *byte = self
                .data
                .pop_front()
                .expect("count bounded by queued bytes");
        }
        Ok(count)
    }

    /// One transfer attempt. Small writes are all-or-none; large writes return
    /// available progress. The client handles waiting/retry and signal policy.
    pub fn write(&mut self, id: DescriptionId, input: &[u8]) -> Result<usize, Error> {
        self.require_ready(id, Access::Write)?;
        if input.is_empty() {
            return Ok(0);
        }
        if !self
            .descriptions
            .iter()
            .any(|entry| entry.access == Access::Read)
        {
            return Err(Error::NoReaders);
        }
        let available = BUFFER_CAPACITY - self.data.len();
        if available == 0
            || (input.len() <= mochios_posix_protocol::PIPE_BUF && input.len() > available)
        {
            return Err(Error::WouldBlock);
        }
        let count = input.len().min(available);
        self.data.try_reserve(count).map_err(|_| Error::NoMemory)?;
        self.data.extend(&input[..count]);
        Ok(count)
    }

    /// Also cancels an unmatched opening. The adapter must retire its native
    /// reference before calling this; a failed publication cannot leak a peer.
    pub fn close(&mut self, id: DescriptionId) -> Result<(), Error> {
        let index = self
            .descriptions
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(Error::BadDescription)?;
        self.descriptions.swap_remove(index);
        if self.descriptions.is_empty() {
            // An inode surviving in the filesystem does not preserve pipe data
            // after its last open reference. Tokens still never get reused.
            self.data = VecDeque::new();
            self.descriptions = Vec::new();
        }
        Ok(())
    }

    fn description(&self, id: DescriptionId) -> Result<&Description, Error> {
        self.descriptions
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(Error::BadDescription)
    }

    fn require_ready(&self, id: DescriptionId, access: Access) -> Result<(), Error> {
        let entry = self.description(id)?;
        if entry.access != access {
            return Err(Error::WrongAccess);
        }
        if !entry.ready {
            return Err(Error::OpenPending);
        }
        Ok(())
    }
}
