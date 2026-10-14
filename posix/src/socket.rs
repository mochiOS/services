//! Userspace UNIX stream descriptions. IDs are private Provider object IDs,
//! never client FDs or lookup authority. A native adapter must authenticate each
//! operation through its attached Handle and release only its final reference.

use mochios_posix_protocol::socket::{Create, Domain, Kind, NONBLOCKING};
use std::collections::VecDeque;

pub const RECEIVE_CAPACITY: usize = 64 * 1024;
pub const MAX_ENDPOINTS: usize = 1024;
pub const MAX_BACKLOG: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shutdown {
    Read,
    Write,
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    pub read_closed: bool,
    pub write_closed: bool,
    pub write_error: bool,
}

struct Listener {
    backlog: usize,
    pending: VecDeque<u64>,
}

struct Endpoint {
    id: u64,
    // None means never connected, not a previously connected peer's close.
    peer: Option<u64>,
    credentials: (u32, u32),
    incoming: VecDeque<u8>,
    read_shutdown: bool,
    write_shutdown: bool,
    options: u32,
    listener: Option<Listener>,
}

/// Serialize operations externally. Dup/fork alias an existing description;
/// they do not create entries here. EAGAIN is returned to the native adapter,
/// which must arrange readiness waiting without blocking its dispatch worker.
pub struct Streams {
    next: u64,
    entries: Vec<Endpoint>,
}

impl Default for Streams {
    fn default() -> Self {
        Self::new()
    }
}

impl Streams {
    pub const fn new() -> Self {
        Self {
            next: 1,
            entries: Vec::new(),
        }
    }

    fn endpoint(&self, id: u64) -> Result<&Endpoint, i32> {
        self.entries.iter().find(|entry| entry.id == id).ok_or(-9)
    }

    fn endpoint_mut(&mut self, id: u64) -> Result<&mut Endpoint, i32> {
        self.entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(-9)
    }

    fn validate_create(request: Create) -> Result<(), i32> {
        if request.options & !NONBLOCKING != 0 {
            return Err(-22);
        }
        if request.domain != Domain::Unix || request.kind != Kind::Stream {
            return Err(-95);
        }
        if request.protocol != 0 {
            return Err(-93);
        }
        Ok(())
    }

    fn create(&mut self, request: Create, credentials: (u32, u32)) -> Result<u64, i32> {
        Self::validate_create(request)?;
        if self.entries.len() == MAX_ENDPOINTS || self.next > i64::MAX as u64 {
            return Err(-23);
        }
        self.entries.try_reserve(1).map_err(|_| -12)?;
        let id = self.next;
        self.entries.push(Endpoint {
            id,
            peer: None,
            credentials,
            incoming: VecDeque::new(),
            read_shutdown: false,
            write_shutdown: false,
            options: request.options,
            listener: None,
        });
        self.next += 1;
        Ok(id)
    }

    fn create_pair(&mut self, request: Create, credentials: (u32, u32)) -> Result<[u64; 2], i32> {
        Self::validate_create(request)?;
        if self.entries.len() > MAX_ENDPOINTS - 2 {
            return Err(-23);
        }
        let second = self
            .next
            .checked_add(1)
            .filter(|id| *id <= i64::MAX as u64)
            .ok_or(-23)?;
        let next = second + 1;
        self.entries.try_reserve(2).map_err(|_| -12)?;
        let ids = [self.next, second];
        for (id, peer) in [(ids[0], ids[1]), (ids[1], ids[0])] {
            self.entries.push(Endpoint {
                id,
                peer: Some(peer),
                credentials,
                incoming: VecDeque::new(),
                read_shutdown: false,
                write_shutdown: false,
                options: request.options,
                listener: None,
            });
        }
        self.next = next;
        Ok(ids)
    }

    pub fn credentials(&self, id: u64) -> Result<(u32, u32), i32> {
        Ok(self.endpoint(id)?.credentials)
    }

    /// Unbound UNIX sockets have no local pathname.
    pub fn address(
        &self,
        id: u64,
    ) -> Result<mochios_posix_protocol::socket::Address<'static>, i32> {
        self.endpoint(id)?;
        Ok(mochios_posix_protocol::socket::Address::UnixUnnamed)
    }

    /// Closing a connected peer does not erase the established address;
    /// a never-connected socket must instead report ENOTCONN.
    pub fn peer_address(
        &self,
        id: u64,
    ) -> Result<mochios_posix_protocol::socket::Address<'static>, i32> {
        self.endpoint(id)?.peer.ok_or(-107)?;
        Ok(mochios_posix_protocol::socket::Address::UnixUnnamed)
    }

    pub fn status(&self, id: u64) -> Result<mochios_posix_protocol::FileStatus, i32> {
        let entry = self.endpoint(id)?;
        Ok(mochios_posix_protocol::FileStatus {
            device: 0x534f,
            inode: entry.id,
            mode: 0o140600,
            // Socket pairs have no filesystem links. Queued bytes are not a
            // regular file extent or allocated filesystem blocks.
            link_count: 0,
            uid: entry.credentials.0,
            gid: entry.credentials.1,
            block_size: mnu_abi::provider::MAX_DATA_LEN as i64,
            // This virtual object does not currently track timestamps.
            ..Default::default()
        })
    }
    /// Internal Provider IDs affected by an operation, not transferable authority.
    pub fn affected(&self, id: u64) -> Result<[u64; 2], i32> {
        Ok([id, self.endpoint(id)?.peer.unwrap_or(id)])
    }
    pub fn options(&self, id: u64) -> Result<u32, i32> {
        Ok(self.endpoint(id)?.options)
    }
    pub fn set_options(&mut self, id: u64, options: u32) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        if options & !NONBLOCKING != 0 {
            return Err(-22);
        }
        entry.options = options;
        Ok(())
    }

    pub fn write(&mut self, id: u64, input: &[u8]) -> Result<usize, i32> {
        let entry = self.endpoint(id)?;
        if input.is_empty() {
            return Ok(0);
        }
        if entry.write_shutdown {
            return Err(-32);
        }
        let peer = entry.peer.ok_or(-107)?;
        let receiver = self.endpoint_mut(peer).map_err(|_| -32)?;
        if receiver.read_shutdown {
            return Err(-32);
        }
        let count = input.len().min(RECEIVE_CAPACITY - receiver.incoming.len());
        if count == 0 {
            return Err(-11);
        }
        receiver.incoming.try_reserve(count).map_err(|_| -12)?;
        receiver.incoming.extend(&input[..count]);
        Ok(count)
    }

    pub fn read(&mut self, id: u64, output: &mut [u8]) -> Result<usize, i32> {
        let ready = self.readiness(id)?;
        let entry = self.endpoint_mut(id)?;
        if output.is_empty() || entry.read_shutdown {
            return Ok(0);
        }
        if entry.peer.is_none() {
            return Err(-107);
        }
        let count = output.len().min(entry.incoming.len());
        if count == 0 && !ready.read_closed {
            return Err(-11);
        }
        for byte in &mut output[..count] {
            *byte = entry.incoming.pop_front().unwrap();
        }
        Ok(count)
    }

    pub fn shutdown(&mut self, id: u64, how: Shutdown) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        entry.peer.ok_or(-107)?;
        if matches!(how, Shutdown::Read | Shutdown::Both) {
            entry.read_shutdown = true;
            entry.incoming.clear();
        }
        if matches!(how, Shutdown::Write | Shutdown::Both) {
            entry.write_shutdown = true;
        }
        Ok(())
    }

    /// The adapter must verify a bound namespace identity before entering this
    /// transition. Allocate pending capacity before publishing or changing it.
    pub fn listen(&mut self, id: u64, backlog: u32) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        if entry.peer.is_some() {
            return Err(-22);
        }
        let backlog = (backlog as usize).clamp(1, MAX_BACKLOG);
        if let Some(listener) = &mut entry.listener {
            listener
                .pending
                .try_reserve(backlog.saturating_sub(listener.pending.len()))
                .map_err(|_| -12)?;
            listener.backlog = backlog;
        } else {
            let mut pending = VecDeque::new();
            pending.try_reserve(backlog).map_err(|_| -12)?;
            entry.listener = Some(Listener { backlog, pending });
        }
        Ok(())
    }

    pub fn listening_backlog(&self, id: u64) -> Result<Option<usize>, i32> {
        Ok(self
            .endpoint(id)?
            .listener
            .as_ref()
            .map(|listener| listener.backlog))
    }

    pub fn readiness(&self, id: u64) -> Result<Readiness, i32> {
        let entry = self.endpoint(id)?;
        if let Some(listener) = &entry.listener {
            return Ok(Readiness {
                readable: !listener.pending.is_empty(),
                writable: false,
                read_closed: false,
                write_closed: false,
                write_error: false,
            });
        }
        if entry.peer.is_none() {
            // An attempted IO completes with ENOTCONN, rather than sleeping.
            return Ok(Readiness {
                readable: true,
                writable: true,
                read_closed: true,
                write_closed: true,
                write_error: false,
            });
        }
        let peer = entry.peer.and_then(|peer| self.endpoint(peer).ok());
        let read_closed = entry.read_shutdown || peer.is_none_or(|peer| peer.write_shutdown);
        let write_error = peer.is_none_or(|peer| peer.read_shutdown);
        let write_closed = entry.write_shutdown || write_error;
        Ok(Readiness {
            readable: !entry.incoming.is_empty() || read_closed,
            writable: !write_closed
                && peer.is_some_and(|peer| peer.incoming.len() < RECEIVE_CAPACITY),
            read_closed,
            write_closed,
            write_error,
        })
    }

    pub fn release(&mut self, id: u64) -> Result<(), i32> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(-9)?;
        self.entries.swap_remove(index);
        Ok(())
    }
}

impl<H: Copy> super::PosixService<H> {
    /// The dispatcher must authenticate process_id through native IPC delivery.
    pub fn create_socket(
        &self,
        peer: super::PeerIdentity,
        request: Create,
        streams: &mut Streams,
    ) -> Result<u64, i32> {
        let session = self.session(peer.process_id).ok_or(-1)?;
        streams.create(request, (session.effective_uid, session.effective_gid))
    }
    /// `peer.process_id` must originate from authenticated native IPC delivery.
    /// Claimed UID/GID in PeerIdentity are deliberately ignored.
    pub fn create_socket_pair(
        &self,
        peer: super::PeerIdentity,
        request: Create,
        streams: &mut Streams,
    ) -> Result<[u64; 2], i32> {
        let session = self.session(peer.process_id).ok_or(-1)?;
        streams.create_pair(request, (session.effective_uid, session.effective_gid))
    }
}
