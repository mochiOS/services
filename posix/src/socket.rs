//! Userspace UNIX stream descriptions. IDs are private Provider object IDs,
//! never client FDs or lookup authority. A native adapter must authenticate each
//! operation through its attached Handle and release only its final reference.

use mochios_posix_protocol::socket::{Create, Domain, Kind, NONBLOCKING};
use std::collections::VecDeque;

pub const RECEIVE_CAPACITY: usize = 64 * 1024;
pub const MIN_RECEIVE_CAPACITY: usize = 256;
pub const SEND_CAPACITY: usize = 64 * 1024;
pub const MIN_SEND_CAPACITY: usize = 256;
pub const MAX_ENDPOINTS: usize = 1024;
pub const MAX_BACKLOG: usize = 128;
/// Private Provider namespace: bit 62 distinguishes connection wait jobs.
/// Stay within the native Provider's signed 64-bit object identity range.
pub const MAX_DESCRIPTION_ID: u64 = (1 << 62) - 1;

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

#[derive(Clone, Copy)]
struct SocketName {
    bytes: [u8; mochios_posix_protocol::socket::MAX_UNIX_NAME_BYTES],
    length: usize,
}
impl SocketName {
    fn new(path: &[u8]) -> Result<Self, i32> {
        if path.is_empty()
            || path.len() > mochios_posix_protocol::socket::MAX_UNIX_NAME_BYTES
            || path.contains(&0)
        {
            return Err(-22);
        }
        let mut bytes = [0; mochios_posix_protocol::socket::MAX_UNIX_NAME_BYTES];
        bytes[..path.len()].copy_from_slice(path);
        Ok(Self {
            bytes,
            length: path.len(),
        })
    }
    fn address(&self) -> mochios_posix_protocol::socket::Address<'_> {
        mochios_posix_protocol::socket::Address::UnixPath(&self.bytes[..self.length])
    }
}

struct Endpoint {
    id: u64,
    // None means never connected, not a previously connected peer's close.
    peer: Option<u64>,
    credentials: (u32, u32),
    incoming: VecDeque<u8>,
    receive_capacity: usize,
    send_capacity: usize,
    error: u32,
    read_shutdown: bool,
    write_shutdown: bool,
    options: u32,
    listener: Option<Listener>,
    pending_listener: Option<u64>,
    accept_retry: Option<u64>,
    local_name: Option<SocketName>,
    peer_name: Option<SocketName>,
}

/// Provider-owned accept transaction. Never serialize these IDs to a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptTicket {
    listener: u64,
    endpoint: u64,
    retry: u64,
}
impl AcceptTicket {
    pub const fn endpoint(self) -> u64 {
        self.endpoint
    }
}

pub struct ReleaseObservers {
    ids: [u64; MAX_BACKLOG + 2],
    length: usize,
}
impl ReleaseObservers {
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.ids[..self.length].iter().copied()
    }
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
        if self.entries.len() == MAX_ENDPOINTS || self.next > MAX_DESCRIPTION_ID {
            return Err(-23);
        }
        self.entries.try_reserve(1).map_err(|_| -12)?;
        let id = self.next;
        self.entries.push(Endpoint {
            id,
            peer: None,
            credentials,
            incoming: VecDeque::new(),
            receive_capacity: RECEIVE_CAPACITY,
            send_capacity: SEND_CAPACITY,
            error: 0,
            read_shutdown: false,
            write_shutdown: false,
            options: request.options,
            listener: None,
            pending_listener: None,
            accept_retry: None,
            local_name: None,
            peer_name: None,
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
            .filter(|id| *id <= MAX_DESCRIPTION_ID)
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
                receive_capacity: RECEIVE_CAPACITY,
                send_capacity: SEND_CAPACITY,
                error: 0,
                read_shutdown: false,
                write_shutdown: false,
                options: request.options,
                listener: None,
                pending_listener: None,
                accept_retry: None,
                local_name: None,
                peer_name: None,
            });
        }
        self.next = next;
        Ok(ids)
    }

    pub fn credentials(&self, id: u64) -> Result<(u32, u32), i32> {
        Ok(self.endpoint(id)?.credentials)
    }

    /// Unbound UNIX sockets have no local pathname.
    pub fn address(&self, id: u64) -> Result<mochios_posix_protocol::socket::Address<'_>, i32> {
        Ok(self.endpoint(id)?.local_name.as_ref().map_or(
            mochios_posix_protocol::socket::Address::UnixUnnamed,
            SocketName::address,
        ))
    }

    /// Closing a connected peer does not erase the established address;
    /// a never-connected socket must instead report ENOTCONN.
    pub fn peer_address(
        &self,
        id: u64,
    ) -> Result<mochios_posix_protocol::socket::Address<'_>, i32> {
        let entry = self.endpoint(id)?;
        entry.peer.ok_or(-107)?;
        Ok(entry.peer_name.as_ref().map_or(
            mochios_posix_protocol::socket::Address::UnixUnnamed,
            SocketName::address,
        ))
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
    pub fn pending_error(&self, id: u64) -> Result<u32, i32> {
        Ok(self.endpoint(id)?.error)
    }
    pub fn take_error(&mut self, id: u64) -> Result<u32, i32> {
        Ok(std::mem::take(&mut self.endpoint_mut(id)?.error))
    }
    pub fn receive_capacity(&self, id: u64) -> Result<usize, i32> {
        Ok(self.endpoint(id)?.receive_capacity)
    }

    /// Clamp to the service's existing per-description memory ceiling. Do not
    /// allocate on a hint or discard queued bytes when shrinking below usage.
    pub fn set_receive_capacity(&mut self, id: u64, requested: u32) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        if requested > i32::MAX as u32 {
            return Err(-22);
        }
        entry.receive_capacity = (requested as usize).clamp(MIN_RECEIVE_CAPACITY, RECEIVE_CAPACITY);
        Ok(())
    }
    pub fn set_options(&mut self, id: u64, options: u32) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        if options & !NONBLOCKING != 0 {
            return Err(-22);
        }
        entry.options = options;
        Ok(())
    }

    pub fn send_capacity(&self, id: u64) -> Result<usize, i32> {
        Ok(self.endpoint(id)?.send_capacity)
    }

    /// Each UNIX stream has one peer, so its queued outgoing bytes are the
    /// peer's incoming queue. Bound that same queue without a second copy.
    /// Shrinking never discards bytes already accepted by a successful write.
    pub fn set_send_capacity(&mut self, id: u64, requested: u32) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        if requested > i32::MAX as u32 {
            return Err(-22);
        }
        entry.send_capacity = (requested as usize).clamp(MIN_SEND_CAPACITY, SEND_CAPACITY);
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
        let send_capacity = entry.send_capacity;
        let receiver = self.endpoint_mut(peer).map_err(|_| -32)?;
        if receiver.read_shutdown {
            return Err(-32);
        }
        let count = input.len().min(
            receiver
                .receive_capacity
                .min(send_capacity)
                .saturating_sub(receiver.incoming.len()),
        );
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
        if count == 0 && entry.error != 0 {
            return Err(-(std::mem::take(&mut entry.error) as i32));
        }
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

    /// Reject invalid state before a potentially costly filesystem lookup.
    pub fn check_connect(&self, client: u64) -> Result<(), i32> {
        let source = self.endpoint(client)?;
        if source.peer.is_some() {
            return Err(-106);
        }
        if source.listener.is_some() {
            return Err(-22);
        }
        Ok(())
    }

    pub fn kind(&self, id: u64) -> Result<Kind, i32> {
        self.endpoint(id)?;
        // validate_create admits only UNIX stream descriptions, including
        // those produced by pair/connect/accept; no other kind is synthesized.
        Ok(Kind::Stream)
    }

    /// Description IDs are private; the adapter resolves the listener through
    /// an authorized, retained filesystem object rather than a client ID/path.
    pub fn connect(&mut self, client: u64, listener: u64) -> Result<u64, i32> {
        self.connect_internal(client, listener, None, None)
    }

    /// Names are snapshots for address queries, not namespace authority. The
    /// caller has already resolved the listener through its retained inode.
    pub fn connect_named(
        &mut self,
        client: u64,
        listener: u64,
        client_path: Option<&[u8]>,
        listener_path: &[u8],
    ) -> Result<u64, i32> {
        let client_name = client_path.map(SocketName::new).transpose()?;
        let listener_name = SocketName::new(listener_path)?;
        self.connect_internal(client, listener, client_name, Some(listener_name))
    }

    fn connect_internal(
        &mut self,
        client: u64,
        listener: u64,
        client_name: Option<SocketName>,
        listener_name: Option<SocketName>,
    ) -> Result<u64, i32> {
        self.check_connect(client)?;
        if client == listener {
            return Err(-22);
        }
        let target = self.endpoint(listener)?;
        let queue = target.listener.as_ref().ok_or(-111)?;
        if queue.pending.len() >= queue.backlog {
            return Err(-11);
        }
        if self.entries.len() == MAX_ENDPOINTS || self.next > MAX_DESCRIPTION_ID {
            return Err(-23);
        }
        let credentials = target.credentials;
        let receive_capacity = target.receive_capacity;
        let send_capacity = target.send_capacity;
        let client_index = self
            .entries
            .iter()
            .position(|entry| entry.id == client)
            .ok_or(-9)?;
        let listener_index = self
            .entries
            .iter()
            .position(|entry| entry.id == listener)
            .ok_or(-9)?;
        self.entries.try_reserve(1).map_err(|_| -12)?;
        let id = self.next;
        // listen() preallocated the bounded queue; no allocation or fallible
        // operation follows publication of either half of this connection.
        self.entries[listener_index]
            .listener
            .as_mut()
            .ok_or(-111)?
            .pending
            .push_back(id);
        self.entries.push(Endpoint {
            id,
            peer: Some(client),
            credentials,
            incoming: VecDeque::new(),
            receive_capacity,
            send_capacity,
            error: 0,
            read_shutdown: false,
            write_shutdown: false,
            options: 0,
            listener: None,
            pending_listener: Some(listener),
            accept_retry: None,
            local_name: listener_name,
            peer_name: client_name,
        });
        self.next += 1;
        self.entries[client_index].peer = Some(id);
        self.entries[client_index].local_name = client_name;
        self.entries[client_index].peer_name = listener_name;
        Ok(id)
    }

    /// Reserve a fresh retry identity before creating the native Provider. The
    /// request stays queued until its Handle can be committed or rolled back.
    pub fn begin_accept(&mut self, listener: u64) -> Result<AcceptTicket, i32> {
        let endpoint = *self
            .endpoint(listener)?
            .listener
            .as_ref()
            .ok_or(-22)?
            .pending
            .front()
            .ok_or(-11)?;
        let queued = self.endpoint(endpoint)?;
        if queued.pending_listener != Some(listener) {
            return Err(-5);
        }
        if queued.accept_retry.is_some() {
            return Err(-16);
        }
        if self.next > MAX_DESCRIPTION_ID {
            return Err(-23);
        }
        let retry = self.next;
        self.next += 1;
        self.endpoint_mut(endpoint)?.accept_retry = Some(retry);
        Ok(AcceptTicket {
            listener,
            endpoint,
            retry,
        })
    }

    fn validate_accept(&self, ticket: AcceptTicket) -> Result<(), i32> {
        let queued = self.endpoint(ticket.endpoint)?;
        let queue = self
            .endpoint(ticket.listener)?
            .listener
            .as_ref()
            .ok_or(-22)?;
        if queue.pending.front() != Some(&ticket.endpoint)
            || queued.pending_listener != Some(ticket.listener)
            || queued.accept_retry != Some(ticket.retry)
        {
            return Err(-22);
        }
        Ok(())
    }

    /// Commit only after native Handle creation. Credentials/options must come
    /// from authenticated accept policy; NONBLOCK is not inherited from listen.
    pub fn commit_accept(
        &mut self,
        ticket: AcceptTicket,
        credentials: (u32, u32),
        options: u32,
    ) -> Result<u64, i32> {
        if options & !NONBLOCKING != 0 {
            return Err(-22);
        }
        self.validate_accept(ticket)?;
        self.endpoint_mut(ticket.listener)?
            .listener
            .as_mut()
            .ok_or(-22)?
            .pending
            .pop_front();
        let accepted = self.endpoint_mut(ticket.endpoint)?;
        accepted.pending_listener = None;
        accepted.accept_retry = None;
        accepted.credentials = credentials;
        accepted.options = options;
        Ok(ticket.endpoint)
    }

    /// Call before closing a failed temporary Provider Handle. Retire its ID
    /// so a delayed native release cannot erase this still-queued connection.
    pub fn abort_accept(&mut self, ticket: AcceptTicket) -> Result<u64, i32> {
        self.validate_accept(ticket)?;
        let queued = self.endpoint_mut(ticket.endpoint)?;
        let peer = queued.peer;
        queued.id = ticket.retry;
        queued.accept_retry = None;
        *self
            .endpoint_mut(ticket.listener)?
            .listener
            .as_mut()
            .ok_or(-22)?
            .pending
            .front_mut()
            .ok_or(-11)? = ticket.retry;
        if let Some(peer) = peer {
            if let Ok(client) = self.endpoint_mut(peer) {
                client.peer = Some(ticket.retry);
            }
        }
        Ok(ticket.retry)
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
                && peer.is_some_and(|peer| {
                    peer.incoming.len() < peer.receive_capacity.min(entry.send_capacity)
                }),
            read_closed,
            write_closed,
            write_error,
        })
    }

    /// Snapshot before final release; queued clients also need readiness
    /// notification when their unaccepted peer is destroyed with the listener.
    /// Fixed storage avoids allocation failure on resource destruction.
    pub fn release_observers(&self, id: u64) -> Result<ReleaseObservers, i32> {
        let entry = self.endpoint(id)?;
        let mut observers = ReleaseObservers {
            ids: [0; MAX_BACKLOG + 2],
            length: 1,
        };
        observers.ids[0] = id;
        if let Some(peer) = entry.peer {
            observers.ids[observers.length] = peer;
            observers.length += 1;
        }
        if let Some(listener) = &entry.listener {
            for pending in &listener.pending {
                if let Ok(queued) = self.endpoint(*pending) {
                    if let Some(peer) = queued.peer {
                        observers.ids[observers.length] = peer;
                        observers.length += 1;
                    }
                }
            }
        }
        Ok(observers)
    }

    pub fn release(&mut self, id: u64) -> Result<(), i32> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(-9)?;
        let removed = self.entries.swap_remove(index);
        self.notify_peer_release(&removed, false);
        if let Some(listener) = removed.listener {
            for pending in listener.pending {
                if let Some(index) = self.entries.iter().position(|entry| entry.id == pending) {
                    let queued = self.entries.swap_remove(index);
                    self.notify_peer_release(&queued, true);
                }
            }
        }
        if let Some(listener) = removed.pending_listener {
            if let Ok(parent) = self.endpoint_mut(listener) {
                if let Some(queue) = &mut parent.listener {
                    queue.pending.retain(|pending| *pending != id);
                }
            }
        }
        Ok(())
    }

    fn notify_peer_release(&mut self, removed: &Endpoint, unaccepted: bool) {
        if unaccepted || !removed.incoming.is_empty() {
            if let Some(peer) = removed.peer.and_then(|id| self.endpoint_mut(id).ok()) {
                if peer.peer == Some(removed.id) && peer.error == 0 {
                    peer.error = 104; // ECONNRESET: unread or unaccepted data lost.
                }
            }
        }
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
