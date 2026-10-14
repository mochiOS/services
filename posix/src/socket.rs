//! Userspace UNIX socket descriptions. IDs are private Provider object IDs,
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
/// Private Provider namespace: bits 59..62 distinguish transfers, routes and jobs.
/// Stay within the native Provider's signed 64-bit object identity range.
pub const MAX_DESCRIPTION_ID: u64 = (1 << 59) - 1;

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
    incoming: crate::socket_stream::StreamQueue,
    records: Option<crate::socket_record::RecordQueue>,
    receive_capacity: usize,
    send_capacity: usize,
    receive_timeout: u64,
    send_timeout: u64,
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
        if request.domain != Domain::Unix || !matches!(request.kind, Kind::Stream | Kind::Datagram)
        {
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
            incoming: crate::socket_stream::StreamQueue::new(),
            records: (request.kind == Kind::Datagram).then(crate::socket_record::RecordQueue::new),
            receive_capacity: RECEIVE_CAPACITY,
            send_capacity: SEND_CAPACITY,
            receive_timeout: 0,
            send_timeout: 0,
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
                incoming: crate::socket_stream::StreamQueue::new(),
                records: (request.kind == Kind::Datagram)
                    .then(crate::socket_record::RecordQueue::new),
                receive_capacity: RECEIVE_CAPACITY,
                send_capacity: SEND_CAPACITY,
                receive_timeout: 0,
                send_timeout: 0,
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
        if let Some(records) = &mut entry.records {
            records.set_capacity(requested)?;
        }
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

    pub fn receive_timeout(&self, id: u64) -> Result<u64, i32> {
        Ok(self.endpoint(id)?.receive_timeout)
    }

    pub fn set_receive_timeout(&mut self, id: u64, nanoseconds: u64) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        // Canonical timeval precision, no C layout or pointer on the wire.
        if nanoseconds % 1000 != 0 {
            return Err(-22);
        }
        entry.receive_timeout = nanoseconds;
        Ok(())
    }

    pub fn send_timeout(&self, id: u64) -> Result<u64, i32> {
        Ok(self.endpoint(id)?.send_timeout)
    }

    pub fn set_send_timeout(&mut self, id: u64, nanoseconds: u64) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        if nanoseconds % 1000 != 0 {
            return Err(-22);
        }
        entry.send_timeout = nanoseconds;
        Ok(())
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
        if entry.records.is_some() {
            return Err(-95);
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
        if input.is_empty() {
            return Ok(0);
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
        receiver.incoming.write(&input[..count])
    }

    pub fn read(&mut self, id: u64, output: &mut [u8]) -> Result<usize, i32> {
        self.receive(id, output, None)
    }

    /// Bound a stream send by current byte and optional ancillary capacity.
    pub fn stream_send_length(&self, id: u64, length: usize, with_rights: bool) -> Result<usize, i32> {
        let source = self.endpoint(id)?;
        if source.records.is_some() {
            return Err(-95);
        }
        if source.write_shutdown {
            return Err(-32);
        }
        let receiver = self.endpoint(source.peer.ok_or(-107)?).map_err(|_| -32)?;
        if receiver.read_shutdown {
            return Err(-32);
        }
        if length == 0 {
            return Ok(0);
        }
        let count = length.min(
            receiver.receive_capacity.min(source.send_capacity)
                .saturating_sub(receiver.incoming.len()),
        );
        if count == 0 || (with_rights && !receiver.incoming.can_attach_rights()) {
            return Err(-11);
        }
        Ok(count)
    }

    /// Wait for at least one byte and one ancillary marker on a stream; retain
    /// full-record capacity semantics for datagrams. No FD enters this policy.
    pub fn ancillary_send_ready(&self, id: u64, length: usize) -> Result<bool, i32> {
        if self.kind(id)? == Kind::Datagram {
            return self.record_send_ready(id, length);
        }
        match self.stream_send_length(id, length, true) {
            Ok(_) => Ok(true),
            Err(-11) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// First-byte ancillary attachment on a connected byte stream. A short
    /// write transfers all rights with its accepted prefix, exactly once.
    /// The native adapter has authenticated the source WRITE lease already.
    pub fn commit_stream_with_rights(
        &mut self,
        id: u64,
        input: &[u8],
        rights: crate::socket_rights::Bundle,
    ) -> Result<(usize, [u64; 2]), (i32, crate::socket_rights::Bundle)> {
        let count = match self.stream_send_length(id, input.len(), !rights.is_empty()) {
            Ok(count) => count,
            Err(error) => return Err((error, rights)),
        };
        let peer = if count == 0 {
            id
        } else {
            self.endpoint(id).unwrap().peer.unwrap()
        };
        let receiver = match self.endpoint_mut(peer) {
            Ok(receiver) => receiver,
            Err(error) => return Err((error, rights)),
        };
        receiver.incoming
            .write_with_rights(&input[..count], rights)
            .map(|count| (count, [id, peer]))
    }

    /// Consume one stream prefix and move its first ancillary bundle. Ordinary
    /// read uses the same boundary calculation but discards the owned bundle.
    pub fn read_stream_with_rights(
        &mut self,
        id: u64,
        output: &mut [u8],
    ) -> Result<(usize, Option<crate::socket_rights::Bundle>), i32> {
        let count = self.stream_read_count(id, output.len(), 0)?;
        Ok(self.endpoint_mut(id)?.incoming.read_owned(&mut output[..count]))
    }

    /// Inspect bytes relative to the current receive head without removing them.
    /// The offset is call-local, not an open-file offset or a retained cursor:
    /// another reader may advance the head between calls. Inspection does not
    /// release send capacity or change readiness. Like a normal read, an empty
    /// queue reports and clears a pending error before reporting EOF.
    pub fn peek(&mut self, id: u64, offset: usize, output: &mut [u8]) -> Result<usize, i32> {
        self.receive(id, output, Some(offset))
    }

    /// Serialized with registration of a receive notification. A terminal
    /// result wakes a waiter even when the requested prefix cannot be filled.
    pub fn receive_wait_ready(&self, id: u64, minimum: u64) -> Result<bool, i32> {
        if minimum == 0 {
            return Err(-22);
        }
        let entry = self.endpoint(id)?;
        if let Some(records) = &entry.records {
            return Ok(records.is_readable() || entry.read_shutdown || entry.error != 0);
        }
        if entry.peer.is_none() {
            return Err(-107);
        }
        Ok(entry.incoming.len() as u64 >= minimum
            || entry.error != 0
            || self.readiness(id)?.read_closed)
    }

    fn receive(
        &mut self,
        id: u64,
        output: &mut [u8],
        peek_offset: Option<usize>,
    ) -> Result<usize, i32> {
        let offset = peek_offset.unwrap_or(0);
        let count = self.stream_read_count(id, output.len(), offset)?;
        let entry = self.endpoint_mut(id)?;
        Ok(if peek_offset.is_some() {
            entry.incoming.peek(offset, &mut output[..count])
        } else {
            entry.incoming.read(&mut output[..count])
        })
    }

    fn stream_read_count(&mut self, id: u64, length: usize, offset: usize) -> Result<usize, i32> {
        let ready = self.readiness(id)?;
        let entry = self.endpoint_mut(id)?;
        if entry.records.is_some() {
            return Err(-95);
        }
        if length == 0 || entry.read_shutdown {
            return Ok(0);
        }
        if entry.peer.is_none() {
            return Err(-107);
        }
        let count = length.min(entry.incoming.len().saturating_sub(offset));
        if entry.incoming.is_empty() && entry.error != 0 {
            return Err(-(std::mem::take(&mut entry.error) as i32));
        }
        if count == 0 && !ready.read_closed {
            return Err(-11);
        }
        Ok(count)
    }

    pub fn shutdown(&mut self, id: u64, how: Shutdown) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        entry.peer.ok_or(-107)?;
        if matches!(how, Shutdown::Read | Shutdown::Both) {
            entry.read_shutdown = true;
            entry.incoming.clear();
            if let Some(records) = &mut entry.records {
                records.clear();
            }
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
        if entry.records.is_some() {
            return Err(-95);
        }
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
        if source.records.is_some() {
            return Err(-95);
        }
        if source.peer.is_some() {
            return Err(-106);
        }
        if source.listener.is_some() {
            return Err(-22);
        }
        Ok(())
    }

    pub fn kind(&self, id: u64) -> Result<Kind, i32> {
        Ok(if self.endpoint(id)?.records.is_some() {
            Kind::Datagram
        } else {
            Kind::Stream
        })
    }

    /// Direct record transport only; the native adapter has authenticated and
    /// identified the explicitly attached socket before supplying this ID.
    pub fn transfer_record(
        &mut self,
        id: u64,
        request: mochios_posix_protocol::socket_record::Request,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
        response: &mut [u8],
    ) -> Result<usize, i32> {
        use mochios_posix_protocol::socket_record::Operation;
        let entry = self.endpoint(id)?;
        if matches!(
            request.operation,
            Operation::WaitSend | Operation::SendRoute
        ) {
            return Err(-22);
        }
        if entry.records.is_none() {
            return Err(-95);
        }
        let send_capacity = entry.send_capacity;
        let source = crate::socket_record::SourceAddress::new(self.address(id)?)?;
        let destination = if request.operation == Operation::Send {
            self.record_destination(id)?
        } else {
            if entry.read_shutdown {
                return mochios_posix_protocol::socket_record::Reply {
                    copied: 0,
                    length: 0,
                    source: Some(mochios_posix_protocol::socket::Address::UnixUnnamed),
                }
                .encode(request, response)
                .map_err(|_| -22);
            }
            id
        };
        let queue = self
            .endpoint_mut(destination)?
            .records
            .as_mut()
            .ok_or(-91)?;
        crate::socket_record_io::transfer_from(queue, request, source, send_capacity, buffer, response, Some(id))
    }

    /// Shared connected-datagram policy. An adapter supplies only a socket ID
    /// already authenticated through native attached authority, never a wire ID.
    fn record_destination(&self, id: u64) -> Result<u64, i32> {
        let entry = self.endpoint(id)?;
        if entry.records.is_none() {
            return Err(-95);
        }
        if entry.write_shutdown {
            return Err(-32);
        }
        let peer = entry.peer.ok_or(-89)?;
        let target = self.endpoint(peer).map_err(|_| -111)?;
        if target.read_shutdown {
            return Err(-111);
        }
        if target.peer.is_some_and(|sender| sender != id) {
            return Err(-1);
        }
        Ok(peer)
    }

    /// Payload and ready ancillary leases become visible together. All errors
    /// return the complete bundle to its staging transaction for retry/abort.
    pub fn commit_record_with_rights(
        &mut self,
        id: u64,
        payload: &[u8],
        rights: crate::socket_rights::Bundle,
    ) -> Result<(usize, [u64; 2]), (i32, crate::socket_rights::Bundle)> {
        let prepared = (|| {
            let destination = self.record_destination(id)?;
            let source = crate::socket_record::SourceAddress::new(self.address(id)?)?;
            Ok((destination, source))
        })();
        let (destination, source) = match prepared {
            Ok(values) => values,
            Err(error) => return Err((error, rights)),
        };
        self.commit_record_to_with_rights(id, destination, source, payload, rights)
    }

    /// Commit through a retained, authorized destination without changing the
    /// source's default peer. Shares sendto's filtering and capacity policy.
    pub fn commit_record_to_with_rights(
        &mut self,
        id: u64,
        destination: u64,
        source: crate::socket_record::SourceAddress,
        payload: &[u8],
        rights: crate::socket_rights::Bundle,
    ) -> Result<(usize, [u64; 2]), (i32, crate::socket_rights::Bundle)> {
        match self.record_send_to_ready(id, destination, payload.len()) {
            Ok(true) => (),
            Ok(false) => return Err((-11, rights)),
            Err(error) => return Err((error, rights)),
        }
        let capacity = match self.endpoint(id) {
            Ok(entry) => entry.send_capacity,
            Err(error) => return Err((error, rights)),
        };
        let queue = match self.endpoint_mut(destination) {
            Ok(entry) => match entry.records.as_mut() {
                Some(queue) => queue,
                None => return Err((-91, rights)),
            },
            Err(error) => return Err((error, rights)),
        };
        queue.push_with_rights(source, payload, capacity, Some(id), rights)
            .map(|count| (count, [id, destination]))
    }

    /// A large atomic write needs its entire capacity, not just POLLOUT's
    /// minimum-size availability. Evaluate and register under queue serialization.
    pub fn record_send_ready(&self, id: u64, length: usize) -> Result<bool, i32> {
        let entry = self.endpoint(id)?;
        if entry.records.is_none() {
            return Err(-95);
        }
        if length > crate::socket_record::MAX_RECORD_SIZE {
            return Err(-90);
        }
        if entry.write_shutdown || entry.peer.is_none() {
            return Ok(true);
        }
        let Some(peer) = entry.peer.and_then(|id| self.endpoint(id).ok()) else {
            return Ok(true);
        };
        if peer.read_shutdown || peer.peer.is_some_and(|sender| sender != id) {
            return Ok(true);
        }
        peer.records
            .as_ref()
            .ok_or(-91)?
            .can_push(length, entry.send_capacity)
    }

    /// Serialize graph construction, native observations and queue destruction
    /// on this worker. Callbacks must use native owner-scoped observations only,
    /// not metadata hints, client-reported counts or reentrant Provider RPC.
    /// Nothing is discarded until EVERY lookup, sample and allocation succeeds.
    pub fn collect_record_cycles(
        &mut self,
        mut identify: impl FnMut(u32) -> Result<Option<u64>, i32>,
        mut reference_count: impl FnMut(u64) -> Result<u64, i32>,
    ) -> Result<Vec<u64>, i32> {
        let mut edges = Vec::new();
        for entry in &self.entries {
            for lease in entry.incoming.ancillary_leases().chain(
                entry.records.iter().flat_map(|queue| queue.ancillary_leases()),
            ) {
                // A peek snapshot shares this one native reference outside
                // the queue. Subtracting it as a queue-only edge would erase
                // that root and could discard reachable data during a peek.
                if !lease.is_exclusive() {
                    continue;
                }
                if let Some(target) = identify(lease.handle())? {
                    edges.try_reserve(1).map_err(|_| -12)?;
                    edges.push((entry.id, target));
                }
            }
        }
        if edges.is_empty() {
            return Ok(Vec::new());
        }
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(self.entries.len()).map_err(|_| -12)?;
        for entry in &self.entries {
            if edges.iter().any(|(source, target)| *source == entry.id || *target == entry.id) {
                nodes.push(crate::socket_gc::Node {
                    id: entry.id,
                    references: reference_count(entry.id)?,
                });
            }
        }
        let garbage = crate::socket_gc::unreachable(&nodes, &edges)?;
        for id in &garbage {
            let entry = self.endpoint_mut(*id)?;
            entry.incoming.clear();
            if let Some(queue) = entry.records.as_mut() {
                queue.clear();
            }
        }
        Ok(garbage)
    }

    pub fn has_ancillary_records(&self) -> bool {
        self.entries.iter().any(|entry| {
            entry.incoming.ancillary_leases().next().is_some()
                || entry.records.as_ref()
                    .is_some_and(|queue| queue.ancillary_leases().next().is_some())
        })
    }

    /// Retain only the rights visible to one peek. The adapter must authenticate
    /// the socket's READ authority and serialize this with data inspection.
    /// These are local ownership pins; IPC later creates receiver references.
    pub fn snapshot_queued_rights(
        &self,
        id: u64,
        length: usize,
        maximum: usize,
    ) -> Result<Option<crate::socket_rights::Bundle>, i32> {
        let entry = self.endpoint(id)?;
        let rights = match &entry.records {
            Some(records) => records.front_rights(),
            None => entry.incoming.read_rights(length),
        };
        rights.map(|rights| rights.snapshot(maximum)).transpose()
    }

    /// Consuming stream ancillary receive. Buffer copy and receipt publication
    /// precede queue consumption; no allocation or fallible work follows them.
    /// The returned span is a stream prefix, not a truncated datagram.
    pub fn receive_stream_with_rights(
        &mut self,
        id: u64,
        offset: u64,
        length: u32,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
        publish: impl FnOnce(crate::socket_record::ReceivedRecord, usize) -> Result<(), i32>,
    ) -> Result<(crate::socket_record::ReceivedRecord, Option<crate::socket_rights::Bundle>), i32> {
        self.receive_stream_rights_using(id, offset, length, None, buffer, publish)
    }

    /// Snapshot the visible prefix before publication without consuming data or
    /// rights. The worker serializes the snapshot and reply with other readers.
    pub fn peek_stream_with_rights(
        &mut self,
        id: u64,
        offset: u64,
        length: u32,
        maximum: usize,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
        publish: impl FnOnce(crate::socket_record::ReceivedRecord, usize) -> Result<(), i32>,
    ) -> Result<(crate::socket_record::ReceivedRecord, Option<crate::socket_rights::Bundle>), i32> {
        self.receive_stream_rights_using(id, offset, length, Some(maximum), buffer, publish)
    }

    fn receive_stream_rights_using(
        &mut self,
        id: u64,
        offset: u64,
        length: u32,
        peek_maximum: Option<usize>,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
        publish: impl FnOnce(crate::socket_record::ReceivedRecord, usize) -> Result<(), i32>,
    ) -> Result<(crate::socket_record::ReceivedRecord, Option<crate::socket_rights::Bundle>), i32> {
        if length as usize > crate::socket_record::MAX_RECORD_SIZE {
            return Err(-22);
        }
        if offset.checked_add(length as u64).ok_or(-22)? > buffer.extent()? {
            return Err(-22);
        }
        let count = self.stream_read_count(id, length as usize, 0)?;
        let queue = &mut self.endpoint_mut(id)?.incoming;
        let count = queue.read_length(count);
        let rights = queue.read_rights(count).map_or(0, |bundle| bundle.len());
        let mut data = Vec::new();
        data.try_reserve_exact(count).map_err(|_| -12)?;
        data.resize(count, 0);
        queue.peek(0, &mut data);
        buffer.write(offset, &data)?;
        let record = crate::socket_record::ReceivedRecord {
            copied: count,
            length: count,
            source: crate::socket_record::SourceAddress::new(
                mochios_posix_protocol::socket::Address::UnixUnnamed,
            )?,
        };
        let snapshot = peek_maximum
            .map(|maximum| {
                queue.read_rights(count).map(|rights| rights.snapshot(maximum)).transpose()
            })
            .transpose()?;
        publish(record, rights)?;
        if let Some(snapshot) = snapshot {
            return Ok((record, snapshot));
        }
        let (_, rights) = queue.read_owned(&mut data);
        Ok((record, rights))
    }

    /// Consuming ancillary receive. All output copies and receipt publication
    /// must succeed before removing the exact head record and moving its leases.
    /// The worker serializes this entire operation; publish must not reenter it.
    pub fn receive_record_with_rights(
        &mut self,
        id: u64,
        offset: u64,
        length: u32,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
        publish: impl FnOnce(crate::socket_record::ReceivedRecord, usize) -> Result<(), i32>,
    ) -> Result<
        (crate::socket_record::ReceivedRecord, Option<crate::socket_rights::Bundle>),
        i32,
    > {
        self.receive_record_rights_using(id, offset, length, None, buffer, publish)
    }

    /// Retain only the requested rights prefix while preserving the exact head
    /// record. No allocation or fallible snapshot work follows publication.
    pub fn peek_record_with_rights(
        &mut self,
        id: u64,
        offset: u64,
        length: u32,
        maximum: usize,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
        publish: impl FnOnce(crate::socket_record::ReceivedRecord, usize) -> Result<(), i32>,
    ) -> Result<(crate::socket_record::ReceivedRecord, Option<crate::socket_rights::Bundle>), i32> {
        self.receive_record_rights_using(id, offset, length, Some(maximum), buffer, publish)
    }

    fn receive_record_rights_using(
        &mut self,
        id: u64,
        offset: u64,
        length: u32,
        peek_maximum: Option<usize>,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
        publish: impl FnOnce(crate::socket_record::ReceivedRecord, usize) -> Result<(), i32>,
    ) -> Result<(crate::socket_record::ReceivedRecord, Option<crate::socket_rights::Bundle>), i32> {
        if length as usize > crate::socket_record::MAX_RECORD_SIZE {
            return Err(-22);
        }
        let end = offset.checked_add(u64::from(length)).ok_or(-22)?;
        let entry = self.endpoint(id)?;
        if entry.records.is_none() {
            return Err(-95);
        }
        if end > buffer.extent()? {
            return Err(-22);
        }
        if entry.read_shutdown {
            let record = crate::socket_record::ReceivedRecord {
                copied: 0,
                length: 0,
                source: crate::socket_record::SourceAddress::new(
                    mochios_posix_protocol::socket::Address::UnixUnnamed,
                )?,
            };
            publish(record, 0)?;
            return Ok((record, None));
        }
        let queue = self.endpoint_mut(id)?.records.as_mut().ok_or(-95)?;
        let mut data = Vec::new();
        data.try_reserve_exact(length as usize).map_err(|_| -12)?;
        data.resize(length as usize, 0);
        let record = queue.receive(&mut data, true)?;
        let rights = queue.front_rights().map_or(0, |bundle| bundle.len());
        buffer.write(offset, &data[..record.copied])?;
        let snapshot = peek_maximum
            .map(|maximum| {
                queue.front_rights().map(|rights| rights.snapshot(maximum)).transpose()
            })
            .transpose()?;
        publish(record, rights)?;
        if let Some(snapshot) = snapshot {
            return Ok((record, snapshot));
        }
        // No allocation, copy, lookup or request processing after publication.
        let (_, rights) = queue.receive_owned(&mut [])?;
        Ok((record, rights))
    }

    /// Explicit-destination sends do not change the description's default
    /// peer or receive filter. Destination authority comes from a retained
    /// lookup ticket in the worker, never from a caller-supplied object ID.
    pub fn record_send_to_ready(
        &self,
        source: u64,
        destination: u64,
        length: usize,
    ) -> Result<bool, i32> {
        let entry = self.endpoint(source)?;
        if entry.records.is_none() {
            return Err(-91);
        }
        if entry.write_shutdown {
            return Err(-32);
        }
        let target = self.endpoint(destination).map_err(|_| -111)?;
        if target.read_shutdown {
            return Err(-111);
        }
        if target.peer.is_some_and(|sender| sender != source) {
            return Err(-1);
        }
        target
            .records
            .as_ref()
            .ok_or(-91)?
            .can_push(length, entry.send_capacity)
    }

    pub fn transfer_record_to(
        &mut self,
        id: u64,
        destination: u64,
        request: mochios_posix_protocol::socket_record::Request,
        source: crate::socket_record::SourceAddress,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
        response: &mut [u8],
    ) -> Result<usize, i32> {
        if request.operation != mochios_posix_protocol::socket_record::Operation::SendRoute {
            return Err(-22);
        }
        if !self.record_send_to_ready(id, destination, request.length as usize)? {
            return Err(-11);
        }
        let capacity = self.endpoint(id)?.send_capacity;
        let queue = self
            .endpoint_mut(destination)?
            .records
            .as_mut()
            .ok_or(-91)?;
        crate::socket_record_io::transfer_from(
            queue,
            request,
            source,
            capacity,
            buffer,
            response,
            Some(id),
        )
    }

    /// One-way datagram peer selection. The adapter has authorized a retained
    /// target inode; names are reporting snapshots only. All checks precede
    /// publication so a failed reconnect leaves peer and receive queue intact.
    pub fn connect_datagram_named(&mut self, client: u64, target: u64, client_path: Option<&[u8]>, target_path: &[u8]) -> Result<(), i32> {
        let local_name = client_path.map(SocketName::new).transpose()?;
        let peer_name = SocketName::new(target_path)?;
        let source = self.endpoint(client)?;
        if source.records.is_none() { return Err(-91); }
        let destination = self.endpoint(target).map_err(|_| -111)?;
        if destination.records.is_none() { return Err(-91); }
        if destination.read_shutdown { return Err(-111); }
        if destination.peer.is_some_and(|peer| peer != client) { return Err(-1); }
        let source = self.endpoint_mut(client)?;
        source.peer = Some(target);
        source.local_name = local_name;
        source.peer_name = Some(peer_name);
        source.records.as_mut().ok_or(-91)?.retain_sender(target);
        Ok(())
    }

    /// Capacity or receive-filter changes affect every connected datagram
    /// sender, not just a symmetric socketpair's single opposite endpoint.
    pub fn record_observers(&self, destination: u64) -> impl Iterator<Item = u64> + '_ {
        self.entries.iter().filter(move |entry| entry.records.is_some() && entry.peer == Some(destination)).map(|entry| entry.id)
    }

    /// Disconnect only the peer association. Do not undo bind, nonblocking,
    /// timeouts or shutdown. An already-unconnected socket keeps any newly
    /// received datagrams: a repeated disconnect is an idempotent no-op.
    pub fn disconnect_datagram(&mut self, id: u64) -> Result<(), i32> {
        let entry = self.endpoint_mut(id)?;
        let records = entry.records.as_mut().ok_or(-95)?;
        if entry.peer.take().is_some() {
            records.clear();
        }
        entry.peer_name = None;
        Ok(())
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
        let receive_timeout = target.receive_timeout;
        let send_timeout = target.send_timeout;
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
            incoming: crate::socket_stream::StreamQueue::new(),
            records: None,
            receive_capacity,
            send_capacity,
            receive_timeout,
            send_timeout,
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
        if let Some(records) = &entry.records {
            let peer = entry.peer.and_then(|peer| self.endpoint(peer).ok());
            let write_error = entry.peer.is_some() && peer.is_none_or(|peer| peer.read_shutdown || peer.peer.is_some_and(|sender| sender != id));
            return Ok(Readiness {
                readable: records.is_readable() || entry.read_shutdown,
                writable: !entry.write_shutdown
                    && !write_error
                    && peer.is_none_or(|peer| {
                        peer.records.as_ref().is_some_and(|queue| {
                            queue.can_push(0, entry.send_capacity).unwrap_or(false)
                        })
                    }),
                read_closed: entry.read_shutdown,
                write_closed: entry.write_shutdown || write_error,
                write_error,
            });
        }
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
