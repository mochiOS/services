// Nonblocking TCP resources for the network Provider. Socket IDs and TCP
// owners are private service labels; native Handle authentication is external.
use alloc::{collections::VecDeque, vec::Vec};
use mochios_net_device_protocol::datagram::Endpoint;
use mochios_network_stack::{
    TCP_EPHEMERAL_END, TCP_EPHEMERAL_START, TCP_FLAG_RST, TcpConnection, TcpConnectionError,
    TcpConnectionTable, TcpListenConfig, TcpOptions, TcpSegment, TcpState, TcpTransmit, TcpTuple,
};

const RESOURCE_LIMIT: usize = 64;
const TCP_LIMIT: usize = 32;
const QUEUE_LIMIT: usize = 64;
pub(crate) const PUMP_BUDGET: usize = 32;
const BUFFER: usize = 16 * 1024;
const CLOSE_TIMEOUT: u64 = 60_000;
const EMPTY: Endpoint = Endpoint {
    address: [0; 4],
    port: 0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Socket(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub readable: bool,
    pub writable: bool,
    pub peer_closed: bool,
    pub connecting: bool,
    pub error: i32,
}

#[derive(Clone, Copy)]
enum Binding {
    Idle,
    Listener(u64),
    Connection { tcp: u64, owner: u64 },
}
struct Row {
    socket: Socket,
    local: Endpoint,
    binding: Binding,
    read_shutdown: bool,
    write_shutdown: bool,
    released: Option<u64>,
    connected: bool,
    failure: Option<i32>,
    pending_error: i32,
    window_update: bool,
}
impl Row {
    fn new(socket: Socket) -> Self {
        Self {
            socket,
            local: EMPTY,
            binding: Binding::Idle,
            read_shutdown: false,
            write_shutdown: false,
            released: None,
            connected: false,
            failure: None,
            pending_error: 0,
            window_update: false,
        }
    }
}
struct Packet {
    tuple: TcpTuple,
    transmit: TcpTransmit,
    origin: Option<u64>,
}

pub(crate) struct Loopback {
    table: TcpConnectionTable,
    rows: Vec<Row>,
    pending: VecDeque<Packet>,
    next: u64,
    next_port: u16,
}
fn error(error: TcpConnectionError) -> i32 {
    match error {
        TcpConnectionError::Capacity => -12,
        TcpConnectionError::SendBufferFull | TcpConnectionError::ReceiveBufferFull => -11,
        TcpConnectionError::PortUnavailable => -98,
        TcpConnectionError::EntropyUnavailable => -5,
        TcpConnectionError::Timeout | TcpConnectionError::RetryLimit => -110,
        TcpConnectionError::ConnectionReset => -104,
        TcpConnectionError::NotFound => -9,
        TcpConnectionError::Ownership => -13,
        _ => -22,
    }
}
fn eof(state: TcpState) -> bool {
    matches!(
        state,
        TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait | TcpState::Closed
    )
}
impl Loopback {
    pub(crate) fn new() -> Self {
        Self {
            table: TcpConnectionTable::new(TCP_LIMIT),
            rows: Vec::new(),
            pending: VecDeque::new(),
            next: 1,
            next_port: TCP_EPHEMERAL_START,
        }
    }
    fn index(&self, socket: Socket) -> Result<usize, i32> {
        self.rows
            .iter()
            .position(|r| r.socket == socket && r.released.is_none())
            .ok_or(-9)
    }
    fn reserve_row(&mut self) -> Result<Socket, i32> {
        if self.rows.len() >= RESOURCE_LIMIT || self.next == u64::MAX {
            return Err(-24);
        }
        self.rows.try_reserve(1).map_err(|_| -12)?;
        let socket = Socket(self.next);
        self.next += 1;
        Ok(socket)
    }
    pub(crate) fn open(&mut self) -> Result<Socket, i32> {
        let socket = self.reserve_row()?;
        self.rows.push(Row::new(socket));
        Ok(socket)
    }
    fn port_available(&self, socket: Socket, local: Endpoint) -> bool {
        !self.rows.iter().any(|r| {
            r.socket != socket
                && r.local.port == local.port
                && (r.local.address == [0; 4]
                    || local.address == [0; 4]
                    || r.local.address == local.address)
        })
    }
    fn local_endpoint(&mut self, socket: Socket, mut local: Endpoint) -> Result<Endpoint, i32> {
        if local.address != [0; 4] && local.address[0] != 127 {
            return Err(-99);
        }
        if local.port != 0 {
            return if self.port_available(socket, local) {
                Ok(local)
            } else {
                Err(-98)
            };
        }
        for _ in TCP_EPHEMERAL_START..=TCP_EPHEMERAL_END {
            local.port = self.next_port;
            self.next_port = if self.next_port == TCP_EPHEMERAL_END {
                TCP_EPHEMERAL_START
            } else {
                self.next_port + 1
            };
            if self.port_available(socket, local)
                && self
                    .table
                    .allocate_port(local.port - TCP_EPHEMERAL_START)
                    .map_err(error)?
                    == local.port
            {
                return Ok(local);
            }
        }
        Err(-99)
    }
    pub(crate) fn bind(&mut self, socket: Socket, local: Endpoint) -> Result<(), i32> {
        let i = self.index(socket)?;
        if !matches!(self.rows[i].binding, Binding::Idle) || self.rows[i].local != EMPTY {
            return Err(-22);
        }
        let local = self.local_endpoint(socket, local)?;
        self.rows[i].local = local;
        Ok(())
    }
    pub(crate) fn local(&self, socket: Socket) -> Result<Endpoint, i32> {
        Ok(self.rows[self.index(socket)?].local)
    }
    pub(crate) fn peer(&mut self, socket: Socket) -> Result<Endpoint, i32> {
        let i = self.index(socket)?;
        let Binding::Connection { tcp, owner } = self.rows[i].binding else {
            return Err(-107);
        };
        let t = self.table.get_mut(tcp, owner).map_err(error)?.tuple;
        Ok(Endpoint {
            address: t.remote_address,
            port: t.remote_port,
        })
    }
    pub(crate) fn connect(
        &mut self,
        socket: Socket,
        remote: Endpoint,
        entropy: impl FnOnce() -> Option<u64>,
    ) -> Result<(), i32> {
        let i = self.index(socket)?;
        if !matches!(self.rows[i].binding, Binding::Idle) {
            return Err(-106);
        }
        if remote.port == 0 || remote.address == [0; 4] {
            return Err(-22);
        }
        if remote.address[0] != 127 {
            return Err(-101);
        }
        let mut local = self.rows[i].local;
        if local.address == [0; 4] {
            local.address = [127, 0, 0, 1];
        }
        local = self.local_endpoint(socket, local)?;
        let random = entropy().ok_or(-5)?;
        let tcp = self
            .table
            .allocate_handle(random.rotate_left(17))
            .map_err(error)?;
        let tuple = TcpTuple {
            local_address: local.address,
            local_port: local.port,
            remote_address: remote.address,
            remote_port: remote.port,
        };
        let connection = TcpConnection::try_connect(
            tcp,
            socket.0,
            tuple,
            (random >> 32) as u32,
            1460,
            BUFFER,
            BUFFER,
            500,
            5,
        )
        .map_err(error)?;
        self.table.insert(connection).map_err(error)?;
        self.rows[i].local = local;
        self.rows[i].binding = Binding::Connection {
            tcp,
            owner: socket.0,
        };
        Ok(())
    }
    pub(crate) fn listen(&mut self, socket: Socket, backlog: usize) -> Result<(), i32> {
        let i = self.index(socket)?;
        if backlog == 0 {
            return Err(-22);
        }
        if let Binding::Listener(tcp) = self.rows[i].binding {
            return self
                .table
                .set_backlog(tcp, socket.0, backlog.min(TCP_LIMIT))
                .map_err(error);
        }
        if !matches!(self.rows[i].binding, Binding::Idle) {
            return Err(-22);
        }
        let local = self.local_endpoint(socket, self.rows[i].local)?;
        let tcp = self.table.allocate_handle(socket.0).map_err(error)?;
        self.table
            .listen(
                tcp,
                socket.0,
                local.address,
                local.port,
                TcpListenConfig {
                    backlog: backlog.min(TCP_LIMIT),
                    local_mss: 1460,
                    send_capacity: BUFFER,
                    receive_capacity: BUFFER,
                    retransmit_timeout: 500,
                    retry_limit: 5,
                },
            )
            .map_err(error)?;
        self.rows[i].local = local;
        self.rows[i].binding = Binding::Listener(tcp);
        Ok(())
    }
    pub(crate) fn accept(&mut self, listener: Socket) -> Result<Socket, i32> {
        let i = self.index(listener)?;
        let Binding::Listener(tcp) = self.rows[i].binding else {
            return Err(-22);
        };
        // Reserve before removing a ready TCB from the listener's queue.
        let socket = self.reserve_row()?;
        let (accepted, tuple) = self
            .table
            .accept(tcp, listener.0)
            .map_err(error)?
            .ok_or(-11)?;
        let mut row = Row::new(socket);
        row.local = Endpoint {
            address: tuple.local_address,
            port: tuple.local_port,
        };
        row.binding = Binding::Connection {
            tcp: accepted,
            owner: listener.0,
        };
        row.connected = true;
        self.rows.push(row);
        Ok(socket)
    }
    pub(crate) fn status(&mut self, socket: Socket) -> Result<Status, i32> {
        let i = self.index(socket)?;
        let row = &self.rows[i];
        let mut s = Status {
            readable: false,
            writable: false,
            peer_closed: false,
            connecting: false,
            error: row.pending_error,
        };
        match row.binding {
            Binding::Idle => {}
            Binding::Listener(tcp) => {
                s.readable = self.table.listener_ready(tcp, socket.0).map_err(error)?
            }
            Binding::Connection { tcp, owner } => {
                let c = self.table.get_mut(tcp, owner).map_err(error)?;
                s.connecting = c.state == TcpState::SynSent;
                s.peer_closed = eof(c.state) || row.failure.is_some();
                s.readable = c.received_len() != 0 || s.peer_closed || row.read_shutdown;
                s.writable = row.failure.is_some()
                    || !row.write_shutdown
                        && matches!(c.state, TcpState::Established | TcpState::CloseWait)
                        && c.send_available() != 0;
            }
        }
        Ok(s)
    }
    pub(crate) fn take_error(&mut self, socket: Socket) -> Result<i32, i32> {
        let i = self.index(socket)?;
        Ok(core::mem::take(&mut self.rows[i].pending_error))
    }
    pub(crate) fn send(&mut self, socket: Socket, bytes: &[u8]) -> Result<usize, i32> {
        let i = self.index(socket)?;
        let row = &self.rows[i];
        if let Some(e) = row.failure {
            return Err(e);
        }
        if row.write_shutdown {
            return Err(-32);
        }
        let Binding::Connection { tcp, owner } = row.binding else {
            return Err(-107);
        };
        let c = self.table.get_mut(tcp, owner).map_err(error)?;
        if c.state == TcpState::SynSent {
            return Err(-11);
        }
        let n = bytes.len().min(c.send_available());
        if n == 0 && !bytes.is_empty() {
            return Err(-11);
        }
        c.queue_send(&bytes[..n]).map_err(error)?;
        Ok(n)
    }
    pub(crate) fn receive(
        &mut self,
        socket: Socket,
        peek: bool,
        bytes: &mut [u8],
    ) -> Result<usize, i32> {
        let i = self.index(socket)?;
        let row = &mut self.rows[i];
        if let Some(e) = row.failure {
            return Err(e);
        }
        let Binding::Connection { tcp, owner } = row.binding else {
            return Err(-107);
        };
        let c = self.table.get_mut(tcp, owner).map_err(error)?;
        if row.read_shutdown || bytes.is_empty() {
            return Ok(0);
        }
        if c.received_len() == 0 {
            return if eof(c.state) { Ok(0) } else { Err(-11) };
        }
        let n = if peek {
            c.peek(bytes)
        } else {
            c.receive(bytes)
        };
        row.window_update |= !peek && n != 0;
        Ok(n)
    }
    pub(crate) fn shutdown(&mut self, socket: Socket, read: bool, write: bool) -> Result<(), i32> {
        let i = self.index(socket)?;
        let row = &mut self.rows[i];
        let Binding::Connection { tcp, owner } = row.binding else {
            return Err(-107);
        };
        let c = self.table.get_mut(tcp, owner).map_err(error)?;
        if let Some(e) = row.failure {
            return Err(e);
        }
        if !read && !write {
            return Err(-22);
        }
        if write && !row.write_shutdown {
            c.request_close().map_err(error)?;
            row.write_shutdown = true;
        }
        if read {
            row.window_update |= c.received_len() != 0;
            c.discard_received();
            row.read_shutdown = true;
        }
        Ok(())
    }
    fn room(&mut self) -> bool {
        self.pending.len() < QUEUE_LIMIT && self.pending.try_reserve(1).is_ok()
    }
    fn abort(&mut self, tcp: u64, owner: u64) {
        if let Ok(c) = self.table.get_mut(tcp, owner) {
            let packet = Packet {
                tuple: c.tuple,
                origin: None,
                transmit: TcpTransmit {
                    sequence: c.send_next,
                    acknowledgment: 0,
                    flags: TCP_FLAG_RST,
                    window: 0,
                    options: TcpOptions::default(),
                    payload: Vec::new(),
                    retransmission: false,
                },
            };
            self.pending.retain(|p| p.origin != Some(tcp));
            if self.room() {
                self.pending.push_back(packet);
            }
        }
        self.table.remove(tcp, owner);
    }
    pub(crate) fn release(&mut self, socket: Socket, now: u64) {
        let Ok(i) = self.index(socket) else { return };
        match self.rows[i].binding {
            Binding::Idle => {
                self.rows.swap_remove(i);
            }
            Binding::Listener(tcp) => {
                // Reset unaccepted children, while preserving connections
                // already published as independent resource references.
                let mut unaccepted = [0; TCP_LIMIT];
                let mut count = 0;
                for c in self.table.connections_mut() {
                    if c.owner == socket.0
                        && !self.rows.iter().any(|row| {
                            matches!(
                                row.binding, Binding::Connection { tcp, .. } if tcp == c.handle
                            )
                        })
                    {
                        unaccepted[count] = c.handle;
                        count += 1;
                    }
                }
                for child in &unaccepted[..count] {
                    self.abort(*child, socket.0);
                }
                let _ = self.table.close_listener(tcp, socket.0);
                self.rows.swap_remove(i);
                let table = &mut self.table;
                self.pending.retain(|p| {
                    p.origin
                        .is_none_or(|id| table.connections_mut().any(|c| c.handle == id))
                });
            }
            Binding::Connection { tcp, owner } => {
                let graceful = self.table.get_mut(tcp, owner).is_ok_and(|c| {
                    if c.received_len() != 0
                        || matches!(
                            c.state,
                            TcpState::SynSent | TcpState::Reset | TcpState::Closed
                        )
                    {
                        return false;
                    }
                    if matches!(c.state, TcpState::Established | TcpState::CloseWait) {
                        let _ = c.request_close();
                    }
                    true
                });
                if graceful {
                    self.rows[i].released = Some(now.saturating_add(CLOSE_TIMEOUT));
                    self.rows[i].read_shutdown = true;
                } else {
                    self.abort(tcp, owner);
                    self.rows.swap_remove(i);
                }
            }
        }
    }
    /// Bounded packet work; pending replies survive a budget boundary. This
    /// must return to the service loop so other clients can make progress.
    pub(crate) fn advance(&mut self, now: u64, mut entropy: impl FnMut() -> Option<u64>) -> usize {
        let pending = &mut self.pending;
        for c in self.table.connections_mut() {
            c.tick(now);
            if pending.len() == QUEUE_LIMIT || pending.try_reserve(1).is_err() {
                break;
            }
            match c.poll_transmit(now) {
                Ok(Some(transmit)) => pending.push_back(Packet {
                    tuple: c.tuple,
                    transmit,
                    origin: Some(c.handle),
                }),
                Err(e) => {
                    for row in &mut self.rows {
                        if matches!(row.binding, Binding::Connection { tcp, .. } if tcp == c.handle)
                            && row.failure.is_none()
                        {
                            row.failure = Some(error(e));
                            row.pending_error = error(e);
                        }
                    }
                }
                _ => {}
            }
        }
        let mut work = 0;
        while work < PUMP_BUDGET {
            let Some(packet) = self.pending.pop_front() else {
                break;
            };
            work += 1;
            let tuple = TcpTuple {
                local_address: packet.tuple.remote_address,
                local_port: packet.tuple.remote_port,
                remote_address: packet.tuple.local_address,
                remote_port: packet.tuple.local_port,
            };
            let tx = packet.transmit;
            let segment = TcpSegment {
                source_port: packet.tuple.local_port,
                destination_port: packet.tuple.remote_port,
                sequence: tx.sequence,
                acknowledgment: tx.acknowledgment,
                flags: tx.flags,
                window: tx.window,
                urgent_pointer: 0,
                options: tx.options,
                payload: &tx.payload,
            };
            if let Ok(received) = self
                .table
                .receive_packet(tuple, &segment, now, &mut entropy)
            {
                if let Some(transmit) = received.reply {
                    // Popping a packet retained one allocation-free queue slot.
                    self.pending.push_back(Packet {
                        tuple,
                        transmit,
                        origin: received.connection,
                    });
                }
            }
        }
        // Preserve terminal observations until the resource is explicitly
        // released. Never call table.remove_closed() on live socket resources.
        for row in &mut self.rows {
            let Binding::Connection { tcp, owner } = row.binding else {
                continue;
            };
            let Ok(c) = self.table.get_mut(tcp, owner) else {
                continue;
            };
            if matches!(c.state, TcpState::Established | TcpState::CloseWait) {
                row.connected = true;
            }
            if c.state == TcpState::Reset && row.failure.is_none() {
                let failure = if row.connected { -104 } else { -111 };
                row.failure = Some(failure);
                row.pending_error = failure;
            }
            if row.read_shutdown && c.received_len() != 0 {
                c.discard_received();
                row.window_update = true;
            }
            if row.window_update
                && self.pending.len() < QUEUE_LIMIT
                && self.pending.try_reserve(1).is_ok()
            {
                self.pending.push_back(Packet {
                    tuple: c.tuple,
                    transmit: c.acknowledgment(),
                    origin: Some(tcp),
                });
                row.window_update = false;
            }
        }
        let mut i = 0;
        while i < self.rows.len() {
            let Some(deadline) = self.rows[i].released else {
                i += 1;
                continue;
            };
            let Binding::Connection { tcp, owner } = self.rows[i].binding else {
                unreachable!()
            };
            let terminal = self
                .table
                .get_mut(tcp, owner)
                .is_ok_and(|c| matches!(c.state, TcpState::Closed | TcpState::Reset));
            if terminal || now >= deadline {
                if terminal {
                    self.table.remove(tcp, owner);
                } else {
                    self.abort(tcp, owner);
                }
                self.rows.swap_remove(i);
            } else {
                i += 1;
            }
        }
        work
    }
}
