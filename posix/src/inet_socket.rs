//! IPv4 UDP Provider descriptions. Private IDs are disjoint from local socket
//! and notification namespaces; only native Provider delivery authorizes them.
use crate::inet_datagram::{Backend, Datagram};
use mnu_abi::provider;
use mochios_posix_protocol::socket as wire;
// Two tag bits form an unused namespace while keeping Identify results in
// the native signed-success range. The top bit is reserved for errors.
pub const TAG: u64 = 3 << 59;
const MASK: u64 = (1 << 59) - 1;
pub fn is_inet(id: u64) -> bool {
    id & !MASK == TAG && id & MASK != 0
}
struct Row<B: Backend> {
    id: u64,
    socket: Datagram<B>,
    forwarded: u64,
}
pub struct Registry<B: Backend> {
    next: u64,
    rows: Vec<Row<B>>,
}
impl<B: Backend> Registry<B> {
    pub const fn new() -> Self {
        Self {
            next: 1,
            rows: Vec::new(),
        }
    }
    pub fn insert(&mut self, socket: Datagram<B>) -> Result<u64, i32> {
        if self.rows.len() == crate::socket::MAX_ENDPOINTS || self.next > MASK {
            return Err(-23);
        }
        self.rows.try_reserve(1).map_err(|_| -12)?;
        let id = TAG | self.next;
        self.next += 1;
        self.rows.push(Row {
            id,
            socket,
            forwarded: 0,
        });
        Ok(id)
    }
    fn row(&mut self, id: u64) -> Result<&mut Row<B>, i32> {
        self.rows.iter_mut().find(|r| r.id == id).ok_or(-9)
    }
    pub fn remove(&mut self, id: u64) -> Result<(), i32> {
        let index = self.rows.iter().position(|r| r.id == id).ok_or(-9)?;
        self.rows.swap_remove(index);
        Ok(())
    }
    pub fn connect(&mut self, id: u64, address: wire::Address<'_>) -> Result<(), i32> {
        self.row(id)?.socket.connect(address)
    }
    /// Poll lower readiness once, then wait only for levels that have not yet
    /// been forwarded. Persistent READABLE/WRITABLE must not spin the worker.
    pub fn pump(&mut self, mut signal: impl FnMut(u64, u64) -> Result<(), i32>) {
        for row in &mut self.rows {
            let set = row.socket.signals().unwrap_or(
                mnu_abi::HANDLE_SIGNAL_READABLE
                    | mnu_abi::HANDLE_SIGNAL_WRITABLE
                    | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
            );
            if set != row.forwarded {
                if signal(row.id, set).is_ok() {
                    row.forwarded = set;
                }
            }
        }
    }
    pub fn watches(&self, mut add: impl FnMut(B::Handle, u64)) {
        let all = mnu_abi::HANDLE_SIGNAL_READABLE
            | mnu_abi::HANDLE_SIGNAL_WRITABLE
            | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
        for row in &self.rows {
            if let Some(handle) = row.socket.binding_handle() {
                let interests = all & !row.forwarded;
                if interests != 0 {
                    add(handle, interests);
                }
            }
        }
    }
    pub fn dispatch(
        &mut self,
        bytes: &[u8],
        delivery: u32,
        count: u32,
        response: &mut [u8],
    ) -> Result<Option<usize>, i32> {
        let (header, payload) = provider::RequestHeader::decode(bytes).map_err(|_| -22)?;
        let native = delivery == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT && count == 0;
        if native && header.opcode == provider::OP_RELEASE {
            self.remove(header.object_id)?;
            return Ok(None);
        }
        let capacity = if matches!(
            header.opcode,
            provider::OP_READ | provider::OP_READ_AT | provider::OP_CONTROL
        ) {
            header.length as usize
        } else {
            0
        };
        if response.len() < provider::RESPONSE_HEADER_LEN + capacity {
            return Err(-22);
        }
        let mut data = [0; provider::MAX_DATA_LEN];
        let result = (|| {
            if !native {
                return Err(-13);
            }
            let socket = &mut self.row(header.object_id)?.socket;
            match header.opcode {
                provider::OP_MEMORY_OBJECT => Ok((0, 0)),
                provider::OP_WRITE => socket.send_to(None, payload).map(|n| (n as u64, 0)),
                provider::OP_READ | provider::OP_READ_AT => {
                    if header.basis != 0 {
                        return Err(-22);
                    }
                    socket
                        .receive_from(
                            header.opcode == provider::OP_READ_AT,
                            &mut data[..header.length as usize],
                        )
                        .map(|r| (r.copied as u64, r.copied))
                }
                provider::OP_CONTROL => match header.basis {
                    wire::CONTROL_KIND if payload.is_empty() && header.length == 4 => {
                        data[..4].copy_from_slice(&(wire::Kind::Datagram as u32).to_le_bytes());
                        Ok((4, 4))
                    }
                    wire::CONTROL_ACCEPTING if payload.is_empty() && header.length == 4 => {
                        Ok((4, 4))
                    }
                    wire::CONTROL_GET_OPTIONS if payload.is_empty() && header.length == 4 => {
                        data[..4].copy_from_slice(&socket.options().to_le_bytes());
                        Ok((4, 4))
                    }
                    wire::CONTROL_SET_OPTIONS if payload.len() == 4 && header.length == 0 => {
                        socket.set_options(u32::from_le_bytes(payload.try_into().unwrap()))?;
                        Ok((0, 0))
                    }
                    wire::CONTROL_GET_RECEIVE_TIMEOUT | wire::CONTROL_GET_SEND_TIMEOUT
                        if payload.is_empty() && header.length == 8 =>
                    {
                        let duration = if header.basis == wire::CONTROL_GET_RECEIVE_TIMEOUT {
                            socket.receive_timeout()
                        } else {
                            socket.send_timeout()
                        };
                        data[..8].copy_from_slice(&duration.to_le_bytes());
                        Ok((8, 8))
                    }
                    wire::CONTROL_SET_RECEIVE_TIMEOUT | wire::CONTROL_SET_SEND_TIMEOUT
                        if payload.len() == 8 && header.length == 0 =>
                    {
                        let duration = u64::from_le_bytes(payload.try_into().unwrap());
                        if header.basis == wire::CONTROL_SET_RECEIVE_TIMEOUT {
                            socket.set_receive_timeout(duration)
                        } else {
                            socket.set_send_timeout(duration)
                        };
                        Ok((0, 0))
                    }
                    wire::CONTROL_BIND if header.length == 0 => {
                        socket.bind(wire::Address::decode(payload).map_err(|_| -22)?)?;
                        Ok((0, 0))
                    }
                    wire::CONTROL_DISCONNECT if payload.is_empty() && header.length == 0 => {
                        socket.disconnect()?;
                        Ok((0, 0))
                    }
                    wire::CONTROL_LOCAL_ADDRESS | wire::CONTROL_PEER_ADDRESS
                        if payload.is_empty() =>
                    {
                        let endpoint = if header.basis == wire::CONTROL_LOCAL_ADDRESS {
                            socket.local_address()?
                        } else {
                            socket.peer_address()?
                        };
                        let n = endpoint
                            .as_address()
                            .encode(&mut data[..header.length as usize])
                            .map_err(|_| -22)?;
                        Ok((n as u64, n))
                    }
                    wire::CONTROL_READINESS if payload.is_empty() && header.length == 4 => {
                        let signals = socket.signals()?;
                        let bits = if signals & mnu_abi::HANDLE_SIGNAL_READABLE != 0 {
                            wire::READY_READ
                        } else {
                            0
                        } | if signals & mnu_abi::HANDLE_SIGNAL_WRITABLE != 0 {
                            wire::READY_WRITE
                        } else {
                            0
                        } | if signals & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED != 0 {
                            wire::ERROR_PENDING | wire::WRITE_ERROR
                        } else {
                            0
                        };
                        data[..4].copy_from_slice(&bits.to_le_bytes());
                        Ok((4, 4))
                    }
                    _ => Err(-95),
                },
                _ => Err(-95),
            }
        })();
        let (status, value, n) = match result {
            Ok((value, n)) => (0, value, n),
            Err(status) => (status, 0, 0),
        };
        provider::ResponseHeader {
            opcode: header.opcode,
            object_id: header.object_id,
            status: i64::from(status),
            value,
            data_length: n as u32,
        }
        .encode(&data[..n], response)
        .map(Some)
        .map_err(|_| -22)
    }
}
