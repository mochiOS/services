use std::collections::{BTreeMap, VecDeque};
use std::vec::Vec;

use mnu_abi::provider;

pub const EIO: i32 = 5;
pub const EAGAIN: i32 = 11;
pub const EBADF: i32 = 9;
pub const ESPIPE: i32 = 29;
pub const ENOTSUP: i32 = 95;

pub const BUFFER_CAPACITY: usize = 64 * 1024;
pub const READINESS_SIGNALS: u64 = mnu_abi::HANDLE_SIGNAL_READABLE
    | mnu_abi::HANDLE_SIGNAL_WRITABLE
    | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtyPair {
    pub master_object_id: u64,
    pub slave_object_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PtySide {
    Master,
    Slave,
}

#[derive(Debug)]
struct PseudoTerminal {
    master_open: bool,
    slave_open: bool,
    input: VecDeque<u8>,
    output: VecDeque<u8>,
}

impl PseudoTerminal {
    fn new() -> Self {
        Self {
            master_open: true,
            slave_open: true,
            input: VecDeque::new(),
            output: VecDeque::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct PtyManager {
    next_id: u64,
    terminals: BTreeMap<u64, PseudoTerminal>,
}

impl PtyManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            terminals: BTreeMap::new(),
        }
    }

    pub fn open(&mut self) -> Result<PtyPair, i32> {
        let id = self.allocate_id().ok_or(EAGAIN)?;
        self.terminals.insert(id, PseudoTerminal::new());
        Ok(PtyPair {
            master_object_id: encode_object_id(id, PtySide::Master),
            slave_object_id: encode_object_id(id, PtySide::Slave),
        })
    }

    pub fn read(&mut self, object_id: u64, maximum: usize) -> Result<Vec<u8>, i32> {
        if maximum == 0 {
            return Ok(Vec::new());
        }
        let (id, side) = decode_object_id(object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        let (queue, peer_open) = match side {
            PtySide::Master => (&mut terminal.output, terminal.slave_open),
            PtySide::Slave => (&mut terminal.input, terminal.master_open),
        };
        let length = maximum.min(queue.len());
        if length == 0 {
            return if peer_open {
                Err(EAGAIN)
            } else {
                Ok(Vec::new())
            };
        }
        Ok(queue.drain(..length).collect())
    }

    pub fn write(&mut self, object_id: u64, bytes: &[u8]) -> Result<usize, i32> {
        let (id, side) = decode_object_id(object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let (queue, peer_open) = match side {
            PtySide::Master => (&mut terminal.input, terminal.slave_open),
            PtySide::Slave => (&mut terminal.output, terminal.master_open),
        };
        if !peer_open {
            return Err(EIO);
        }
        let available = BUFFER_CAPACITY.saturating_sub(queue.len());
        if available == 0 {
            return Err(EAGAIN);
        }
        let length = available.min(bytes.len());
        queue.extend(&bytes[..length]);
        Ok(length)
    }

    pub fn seek(&self, object_id: u64) -> Result<u64, i32> {
        let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
        self.terminals.contains_key(&id).then_some(0).ok_or(EBADF)?;
        Err(ESPIPE)
    }

    pub fn release(&mut self, object_id: u64) -> Result<(), i32> {
        let (id, side) = decode_object_id(object_id).ok_or(EBADF)?;
        let remove = {
            let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
            match side {
                PtySide::Master if terminal.master_open => terminal.master_open = false,
                PtySide::Slave if terminal.slave_open => terminal.slave_open = false,
                _ => return Err(EBADF),
            }
            !terminal.master_open && !terminal.slave_open
        };
        if remove {
            self.terminals.remove(&id);
        }
        Ok(())
    }

    pub fn discard(&mut self, pair: PtyPair) {
        if let Some((id, _)) = decode_object_id(pair.master_object_id) {
            self.terminals.remove(&id);
        }
    }

    pub fn object_ids(&self, object_id: u64) -> Result<[u64; 2], i32> {
        let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
        self.terminals
            .contains_key(&id)
            .then_some([
                encode_object_id(id, PtySide::Master),
                encode_object_id(id, PtySide::Slave),
            ])
            .ok_or(EBADF)
    }

    pub fn signals(&self, object_id: u64) -> Result<u64, i32> {
        let (id, side) = decode_object_id(object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get(&id).ok_or(EBADF)?;
        let (readable, writable, peer_closed) = match side {
            PtySide::Master => (
                !terminal.output.is_empty(),
                terminal.slave_open && terminal.input.len() < BUFFER_CAPACITY,
                !terminal.slave_open,
            ),
            PtySide::Slave => (
                !terminal.input.is_empty(),
                terminal.master_open && terminal.output.len() < BUFFER_CAPACITY,
                !terminal.master_open,
            ),
        };
        let mut signals = 0;
        if readable {
            signals |= mnu_abi::HANDLE_SIGNAL_READABLE;
        }
        if writable {
            signals |= mnu_abi::HANDLE_SIGNAL_WRITABLE;
        }
        if peer_closed {
            signals |= mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
        }
        Ok(signals)
    }

    fn allocate_id(&mut self) -> Option<u64> {
        const MAX_ID: u64 = (i64::MAX as u64) >> 1;
        for _ in 0..self.terminals.len().saturating_add(1) {
            let id = self.next_id.clamp(1, MAX_ID);
            self.next_id = if id == MAX_ID { 1 } else { id + 1 };
            if !self.terminals.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }
}

pub fn handle_provider_request(
    ptys: &mut PtyManager,
    request: &[u8],
    response: &mut [u8],
) -> Option<usize> {
    let (header, payload) = provider::RequestHeader::decode(request).ok()?;
    if header.opcode == provider::OP_RELEASE {
        let _ = ptys.release(header.object_id);
        return None;
    }
    let result = match header.opcode {
        provider::OP_READ => ptys
            .read(header.object_id, header.length as usize)
            .map(|data| (data.len() as u64, data)),
        provider::OP_WRITE => ptys
            .write(header.object_id, payload)
            .map(|written| (written as u64, Vec::new())),
        provider::OP_SEEK => ptys
            .seek(header.object_id)
            .map(|offset| (offset, Vec::new())),
        provider::OP_CONTROL => Err(ENOTSUP),
        _ => unreachable!("provider decoder rejects unknown operations"),
    };
    let (status, value, data) = match result {
        Ok((value, data)) => (0, value, data),
        Err(errno) => (-(i64::from(errno)), 0, Vec::new()),
    };
    provider::ResponseHeader {
        opcode: header.opcode,
        status,
        object_id: header.object_id,
        value,
        data_length: data.len() as u32,
    }
    .encode(&data, response)
    .ok()
}

const fn encode_object_id(id: u64, side: PtySide) -> u64 {
    (id << 1)
        | match side {
            PtySide::Master => 0,
            PtySide::Slave => 1,
        }
}

const fn decode_object_id(object_id: u64) -> Option<(u64, PtySide)> {
    let id = object_id >> 1;
    if id == 0 || object_id > i64::MAX as u64 {
        return None;
    }
    let side = if object_id & 1 == 0 {
        PtySide::Master
    } else {
        PtySide::Slave
    };
    Some((id, side))
}
