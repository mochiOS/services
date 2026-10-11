use std::collections::{BTreeMap, VecDeque};
use std::vec::Vec;

use mnu_abi::provider;
use mochios_posix_protocol as posix_protocol;

pub const EIO: i32 = 5;
pub const EAGAIN: i32 = 11;
pub const EBADF: i32 = 9;
pub const EINVAL: i32 = 22;
pub const ESPIPE: i32 = 29;
pub const ENOTSUP: i32 = 95;

pub const BUFFER_CAPACITY: usize = 64 * 1024;
pub const READINESS_SIGNALS: u64 = mnu_abi::HANDLE_SIGNAL_READABLE
    | mnu_abi::HANDLE_SIGNAL_WRITABLE
    | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
    | mnu_abi::HANDLE_SIGNAL_IDLE;

const SUPPORTED_INPUT_FLAGS: u32 = posix_protocol::TERMINAL_IFLAG_ISTRIP
    | posix_protocol::TERMINAL_IFLAG_INLCR
    | posix_protocol::TERMINAL_IFLAG_IGNCR
    | posix_protocol::TERMINAL_IFLAG_ICRNL;
const SUPPORTED_OUTPUT_FLAGS: u32 =
    posix_protocol::TERMINAL_OFLAG_OPOST | posix_protocol::TERMINAL_OFLAG_ONLCR;
const SUPPORTED_LOCAL_FLAGS: u32 = posix_protocol::TERMINAL_LFLAG_ICANON
    | posix_protocol::TERMINAL_LFLAG_ISIG
    | posix_protocol::TERMINAL_LFLAG_ECHO
    | posix_protocol::TERMINAL_LFLAG_ECHOE
    | posix_protocol::TERMINAL_LFLAG_ECHOK
    | posix_protocol::TERMINAL_LFLAG_ECHONL
    | posix_protocol::TERMINAL_LFLAG_NOFLSH;

fn terminal_attributes_supported(attributes: posix_protocol::TerminalAttributes) -> bool {
    attributes.input_flags & !SUPPORTED_INPUT_FLAGS == 0
        && attributes.output_flags & !SUPPORTED_OUTPUT_FLAGS == 0
        && attributes.local_flags & !SUPPORTED_LOCAL_FLAGS == 0
        && attributes.control_flags
            == (posix_protocol::TERMINAL_CFLAG_CS8 | posix_protocol::TERMINAL_CFLAG_CREAD)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtyPair {
    pub master_object_id: u64,
    pub slave_object_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSignal {
    pub terminal_id: u64,
    pub signal: u32,
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
    input_records: VecDeque<InputRecord>,
    canonical_input: VecDeque<u8>,
    output: VecDeque<u8>,
    attributes: posix_protocol::TerminalAttributes,
    window_size: posix_protocol::TerminalWindowSize,
}

#[derive(Clone, Copy, Debug)]
struct InputRecord {
    remaining: usize,
    canonical: bool,
}

impl PseudoTerminal {
    fn new() -> Self {
        Self {
            master_open: true,
            slave_open: true,
            input: VecDeque::new(),
            input_records: VecDeque::new(),
            canonical_input: VecDeque::new(),
            output: VecDeque::new(),
            attributes: posix_protocol::TerminalAttributes::sane(),
            window_size: posix_protocol::TerminalWindowSize::default(),
        }
    }

    fn input_occupancy(&self) -> usize {
        self.input.len() + self.canonical_input.len()
    }

    fn output_bytes_for(&self, byte: u8) -> usize {
        if byte == b'\n'
            && self.attributes.output_flags & posix_protocol::TERMINAL_OFLAG_OPOST != 0
            && self.attributes.output_flags & posix_protocol::TERMINAL_OFLAG_ONLCR != 0
        {
            2
        } else {
            1
        }
    }

    fn can_append_output(&self, bytes: &[u8]) -> bool {
        let required = bytes.iter().copied().fold(0usize, |total, byte| {
            total.saturating_add(self.output_bytes_for(byte))
        });
        required <= BUFFER_CAPACITY.saturating_sub(self.output.len())
    }

    fn append_output(&mut self, byte: u8) {
        if self.output_bytes_for(byte) == 2 {
            self.output.push_back(b'\r');
        }
        self.output.push_back(byte);
    }

    fn append_raw_input(&mut self, byte: u8) {
        self.input.push_back(byte);
        if let Some(record) = self.input_records.back_mut()
            && !record.canonical
        {
            record.remaining += 1;
            return;
        }
        self.input_records.push_back(InputRecord {
            remaining: 1,
            canonical: false,
        });
    }

    fn commit_canonical_input(&mut self) {
        let length = self.canonical_input.len();
        self.input.extend(self.canonical_input.drain(..));
        self.input_records.push_back(InputRecord {
            remaining: length,
            canonical: true,
        });
    }

    fn read_input(&mut self, maximum: usize) -> Result<Vec<u8>, i32> {
        let Some(record) = self.input_records.front_mut() else {
            return if self.master_open {
                Err(EAGAIN)
            } else {
                Ok(Vec::new())
            };
        };
        if record.remaining == 0 {
            self.input_records.pop_front();
            return Ok(Vec::new());
        }
        let length = maximum.min(record.remaining);
        record.remaining -= length;
        if record.remaining == 0 {
            self.input_records.pop_front();
        }
        Ok(self.input.drain(..length).collect())
    }

    fn transformed_input_byte(&self, mut byte: u8) -> Option<u8> {
        if self.attributes.input_flags & posix_protocol::TERMINAL_IFLAG_ISTRIP != 0 {
            byte &= 0x7f;
        }
        if byte == b'\r' {
            if self.attributes.input_flags & posix_protocol::TERMINAL_IFLAG_IGNCR != 0 {
                return None;
            }
            if self.attributes.input_flags & posix_protocol::TERMINAL_IFLAG_ICRNL != 0 {
                byte = b'\n';
            }
        } else if byte == b'\n'
            && self.attributes.input_flags & posix_protocol::TERMINAL_IFLAG_INLCR != 0
        {
            byte = b'\r';
        }
        Some(byte)
    }

    fn should_echo(&self, byte: u8) -> bool {
        let local = self.attributes.local_flags;
        if byte == b'\n'
            && local & posix_protocol::TERMINAL_LFLAG_ECHO == 0
            && local & posix_protocol::TERMINAL_LFLAG_ECHONL != 0
        {
            true
        } else {
            local & posix_protocol::TERMINAL_LFLAG_ECHO != 0
        }
    }

    fn signal_for_input(&self, byte: u8) -> Option<u32> {
        if self.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ISIG == 0 {
            return None;
        }
        [
            (
                posix_protocol::TERMINAL_CC_VINTR,
                posix_protocol::SIGNAL_INT,
            ),
            (
                posix_protocol::TERMINAL_CC_VQUIT,
                posix_protocol::SIGNAL_QUIT,
            ),
            (
                posix_protocol::TERMINAL_CC_VSUSP,
                posix_protocol::SIGNAL_TSTP,
            ),
        ]
        .into_iter()
        .find_map(|(index, signal)| {
            let character = self.attributes.control_characters[index];
            (character != 0 && byte == character).then_some(signal)
        })
    }

    fn flush_for_signal(&mut self) {
        if self.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_NOFLSH != 0 {
            return;
        }
        self.input.clear();
        self.input_records.clear();
        self.canonical_input.clear();
        self.output.clear();
    }

    fn write_master(&mut self, bytes: &[u8]) -> Result<(usize, Vec<u32>), i32> {
        if !self.slave_open {
            return Err(EIO);
        }
        let canonical = self.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ICANON != 0;
        let mut consumed = 0;
        let mut signals = Vec::new();
        for source in bytes.iter().copied() {
            let Some(byte) = self.transformed_input_byte(source) else {
                consumed += 1;
                continue;
            };
            if let Some(signal) = self.signal_for_input(byte) {
                self.flush_for_signal();
                signals.push(signal);
                consumed += 1;
                continue;
            }
            if canonical {
                let erase = self.attributes.control_characters[posix_protocol::TERMINAL_CC_VERASE];
                let kill = self.attributes.control_characters[posix_protocol::TERMINAL_CC_VKILL];
                let eof = self.attributes.control_characters[posix_protocol::TERMINAL_CC_VEOF];
                if erase != 0 && byte == erase {
                    if self.canonical_input.is_empty() {
                        consumed += 1;
                        continue;
                    }
                    let single = [byte];
                    let echo: &[u8] = if self.attributes.local_flags
                        & (posix_protocol::TERMINAL_LFLAG_ECHO
                            | posix_protocol::TERMINAL_LFLAG_ECHOE)
                        == (posix_protocol::TERMINAL_LFLAG_ECHO
                            | posix_protocol::TERMINAL_LFLAG_ECHOE)
                    {
                        b"\x08 \x08".as_slice()
                    } else if self.should_echo(byte) {
                        &single
                    } else {
                        b""
                    };
                    if !self.can_append_output(echo) {
                        break;
                    }
                    self.canonical_input.pop_back();
                    for byte in echo.iter().copied() {
                        self.append_output(byte);
                    }
                    consumed += 1;
                    continue;
                }
                if kill != 0 && byte == kill {
                    let single = [byte];
                    let echo: &[u8] = if self.attributes.local_flags
                        & (posix_protocol::TERMINAL_LFLAG_ECHO
                            | posix_protocol::TERMINAL_LFLAG_ECHOK)
                        == (posix_protocol::TERMINAL_LFLAG_ECHO
                            | posix_protocol::TERMINAL_LFLAG_ECHOK)
                    {
                        b"\n".as_slice()
                    } else if self.should_echo(byte) {
                        &single
                    } else {
                        b""
                    };
                    if !self.can_append_output(echo) {
                        break;
                    }
                    self.canonical_input.clear();
                    for byte in echo.iter().copied() {
                        self.append_output(byte);
                    }
                    consumed += 1;
                    continue;
                }
                if eof != 0 && byte == eof {
                    self.commit_canonical_input();
                    consumed += 1;
                    continue;
                }
            }
            if self.input_occupancy() == BUFFER_CAPACITY {
                break;
            }
            let single = [byte];
            let echo: &[u8] = if self.should_echo(byte) { &single } else { b"" };
            if !self.can_append_output(echo) {
                break;
            }
            if canonical {
                self.canonical_input.push_back(byte);
            } else {
                self.append_raw_input(byte);
            }
            for byte in echo.iter().copied() {
                self.append_output(byte);
            }
            if canonical {
                let eol = self.attributes.control_characters[posix_protocol::TERMINAL_CC_VEOL];
                let eol2 = self.attributes.control_characters[posix_protocol::TERMINAL_CC_VEOL2];
                if byte == b'\n' || (eol != 0 && byte == eol) || (eol2 != 0 && byte == eol2) {
                    self.commit_canonical_input();
                }
            }
            consumed += 1;
        }
        if consumed == 0 && !bytes.is_empty() {
            Err(EAGAIN)
        } else {
            Ok((consumed, signals))
        }
    }

    fn write_slave(&mut self, bytes: &[u8]) -> Result<usize, i32> {
        if !self.master_open {
            return Err(EIO);
        }
        let mut consumed = 0;
        for byte in bytes.iter().copied() {
            if !self.can_append_output(core::slice::from_ref(&byte)) {
                break;
            }
            self.append_output(byte);
            consumed += 1;
        }
        if consumed == 0 && !bytes.is_empty() {
            Err(EAGAIN)
        } else {
            Ok(consumed)
        }
    }
}

#[derive(Debug, Default)]
pub struct PtyManager {
    next_id: u64,
    terminals: BTreeMap<u64, PseudoTerminal>,
    pending_signals: VecDeque<TerminalSignal>,
}

impl PtyManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            terminals: BTreeMap::new(),
            pending_signals: VecDeque::new(),
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
        if side == PtySide::Slave {
            return terminal.read_input(maximum);
        }
        let length = maximum.min(terminal.output.len());
        if length != 0 {
            return Ok(terminal.output.drain(..length).collect());
        }
        if terminal.slave_open {
            Err(EAGAIN)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn write(&mut self, object_id: u64, bytes: &[u8]) -> Result<usize, i32> {
        let (id, side) = decode_object_id(object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        match side {
            PtySide::Master => {
                let (written, signals) = terminal.write_master(bytes)?;
                self.pending_signals
                    .extend(signals.into_iter().map(|signal| TerminalSignal {
                        terminal_id: id,
                        signal,
                    }));
                Ok(written)
            }
            PtySide::Slave => terminal.write_slave(bytes),
        }
    }

    pub fn take_terminal_signal(&mut self) -> Option<TerminalSignal> {
        self.pending_signals.pop_front()
    }

    pub fn seek(&self, object_id: u64) -> Result<u64, i32> {
        let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
        self.terminals.contains_key(&id).then_some(0).ok_or(EBADF)?;
        Err(ESPIPE)
    }

    pub fn attributes(&self, object_id: u64) -> Result<posix_protocol::TerminalAttributes, i32> {
        let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
        self.terminals
            .get(&id)
            .map(|terminal| terminal.attributes)
            .ok_or(EBADF)
    }

    pub fn set_attributes(
        &mut self,
        object_id: u64,
        attributes: posix_protocol::TerminalAttributes,
    ) -> Result<(), i32> {
        if !terminal_attributes_supported(attributes) {
            return Err(ENOTSUP);
        }
        let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        let was_canonical =
            terminal.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ICANON != 0;
        let is_canonical = attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ICANON != 0;
        terminal.attributes = attributes;
        if was_canonical && !is_canonical && !terminal.canonical_input.is_empty() {
            let pending: Vec<_> = terminal.canonical_input.drain(..).collect();
            for byte in pending {
                terminal.append_raw_input(byte);
            }
        }
        Ok(())
    }

    fn set_attributes_when_drained(
        &mut self,
        object_id: u64,
        attributes: posix_protocol::TerminalAttributes,
        flush_input: bool,
    ) -> Result<(), i32> {
        if !terminal_attributes_supported(attributes) {
            return Err(ENOTSUP);
        }
        let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
        {
            let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
            if !terminal.output.is_empty() && terminal.master_open {
                return Err(EAGAIN);
            }
            if !terminal.master_open {
                terminal.output.clear();
            }
            if flush_input {
                terminal.input.clear();
                terminal.input_records.clear();
                terminal.canonical_input.clear();
            }
        }
        self.set_attributes(object_id, attributes)
    }

    fn drain_output(&mut self, object_id: u64) -> Result<(), i32> {
        let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        if !terminal.output.is_empty() && terminal.master_open {
            return Err(EAGAIN);
        }
        if !terminal.master_open {
            terminal.output.clear();
        }
        Ok(())
    }

    fn flush_queues(&mut self, object_id: u64, flags: u32) -> Result<(), i32> {
        let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        if flags & posix_protocol::TERMINAL_FLUSH_INPUT != 0 {
            terminal.input.clear();
            terminal.input_records.clear();
            terminal.canonical_input.clear();
        }
        if flags & posix_protocol::TERMINAL_FLUSH_OUTPUT != 0 {
            terminal.output.clear();
        }
        Ok(())
    }

    pub fn control(
        &mut self,
        object_id: u64,
        code: u64,
        input: &[u8],
        output_capacity: usize,
    ) -> Result<Vec<u8>, i32> {
        match code {
            posix_protocol::PTY_CONTROL_GET_WINDOW_SIZE => {
                if !input.is_empty()
                    || output_capacity < posix_protocol::TERMINAL_WINDOW_SIZE_LEN
                {
                    return Err(EINVAL);
                }
                let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
                let terminal = self.terminals.get(&id).ok_or(EBADF)?;
                let mut output = vec![0; posix_protocol::TERMINAL_WINDOW_SIZE_LEN];
                posix_protocol::encode_terminal_window_size(terminal.window_size, &mut output)
                    .map_err(|_| EINVAL)?;
                Ok(output)
            }
            posix_protocol::PTY_CONTROL_SET_WINDOW_SIZE => {
                if output_capacity != 0 {
                    return Err(EINVAL);
                }
                let size = posix_protocol::decode_terminal_window_size(input).map_err(|_| EINVAL)?;
                let (id, _) = decode_object_id(object_id).ok_or(EBADF)?;
                let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
                if terminal.window_size != size {
                    terminal.window_size = size;
                    self.pending_signals.push_back(TerminalSignal {
                        terminal_id: id,
                        signal: posix_protocol::SIGNAL_WINCH,
                    });
                }
                Ok(Vec::new())
            }
            posix_protocol::PTY_CONTROL_GET_ATTRIBUTES => {
                if !input.is_empty() || output_capacity < posix_protocol::TERMINAL_ATTRIBUTES_LEN {
                    return Err(EINVAL);
                }
                let mut output = vec![0; posix_protocol::TERMINAL_ATTRIBUTES_LEN];
                posix_protocol::encode_terminal_attributes(
                    self.attributes(object_id)?,
                    &mut output,
                )
                .map_err(|_| EINVAL)?;
                Ok(output)
            }
            posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_NOW
            | posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_DRAIN
            | posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_FLUSH => {
                if output_capacity != 0 {
                    return Err(EINVAL);
                }
                let attributes =
                    posix_protocol::decode_terminal_attributes(input).map_err(|_| EINVAL)?;
                match code {
                    posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_NOW => {
                        self.set_attributes(object_id, attributes)?;
                    }
                    posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_DRAIN => {
                        self.set_attributes_when_drained(object_id, attributes, false)?;
                    }
                    posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_FLUSH => {
                        self.set_attributes_when_drained(object_id, attributes, true)?;
                    }
                    _ => unreachable!(),
                }
                Ok(Vec::new())
            }
            posix_protocol::PTY_CONTROL_DRAIN => {
                if !input.is_empty() || output_capacity != 0 {
                    return Err(EINVAL);
                }
                self.drain_output(object_id)?;
                Ok(Vec::new())
            }
            posix_protocol::PTY_CONTROL_FLUSH => {
                if output_capacity != 0 {
                    return Err(EINVAL);
                }
                let flags = posix_protocol::decode_terminal_flush(input).map_err(|_| EINVAL)?;
                self.flush_queues(object_id, flags)?;
                Ok(Vec::new())
            }
            _ => Err(ENOTSUP),
        }
    }

    pub fn release(&mut self, object_id: u64) -> Result<(), i32> {
        let (id, side) = decode_object_id(object_id).ok_or(EBADF)?;
        let remove = {
            let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
            match side {
                PtySide::Master if terminal.master_open => {
                    terminal.master_open = false;
                    self.pending_signals.push_back(TerminalSignal {
                        terminal_id: id,
                        signal: posix_protocol::SIGNAL_HUP,
                    });
                }
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

    pub fn slave_terminal_id(&self, object_id: u64) -> Result<u64, i32> {
        let (id, side) = decode_object_id(object_id).ok_or(EBADF)?;
        if side != PtySide::Slave || !self.terminals.contains_key(&id) {
            return Err(EBADF);
        }
        Ok(id)
    }

    pub fn signals(&self, object_id: u64) -> Result<u64, i32> {
        let (id, side) = decode_object_id(object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get(&id).ok_or(EBADF)?;
        let (readable, writable, peer_closed) = match side {
            PtySide::Master => (
                !terminal.output.is_empty(),
                terminal.slave_open
                    && terminal.input_occupancy() < BUFFER_CAPACITY
                    && (terminal.attributes.local_flags
                        & (posix_protocol::TERMINAL_LFLAG_ECHO
                            | posix_protocol::TERMINAL_LFLAG_ECHONL)
                        == 0
                        || terminal.output.len() < BUFFER_CAPACITY),
                !terminal.slave_open,
            ),
            PtySide::Slave => (
                !terminal.input_records.is_empty(),
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
        if terminal.output.is_empty() {
            signals |= mnu_abi::HANDLE_SIGNAL_IDLE;
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
        provider::OP_CONTROL => ptys
            .control(
                header.object_id,
                header.basis,
                payload,
                header.length as usize,
            )
            .map(|data| (data.len() as u64, data)),
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
