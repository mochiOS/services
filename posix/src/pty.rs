use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::vec::Vec;

use mnu_abi::provider;
use mochios_posix_protocol as posix_protocol;

mod editing;

pub const EIO: i32 = 5;
pub const EACCES: i32 = 13;
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
    | posix_protocol::TERMINAL_IFLAG_IUTF8
    | posix_protocol::TERMINAL_IFLAG_INLCR
    | posix_protocol::TERMINAL_IFLAG_IGNCR
    | posix_protocol::TERMINAL_IFLAG_ICRNL
    | posix_protocol::TERMINAL_IFLAG_IXON
    | posix_protocol::TERMINAL_IFLAG_IXANY;
const SUPPORTED_OUTPUT_FLAGS: u32 =
    posix_protocol::TERMINAL_OFLAG_OPOST | posix_protocol::TERMINAL_OFLAG_ONLCR;
const SUPPORTED_LOCAL_FLAGS: u32 = posix_protocol::TERMINAL_LFLAG_ICANON
    | posix_protocol::TERMINAL_LFLAG_ISIG
    | posix_protocol::TERMINAL_LFLAG_ECHO
    | posix_protocol::TERMINAL_LFLAG_ECHOE
    | posix_protocol::TERMINAL_LFLAG_ECHOK
    | posix_protocol::TERMINAL_LFLAG_ECHONL
    | posix_protocol::TERMINAL_LFLAG_TOSTOP
    | posix_protocol::TERMINAL_LFLAG_IEXTEN
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

/// Authenticate the service-private readiness synchronization message before
/// accepting its provider-owned object IDs. Identity must come from native
/// endpoint metadata, never from the request or attached objects.
pub fn authorize_sync_request(
    request: &[u8],
    sender: Option<mnu_abi::ExecutionIdentity>,
    service_process_id: u64,
    attached_count: u32,
) -> Result<PtyPair, i32> {
    if service_process_id == 0
        || !sender.is_some_and(|identity| {
            identity.process_id == service_process_id && identity.thread_id != 0
        })
    {
        return Err(EACCES);
    }
    if request.len() != 20 || request[..4] != *b"PTYS" || attached_count != 0 {
        return Err(EINVAL);
    }
    Ok(PtyPair {
        master_object_id: u64::from_le_bytes(request[4..12].try_into().unwrap()),
        slave_object_id: u64::from_le_bytes(request[12..20].try_into().unwrap()),
    })
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
    pair: PtyPair,
    live_objects: BTreeSet<u64>,
    master_open: bool,
    slave_open: bool,
    input: VecDeque<u8>,
    input_records: VecDeque<InputRecord>,
    canonical_input: VecDeque<u8>,
    output: VecDeque<u8>,
    edit_echo: VecDeque<u8>,
    attributes: posix_protocol::TerminalAttributes,
    window_size: posix_protocol::TerminalWindowSize,
    output_stopped: bool,
    output_manually_stopped: bool,
    literal_next: bool,
}

#[derive(Clone, Copy, Debug)]
struct InputRecord {
    remaining: usize,
    canonical: bool,
}

impl PseudoTerminal {
    fn new(pair: PtyPair) -> Self {
        Self {
            pair,
            live_objects: BTreeSet::from([pair.master_object_id, pair.slave_object_id]),
            master_open: true,
            slave_open: true,
            input: VecDeque::new(),
            input_records: VecDeque::new(),
            canonical_input: VecDeque::new(),
            output: VecDeque::new(),
            edit_echo: VecDeque::new(),
            attributes: posix_protocol::TerminalAttributes::sane(),
            window_size: posix_protocol::TerminalWindowSize::default(),
            output_stopped: false,
            output_manually_stopped: false,
            literal_next: false,
        }
    }

    fn input_occupancy(&self) -> usize {
        self.input.len() + self.canonical_input.len()
    }

    fn has_input_capacity(&self) -> bool {
        // VEOF can queue a zero-byte record. Bound metadata as well as data;
        // leave a slot for any pending canonical line before accepting bytes.
        self.edit_echo.is_empty()
            && self.input_occupancy() < BUFFER_CAPACITY
            && self.input_records.len() < BUFFER_CAPACITY
    }

    fn canonical_erase_length(&self, end: usize) -> usize {
        if self.attributes.input_flags & posix_protocol::TERMINAL_IFLAG_IUTF8 == 0 {
            return 1;
        }
        // Inspect at most one scalar, including when VecDeque storage wraps.
        // Invalid/incomplete encodings remain bytewise: never eat a preceding
        // character just because untrusted input ends in continuation bytes.
        let mut suffix = [0u8; 4];
        for (index, byte) in self.canonical_input.range(..end).rev().take(4).enumerate() {
            suffix[3 - index] = *byte;
            if byte & 0xc0 != 0x80 {
                return if core::str::from_utf8(&suffix[3 - index..]).is_ok() {
                    index + 1
                } else {
                    1
                };
            }
        }
        1
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
        if !self.edit_echo.is_empty() {
            return false;
        }
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
            // In polling mode an empty read completes, rather than making
            // the runtime wait for a readability event. This policy lives
            // with the line discipline, not in the generic Handle reader.
            let polling = self.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ICANON == 0
                && self.attributes.control_characters[posix_protocol::TERMINAL_CC_VMIN] == 0
                && self.attributes.control_characters[posix_protocol::TERMINAL_CC_VTIME] == 0;
            return if !self.master_open || polling {
                Ok(Vec::new())
            } else {
                Err(EAGAIN)
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
        self.literal_next = false;
        self.output.clear();
        self.edit_echo.clear();
    }

    fn write_master(&mut self, bytes: &[u8]) -> Result<(usize, Vec<u32>), i32> {
        if !self.slave_open {
            return Err(EIO);
        }
        let canonical = self.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ICANON != 0;
        let mut consumed = 0;
        let mut signals = Vec::new();
        for source in bytes.iter().copied() {
            if self.literal_next {
                // Quote one byte across provider requests. ISTRIP still
                // applies, but no CR/NL mapping, signal, flow, or delimiter
                // recognition does. Retain the quote until the byte commits.
                let byte = if self.attributes.input_flags
                    & posix_protocol::TERMINAL_IFLAG_ISTRIP != 0
                {
                    source & 0x7f
                } else {
                    source
                };
                let single = [byte];
                let echo: &[u8] = if self.should_echo(byte) { &single } else { b"" };
                if !self.has_input_capacity() || !self.can_append_output(echo) {
                    break;
                }
                self.canonical_input.push_back(byte);
                for byte in echo.iter().copied() {
                    self.append_output(byte);
                }
                self.literal_next = false;
                consumed += 1;
                continue;
            }
            let Some(byte) = self.transformed_input_byte(source) else {
                consumed += 1;
                continue;
            };
            let flow = self.attributes.input_flags & posix_protocol::TERMINAL_IFLAG_IXON != 0;
            let stop = self.attributes.control_characters[posix_protocol::TERMINAL_CC_VSTOP];
            // Restart output before admission of ordinary input/echo. Even a
            // full input queue must not prevent draining stopped output. The
            // byte still follows normal processing and is not consumed here.
            // Quoted bytes bypass this path, and tcflow's manual stop remains
            // independent of software START/STOP.
            if flow
                && self.attributes.input_flags & posix_protocol::TERMINAL_IFLAG_IXANY != 0
                && (stop == 0 || byte != stop)
            {
                self.output_stopped = false;
            }
            if let Some(signal) = self.signal_for_input(byte) {
                self.flush_for_signal();
                signals.push(signal);
                consumed += 1;
                continue;
            }
            // Flow characters never enter the input/echo queues. Process
            // them before capacity checks so a full queue cannot trap STOP.
            if flow {
                let start = self.attributes.control_characters[posix_protocol::TERMINAL_CC_VSTART];
                if stop != 0 && byte == stop {
                    self.output_stopped = if stop == start {
                        !self.output_stopped
                    } else {
                        true
                    };
                    consumed += 1;
                    continue;
                }
                if start != 0 && byte == start {
                    self.output_stopped = false;
                    consumed += 1;
                    continue;
                }
            }
            if canonical {
                match self.extended_edit(byte) {
                    Ok(true) => {
                        consumed += 1;
                        continue;
                    }
                    Err(()) => break,
                    Ok(false) => {}
                }
                // Output-discard remains an unimplemented extension function.
                let literal =
                    self.attributes.control_characters[posix_protocol::TERMINAL_CC_VLNEXT];
                if self.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_IEXTEN != 0
                    && literal != 0
                    && byte == literal
                {
                    let echo: &[u8] = if self.attributes.local_flags
                        & posix_protocol::TERMINAL_LFLAG_ECHO != 0
                    {
                        b"^\x08"
                    } else {
                        b""
                    };
                    if !self.has_input_capacity() || !self.can_append_output(echo) {
                        break;
                    }
                    for byte in echo.iter().copied() {
                        self.append_output(byte);
                    }
                    self.literal_next = true;
                    consumed += 1;
                    continue;
                }
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
                    let remaining = self.canonical_input.len()
                        - self.canonical_erase_length(self.canonical_input.len());
                    self.canonical_input.truncate(remaining);
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
                    if self.input_records.len() >= BUFFER_CAPACITY {
                        break;
                    }
                    self.commit_canonical_input();
                    consumed += 1;
                    continue;
                }
            }
            if !self.has_input_capacity() {
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
    next_object_id: u64,
    terminals: BTreeMap<u64, PseudoTerminal>,
    objects: BTreeMap<u64, (u64, PtySide)>,
    // Separate provider objects: a factory keeps identity, not a data open.
    slave_factories: BTreeMap<u64, u64>,
    metadata: BTreeMap<u64, crate::pty_metadata::Reference>,
    pending_signals: VecDeque<TerminalSignal>,
}

impl PtyManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            next_object_id: 2,
            terminals: BTreeMap::new(),
            objects: BTreeMap::new(),
            slave_factories: BTreeMap::new(),
            metadata: BTreeMap::new(),
            pending_signals: VecDeque::new(),
        }
    }

    pub fn open(&mut self) -> Result<PtyPair, i32> {
        let id = self.allocate_id().ok_or(EAGAIN)?;
        let master_object_id = self.allocate_object_id().ok_or(EAGAIN)?;
        self.objects.insert(master_object_id, (id, PtySide::Master));
        let slave_object_id = match self.allocate_object_id() {
            Some(object_id) => object_id,
            None => {
                self.objects.remove(&master_object_id);
                return Err(EAGAIN);
            }
        };
        let pair = PtyPair {
            master_object_id,
            slave_object_id,
        };
        self.terminals.insert(id, PseudoTerminal::new(pair));
        self.objects.insert(pair.slave_object_id, (id, PtySide::Slave));
        Ok(pair)
    }

    /// Create a distinct slave open after the caller's namespace/permission
    /// admission. This service-private method conveys no authority via an IPC
    /// object number. Each returned ID must get exactly one native provider
    /// object, with duplicates retaining that same object's lifetime.
    pub fn reopen_slave(&mut self, master_object_id: u64) -> Result<u64, i32> {
        let (id, side) = self.endpoint(master_object_id)?;
        if side != PtySide::Master {
            return Err(EBADF);
        }
        let object_id = self.allocate_object_id().ok_or(EAGAIN)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        terminal.live_objects.insert(object_id);
        terminal.slave_open = true;
        self.objects.insert(object_id, (id, PtySide::Slave));
        Ok(object_id)
    }

    /// Allocate a resource-scoped factory object, not another master open.
    ///
    /// These are service-private object IDs, never wire authority. The IPC
    /// adapter must identify an explicitly attached, sufficiently authorized
    /// master Handle before minting, publish a DUPLICATE|TRANSFER-only native
    /// provider object, and discard it on failed publication.
    pub fn create_slave_factory(&mut self, master_object_id: u64) -> Result<u64, i32> {
        let (terminal_id, side) = self.endpoint(master_object_id)?;
        if side != PtySide::Master {
            return Err(EBADF);
        }
        let object_id = self.allocate_object_id().ok_or(EAGAIN)?;
        self.slave_factories.insert(object_id, terminal_id);
        Ok(object_id)
    }

    /// The adapter must identify an explicitly attached native factory Handle;
    /// a numeric ID supplied by a requester must never reach this method.
    /// Namespace admission and native object publication remain its obligation.
    pub fn open_slave_from_factory(&mut self, factory_object_id: u64) -> Result<u64, i32> {
        let terminal_id = *self.slave_factories.get(&factory_object_id).ok_or(EBADF)?;
        let terminal = self.terminals.get(&terminal_id).ok_or(EBADF)?;
        if !terminal.master_open {
            return Err(EBADF);
        }
        self.reopen_slave(terminal.pair.master_object_id)
    }

    /// Retain the admitted filesystem metadata reference for this independent
    /// open, not the terminal or factory lifetime. Failed native publication
    /// must release the returned open ID; dup/fork share that same native open.
    pub fn open_slave_with_metadata(
        &mut self,
        factory_object_id: u64,
        metadata: crate::pty_metadata::Reference,
    ) -> Result<u64, i32> {
        let object_id = self.open_slave_from_factory(factory_object_id)?;
        self.metadata.insert(object_id, metadata);
        Ok(object_id)
    }

    /// Only the adapter's native identification of an attached data Handle may
    /// select an open. Inline IDs and caller-reported rights are not authority.
    pub fn duplicate_slave_metadata(
        &self,
        object_id: u64,
        source_rights: u64,
        requested_rights: u64,
    ) -> Result<u32, i32> {
        self.slave_terminal_id(object_id)?;
        self.metadata
            .get(&object_id)
            .ok_or(ENOTSUP)?
            .duplicate(source_rights, requested_rights)
    }

    fn endpoint(&self, object_id: u64) -> Result<(u64, PtySide), i32> {
        self.objects.get(&object_id).copied().ok_or(EBADF)
    }

    /// All live open objects on this terminal must observe queue transitions.
    pub fn signal_object_ids(&self, object_id: u64) -> Result<Vec<u64>, i32> {
        let (id, _) = self.endpoint(object_id)?;
        let terminal = self.terminals.get(&id).ok_or(EBADF)?;
        Ok(terminal.live_objects.iter().copied().collect())
    }

    pub fn read(&mut self, object_id: u64, maximum: usize) -> Result<Vec<u8>, i32> {
        if maximum == 0 {
            return Ok(Vec::new());
        }
        let (id, side) = self.endpoint(object_id)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        if side == PtySide::Slave {
            return terminal.read_input(maximum);
        }
        if (terminal.output_stopped || terminal.output_manually_stopped) && terminal.slave_open {
            return Err(EAGAIN);
        }
        let length = maximum.min(terminal.output.len());
        if length != 0 {
            let bytes = terminal.output.drain(..length).collect();
            terminal.refill_edit_echo();
            return Ok(bytes);
        }
        if terminal.slave_open {
            Err(EAGAIN)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn write(&mut self, object_id: u64, bytes: &[u8]) -> Result<usize, i32> {
        let (id, side) = self.endpoint(object_id)?;
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
        let (id, _) = self.endpoint(object_id)?;
        self.terminals.contains_key(&id).then_some(0).ok_or(EBADF)?;
        Err(ESPIPE)
    }

    pub fn attributes(&self, object_id: u64) -> Result<posix_protocol::TerminalAttributes, i32> {
        let (id, _) = self.endpoint(object_id)?;
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
        let (id, _) = self.endpoint(object_id)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        let was_canonical =
            terminal.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ICANON != 0;
        let is_canonical = attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ICANON != 0;
        terminal.attributes = attributes;
        if !is_canonical || attributes.local_flags & posix_protocol::TERMINAL_LFLAG_IEXTEN == 0 {
            terminal.literal_next = false;
        }
        if attributes.input_flags & posix_protocol::TERMINAL_IFLAG_IXON == 0 {
            terminal.output_stopped = false;
        }
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
        let (id, _) = self.endpoint(object_id)?;
        {
            let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
            if !terminal.output.is_empty() && terminal.master_open {
                return Err(EAGAIN);
            }
            if !terminal.master_open {
                terminal.output.clear();
                terminal.edit_echo.clear();
            }
            if flush_input {
                terminal.input.clear();
                terminal.input_records.clear();
                terminal.canonical_input.clear();
                terminal.literal_next = false;
            }
        }
        self.set_attributes(object_id, attributes)
    }

    fn drain_output(&mut self, object_id: u64) -> Result<(), i32> {
        let (id, _) = self.endpoint(object_id)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        if !terminal.output.is_empty() && terminal.master_open {
            return Err(EAGAIN);
        }
        if !terminal.master_open {
            terminal.output.clear();
            terminal.edit_echo.clear();
        }
        Ok(())
    }

    fn flush_queues(&mut self, object_id: u64, flags: u32) -> Result<(), i32> {
        let (id, _) = self.endpoint(object_id)?;
        let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
        if flags & posix_protocol::TERMINAL_FLUSH_INPUT != 0 {
            terminal.input.clear();
            terminal.input_records.clear();
            terminal.canonical_input.clear();
            terminal.literal_next = false;
        }
        if flags & posix_protocol::TERMINAL_FLUSH_OUTPUT != 0 {
            terminal.output.clear();
            terminal.edit_echo.clear();
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
            posix_protocol::PTY_CONTROL_FLOW => {
                if output_capacity != 0 {
                    return Err(EINVAL);
                }
                let action = posix_protocol::decode_terminal_flow(input).map_err(|_| EINVAL)?;
                let (id, _) = self.endpoint(object_id)?;
                let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
                match action {
                    posix_protocol::TERMINAL_FLOW_OUTPUT_STOP => {
                        terminal.output_manually_stopped = true;
                    }
                    posix_protocol::TERMINAL_FLOW_OUTPUT_START => {
                        terminal.output_manually_stopped = false;
                        terminal.output_stopped = false;
                    }
                    posix_protocol::TERMINAL_FLOW_INPUT_STOP
                    | posix_protocol::TERMINAL_FLOW_INPUT_START => {
                        let index = if action == posix_protocol::TERMINAL_FLOW_INPUT_STOP {
                            posix_protocol::TERMINAL_CC_VSTOP
                        } else {
                            posix_protocol::TERMINAL_CC_VSTART
                        };
                        let byte = terminal.attributes.control_characters[index];
                        if byte != 0 {
                            if !terminal.master_open {
                                return Err(EIO);
                            }
                            if terminal.output.len() == BUFFER_CAPACITY {
                                return Err(EAGAIN);
                            }
                            // Transmit the configured control byte verbatim,
                            // without the terminal's output transformations.
                            terminal.output.push_back(byte);
                        }
                    }
                    _ => unreachable!("flow decoder validates actions"),
                }
                Ok(Vec::new())
            }
            posix_protocol::PTY_CONTROL_GET_WINDOW_SIZE => {
                if !input.is_empty()
                    || output_capacity < posix_protocol::TERMINAL_WINDOW_SIZE_LEN
                {
                    return Err(EINVAL);
                }
                let (id, _) = self.endpoint(object_id)?;
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
                let (id, _) = self.endpoint(object_id)?;
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
        if let Some(id) = self.slave_factories.remove(&object_id) {
            if self
                .terminals
                .get(&id)
                .is_some_and(|terminal| !terminal.master_open && !terminal.slave_open)
                && !self.slave_factories.values().any(|terminal| *terminal == id)
            {
                self.terminals.remove(&id);
            }
            return Ok(());
        }
        let (id, side) = self.endpoint(object_id)?;
        self.objects.remove(&object_id);
        self.metadata.remove(&object_id);
        let remove = {
            let terminal = self.terminals.get_mut(&id).ok_or(EBADF)?;
            terminal.live_objects.remove(&object_id);
            match side {
                PtySide::Master if terminal.master_open => {
                    terminal.master_open = false;
                    self.pending_signals.push_back(TerminalSignal {
                        terminal_id: id,
                        signal: posix_protocol::SIGNAL_HUP,
                    });
                }
                PtySide::Slave if terminal.slave_open => {
                    if terminal.live_objects.len() == usize::from(terminal.master_open) {
                        terminal.slave_open = false;
                        terminal.output_stopped = false;
                        terminal.output_manually_stopped = false;
                    }
                }
                _ => return Err(EBADF),
            }
            !terminal.master_open
                && !terminal.slave_open
                && !self.slave_factories.values().any(|terminal| *terminal == id)
        };
        if remove {
            self.terminals.remove(&id);
        }
        Ok(())
    }

    pub fn discard(&mut self, pair: PtyPair) {
        // A native provider's final release can arrive before failed-launch
        // cleanup. Match the exact owned pair even if its master is retired.
        let id = self.terminals.iter().find_map(|(id, terminal)| {
            (terminal.pair == pair).then_some(*id)
        });
        if let Some(id) = id {
            if let Some(terminal) = self.terminals.get(&id) {
                for object_id in &terminal.live_objects {
                    self.metadata.remove(object_id);
                }
            }
            self.terminals.remove(&id);
            self.objects.retain(|_, (terminal, _)| *terminal != id);
            self.slave_factories.retain(|_, terminal| *terminal != id);
            self.pending_signals.retain(|signal| signal.terminal_id != id);
        }
    }

    pub fn object_ids(&self, object_id: u64) -> Result<[u64; 2], i32> {
        let (id, _) = self.endpoint(object_id)?;
        let pair = self.terminals.get(&id).ok_or(EBADF)?.pair;
        Ok([pair.master_object_id, pair.slave_object_id])
    }

    pub fn slave_terminal_id(&self, object_id: u64) -> Result<u64, i32> {
        let (id, side) = self.endpoint(object_id)?;
        if side != PtySide::Slave || !self.terminals.contains_key(&id) {
            return Err(EBADF);
        }
        Ok(id)
    }

    /// The master is the terminal controller, not a job's terminal endpoint.
    /// Zero-length data operations do not consume or produce terminal data.
    /// Setting terminal parameters requires SIGTTOU policy even without TOSTOP;
    /// a control request's length is output capacity, not its input size.
    pub fn job_control_access(&self, header: provider::RequestHeader) -> Option<(u64, bool, bool)> {
        let terminal_id = self.slave_terminal_id(header.object_id).ok()?;
        if header.opcode == provider::OP_CONTROL
            && matches!(
                header.basis,
                posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_NOW
                    | posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_DRAIN
                    | posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_FLUSH
                    | posix_protocol::PTY_CONTROL_DRAIN
                    | posix_protocol::PTY_CONTROL_FLUSH
                    | posix_protocol::PTY_CONTROL_FLOW
            )
        {
            return Some((terminal_id, false, true));
        }
        if header.length == 0 || !matches!(header.opcode, provider::OP_READ | provider::OP_WRITE) {
            return None;
        }
        let attributes = self.attributes(header.object_id).ok()?;
        Some((
            terminal_id,
            header.opcode == provider::OP_READ,
            attributes.local_flags & posix_protocol::TERMINAL_LFLAG_TOSTOP != 0,
        ))
    }

    pub fn signals(&self, object_id: u64) -> Result<u64, i32> {
        let (id, side) = self.endpoint(object_id)?;
        let terminal = self.terminals.get(&id).ok_or(EBADF)?;
        let (readable, writable, peer_closed) = match side {
            PtySide::Master => (
                ((!terminal.output_stopped && !terminal.output_manually_stopped)
                    || !terminal.slave_open)
                    && !terminal.output.is_empty(),
                terminal.slave_open
                    && terminal.has_input_capacity()
                    && (terminal.attributes.local_flags
                        & (posix_protocol::TERMINAL_LFLAG_ECHO
                            | posix_protocol::TERMINAL_LFLAG_ECHONL)
                        == 0
                        || terminal.output.len() < BUFFER_CAPACITY),
                !terminal.slave_open,
            ),
            PtySide::Slave => (
                !terminal.input_records.is_empty(),
                terminal.master_open
                    && terminal.edit_echo.is_empty()
                    && terminal.output.len() < BUFFER_CAPACITY,
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

    /// Only explicitly read-only selectors are reachable through OP_QUERY.
    pub fn query(
        &self,
        object_id: u64,
        code: u64,
        input: &[u8],
        capacity: usize,
    ) -> Result<Vec<u8>, i32> {
        if code != posix_protocol::PTY_QUERY_READ_SETTINGS {
            return Err(ENOTSUP);
        }
        if !input.is_empty() || capacity < posix_protocol::TERMINAL_READ_SETTINGS_LEN {
            return Err(EINVAL);
        }
        let (id, side) = self.endpoint(object_id)?;
        let terminal = self.terminals.get(&id).ok_or(EBADF)?;
        let noncanonical = side == PtySide::Slave
            && terminal.attributes.local_flags & posix_protocol::TERMINAL_LFLAG_ICANON == 0;
        let settings = posix_protocol::TerminalReadSettings {
            noncanonical,
            minimum: if noncanonical {
                terminal.attributes.control_characters[posix_protocol::TERMINAL_CC_VMIN]
            } else {
                0
            },
            deciseconds: if noncanonical {
                terminal.attributes.control_characters[posix_protocol::TERMINAL_CC_VTIME]
            } else {
                0
            },
        };
        let mut output = vec![0; posix_protocol::TERMINAL_READ_SETTINGS_LEN];
        posix_protocol::encode_terminal_read_settings(settings, &mut output).map_err(|_| EIO)?;
        Ok(output)
    }

    fn allocate_object_id(&mut self) -> Option<u64> {
        const MAX_ID: u64 = i64::MAX as u64;
        for _ in 0..self
            .objects
            .len()
            .saturating_add(self.slave_factories.len())
            .saturating_add(1)
        {
            let id = self.next_object_id.clamp(2, MAX_ID);
            self.next_object_id = if id == MAX_ID { 2 } else { id + 1 };
            if !self.objects.contains_key(&id) && !self.slave_factories.contains_key(&id) {
                return Some(id);
            }
        }
        None
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
        provider::OP_QUERY => ptys
            .query(header.object_id, header.basis, payload, header.length as usize)
            .map(|data| (data.len() as u64, data)),
        provider::OP_MEMORY_OBJECT => ptys
            .object_ids(header.object_id)
            .map(|_| (0, Vec::new())),
        // The generic decoder also accepts optional file/pager operations.
        // A terminal is a byte stream, not a file-backed memory object.
        _ => Err(ENOTSUP),
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
