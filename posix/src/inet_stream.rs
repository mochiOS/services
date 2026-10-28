//! Shared POSIX TCP description state. One instance belongs to a Provider,
//! independent of process-local descriptor numbers and CLOEXEC flags.
use crate::inet_datagram::Endpoint;
use mochios_posix_protocol::socket::{self as wire, Address, Domain, Kind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub readable: bool,
    pub writable: bool,
    pub peer_closed: bool,
    pub connecting: bool,
    pub error: i32,
}

/// The implementation owns its explicitly delegated factory. Each opened or
/// accepted handle has one owner here; accepted backends need no new factory.
pub trait Backend: Sized {
    type Handle: Copy;
    fn open(&mut self) -> Result<Self::Handle, i32>;
    fn close(&mut self, handle: Self::Handle);
    fn local(&mut self, handle: Self::Handle) -> Result<Endpoint, i32>;
    fn peer(&mut self, handle: Self::Handle) -> Result<Endpoint, i32>;
    fn bind(&mut self, handle: Self::Handle, local: Endpoint) -> Result<(), i32>;
    fn connect(&mut self, handle: Self::Handle, peer: Endpoint) -> Result<(), i32>;
    fn listen(&mut self, handle: Self::Handle, backlog: usize) -> Result<(), i32>;
    fn accept(&mut self, handle: Self::Handle) -> Result<(Self, Self::Handle), i32>;
    fn observe(&mut self, handle: Self::Handle) -> Result<Observation, i32>;
    fn take_error(&mut self, handle: Self::Handle) -> Result<i32, i32>;
    fn send(&mut self, handle: Self::Handle, bytes: &[u8]) -> Result<usize, i32>;
    fn receive(&mut self, handle: Self::Handle, peek: bool, bytes: &mut [u8])
    -> Result<usize, i32>;
    fn shutdown(&mut self, handle: Self::Handle, read: bool, write: bool) -> Result<(), i32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectProgress {
    Pending,
    Connected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Fresh,
    Bound,
    Connecting,
    Connected,
    Listening,
    Failed,
}

pub struct Stream<B: Backend> {
    backend: B,
    handle: B::Handle,
    phase: Phase,
    peer: Option<Endpoint>,
    options: u32,
    receive_timeout: u64,
    send_timeout: u64,
    read_shutdown: bool,
    write_shutdown: bool,
    read_eof: bool,
    failure: Option<i32>,
    pending_error: i32,
    attempt: u64,
}
fn endpoint(address: Address<'_>) -> Result<Endpoint, i32> {
    match address {
        Address::Ipv4 { address, port } => Ok(Endpoint { address, port }),
        _ => Err(-97),
    }
}
fn valid_peer(peer: Endpoint) -> bool {
    peer.address != [0; 4] && peer.port != 0
}

impl<B: Backend> Stream<B> {
    pub fn new(mut backend: B, create: wire::Create) -> Result<Self, i32> {
        if create.domain != Domain::Ipv4 {
            return Err(-97);
        }
        if create.kind != Kind::Stream {
            return Err(-94);
        }
        if !matches!(create.protocol, 0 | 6) {
            return Err(-93);
        }
        if create.options & !wire::NONBLOCKING != 0 {
            return Err(-22);
        }
        let handle = backend.open()?;
        match backend.local(handle) {
            Ok(Endpoint {
                address: [0, 0, 0, 0],
                port: 0,
            }) => {}
            result => {
                backend.close(handle);
                return Err(result.err().unwrap_or(-5));
            }
        }
        Ok(Self::from_opened(
            backend,
            handle,
            create.options,
            Phase::Fresh,
        ))
    }
    fn from_opened(backend: B, handle: B::Handle, options: u32, phase: Phase) -> Self {
        Self {
            backend,
            handle,
            phase,
            peer: None,
            options,
            receive_timeout: 0,
            send_timeout: 0,
            read_shutdown: false,
            write_shutdown: false,
            read_eof: false,
            failure: None,
            pending_error: 0,
            attempt: 0,
        }
    }
    /// Borrowed transport reference, for readiness observation only. Drop is
    /// responsible for its one owned close, including construction rollback.
    pub fn binding_handle(&self) -> B::Handle {
        self.handle
    }
    pub fn options(&self) -> u32 {
        self.options
    }
    pub fn set_options(&mut self, options: u32) -> Result<(), i32> {
        if options & !wire::NONBLOCKING != 0 {
            return Err(-22);
        }
        self.options = options;
        Ok(())
    }
    pub fn receive_timeout(&self) -> u64 {
        self.receive_timeout
    }
    pub fn send_timeout(&self) -> u64 {
        self.send_timeout
    }
    pub fn set_receive_timeout(&mut self, value: u64) {
        self.receive_timeout = value;
    }
    pub fn set_send_timeout(&mut self, value: u64) {
        self.send_timeout = value;
    }
    pub fn accepting(&self) -> bool {
        self.phase == Phase::Listening
    }
    pub fn bind(&mut self, address: Address<'_>) -> Result<(), i32> {
        if self.phase != Phase::Fresh {
            return Err(-22);
        }
        let requested = endpoint(address)?;
        self.backend.bind(self.handle, requested)?;
        self.phase = Phase::Bound;
        let actual = self.backend.local(self.handle)?;
        if actual.port == 0
            || actual.address != requested.address
            || requested.port != 0 && actual.port != requested.port
        {
            return Err(-5);
        }
        Ok(())
    }
    pub fn local_address(&mut self) -> Result<Endpoint, i32> {
        self.backend.local(self.handle)
    }
    pub fn peer_address(&mut self) -> Result<Endpoint, i32> {
        self.refresh()?;
        if self.phase != Phase::Connected {
            return Err(-107);
        }
        let actual = self.backend.peer(self.handle)?;
        if Some(actual) != self.peer || !valid_peer(actual) {
            return Err(-5);
        }
        Ok(actual)
    }
    pub fn listen(&mut self, backlog: usize) -> Result<(), i32> {
        if !matches!(self.phase, Phase::Fresh | Phase::Bound | Phase::Listening) {
            return Err(-22);
        }
        self.backend.listen(self.handle, backlog.max(1))?;
        self.phase = Phase::Listening;
        if self.backend.local(self.handle)?.port == 0 {
            return Err(-5);
        }
        Ok(())
    }
    pub fn accept(&mut self, request: wire::Accept) -> Result<Self, i32> {
        if self.phase != Phase::Listening {
            return Err(-22);
        }
        if request.options & !wire::NONBLOCKING != 0 {
            return Err(-22);
        }
        let (backend, handle) = self.backend.accept(self.handle)?;
        // Construct an owner before validating lower replies; every failure
        // drops the provisional connection without altering the listener.
        let mut accepted = Self::from_opened(backend, handle, request.options, Phase::Connected);
        let peer = accepted.backend.peer(handle)?;
        if !valid_peer(peer) || !valid_peer(accepted.backend.local(handle)?) {
            return Err(-5);
        }
        accepted.peer = Some(peer);
        accepted.receive_timeout = self.receive_timeout;
        accepted.send_timeout = self.send_timeout;
        accepted.refresh()?;
        Ok(accepted)
    }
    pub fn connect(&mut self, address: Address<'_>) -> Result<ConnectProgress, i32> {
        self.refresh()?;
        match self.phase {
            Phase::Connecting => return Err(-114),
            Phase::Connected => return Err(-106),
            Phase::Listening => return Err(-95),
            Phase::Failed => return Err(-103),
            _ => {}
        }
        let peer = endpoint(address)?;
        if !valid_peer(peer) {
            return Err(-22);
        }
        let attempt = self.attempt.checked_add(1).ok_or(-75)?;
        self.backend.connect(self.handle, peer)?;
        self.peer = Some(peer);
        self.attempt = attempt;
        self.phase = Phase::Connecting;
        self.connect_result(attempt)
    }
    /// A retained attempt tag prevents a later operation on this description
    /// from being mistaken for this result. Tags are not authority: the caller
    /// must already hold the description's native reference.
    pub fn attempt(&self) -> u64 {
        self.attempt
    }
    pub fn connect_result(&mut self, attempt: u64) -> Result<ConnectProgress, i32> {
        if attempt == 0 || attempt != self.attempt {
            return Err(-9);
        }
        self.refresh()?;
        match self.phase {
            Phase::Connected => Ok(ConnectProgress::Connected),
            Phase::Connecting => Ok(ConnectProgress::Pending),
            Phase::Failed => Err(self.failure.unwrap_or(-103)),
            _ => Err(-107),
        }
    }
    fn fail(&mut self, error: i32) {
        if self.failure.is_none() {
            self.failure = Some(error);
            self.pending_error = error;
            self.phase = Phase::Failed;
        }
    }
    fn refresh(&mut self) -> Result<Observation, i32> {
        let observation = self.backend.observe(self.handle)?;
        if observation.error > 0 || observation.error < -4095 {
            self.fail(-5);
            return Err(-5);
        }
        if observation.error != 0 {
            // Retain the failure before consuming the lower notification. A
            // malformed/failed take must never turn a refused connect into a
            // successful one when the next observation has no pending error.
            self.fail(observation.error);
            let error = self.backend.take_error(self.handle)?;
            if error != observation.error {
                self.failure = Some(-5);
                self.pending_error = -5;
                return Err(-5);
            }
        }
        if self.phase == Phase::Connecting && !observation.connecting && self.failure.is_none() {
            if !observation.writable {
                self.fail(-5);
                return Err(-5);
            }
            let actual = self.backend.peer(self.handle)?;
            if Some(actual) != self.peer
                || !valid_peer(actual)
                || !valid_peer(self.backend.local(self.handle)?)
            {
                self.fail(-5);
                return Err(-5);
            }
            self.phase = Phase::Connected;
        }
        if self.phase == Phase::Connected && observation.connecting {
            self.fail(-5);
            return Err(-5);
        }
        if self.phase == Phase::Connected {
            self.read_eof |= observation.peer_closed;
        }
        Ok(observation)
    }
    /// SO_ERROR is one shared, consuming observation. Connection completion
    /// retains a separate result for an already-started blocking operation.
    pub fn take_error(&mut self) -> Result<u32, i32> {
        self.refresh()?;
        Ok(core::mem::take(&mut self.pending_error).unsigned_abs())
    }
    pub fn readiness(&mut self) -> Result<u32, i32> {
        let observation = self.refresh()?;
        if self.phase == Phase::Listening {
            return Ok(if observation.readable {
                wire::READY_READ
            } else {
                0
            });
        }
        if self.phase == Phase::Connecting {
            return Ok(0);
        }
        if matches!(self.phase, Phase::Fresh | Phase::Bound) {
            return Ok(wire::READY_READ
                | wire::READY_WRITE
                | wire::READ_CLOSED
                | wire::WRITE_CLOSED);
        }
        let failed = self.failure.is_some();
        let read_closed = self.read_shutdown || self.read_eof || failed;
        let write_closed = self.write_shutdown || failed;
        Ok(if observation.readable || read_closed {
            wire::READY_READ
        } else {
            0
        } | if !self.write_shutdown && observation.writable || failed {
            wire::READY_WRITE
        } else {
            0
        } | if read_closed { wire::READ_CLOSED } else { 0 }
            | if write_closed { wire::WRITE_CLOSED } else { 0 }
            | if failed { wire::WRITE_ERROR } else { 0 }
            | if self.pending_error != 0 {
                wire::ERROR_PENDING
            } else {
                0
            })
    }
    pub fn send(&mut self, bytes: &[u8]) -> Result<usize, i32> {
        self.refresh()?;
        if self.pending_error != 0 {
            return Err(core::mem::take(&mut self.pending_error));
        }
        if self.write_shutdown || self.failure.is_some() {
            return Err(-32);
        }
        if self.phase == Phase::Connecting {
            return Err(-11);
        }
        if self.phase != Phase::Connected {
            return Err(-107);
        }
        match self.backend.send(self.handle, bytes) {
            Ok(n) if n <= bytes.len() => Ok(n),
            Ok(_) => Err(-5),
            Err(e @ (-104 | -110 | -111)) => {
                self.fail(e);
                Err(core::mem::take(&mut self.pending_error))
            }
            Err(e) => Err(e),
        }
    }
    pub fn receive(&mut self, peek: bool, bytes: &mut [u8]) -> Result<usize, i32> {
        self.refresh()?;
        if self.pending_error != 0 {
            return Err(core::mem::take(&mut self.pending_error));
        }
        if self.read_shutdown || self.failure.is_some() {
            return Ok(0);
        }
        if self.phase == Phase::Connecting {
            return Err(-11);
        }
        if self.phase != Phase::Connected {
            return Err(-107);
        }
        match self.backend.receive(self.handle, peek, bytes) {
            Ok(n) if n <= bytes.len() => {
                if n == 0 && !bytes.is_empty() {
                    self.read_eof = true;
                }
                Ok(n)
            }
            Ok(_) => Err(-5),
            Err(e @ (-104 | -110 | -111)) => {
                self.fail(e);
                Err(core::mem::take(&mut self.pending_error))
            }
            Err(e) => Err(e),
        }
    }
    pub fn shutdown(&mut self, how: u32) -> Result<(), i32> {
        let (read, write) = match how {
            wire::SHUTDOWN_READ => (true, false),
            wire::SHUTDOWN_WRITE => (false, true),
            wire::SHUTDOWN_BOTH => (true, true),
            _ => return Err(-22),
        };
        self.refresh()?;
        if self.phase != Phase::Connected {
            return Err(-107);
        }
        self.backend.shutdown(self.handle, read, write)?;
        self.read_shutdown |= read;
        self.write_shutdown |= write;
        Ok(())
    }
}
impl<B: Backend> Drop for Stream<B> {
    fn drop(&mut self) {
        self.backend.close(self.handle);
    }
}
