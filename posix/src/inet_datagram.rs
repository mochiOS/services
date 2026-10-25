//! Shared IPv4 datagram description policy. One instance belongs to a Provider
//! object, never to a process-local FD. Backend authority is explicit and owned.
use mochios_posix_protocol::socket::{self as wire, Address, Domain, Kind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: [u8; 4],
    pub port: u16,
}
impl Endpoint {
    pub const UNSPECIFIED: Self = Self {
        address: [0; 4],
        port: 0,
    };
    fn from_address(address: Address<'_>) -> Result<Self, i32> {
        match address {
            Address::Ipv4 { address, port } => Ok(Self { address, port }),
            _ => Err(-97),
        }
    }
    pub fn as_address(self) -> Address<'static> {
        Address::Ipv4 {
            address: self.address,
            port: self.port,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received {
    pub source: Endpoint,
    pub copied: usize,
    pub original: usize,
}

/// A backend owns the factory authority used by open. Handles are private to
/// the socket worker; no client may nominate an integer as resource authority.
pub trait Backend {
    type Handle: Copy;
    fn open(&mut self, local: Endpoint) -> Result<Self::Handle, i32>;
    fn close(&mut self, handle: Self::Handle);
    fn local(&mut self, handle: Self::Handle) -> Result<Endpoint, i32>;
    fn source(&mut self, handle: Self::Handle, destination: Endpoint) -> Result<Endpoint, i32>;
    fn set_peer(&mut self, handle: Self::Handle, peer: Option<Endpoint>) -> Result<(), i32>;
    fn send(
        &mut self,
        handle: Self::Handle,
        destination: Endpoint,
        payload: &[u8],
    ) -> Result<(), i32>;
    fn receive(
        &mut self,
        handle: Self::Handle,
        peek: bool,
        output: &mut [u8],
    ) -> Result<Received, i32>;
    fn signals(&mut self, _handle: Self::Handle) -> Result<u64, i32> {
        Err(-95)
    }
    fn maximum_payload(&self) -> usize;
}

pub struct Datagram<B: Backend> {
    backend: B,
    binding: Option<B::Handle>,
    peer: Option<Endpoint>,
    options: u32,
    receive_timeout: u64,
    send_timeout: u64,
}
impl<B: Backend> Datagram<B> {
    /// Factory acquisition/transfer must happen at the authenticated caller
    /// boundary. Creating the description does not reserve a UDP port.
    pub fn new(backend: B, request: wire::Create) -> Result<Self, i32> {
        if request.domain != Domain::Ipv4 {
            return Err(-97);
        }
        if request.kind != Kind::Datagram {
            return Err(-94);
        }
        if !matches!(request.protocol, 0 | 17) {
            return Err(-93);
        }
        if request.options & !wire::NONBLOCKING != 0 {
            return Err(-22);
        }
        Ok(Self {
            backend,
            binding: None,
            peer: None,
            options: request.options,
            receive_timeout: 0,
            send_timeout: 0,
        })
    }
    pub fn maximum_payload(&self) -> usize {
        self.backend.maximum_payload()
    }
    pub fn binding_handle(&self) -> Option<B::Handle> {
        self.binding
    }
    pub fn signals(&mut self) -> Result<u64, i32> {
        match self.binding {
            Some(handle) => self.backend.signals(handle),
            None => Ok(mnu_abi::HANDLE_SIGNAL_WRITABLE),
        }
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
    pub fn set_receive_timeout(&mut self, duration: u64) {
        self.receive_timeout = duration;
    }
    pub fn set_send_timeout(&mut self, duration: u64) {
        self.send_timeout = duration;
    }
    pub fn bind(&mut self, address: Address<'_>) -> Result<(), i32> {
        if self.binding.is_some() {
            return Err(-22);
        }
        let local = Endpoint::from_address(address)?;
        self.open_binding(local).map(|_| ())
    }
    fn open_binding(&mut self, local: Endpoint) -> Result<B::Handle, i32> {
        let handle = self.backend.open(local)?;
        // Validate the reply before publishing description state. Failed
        // publication closes the provisional resource, allowing a later retry.
        match self.backend.local(handle) {
            Ok(actual)
                if actual.port != 0
                    && actual.address == local.address
                    && (local.port == 0 || actual.port == local.port) =>
            {
                self.binding = Some(handle);
                Ok(handle)
            }
            result => {
                self.backend.close(handle);
                Err(result.err().unwrap_or(-5))
            }
        }
    }
    fn autobind(&mut self) -> Result<B::Handle, i32> {
        match self.binding {
            Some(handle) => Ok(handle),
            None => self.open_binding(Endpoint::UNSPECIFIED),
        }
    }
    pub fn local_address(&mut self) -> Result<Endpoint, i32> {
        let Some(handle) = self.binding else {
            return Ok(Endpoint::UNSPECIFIED);
        };
        let local = self.backend.local(handle)?;
        if local.address == [0; 4] {
            if let Some(peer) = self.peer {
                return self.routed_source(handle, local, peer);
            }
        }
        Ok(local)
    }
    fn routed_source(
        &mut self,
        handle: B::Handle,
        local: Endpoint,
        peer: Endpoint,
    ) -> Result<Endpoint, i32> {
        let source = self.backend.source(handle, peer)?;
        if source.address == [0; 4]
            || source.port == 0
            || source.port != local.port
            || (local.address != [0; 4] && source.address != local.address)
        {
            return Err(-5);
        }
        Ok(source)
    }
    pub fn peer_address(&self) -> Result<Endpoint, i32> {
        self.peer.ok_or(-107)
    }
    pub fn connect(&mut self, address: Address<'_>) -> Result<(), i32> {
        let peer = Self::destination(Endpoint::from_address(address)?)?;
        let handle = self.autobind()?;
        let local = self.backend.local(handle)?;
        self.routed_source(handle, local, peer)?;
        self.backend.set_peer(handle, Some(peer))?;
        self.peer = Some(peer);
        Ok(())
    }
    pub fn disconnect(&mut self) -> Result<(), i32> {
        if let Some(handle) = self.binding {
            self.backend.set_peer(handle, None)?;
        }
        self.peer = None;
        Ok(())
    }
    fn destination(mut endpoint: Endpoint) -> Result<Endpoint, i32> {
        if endpoint.port == 0 {
            return Err(-22);
        }
        // IPv4 unspecified as a remote destination denotes this host. This
        // normalization belongs to the POSIX adapter, not the packet backend.
        if endpoint.address == [0; 4] {
            endpoint.address = [127, 0, 0, 1];
        }
        Ok(endpoint)
    }
    pub fn send_to(&mut self, address: Option<Address<'_>>, payload: &[u8]) -> Result<usize, i32> {
        if payload.len() > self.backend.maximum_payload() {
            return Err(-90);
        }
        let destination = match address {
            Some(address) => Self::destination(Endpoint::from_address(address)?)?,
            None => self.peer.ok_or(-89)?,
        };
        let handle = self.autobind()?;
        self.backend.send(handle, destination, payload)?;
        Ok(payload.len())
    }
    /// Blocking/retry/timeout policy stays at the client boundary. This single
    /// operation returns EAGAIN rather than holding the Provider dispatch loop.
    pub fn receive_from(&mut self, peek: bool, output: &mut [u8]) -> Result<Received, i32> {
        let handle = self.autobind()?;
        let received = self.backend.receive(handle, peek, output)?;
        if received.copied > output.len()
            || received.copied > received.original
            || received.original > self.backend.maximum_payload()
        {
            return Err(-5);
        }
        Ok(received)
    }
}
impl<B: Backend> Drop for Datagram<B> {
    fn drop(&mut self) {
        if let Some(handle) = self.binding.take() {
            self.backend.close(handle);
        }
    }
}
