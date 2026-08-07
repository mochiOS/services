#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    WouldBlock,
    Disconnected,
    InvalidDevice,
    Io(u64),
}

pub trait ControlTransport {
    fn poll(&mut self) -> Result<(), TransportError>;
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError>;
    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError>;
    fn is_connected(&self) -> bool;
    fn reset_connection(&mut self);
}

#[cfg(any(target_os = "mochios", test))]
pub(crate) mod model;

#[cfg(target_os = "mochios")]
pub mod virtio;
