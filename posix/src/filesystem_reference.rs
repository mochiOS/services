//! Owned filesystem metadata references for userspace data providers.
//! Neither this reference nor its lookup proxies data operations.
const EACCES: i32 = 13;
const EIO: i32 = 5;
use mnu_abi::{HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_TRANSFER};

/// An owned reference. Dropping the backend releases its local native Handle.
/// Duplication and destruction must use native local Handle operations, not
/// synchronous peer RPC: they can execute under a provider manager lock.
pub trait Backend: std::fmt::Debug + Send {
    fn duplicate(&self, rights: u64) -> Result<u32, i32>;
}

#[derive(Debug)]
pub struct Reference {
    backend: Box<dyn Backend>,
    rights: u64,
}

impl Reference {
    /// Consume one receiver-local IPC attachment. The caller must already have
    /// validated delivery provenance/count and must not close this reference
    /// again, including when this constructor fails.
    pub fn from_received(object: mnu_abi::IpcObjectHandle) -> Result<Self, i32> {
        let backend = Box::new(NativeBackend {
            handle: object.handle,
        });
        if object.handle == 0 || object.reserved != 0 {
            return Err(EACCES);
        }
        Self::new(backend, object.rights)
    }

    /// Takes ownership even on rejection. No data or endpoint authority belongs
    /// in this slot. Native IPC admission must supply the actual received rights.
    pub fn new(backend: Box<dyn Backend>, rights: u64) -> Result<Self, i32> {
        let required = HANDLE_RIGHT_DUPLICATE | HANDLE_RIGHT_TRANSFER;
        if rights & required != required || rights & !(required | HANDLE_RIGHT_CONTROL) != 0 {
            return Err(EACCES);
        }
        Ok(Self { backend, rights })
    }

    /// Source rights are those of the explicitly attached data Handle,
    /// not the provider's original full-authority local reference. A write-only
    /// description can provide metadata; no READ right is required or manufactured.
    pub fn duplicate(&self, source_rights: u64, requested_rights: u64) -> Result<u32, i32> {
        if requested_rights & HANDLE_RIGHT_TRANSFER == 0
            || requested_rights & !(HANDLE_RIGHT_TRANSFER | HANDLE_RIGHT_CONTROL) != 0
            || requested_rights & source_rights != requested_rights
            || requested_rights & self.rights != requested_rights
        {
            return Err(EACCES);
        }
        let handle = self.backend.duplicate(requested_rights)?;
        if handle == 0 { Err(EIO) } else { Ok(handle) }
    }
}

#[derive(Debug)]
struct NativeBackend {
    handle: u32,
}
impl Backend for NativeBackend {
    fn duplicate(&self, rights: u64) -> Result<u32, i32> {
        mochi_user_platform::handle::duplicate(self.handle, rights)
            .map_err(|error| -mochios_posix_protocol::status::normalize_failure(error.raw()))
    }
}
impl Drop for NativeBackend {
    fn drop(&mut self) {
        if self.handle != 0 {
            let _ = mochi_user_platform::handle::close(self.handle);
        }
    }
}
