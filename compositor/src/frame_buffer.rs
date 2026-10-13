use crate::platform;
use platform::memory_object::{MemoryMapping, MemoryObject};
use platform::syscall::{SysError, SysResult};

/// Fixed backing: display receives READ|MAP, never a sender virtual address.
/// A replacement is constructed completely before the old mapping is dropped.
pub(crate) struct FrameBuffer {
    mapping: MemoryMapping,
    object: MemoryObject,
    offered_endpoint: Option<u64>,
}

impl FrameBuffer {
    pub(crate) fn new(capacity: u64) -> SysResult<Self> {
        let object = MemoryObject::create(capacity)?;
        let mapping = object.map(
            0,
            capacity,
            platform::syscall::MEMORY_ACCESS_READ | platform::syscall::MEMORY_ACCESS_WRITE,
        )?;
        Ok(Self {
            mapping,
            object,
            offered_endpoint: None,
        })
    }

    pub(crate) fn address(&self) -> u64 {
        self.mapping.address()
    }

    pub(crate) fn capacity(&self) -> u64 {
        self.mapping.capacity()
    }

    pub(crate) fn invalidate_offer(&mut self) {
        self.offered_endpoint = None;
    }

    pub(crate) fn offer(&mut self, endpoint: u64) -> SysResult<()> {
        if endpoint == 0 {
            return Err(SysError::from_raw(platform::syscall::EINVAL as i64));
        }
        if self.offered_endpoint != Some(endpoint) {
            self.object.send_readonly(endpoint, 0, self.capacity())?;
            self.offered_endpoint = Some(endpoint);
        }
        Ok(())
    }
}
