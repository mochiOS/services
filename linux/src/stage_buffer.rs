use super::{HostError, platform};
use platform::memory_object::{MemoryMapping, MemoryObject};

pub(super) struct SharedStageBuffer {
    _mapping: MemoryMapping,
    _object: MemoryObject,
    pub(super) address: u64,
    pub(super) capacity: usize,
}

impl SharedStageBuffer {
    pub(super) fn new(endpoint: u64, length: usize) -> Result<Self, HostError> {
        let capacity = length
            .checked_add(4095)
            .map(|value| value & !4095)
            .filter(|value| *value != 0)
            .ok_or(HostError::Unavailable)?;
        let object = MemoryObject::create(capacity as u64).map_err(|_| HostError::Unavailable)?;
        let mapping = object
            .map(
                0,
                capacity as u64,
                platform::syscall::MEMORY_ACCESS_READ | platform::syscall::MEMORY_ACCESS_WRITE,
            )
            .map_err(|_| HostError::Unavailable)?;
        object
            .send_readonly(endpoint, 0, capacity as u64)
            .map_err(|_| HostError::Unavailable)?;
        Ok(Self {
            address: mapping.address(),
            capacity,
            _mapping: mapping,
            _object: object,
        })
    }
}
