use super::{CompositorError, PAGE_SIZE, platform};
use platform::memory_object::{MemoryMapping, MemoryObject};

pub(super) struct SharedBuffer {
    mapping: MemoryMapping,
    object: MemoryObject,
    byte_capacity: usize,
    pub(super) width: u16,
    pub(super) height: u16,
    offered_endpoint: Option<u64>,
}

impl SharedBuffer {
    pub(super) fn allocate(width: u16, height: u16) -> Result<Self, CompositorError> {
        let bytes = usize::from(width)
            .checked_mul(usize::from(height))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(CompositorError::InvalidSize)?;
        let byte_capacity = bytes
            .checked_add(PAGE_SIZE - 1)
            .map(|rounded| rounded & !(PAGE_SIZE - 1))
            .filter(|capacity| *capacity != 0)
            .ok_or(CompositorError::InvalidSize)?;
        let object =
            MemoryObject::create(byte_capacity as u64).map_err(|_| CompositorError::Unavailable)?;
        let mapping = object
            .map(
                0,
                byte_capacity as u64,
                platform::syscall::MEMORY_ACCESS_READ | platform::syscall::MEMORY_ACCESS_WRITE,
            )
            .map_err(|_| CompositorError::Unavailable)?;
        Ok(Self {
            mapping,
            object,
            byte_capacity,
            width,
            height,
            offered_endpoint: None,
        })
    }

    pub(super) fn copy_from(&mut self, frame: &[u8]) -> Result<(), CompositorError> {
        if frame.len() > self.byte_capacity {
            return Err(CompositorError::InvalidSize);
        }
        // The receiver aliases this storage. Never create an exclusive Rust
        // slice over shared bytes; the frame source is separately owned.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), self.mapping.as_mut_ptr(), frame.len());
        }
        Ok(())
    }

    pub(super) fn send_to(&mut self, compositor: u64) -> Result<(), CompositorError> {
        if self.offered_endpoint != Some(compositor) {
            self.object
                .send_readonly(compositor, 0, self.byte_capacity as u64)
                .map_err(|_| CompositorError::Unavailable)?;
            self.offered_endpoint = Some(compositor);
        }
        Ok(())
    }
}
