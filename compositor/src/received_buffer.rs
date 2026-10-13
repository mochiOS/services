use crate::platform;
use alloc::sync::Arc;
use platform::memory_object::{MemoryMapping, MemoryObject, ReadOnlyOffer, receive_readonly_offer};
use platform::syscall::{SysError, SysResult};

/// Carries ownership even while a message is deferred by input coalescing.
#[derive(Default)]
pub(crate) struct ReceivedHandles(pub(crate) platform::ipc::IpcObjectHandles);

impl Drop for ReceivedHandles {
    fn drop(&mut self) {
        for entry in &mut self.0.handles {
            if entry.handle != 0 {
                let _ = platform::handle::close(entry.handle);
                entry.handle = 0;
            }
        }
    }
}

/// Pending/current surfaces may share a view; the final reference unmaps it.
#[derive(Clone)]
pub(crate) struct ReceivedBuffer {
    mapping: Arc<MemoryMapping>,
    length: u64,
}

impl ReceivedBuffer {
    pub(crate) fn receive(
        bytes: &[u8],
        handles: &mut ReceivedHandles,
        maximum_length: u64,
    ) -> SysResult<Self> {
        if handles.0.count != 1 || handles.0.handles[0].handle == 0 {
            return Err(SysError::from_raw(platform::syscall::EINVAL as i64));
        }
        let offer = ReadOnlyOffer::decode(bytes)?;
        let raw = handles.0.handles[0].handle;
        handles.0.handles[0] = Default::default();
        handles.0.count = 0;
        // SAFETY: IPC installed this owned reference and its slot was cleared.
        let object = unsafe { MemoryObject::from_owned_handle(raw) };
        let mapping = receive_readonly_offer(bytes, object, maximum_length)?;
        Ok(Self {
            mapping: Arc::new(mapping),
            length: offer.length,
        })
    }

    pub(crate) fn view(&self) -> (u64, u64) {
        (self.mapping.address(), self.length)
    }
}
