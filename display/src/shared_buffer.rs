use crate::platform;
use platform::memory_object::{receive_readonly_offer, MemoryMapping, MemoryObject, ReadOnlyOffer};

const MAX_BUFFER_BYTES: u64 = 256 * 1024 * 1024;

/// The mapping guard outlives every present using its receiver-local address.
pub(crate) struct SharedBuffer {
    sender: u64,
    address: u64,
    length: u64,
    _mapping: Option<MemoryMapping>,
}

impl SharedBuffer {
    pub(crate) fn receive(
        sender: u64,
        owner: u64,
        bytes: &[u8],
        handles: &mut platform::ipc::IpcObjectHandles,
    ) -> Result<Self, u64> {
        let result = (|| {
            if owner != 0 && sender != owner {
                return Err(platform::syscall::EACCES);
            }
            if handles.count != 1 || handles.handles[0].handle == 0 {
                return Err(platform::syscall::EINVAL);
            }
            let offer = ReadOnlyOffer::decode(bytes).map_err(|error| error.raw() as u64)?;
            let raw = handles.handles[0].handle;
            handles.handles[0] = Default::default();
            handles.count = 0;
            // SAFETY: the IPC receiver installed this owned reference. Clearing
            // its slot relinquishes ownership to the single RAII object below.
            let object = unsafe { MemoryObject::from_owned_handle(raw) };
            let mapping = receive_readonly_offer(bytes, object, MAX_BUFFER_BYTES)
                .map_err(|error| error.raw() as u64)?;
            Ok(Self {
                sender,
                address: mapping.address(),
                length: offer.length,
                _mapping: Some(mapping),
            })
        })();
        close_attachments(handles);
        result
    }

    // Retained solely until legacy producers have been migrated to offers.
    pub(crate) fn legacy(sender: u64, address: u64, length: u64) -> Self {
        Self {
            sender,
            address,
            length,
            _mapping: None,
        }
    }

    pub(crate) fn view(&self) -> (u64, u64, u64) {
        (self.sender, self.address, self.length)
    }
}

pub(crate) fn close_attachments(handles: &mut platform::ipc::IpcObjectHandles) {
    for entry in &mut handles.handles {
        if entry.handle != 0 {
            let _ = platform::handle::close(entry.handle);
        }
        *entry = Default::default();
    }
    handles.count = 0;
    handles.delivery_flags = 0;
}
