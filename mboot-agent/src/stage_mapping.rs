use super::platform;
use platform::memory_object::{MemoryMapping, MemoryObject, ReadOnlyOffer, receive_readonly_offer};

#[derive(Default)]
pub(super) struct Attachments {
    pub(super) handles: platform::ipc::IpcObjectHandles,
}

impl Attachments {
    pub(super) fn is_empty(&self) -> bool {
        self.handles.count == 0
            && self.handles.delivery_flags == 0
            && self.handles.handles.iter().all(|entry| entry.handle == 0)
    }
}

impl Drop for Attachments {
    fn drop(&mut self) {
        for entry in &mut self.handles.handles {
            if entry.handle != 0 {
                let _ = platform::handle::close(entry.handle);
            }
            *entry = Default::default();
        }
    }
}

pub(super) struct SharedStageMapping {
    mapping: MemoryMapping,
    length: u64,
    owner: u64,
}

impl SharedStageMapping {
    pub(super) fn receive(
        sender: u64,
        authorized: bool,
        bytes: &[u8],
        attachments: &mut Attachments,
        maximum_length: u64,
    ) -> Result<Self, u64> {
        if !authorized {
            return Err(platform::syscall::EACCES);
        }
        let handles = &mut attachments.handles;
        if handles.count != 1
            || handles.delivery_flags != 0
            || handles.handles[0].handle == 0
            || handles.handles[1..].iter().any(|entry| entry.handle != 0)
        {
            return Err(platform::syscall::EINVAL);
        }
        let offer = ReadOnlyOffer::decode(bytes).map_err(|error| error.raw() as u64)?;
        let raw = handles.handles[0].handle;
        handles.handles[0] = Default::default();
        handles.count = 0;
        // The IPC attachment is this process's owned reference. Removing the
        // slot transfers ownership to the RAII object, never a PID/FD lookup.
        let object = unsafe { MemoryObject::from_owned_handle(raw) };
        let mapping = receive_readonly_offer(bytes, object, maximum_length)
            .map_err(|error| error.raw() as u64)?;
        Ok(Self {
            mapping,
            length: offer.length,
            owner: sender,
        })
    }

    pub(super) fn snapshot(&self, sender: u64, length: usize) -> Result<Vec<u8>, u64> {
        if sender != self.owner || length == 0 || length as u64 > self.length {
            return Err(platform::syscall::EINVAL);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| platform::syscall::ENOMEM)?;
        // The sender may still write mapped storage. Read into privately owned
        // bytes without constructing a Rust slice over concurrently aliased RAM.
        for index in 0..length {
            bytes.push(unsafe { core::ptr::read_volatile(self.mapping.as_ptr().add(index)) });
        }
        Ok(bytes)
    }
}
