//! External device creation only. The returned native Handle, not filesystem
//! byte forwarding, is the application's data path.
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as CONTROL, HANDLE_RIGHT_DUPLICATE as DUPLICATE,
    HANDLE_RIGHT_SEND as SEND, HANDLE_RIGHT_TRANSFER as TRANSFER, IpcObjectHandle,
    IpcObjectHandles,
};
use mochi_user_platform as platform;
use mochios_filesystem_protocol::device_open::Request;

pub trait Factory: std::fmt::Debug + Send + Sync {
    /// Metadata is borrowed locally and explicitly attached to the creation
    /// request. Success returns one newly owned data reference, exact rights.
    fn open(&self, metadata: IpcObjectHandle, request: Request) -> Result<IpcObjectHandle, i32>;
}

/// Owns a SEND endpoint and a resource-scoped factory grant. Neither a service
/// name nor a globally addressed endpoint/object number is resolved here.
#[derive(Debug)]
pub struct NativeFactory {
    endpoint: u32,
    factory: u32,
}
impl NativeFactory {
    /// Consume both received references, even on rejection. The registration
    /// adapter must first validate delivery provenance and directory authority.
    pub fn from_received(endpoint: IpcObjectHandle, factory: IpcObjectHandle) -> Result<Self, i32> {
        let owned = Self {
            endpoint: endpoint.handle,
            factory: factory.handle,
        };
        if endpoint.handle == 0
            || factory.handle == 0
            || endpoint.handle == factory.handle
            || endpoint.reserved != 0
            || factory.reserved != 0
            || endpoint.rights != SEND
            || factory.rights & TRANSFER == 0
            || factory.rights & !(DUPLICATE | TRANSFER) != 0
        {
            return Err(13);
        }
        Ok(owned)
    }
}
impl Drop for NativeFactory {
    fn drop(&mut self) {
        if self.endpoint != 0 {
            let _ = platform::handle::close(self.endpoint);
        }
        if self.factory != 0 && self.factory != self.endpoint {
            let _ = platform::handle::close(self.factory);
        }
    }
}
impl Factory for NativeFactory {
    fn open(&self, metadata: IpcObjectHandle, request: Request) -> Result<IpcObjectHandle, i32> {
        open_with(
            self.endpoint,
            self.factory,
            metadata,
            request,
            |endpoint, bytes, reply, objects| {
                platform::ipc::call_object_handles(endpoint, bytes, reply, objects)
                    .map_err(crate::memory_updates::native_error)
            },
            |handle| {
                let _ = platform::handle::close(handle);
            },
        )
    }
}

/// Borrowed request references are never returned to reply cleanup after a
/// failed native call. On native success, all malformed/unexpected response
/// references are reclaimed; only an exact-rights successful result escapes.
pub fn open_with(
    endpoint: u32,
    factory: u32,
    metadata: IpcObjectHandle,
    request: Request,
    invoke: impl FnOnce(u32, &[u8], &mut [u8], &mut IpcObjectHandles) -> Result<u64, i32>,
    mut close: impl FnMut(u32),
) -> Result<IpcObjectHandle, i32> {
    let required = DUPLICATE | TRANSFER;
    if endpoint == 0
        || factory == 0
        || metadata.handle == 0
        || metadata.reserved != 0
        || metadata.rights & required != required
        || metadata.rights & !(required | CONTROL) != 0
        || request.rights & TRANSFER == 0
    {
        return Err(13);
    }
    let mut exchanged = IpcObjectHandles::default();
    exchanged.count = 2;
    exchanged.handles[0] = IpcObjectHandle {
        handle: factory,
        reserved: 0,
        rights: TRANSFER,
    };
    exchanged.handles[1] = metadata;
    let mut reply = [0; 8];
    // A failing syscall rolls back reply installation. `exchanged` may still
    // contain the borrowed request handles, including after transport failure.
    let delivered = invoke(endpoint, &request.encode(), &mut reply, &mut exchanged)?;
    let result = (|| {
        if delivered as u32 as usize != reply.len() || exchanged.delivery_flags != 0 {
            return Err(5);
        }
        let status = i64::from_le_bytes(reply);
        if status != 0 {
            return Err(
                if status < 0 && status >= -(i32::MAX as i64) && exchanged.count == 0 {
                    -status as i32
                } else {
                    5
                },
            );
        }
        if exchanged.count != 1 {
            return Err(5);
        }
        let opened = exchanged.handles[0];
        if opened.handle == 0 || opened.reserved != 0 || opened.rights != request.rights {
            return Err(5);
        }
        Ok(opened)
    })();
    if result.is_err() {
        for (index, object) in exchanged
            .handles
            .iter()
            .take(exchanged.count as usize)
            .enumerate()
        {
            if object.handle != 0
                && !exchanged.handles[..index]
                    .iter()
                    .any(|old| old.handle == object.handle)
            {
                close(object.handle);
            }
        }
    }
    result
}
