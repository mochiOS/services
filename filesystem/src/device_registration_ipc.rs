//! Directory authority and explicit factory capabilities, not names/inline IDs.
use crate::{
    device_factory::{Factory, NativeFactory},
    service::{FilesystemService, Response},
};
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_SEND as S,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol as wire;
use std::sync::Arc;

/// The directory attachment stays borrowed for common request cleanup. Once
/// adoption starts, endpoint/grant references are owned by `adopt` on both
/// success and failure; their slots are cleared before invoking the callback.
pub fn handle(
    service: &mut FilesystemService,
    header: wire::Header,
    payload: &[u8],
    attached: &mut IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i32>,
    adopt: impl FnOnce(IpcObjectHandle, IpcObjectHandle) -> Result<Arc<dyn Factory>, i32>,
) -> Result<Response, i32> {
    if attached.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(13);
    }
    if header.opcode != wire::OP_DEVICE_NODE_REGISTER_EXTERNAL {
        return Err(38);
    }
    if attached.count != 3
        || header.mount_id != 0
        || header.node_id != 0
        || header.open_id != 0
        || header.offset != 0
        || header.flags != 0
        || header.status != 0
        || header.mode != 0
        || header.length as usize != payload.len()
    {
        return Err(22);
    }
    let parent = attached.handles[0];
    let endpoint = attached.handles[1];
    let factory = attached.handles[2];
    if [parent, endpoint, factory]
        .iter()
        .any(|o| o.handle == 0 || o.reserved != 0)
        || parent.handle == endpoint.handle
        || parent.handle == factory.handle
        || endpoint.handle == factory.handle
        || parent.rights & (C | T) != C | T
        || endpoint.rights != S
        || factory.rights & T == 0
        || factory.rights & !(D | T) != 0
    {
        return Err(13);
    }
    let config = wire::device_registration::decode(payload).map_err(|_| 22)?;
    let parent_id = identify(parent.handle)?;
    attached.handles[1] = IpcObjectHandle::default();
    attached.handles[2] = IpcObjectHandle::default();
    let factory = adopt(endpoint, factory)?;
    service.register_external_device(header, config, parent_id, factory)
}

pub fn handle_native(
    service: &mut FilesystemService,
    header: wire::Header,
    payload: &[u8],
    attached: &mut IpcObjectHandles,
) -> Result<Response, i32> {
    handle(
        service,
        header,
        payload,
        attached,
        |handle| mochi_user_platform::handle::identify_provider_object(handle).map_err(|_| 9),
        |endpoint, factory| {
            NativeFactory::from_received(endpoint, factory)
                .map(|factory| Arc::new(factory) as Arc<dyn Factory>)
        },
    )
}
