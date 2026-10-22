//! Explicit control-endpoint delivery and an owned directory attachment admit
//! owner configuration. Native identification receives only that Handle.
use crate::service::{FilesystemService, Response};
use mnu_abi::{
    HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_TRANSFER, IPC_DELIVERY_ENDPOINT_HANDLE, IpcObjectHandles,
};
use mochios_filesystem_protocol as wire;
pub fn requested(header: wire::Header) -> bool {
    matches!(
        header.opcode,
        wire::OP_DEVICE_NODE_CREATE
            | wire::OP_DEVICE_NODE_SET_ATTRIBUTES
            | wire::OP_DEVICE_NODE_REMOVE
            | wire::OP_DEVICE_NODE_REMOVE_IF_SAME
    )
}
pub fn handle(
    service: &mut FilesystemService,
    header: wire::Header,
    payload: &[u8],
    attached: &IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i32>,
) -> Result<Response, i32> {
    if attached.delivery_flags != IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(13);
    }
    if !requested(header) {
        return Err(38);
    }
    if header.mount_id != 0
        || header.node_id != 0
        || header.open_id != 0
        || header.offset != 0
        || header.flags != 0
        || header.status != 0
        || header.mode != 0
        || header.length as usize != payload.len()
        || attached.count != 1
    {
        return Err(22);
    }
    let object = attached.handles[0];
    let required = HANDLE_RIGHT_CONTROL | HANDLE_RIGHT_TRANSFER;
    if object.handle == 0 || object.reserved != 0 || object.rights & required != required {
        return Err(13);
    }
    if header.opcode == wire::OP_DEVICE_NODE_REMOVE_IF_SAME {
        wire::device_removal::decode(payload).map_err(|_| 22)?;
    } else {
        wire::device_namespace::decode(header.opcode, payload).map_err(|_| 22)?;
    }
    let parent = identify(object.handle)?;
    service.configure_device_node(header, payload, parent)
}
