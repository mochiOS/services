//! Validate a retained FIFO reply from the explicitly held filesystem control
//! endpoint. Only use receiver-owned attachments after successful native IPC.
//! This validator borrows them: the caller must adopt or close every reference.
//! Metadata authority alone does not authorize a read/write data endpoint.
//! Carry the admitted access from the authenticated open policy separately;
//! never turn a client's self-reported direction into new data authority.
use mnu_abi::IpcObjectHandles;
use mochios_filesystem_protocol as wire;

pub const METADATA_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;

pub fn validate_reply(
    response: wire::Header,
    request_id: u64,
    payload: &[u8],
    objects: &IpcObjectHandles,
) -> Result<wire::NodeStatus, i32> {
    if response.opcode != wire::OP_STATUS || response.request_id != request_id {
        return Err(-5);
    }
    if response.status < 0
        && response.flags == 0
        && payload.is_empty()
        && response.length == 0
        && objects.count == 0
    {
        return Err(response.status);
    }
    if response.status != 0
        || response.flags != wire::OPEN_REPLY_FIFO
        || response.length as usize != wire::NODE_STATUS_LEN
        || payload.len() != wire::NODE_STATUS_LEN
        || objects.count != 1
        || response.open_id == 0
        || response.open_id > i64::MAX as u64
    {
        return Err(-5);
    }
    let object = objects.handles[0];
    if object.handle == 0 || object.reserved != 0 || object.rights != METADATA_RIGHTS {
        return Err(-5);
    }
    let status = wire::decode_node_status(payload).map_err(|_| -5)?;
    if status.kind != wire::NODE_TYPE_FIFO
        || status.node_id != response.node_id
        || status.node_id as u32 == 0
        || status.device != status.node_id >> 32
        || status.mode & !0o7777 != 0
        || status.special_device != 0
        || status.size != 0
        || status.blocks != 0
    {
        return Err(-5);
    }
    Ok(status)
}
