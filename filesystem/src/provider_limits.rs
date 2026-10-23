//! Observation of the filesystem owning an already authenticated provider ID.
//! No path lookup, data read, position change, PID or client FD is involved.
use crate::service::FilesystemService;
use mnu_abi::provider;
use mochios_filesystem_protocol::object_limits as wire;

pub(crate) fn filesystem_limits(filesystem: &ext4plus::Ext4) -> wire::Limits {
    wire::Limits {
        name_bytes_max: ext4plus::DirEntryName::MAX_LEN as u32,
        path_bytes_max: mochios_filesystem_protocol::MAX_PATH_LEN as u32,
        link_count_max: u32::from(u16::MAX),
        filesystem_block_bytes: filesystem.block_size_bytes(),
    }
}

pub fn handle(
    service: &FilesystemService,
    header: provider::RequestHeader,
    payload: &[u8],
    attachments: u32,
) -> Result<(u64, Vec<u8>), i32> {
    if attachments != 0
        || header.argument != 0
        || header.data_length as usize != payload.len()
        || !payload.is_empty()
        || header.length != wire::RESPONSE_LEN as u32
    {
        return Err(22);
    }
    if !matches!(header.opcode, provider::OP_QUERY | provider::OP_CONTROL)
        || header.basis != wire::GET
    {
        return Err(95);
    }
    let bytes = service.provider_limits(header.object_id)?.encode();
    Ok((bytes.len() as u64, bytes.to_vec()))
}
