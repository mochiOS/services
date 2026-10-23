//! Observation of the filesystem owning an already authenticated provider ID.
//! No path lookup, data read, position change, PID or client FD is involved.
use crate::service::FilesystemService;
use mnu_abi::provider;
use mochios_filesystem_protocol::object_limits as wire;

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
