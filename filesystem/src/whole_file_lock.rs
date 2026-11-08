//! Description-owned locks; Handle aliases and fork inherit the same owner.
//! The existing final-reference OP_RELEASE destroys the owning OpenFile.
use crate::service::FilesystemService;
use mnu_abi::provider;
use mochios_filesystem_protocol::whole_file_lock as wire;

/// Only native CONTROL dispatch may call this handler. Numeric legacy IPC
/// identifiers cannot select it; kernel Handle authority selects object_id.
pub fn handle(
    service: &mut FilesystemService,
    header: provider::RequestHeader,
    payload: &[u8],
    attachments: u32,
) -> Result<(u64, Vec<u8>), i32> {
    if header.opcode != provider::OP_CONTROL
        || header.basis != wire::UPDATE
        || header.length != 0
        || header.argument != 0
        || attachments != 0
        || header.data_length as usize != payload.len()
    {
        return Err(22);
    }
    service.whole_file_lock(header.object_id, wire::decode(payload).ok_or(22)?)?;
    Ok((0, Vec::new()))
}
