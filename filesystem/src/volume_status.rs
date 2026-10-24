//! Volume accounting follows the retained open's mount, never the current path.
use crate::service::FilesystemService;
use mnu_abi::provider;
use mochios_filesystem_protocol::volume_status as wire;

pub(crate) fn filesystem_status(
    filesystem: &ext4plus::Ext4,
    volume: u32,
) -> Result<wire::Status, i32> {
    let superblock = filesystem.superblock();
    let status = wire::Status {
        block_bytes: filesystem.block_size_bytes(),
        flags: if filesystem.is_read_only() {
            wire::READ_ONLY
        } else {
            0
        },
        blocks: superblock.blocks_count(),
        free_blocks: superblock.free_blocks_count(),
        inodes: u64::from(superblock.inodes_count()),
        free_inodes: u64::from(superblock.free_inodes_count()),
        filesystem_id: u64::from(volume),
        name_bytes_max: ext4plus::DirEntryName::MAX_LEN as u32,
    };
    wire::Status::decode(&status.encode()).ok_or(5)
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
    let bytes = service.provider_volume_status(header.object_id)?.encode();
    Ok((bytes.len() as u64, bytes.to_vec()))
}
