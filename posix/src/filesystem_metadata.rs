//! Translate provider identities into the POSIX (device, inode) pair.

use mochios_filesystem_protocol as filesystem;
use mochios_posix_protocol::FileStatus;

pub fn translate(status: filesystem::NodeStatus) -> Result<FileStatus, i32> {
    // Filesystem node IDs are volume-scoped: high 32 bits are the volume,
    // low 32 bits are its inode. Keep both halves, without truncating either
    // identity or leaking the composite ID into the libc ino_t field.
    if status.device != status.node_id >> 32 {
        return Err(-5);
    }
    let file_type = match status.kind {
        filesystem::NODE_TYPE_REGULAR => 0o100000,
        filesystem::NODE_TYPE_DIRECTORY => 0o040000,
        filesystem::NODE_TYPE_SYMLINK => 0o120000,
        filesystem::NODE_TYPE_SOCKET => 0o140000,
        filesystem::NODE_TYPE_SPECIAL => 0o020000,
        _ => return Err(-5),
    };
    Ok(FileStatus {
        device: status.device,
        inode: u64::from(status.node_id as u32),
        mode: file_type | (status.mode & 0o7777),
        link_count: status.link_count,
        uid: status.uid,
        gid: status.gid,
        special_device: status.special_device,
        size: i64::try_from(status.size).map_err(|_| -75)?,
        block_size: i64::from(status.block_size),
        blocks: i64::try_from(status.blocks).map_err(|_| -75)?,
        access_time_seconds: i64::try_from(status.access_time_seconds).map_err(|_| -75)?,
        access_time_nanoseconds: i64::from(status.access_time_nanoseconds),
        modification_time_seconds: i64::try_from(status.modification_time_seconds)
            .map_err(|_| -75)?,
        modification_time_nanoseconds: i64::from(status.modification_time_nanoseconds),
        change_time_seconds: i64::try_from(status.change_time_seconds).map_err(|_| -75)?,
        change_time_nanoseconds: i64::from(status.change_time_nanoseconds),
    })
}
