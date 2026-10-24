//! Translate provider identities into the POSIX (device, inode) pair.

use mochios_filesystem_protocol as filesystem;
use mochios_posix_protocol::FileStatus;

/// Probe the native filesystem owner first. Only an owner-identification
/// rejection (EBADF), not an ordinary filesystem error, permits resolving the
/// explicitly attached data Handle through its device provider. Run outside
/// the POSIX-state lock: that provider also authorizes concurrent terminal IO.
pub fn through_provider<T>(
    source: mnu_abi::IpcObjectHandle,
    stat: impl FnMut(mnu_abi::IpcObjectHandle) -> Result<T, i32>,
    query: impl FnOnce(mnu_abi::IpcObjectHandle) -> Result<crate::OpenedObject<u32>, i32>,
    close: impl FnMut(u32),
) -> Result<T, i32> {
    operate(source, mnu_abi::HANDLE_RIGHT_TRANSFER, stat, query, close)
}

/// Metadata mutations require CONTROL on the explicitly attached data object.
/// Only EBADF from owner identification permits provider resolution: permission
/// and mutation errors must never be retried through a different authority.
/// Like `through_provider`, this must run outside the POSIX-state lock.
pub fn mutate_through_provider<T>(
    source: mnu_abi::IpcObjectHandle,
    operation: impl FnMut(mnu_abi::IpcObjectHandle) -> Result<T, i32>,
    query: impl FnOnce(mnu_abi::IpcObjectHandle) -> Result<crate::OpenedObject<u32>, i32>,
    close: impl FnMut(u32),
) -> Result<T, i32> {
    operate(
        source,
        mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER,
        operation,
        query,
        close,
    )
}

fn operate<T>(
    source: mnu_abi::IpcObjectHandle,
    rights: u64,
    mut operation: impl FnMut(mnu_abi::IpcObjectHandle) -> Result<T, i32>,
    query: impl FnOnce(mnu_abi::IpcObjectHandle) -> Result<crate::OpenedObject<u32>, i32>,
    mut close: impl FnMut(u32),
) -> Result<T, i32> {
    if source.handle == 0 || source.reserved != 0 || source.rights & rights != rights {
        return Err(-13);
    }
    let source = mnu_abi::IpcObjectHandle { rights, ..source };
    match operation(source) {
        Err(-9) => {}
        result => return result,
    }
    let metadata = query(source)?;
    if metadata.handle == 0 || metadata.handle == source.handle || metadata.rights != rights {
        if metadata.handle != 0 && metadata.handle != source.handle {
            close(metadata.handle);
        }
        return Err(-5);
    }
    let result = operation(mnu_abi::IpcObjectHandle {
        handle: metadata.handle,
        reserved: 0,
        rights,
    });
    close(metadata.handle);
    result
}

pub fn fstat_response<H>(
    request_id: u64,
    result: Result<FileStatus, i32>,
) -> crate::ObjectResponse<H> {
    match result {
        Ok(status) => crate::object_status(request_id, status),
        Err(status) => crate::object_error(request_id, status),
    }
}

pub fn volume_status_response<H>(
    request_id: u64,
    result: Result<filesystem::volume_status::Status, i32>,
) -> crate::ObjectResponse<H> {
    match result {
        Ok(status) => crate::object_payload(request_id, status.encode().to_vec()),
        Err(status) => crate::object_error(request_id, status),
    }
}

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
        filesystem::NODE_TYPE_FIFO => 0o010000,
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
        access_time_seconds: status.access_time_seconds,
        access_time_nanoseconds: i64::from(status.access_time_nanoseconds),
        modification_time_seconds: status.modification_time_seconds,
        modification_time_nanoseconds: i64::from(status.modification_time_nanoseconds),
        change_time_seconds: status.change_time_seconds,
        change_time_nanoseconds: i64::from(status.change_time_nanoseconds),
    })
}
