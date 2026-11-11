//! Import an immutable copy of explicitly attached caller-owned RAM.
#[cfg(target_os = "mochios")]
pub fn handle(
    service: &mut crate::service::FilesystemService,
    endpoint: u32,
    request: &[u8],
    attached: &mochi_user_platform::ipc::IpcObjectHandles,
) -> Result<mnu_abi::IpcObjectHandle, i32> {
    use mochi_user_platform::{handle, memory};
    use mochios_filesystem_protocol::readonly_tree as wire;
    if request.len() != wire::REQUEST_LEN
        || request[..8] != wire::MAGIC
        || !attached.is_user_delivery()
        || attached.count != 1
    {
        return Err(22);
    }
    let length = usize::try_from(u64::from_le_bytes(
        request[8..16].try_into().map_err(|_| 22)?,
    ))
    .map_err(|_| 27)?;
    if !(wire::REQUEST_LEN..=wire::MAX_BYTES).contains(&length) {
        return Err(27);
    }
    let source = attached.handles[0];
    let rights = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER;
    if source.handle == 0 || source.reserved != 0 || source.rights != rights {
        return Err(13);
    }
    // Checking an anonymous RAM object prevents recursive provider callbacks.
    if memory::object_length(source.handle as u64).map_err(|_| 22)? != length as u64 {
        return Err(22);
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| 12)?;
    bytes.resize(length, 0);
    let mut offset = 0;
    while offset < length {
        let end = length.min(offset + mnu_abi::provider::MAX_SHARED_READ_LEN);
        let n = handle::read_at(source.handle, &mut bytes[offset..end], offset as u64)
            .map_err(|_| 5)?;
        if n == 0 || n > end - offset {
            return Err(5);
        }
        offset += n;
    }
    let id = service.create_readonly_tree(bytes)?;
    crate::open_publication::publish_native(
        service,
        endpoint,
        id,
        service.snapshot_rights(id).ok_or(5)?,
    )
}
