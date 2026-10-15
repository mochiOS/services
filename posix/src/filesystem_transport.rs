//! Keep borrowed request attachments separate from owned native IPC replies.

use mnu_abi::IpcObjectHandles;

/// Validate the complete metadata reply before trusting a retry guarantee.
/// Error replies never transfer objects; a successful open transfers one.
pub fn metadata_status(
    response: mochios_filesystem_protocol::Header,
    request_id: u64,
    payload: &[u8],
    object_count: usize,
    success_objects: usize,
) -> Result<(), i32> {
    if response.opcode != mochios_filesystem_protocol::OP_STATUS
        || response.request_id != request_id
        || !payload.is_empty()
        || response.status > 0
        || object_count
            != if response.status == 0 {
                success_objects
            } else {
                0
            }
    {
        return Err(-5);
    }
    if response.status == 0 {
        Ok(())
    } else {
        Err(response.status)
    }
}

/// The native syscall installs reply references only on success; on failure
/// it rolls back installation, and its in/out buffer may still hold borrowed
/// request handles. Never expose that buffer to a caller's reply cleanup.
pub fn call_native<R, E>(
    handles: &mut IpcObjectHandles,
    invoke: impl FnOnce(&mut IpcObjectHandles) -> Result<R, E>,
) -> Result<R, E> {
    let mut exchanged = core::mem::take(handles);
    let result = invoke(&mut exchanged)?;
    *handles = exchanged;
    Ok(result)
}
