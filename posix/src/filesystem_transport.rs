//! Keep borrowed request attachments separate from owned native IPC replies.

use mnu_abi::IpcObjectHandles;

#[derive(Debug, PartialEq, Eq)]
pub enum MutationReply {
    Ready,
    Wait,
}

/// Only opted-in mutation calls may receive an error carrying an object.
/// All malformed envelopes and object-free busy errors fail closed, without
/// granting a replay guarantee. Ownership remains with the caller's cleanup.
pub fn mutation_status(
    response: mochios_filesystem_protocol::Header,
    request_id: u64,
    payload: &[u8],
    objects: &IpcObjectHandles,
    success_objects: usize,
) -> Result<MutationReply, i32> {
    use mochios_filesystem_protocol as filesystem;
    if response.opcode != filesystem::OP_STATUS
        || response.request_id != request_id
        || response.flags != 0
        || response.length != 0
        || !payload.is_empty()
        || response.status > 0
        || objects.count as usize > objects.handles.len()
    {
        return Err(-5);
    }
    if response.status == -filesystem::ERROR_MEMORY_ADMISSION_BUSY {
        if objects.count == 1 {
            let ticket = objects.handles[0];
            if ticket.handle != 0
                && ticket.reserved == 0
                && ticket.rights == crate::mutation_admission::TICKET_RIGHTS
            {
                return Ok(MutationReply::Wait);
            }
        }
        return Err(-5);
    }
    metadata_status(
        response,
        request_id,
        payload,
        objects.count as usize,
        success_objects,
    )?;
    if objects
        .handles
        .iter()
        .take(objects.count as usize)
        .any(|object| object.handle == 0 || object.reserved != 0)
    {
        return Err(-5);
    }
    Ok(MutationReply::Ready)
}

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
