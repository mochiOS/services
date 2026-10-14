//! Keep borrowed request attachments separate from owned native IPC replies.

use mnu_abi::IpcObjectHandles;

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
