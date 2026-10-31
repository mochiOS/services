//! Establish the consent authority after the retained input process is ready.
use mochi_user_platform as p;

pub(crate) fn install() -> Result<(), p::syscall::SysError> {
    let denied =
        || p::syscall::SysError::from_raw(p::syscall::NativeError::AccessDenied.into_raw() as i64);
    let destination = p::process::find_by_name("capability.service")?;
    let before = p::ipc::endpoint_execution_identity(destination)?;
    let mut reply = [0; 8];
    let mut handles = p::ipc::IpcObjectHandles::default();
    let result = (|| {
        let message = p::ipc::call_object_handles(
            u32::try_from(destination).map_err(|_| denied())?,
            &p::capability::input_authority::INSTALL_OPCODE.to_le_bytes(),
            &mut reply,
            &mut handles,
        )?;
        if message >> 32 != destination
            || message as u32 != 8
            || handles.count != 0
            || handles.delivery_flags != 0
            || p::ipc::endpoint_execution_identity(destination)? != before
        {
            return Err(denied());
        }
        let status = u64::from_le_bytes(reply);
        if status > 4095 {
            return Err(denied());
        }
        if status != 0 {
            return Err(p::syscall::SysError::from_raw(-(status as i64)));
        }
        Ok(())
    })();
    let entries = &handles.handles[..(handles.count as usize).min(handles.handles.len())];
    for (index, entry) in entries.iter().enumerate() {
        if entry.handle != 0
            && !entries[..index]
                .iter()
                .any(|old| old.handle == entry.handle)
        {
            let _ = p::handle::close(entry.handle);
        }
    }
    result
}
