use mochi_user_platform as platform;

pub(crate) fn validate(
    attached: &platform::ipc::IpcObjectHandles,
    sender_authorized: bool,
) -> Result<platform::handle::Handle, u64> {
    if !sender_authorized {
        return Err(platform::syscall::EACCES);
    }
    if !attached.is_user_delivery() || attached.count != 1 {
        return Err(platform::syscall::EINVAL);
    }
    let handle = &attached.handles[0];
    if handle.handle == 0
        || handle.reserved != 0
        || handle.rights != platform::handle::HANDLE_RIGHT_SEND
    {
        return Err(platform::syscall::EINVAL);
    }
    Ok(handle.handle)
}
