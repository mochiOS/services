//! Owned executable attachments for trusted native launchers.

use mochi_user_platform as platform;

fn sys_error(errno: u64) -> platform::syscall::SysError {
    let raw = errno as i64;
    platform::syscall::SysError::from_raw(if raw > 0 { -raw } else { raw })
}

pub(crate) struct PreparedImage(u32);
impl PreparedImage {
    pub(crate) fn handle(&self) -> u32 {
        self.0
    }
}
impl Drop for PreparedImage {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.0);
    }
}

struct ReplyHandles(platform::ipc::IpcObjectHandles);
impl Drop for ReplyHandles {
    fn drop(&mut self) {
        let entries = &self.0.handles[..(self.0.count as usize).min(self.0.handles.len())];
        for (index, entry) in entries.iter().enumerate() {
            if entry.handle != 0
                && !entries[..index]
                    .iter()
                    .any(|previous| previous.handle == entry.handle)
            {
                let _ = platform::handle::close(entry.handle);
            }
        }
    }
}

pub(crate) fn prepare(
    endpoint: u32,
    path: &str,
    class: platform::service::ExecutionClass,
) -> Result<PreparedImage, platform::syscall::SysError> {
    let request =
        platform::capability::encode_prepare_execution_image_request(class.as_raw(), path)
            .map_err(|_| sys_error(platform::syscall::EINVAL))?;
    let mut reply = [0; 8];
    let mut handles = platform::ipc::IpcObjectHandles::default();
    // No borrowed request references. Failure installs no reply ownership.
    let received =
        platform::ipc::call_object_handles(endpoint, &request, &mut reply, &mut handles)?;
    let mut handles = ReplyHandles(handles);
    if received as u32 as usize != reply.len() || handles.0.delivery_flags != 0 {
        return Err(sys_error(platform::syscall::EIO));
    }
    let status = platform::capability::decode_prepare_execution_image_reply(&reply)
        .map_err(|_| sys_error(platform::syscall::EIO))?;
    if status != 0 {
        return Err(sys_error(if handles.0.count == 0 {
            status
        } else {
            platform::syscall::EIO
        }));
    }
    let image = handles.0.handles[0];
    if handles.0.count != 1
        || image.handle == 0
        || image.reserved != 0
        || image.rights != platform::handle::HANDLE_RIGHT_READ
        || platform::handle::rights(image.handle)? != platform::handle::HANDLE_RIGHT_READ
    {
        return Err(sys_error(platform::syscall::EACCES));
    }
    handles.0.handles[0].handle = 0;
    Ok(PreparedImage(image.handle))
}
