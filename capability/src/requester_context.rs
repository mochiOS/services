use mochi_user_platform as platform;
use mochios_posix_client::ObjectHandleAttachment;
use mochios_posix_protocol::SessionInfo;

/// Native package identity and POSIX credentials have different authorities.
/// The legacy context type is only a userspace container here: never copy its
/// kernel UID/GID into permission policy, and never write POSIX IDs to mnu.
pub(crate) fn read(
    endpoint: u64,
    credentials: impl FnOnce(
        ObjectHandleAttachment<platform::handle::Handle>,
    ) -> Result<SessionInfo, platform::syscall::SysError>,
) -> Result<platform::syscall::ThreadSecurityContext, platform::syscall::SysError> {
    let mut context = platform::process::thread_security_context(endpoint)?;
    let handle = platform::process::open_handle_for_endpoint(
        endpoint,
        platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_TRANSFER,
    )?;
    let result = (|| {
        let process = platform::process::handle_status(handle)?;
        if process.process_id != context.process_id {
            return Err(platform::syscall::SysError::from_raw(
                platform::syscall::EACCES as i64,
            ));
        }
        let identity = credentials(ObjectHandleAttachment {
            handle,
            rights: platform::handle::HANDLE_RIGHT_WAIT,
        })?;
        context.effective_uid = identity.effective_uid;
        context.effective_gid = identity.effective_gid;
        Ok(context)
    })();
    let _ = platform::handle::close(handle);
    result
}
