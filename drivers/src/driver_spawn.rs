use crate::spawn_support::{resolve_execution_security, sys_error};
use alloc::{string::ToString, vec::Vec};
use mochi_user_platform as platform;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, OpenAtBase, SyscallEndpointTransport,
};

pub(crate) struct DriverProcess {
    handle: platform::handle::Handle,
}

impl DriverProcess {
    pub(crate) fn retry_rollback(
        &self,
        endpoint: platform::handle::Handle,
    ) -> Result<(), platform::syscall::SysError> {
        if platform::process::handle_status(self.handle)?.state != mnu_abi::PROCESS_STATE_EXITED {
            platform::process::terminate_handle(self.handle, 127)?;
            if platform::process::handle_status(self.handle)?.state != mnu_abi::PROCESS_STATE_EXITED
            {
                return Err(sys_error(mochi_user_syscall::EAGAIN));
            }
        }
        let client = Client::new(SyscallEndpointTransport::new(endpoint));
        match client.abort_launched_child(ObjectHandleAttachment {
            handle: self.handle,
            rights: mnu_abi::HANDLE_RIGHT_WAIT,
        }) {
            Ok(()) => Ok(()),
            Err(ClientError::Remote(mochios_posix_protocol::STATUS_ESRCH)) => Ok(()),
            Err(error) => Err(client_error(error)),
        }
    }
}
impl Drop for DriverProcess {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.handle);
    }
}
fn client_error(error: ClientError<platform::syscall::SysError>) -> platform::syscall::SysError {
    match error {
        ClientError::Transport(error) => error,
        ClientError::Remote(status) => sys_error(status.unsigned_abs() as u64),
        _ => sys_error(mochi_user_syscall::EIO),
    }
}
pub(crate) fn spawn(
    entry_path: &str,
    args: Option<&[u8]>,
    logger_endpoint: u64,
    posix_endpoint: platform::handle::Handle,
    raw_input: platform::handle::Handle,
    rollback: impl FnOnce(DriverProcess),
) -> Result<DriverProcess, platform::syscall::SysError> {
    let mut arguments = Vec::new();
    if let Some(args) = args {
        let text = core::str::from_utf8(args).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
        for part in text.split('\0').filter(|part| !part.is_empty()) {
            arguments.push(part.to_string());
        }
    }
    if logger_endpoint != 0 {
        arguments.push(logger_endpoint.to_string());
    }
    let rights = mnu_abi::HANDLE_RIGHT_SEND
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER;
    arguments.push(alloc::format!(
        "{}{}:{posix_endpoint}:{rights}",
        mochios_posix_client::launch_arguments::INHERITED_HANDLE_PREFIX,
        mochios_posix_protocol::CONTROL_HANDLE_KEY
    ));
    let mut random = [0; 16];
    platform::random::fill(&mut random)?;
    let label = entry_path
        .rsplit('/')
        .find(|part| part.ends_with(".driver"))
        .or_else(|| entry_path.rsplit('/').next())
        .ok_or_else(|| sys_error(mochi_user_syscall::EINVAL))?;
    let client = Client::new(SyscallEndpointTransport::new(posix_endpoint));
    client.register_session().map_err(client_error)?;
    let image = client
        .open_at(
            OpenAtBase::ProcessRoot,
            mochios_posix_protocol::OPEN_READ,
            0,
            entry_path,
        )
        .map_err(client_error)?;
    let result = (|| {
        // Keep the driver's unprivileged execution class. Authorization binds
        // the actual image digest; legacy identity strings never become argv.
        let capabilities = resolve_execution_security(
            entry_path,
            platform::service::ExecutionClass::Unprivileged,
        )?;
        if capabilities.split(|byte| *byte == 0).any(|name| {
            matches!(name, b"device.input" | b"input.keyboard" | b"input.pointer")
        }) {
            // Input authority follows the verified launch capabilities, never
            // an argv flag or a driver basename. Children cannot redelegate it.
            arguments.push(alloc::format!(
                "{}{}:{raw_input}:{}",
                mochios_posix_client::launch_arguments::INHERITED_HANDLE_PREFIX,
                platform::input::RAW_INPUT_HANDLE_KEY,
                mnu_abi::HANDLE_RIGHT_SEND,
            ));
        }
        let metadata = mochios_posix_client::launch_arguments::encode_native_launch(
            entry_path, label, &arguments, random,
        )
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
        let (handle, process_id) = mochios_posix_client::process_creation::create_with_rollback(
            || platform::process::create_stopped(image.handle, &metadata),
            |handle| {
                client
                    .register_spawned_child(
                        ObjectHandleAttachment {
                            handle,
                            rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
                        },
                        0,
                        0,
                        &[],
                    )
                    .map(|_| ())
                    .map_err(client_error)
            },
            |handle| platform::process::handle_status(handle).map(|status| status.process_id),
            platform::process::resume_handle,
            |handle| {
                let _ = platform::process::terminate_handle(handle, 127);
            },
            |handle| rollback(DriverProcess { handle }),
        )?;
        eprintln!("drivers.service: native driver created path={entry_path} pid={process_id}");
        Ok(DriverProcess { handle })
    })();
    let _ = platform::handle::close(image.handle);
    result
}
