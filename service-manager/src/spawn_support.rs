use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;

const CAPABILITY_SERVICE_NAME: &str = "capability.service";
const PACKAGE_SERVICE_NAME: &str = "package.service";

pub(crate) fn errno(error: mochi_user_syscall::SysError) -> u64 {
    error.errno().map_or(0, |errno| errno)
}

pub(crate) fn sys_error(errno: u64) -> mochi_user_syscall::SysError {
    mochi_user_syscall::SysError::from_raw(-(errno as i64))
}

pub(crate) fn call_with_wait(
    service_tid: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<u64, mochi_user_syscall::SysError> {
    match platform::ipc::call(service_tid, request, reply) {
        Ok(message) => Ok(message),
        Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => loop {
            match platform::ipc::try_wait(reply) {
                Ok(message) => break Ok(message),
                Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {
                    platform::thread::yield_now();
                }
                Err(error) => break Err(error),
            }
        },
        Err(error) => Err(error),
    }
}

fn install_posix_endpoint_for(
    service_name: &str,
    opcode: u32,
    endpoint: platform::handle::Handle,
) -> Result<(), mochi_user_syscall::SysError> {
    let destination = platform::process::find_by_name(service_name)?;
    install_posix_endpoint_at(destination, opcode, endpoint)
}

fn install_posix_endpoint_at(
    destination: u64,
    opcode: u32,
    endpoint: platform::handle::Handle,
) -> Result<(), mochi_user_syscall::SysError> {
    if destination == 0 {
        return Err(sys_error(mochi_user_syscall::ENOENT));
    }
    let destination =
        u32::try_from(destination).map_err(|_| sys_error(mochi_user_syscall::EOVERFLOW))?;
    let request = opcode.to_le_bytes();
    let mut reply = [0u8; core::mem::size_of::<u64>()];
    let mut handles = platform::ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0].handle = endpoint;
    handles.handles[0].rights = platform::handle::HANDLE_RIGHT_SEND;
    let message =
        platform::ipc::call_object_handles(destination, &request, &mut reply, &mut handles)?;
    if handles.count != 0 || (message & 0xffff_ffff) as usize != reply.len() {
        return Err(sys_error(mochi_user_syscall::EIO));
    }
    let status = u64::from_le_bytes(reply);
    if status != 0 {
        return Err(mochi_user_syscall::SysError::from_raw(status as i64));
    }
    Ok(())
}

pub(crate) fn install_early_posix_endpoints(
    endpoint: platform::handle::Handle,
    logger_endpoint: u64,
) -> Result<(), mochi_user_syscall::SysError> {
    install_posix_endpoint_for(
        CAPABILITY_SERVICE_NAME,
        platform::capability::INSTALL_POSIX_ENDPOINT_OPCODE,
        endpoint,
    )?;
    install_posix_endpoint_for(
        PACKAGE_SERVICE_NAME,
        mochios_package_protocol::INSTALL_POSIX_ENDPOINT_OPCODE,
        endpoint,
    )?;
    install_posix_endpoint_at(
        logger_endpoint,
        platform::logger::INSTALL_POSIX_ENDPOINT_OPCODE,
        endpoint,
    )
}

pub(crate) fn resolve_capabilities(
    entry_path: &str,
) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let service_tid = match platform::process::find_by_name(CAPABILITY_SERVICE_NAME) {
        Ok(tid) => tid,
        Err(error) => {
            platform::logln!(
                "service-manager.service: capability.service lookup failed errno={}",
                errno(error)
            );
            return Err(error);
        }
    };
    if service_tid == 0 {
        platform::logln!("service-manager.service: capability.service not found");
        return Err(sys_error(mochi_user_syscall::ENOENT));
    }
    let request = platform::capability::encode_resolve_capabilities_request(entry_path)
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    let mut reply = [0u8; 1024];
    let message = match call_with_wait(service_tid, &request, &mut reply) {
        Ok(message) => message,
        Err(error) => {
            platform::logln!(
                "service-manager.service: capability request failed {} errno={}",
                entry_path,
                errno(error)
            );
            return Err(error);
        }
    };
    let length = (message & 0xffff_ffff) as usize;
    if length > reply.len() {
        platform::logln!(
            "service-manager.service: capability reply invalid {} len={}",
            entry_path,
            length
        );
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let response = platform::capability::decode_resolve_capabilities_reply(&reply[..length])
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    if response.status != 0 {
        platform::logln!(
            "service-manager.service: capability denied {} errno={}",
            entry_path,
            response.status
        );
        return Err(sys_error(response.status));
    }
    Ok(response.capabilities.to_vec())
}

pub(crate) struct ExecutionSecurity {
    pub(crate) identity: Vec<String>,
    pub(crate) capabilities: Vec<u8>,
}

fn decode_nul_list(bytes: &[u8]) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let mut items = Vec::new();
    for item in bytes.split(|byte| *byte == 0) {
        if item.is_empty() {
            continue;
        }
        let item = core::str::from_utf8(item)
            .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
        items.push(item.into());
    }
    Ok(items)
}

pub(crate) fn resolve_execution_security(
    entry_path: &str,
    execution_class: platform::service::ExecutionClass,
) -> Result<ExecutionSecurity, mochi_user_syscall::SysError> {
    let service_tid = platform::process::find_by_name(CAPABILITY_SERVICE_NAME)?;
    if service_tid == 0 {
        return Err(sys_error(mochi_user_syscall::ENOENT));
    }
    let request = platform::capability::encode_resolve_execution_security_request(
        execution_class.as_raw(),
        entry_path,
    )
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    let mut reply = [0u8; 1024];
    let message = call_with_wait(service_tid, &request, &mut reply)?;
    let length = (message & 0xffff_ffff) as usize;
    let bytes = reply
        .get(..length)
        .ok_or_else(|| sys_error(mochi_user_syscall::EINVAL))?;
    let response = platform::capability::decode_resolve_execution_security_reply(bytes)
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    if response.status != 0 {
        return Err(sys_error(response.status));
    }
    Ok(ExecutionSecurity {
        identity: decode_nul_list(response.identity)?,
        capabilities: response.capabilities.to_vec(),
    })
}
