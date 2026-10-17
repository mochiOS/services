use alloc::vec::Vec;

use mochi_user_platform as platform;

const CAPABILITY_SERVICE_NAME: &str = "capability.service";

pub(crate) fn sys_error(errno: u64) -> mochi_user_syscall::SysError {
    mochi_user_syscall::SysError::from_raw(-(errno as i64))
}

fn call_capability_service(
    service_tid: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<u64, mochi_user_syscall::SysError> {
    platform::ipc::call(service_tid, request, reply)
}

pub(crate) fn resolve_capabilities(
    entry_path: &str,
) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let service_tid = match platform::process::find_by_name(CAPABILITY_SERVICE_NAME) {
        Ok(tid) => tid,
        Err(err) => {
            platform::logln!(
                "drivers.service: capability.service lookup failed errno={}",
                err.errno().unwrap_or(0)
            );
            return Err(err);
        }
    };
    if service_tid == 0 {
        platform::logln!("drivers.service: capability.service not found");
        return Err(sys_error(mochi_user_syscall::ENOENT));
    }
    let request = platform::capability::encode_resolve_capabilities_request(entry_path)
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    let mut reply = [0u8; 1024];
    let msg = match call_capability_service(service_tid, &request, &mut reply) {
        Ok(msg) => msg,
        Err(err) => {
            platform::logln!(
                "drivers.service: capability request failed {} errno={}",
                entry_path,
                err.errno().unwrap_or(0)
            );
            return Err(err);
        }
    };
    let len = (msg & 0xffff_ffff) as usize;
    if len > reply.len() {
        platform::logln!(
            "drivers.service: capability reply invalid {} len={}",
            entry_path,
            len
        );
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let response = platform::capability::decode_resolve_capabilities_reply(&reply[..len])
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    if response.status != 0 {
        platform::logln!(
            "drivers.service: capability denied {} errno={}",
            entry_path,
            response.status
        );
        return Err(sys_error(response.status));
    }
    Ok(response.capabilities.to_vec())
}

pub(crate) fn resolve_execution_security(
    entry_path: &str,
    execution_class: platform::service::ExecutionClass,
) -> Result<(), mochi_user_syscall::SysError> {
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
    let message = call_capability_service(service_tid, &request, &mut reply)?;
    let length = (message & 0xffff_ffff) as usize;
    let bytes = reply
        .get(..length)
        .ok_or_else(|| sys_error(mochi_user_syscall::EINVAL))?;
    let response = platform::capability::decode_resolve_execution_security_reply(bytes)
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    if response.status != 0 {
        return Err(sys_error(response.status));
    }
    if !response.identity.is_empty() && response.identity.last() != Some(&0) {
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    for item in response.identity.split(|byte| *byte == 0) {
        if item.is_empty() {
            continue;
        }
        core::str::from_utf8(item).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    }
    Ok(())
}
