use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;

const CAPABILITY_SERVICE_NAME: &str = "capability.service";

pub(crate) fn encode_spawn_args(items: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.resize(512, 0);
    let mut cursor = 0usize;
    for item in items {
        let bytes = item.as_bytes();
        if cursor + bytes.len() + 2 > out.len() {
            break;
        }
        out[cursor..cursor + bytes.len()].copy_from_slice(bytes);
        cursor += bytes.len();
        out[cursor] = 0;
        cursor += 1;
    }
    out
}

pub(crate) fn sys_error(errno: u64) -> mochi_user_syscall::SysError {
    mochi_user_syscall::SysError::from_raw(-(errno as i64))
}

fn call_capability_service(
    service_tid: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<u64, mochi_user_syscall::SysError> {
    match platform::ipc::call(service_tid, request, reply) {
        Ok(msg) => Ok(msg),
        Err(err) if err.raw() == mochi_user_syscall::EAGAIN as i64 => loop {
            match platform::ipc::try_wait(reply) {
                Ok(msg) => break Ok(msg),
                Err(err) if err.raw() == mochi_user_syscall::EAGAIN as i64 => {
                    platform::thread::yield_now();
                }
                Err(err) => break Err(err),
            }
        },
        Err(err) => Err(err),
    }
}

pub(crate) fn resolve_capabilities(
    entry_path: &str,
) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let service_tid = match platform::process::find_by_name(CAPABILITY_SERVICE_NAME) {
        Ok(tid) => tid,
        Err(err) => {
            platform::println!(
                "drivers.service: capability.service lookup failed errno={}",
                err.errno().unwrap_or(0)
            );
            return Err(err);
        }
    };
    if service_tid == 0 {
        platform::println!("drivers.service: capability.service not found");
        return Err(sys_error(mochi_user_syscall::ENOENT));
    }
    let request = platform::capability::encode_resolve_capabilities_request(entry_path)
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    let mut reply = [0u8; 1024];
    let msg = match call_capability_service(service_tid, &request, &mut reply) {
        Ok(msg) => msg,
        Err(err) => {
            platform::println!(
                "drivers.service: capability request failed {} errno={}",
                entry_path,
                err.errno().unwrap_or(0)
            );
            return Err(err);
        }
    };
    let len = (msg & 0xffff_ffff) as usize;
    if len > reply.len() {
        platform::println!(
            "drivers.service: capability reply invalid {} len={}",
            entry_path,
            len
        );
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let response = platform::capability::decode_resolve_capabilities_reply(&reply[..len])
        .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
    if response.status != 0 {
        platform::println!(
            "drivers.service: capability denied {} errno={}",
            entry_path,
            response.status
        );
        return Err(sys_error(response.status));
    }
    Ok(response.capabilities.to_vec())
}
