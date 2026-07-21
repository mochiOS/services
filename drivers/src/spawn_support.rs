use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;

const CAPABILITY_SERVICE_NAME: &str = "capability.service";
const RESOLVE_CAPS_OPCODE: u32 = 0x4341_5053;

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
    let mut request = Vec::with_capacity(4 + entry_path.len());
    request.extend_from_slice(&RESOLVE_CAPS_OPCODE.to_le_bytes());
    request.extend_from_slice(entry_path.as_bytes());
    let mut reply = [0u8; 1024];
    let msg = match platform::ipc::call(service_tid, &request, &mut reply) {
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
    if len < 8 || len > reply.len() {
        platform::println!(
            "drivers.service: capability reply invalid {} len={}",
            entry_path,
            len
        );
        return Err(sys_error(mochi_user_syscall::EINVAL));
    }
    let status = u64::from_le_bytes(
        reply[..8]
            .try_into()
            .map_err(|_| sys_error(mochi_user_syscall::EINVAL))?,
    );
    if status != 0 {
        platform::println!(
            "drivers.service: capability denied {} errno={}",
            entry_path,
            status
        );
        return Err(sys_error(status));
    }
    Ok(reply[8..len].to_vec())
}
