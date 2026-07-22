use alloc::string::{String, ToString};
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::app_spawn::{SPAWN_APP_OPCODE, spawn_application_from_manifest};
use crate::dynamic_grant::authorize_dynamic_capability;
use crate::persistent_grant::authorize_persistent_capability;
use crate::resolver::{encode_nul_list, resolve_capabilities_for_path};
use crate::state::CapabilityServiceState;

const RESOLVE_CAPS_OPCODE: u32 = 0x4341_5053;
const REPLY_OK: u64 = 0;

fn capability_reply(sender: u64, status: u64) {
    let _ = platform::ipc::reply(sender, &status.to_le_bytes());
}

fn parse_resolve_caps_request(buf: &[u8]) -> Result<String, mochi_user_syscall::SysError> {
    if buf.len() <= 4 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let opcode = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if opcode != RESOLVE_CAPS_OPCODE {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let path_bytes = &buf[4..];
    if path_bytes.is_empty() || path_bytes.contains(&0) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let path = core::str::from_utf8(path_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if !path.starts_with('/') {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    Ok(path.to_string())
}

fn reply_capabilities(sender: u64, result: Result<Vec<String>, mochi_user_syscall::SysError>) {
    let mut reply = Vec::new();
    match result {
        Ok(caps) => {
            reply.extend_from_slice(&REPLY_OK.to_le_bytes());
            reply.extend_from_slice(&encode_nul_list(&caps));
        }
        Err(err) => {
            let status = err.errno().unwrap_or(mochi_user_syscall::EIO);
            reply.extend_from_slice(&status.to_le_bytes());
        }
    }
    let _ = platform::ipc::reply(sender, &reply);
}

fn reply_spawn(sender: u64, result: Result<u64, mochi_user_syscall::SysError>) {
    let mut reply = [0u8; 16];
    match result {
        Ok(pid) => {
            reply[..8].copy_from_slice(&0u64.to_le_bytes());
            reply[8..16].copy_from_slice(&pid.to_le_bytes());
        }
        Err(err) => {
            reply[..8]
                .copy_from_slice(&err.errno().unwrap_or(mochi_user_syscall::EIO).to_le_bytes());
        }
    }
    let _ = platform::ipc::reply(sender, &reply);
}

fn parse_decision_request(
    buf: &[u8],
) -> Result<platform::capability::CapabilityDecisionRequest, mochi_user_syscall::SysError> {
    platform::capability::decode_decision_request(buf)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))
}

fn parse_persistent_query(
    buf: &[u8],
) -> Result<platform::capability::CapabilityRequest, mochi_user_syscall::SysError> {
    platform::capability::decode_request(buf)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))
}

pub(crate) fn serve_capability_requests(state: CapabilityServiceState) -> ! {
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(err) => {
            platform::println!(
                "capability.service: endpoint create failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    };
    platform::println!("capability.service: ready");
    let mut buf = [0u8; 1024];
    loop {
        let msg = match platform::ipc::wait(endpoint, &mut buf) {
            Ok(msg) => msg,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        let slice = &buf[..len.min(buf.len())];
        let opcode = if slice.len() >= 4 {
            u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
        } else {
            0
        };
        if opcode == RESOLVE_CAPS_OPCODE {
            let result = parse_resolve_caps_request(slice)
                .and_then(|path| resolve_capabilities_for_path(&state.package_index, &path));
            reply_capabilities(sender, result);
            continue;
        }
        if opcode == SPAWN_APP_OPCODE {
            let result = spawn_application_from_manifest(
                &state.package_index,
                &state.app_prompt_policy,
                sender,
                slice,
            );
            reply_spawn(sender, result);
            continue;
        }
        if opcode == platform::capability::CAPABILITY_DECISION_OPCODE {
            let status = parse_decision_request(slice)
                .and_then(|decision| {
                    authorize_dynamic_capability(
                        &state.package_index,
                        decision.decision,
                        decision.reserved,
                        &decision.request,
                    )
                })
                .map(|_| REPLY_OK)
                .unwrap_or_else(|err| err.errno().unwrap_or(mochi_user_syscall::EIO));
            capability_reply(sender, status);
            continue;
        }
        if opcode == platform::capability::CAPABILITY_PERSISTENT_QUERY_OPCODE {
            let status = parse_persistent_query(slice)
                .and_then(|request| {
                    authorize_persistent_capability(&state.package_index, sender, &request)
                })
                .map(|_| REPLY_OK)
                .unwrap_or_else(|err| err.errno().unwrap_or(mochi_user_syscall::EIO));
            capability_reply(sender, status);
            continue;
        }
        capability_reply(sender, mochi_user_syscall::EINVAL);
    }
}
