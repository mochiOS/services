use alloc::string::ToString;
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::spawn_support::{encode_spawn_args, resolve_capabilities, sys_error};

fn spawn_bundle(
    entry_path: &str,
    args: Option<&[u8]>,
    logger_endpoint: u64,
) -> Result<u64, mochi_user_syscall::SysError> {
    let caps_nul = resolve_capabilities(entry_path)?;
    let mut spawn_args = Vec::new();
    if let Some(args) = args {
        let text = core::str::from_utf8(args).map_err(|_| sys_error(mochi_user_syscall::EINVAL))?;
        for part in text.split('\0') {
            if !part.is_empty() {
                spawn_args.push(part.to_string());
            }
        }
    }
    if logger_endpoint != 0 {
        spawn_args.push(logger_endpoint.to_string());
    }
    let args_nul = encode_spawn_args(&spawn_args);
    platform::service::spawn_manifest(
        entry_path,
        platform::service::ROLE_DRIVER,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

pub(crate) fn spawn(entry_path: &str, args: Option<&[u8]>, logger_endpoint: u64) -> bool {
    match spawn_bundle(entry_path, args, logger_endpoint) {
        Ok(pid) => {
            platform::logln!("drivers.service: spawned driver pid={}", pid);
            true
        }
        Err(err) => {
            platform::logln!(
                "drivers.service: spawn failed {} errno={}",
                entry_path,
                err.errno().unwrap_or(0)
            );
            false
        }
    }
}
