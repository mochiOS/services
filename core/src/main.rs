#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::arch::global_asm;
use mochi_user_platform as platform;

global_asm!(
    r#"
    .global _start
_start:
    xor rbp, rbp
    mov rdi, rsp
    and rsp, -16
    call service_main
1:
    hlt
    jmp 1b
"#
);

const LOGGER_SERVICE_PATH: &str = "/system/services/logger.service";
const LOGGER_PACKAGE_MANIFEST_PATH: &str = "/system/packages/logger/manifest.toml";
const CAPABILITY_SERVICE_PATH: &str = "/system/services/capability.service";
const CAPABILITY_PACKAGE_MANIFEST_PATH: &str = "/system/packages/capability/manifest.toml";

fn encode_nul_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.as_bytes());
        out.push(0);
    }
    out
}

fn encode_spawn_args(items: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.resize(256, 0);
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

fn register_delegate_with_retry(kind: u64, pid: u64) -> Result<(), mochi_user_syscall::SysError> {
    let mut last_err = None;
    for _ in 0..32 {
        match platform::service::register_delegate(kind, pid) {
            Ok(_) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if err.errno().unwrap_or(0) != mochi_user_syscall::ESRCH {
                    return Err(err);
                }
                platform::thread::yield_now();
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ESRCH as i64)
    }))
}

fn spawn_logger_service() -> Result<u64, mochi_user_syscall::SysError> {
    let bootstrap = platform::ipc::create()?;
    let manifest = platform::package::read_manifest(LOGGER_PACKAGE_MANIFEST_PATH)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = manifest.binary_requires(LOGGER_SERVICE_PATH).unwrap_or(&[]);
    let caps_nul = encode_nul_list(&caps);
    let args = [bootstrap.to_string()];
    let args_nul = encode_spawn_args(&args);
    let pid = platform::service::spawn_manifest(
        LOGGER_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )?;
    let mut buf = [0u8; 16];
    let msg = platform::ipc::wait(bootstrap, &mut buf)?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
    }
    let logger_endpoint = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    platform::logger::init(logger_endpoint);
    Ok(pid)
}

fn spawn_capability_service() -> Result<u64, mochi_user_syscall::SysError> {
    let manifest = platform::package::read_manifest(CAPABILITY_PACKAGE_MANIFEST_PATH)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = manifest.binary_requires(CAPABILITY_SERVICE_PATH).unwrap_or(&[]);
    platform::println!(
        "core.service: parsed capability.service package caps={}",
        caps.len()
    );
    let caps_nul = encode_nul_list(&caps);
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    let args = [logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    platform::service::spawn_manifest(
        CAPABILITY_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(_sp: *const usize) -> ! {
    let _logger_pid = match spawn_logger_service() {
        Ok(pid) => pid,
        Err(err) => {
            platform::println!(
                "core.service: logger.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    };

    main();
    platform::process::exit(0)
}

fn main() {
    platform::println!("core.service: start");
    match spawn_capability_service() {
        Ok(pid) => {
            platform::println!("core.service: capability.service spawned pid={}", pid);
            match register_delegate_with_retry(platform::service::DELEGATE_SERVICE_SPAWN, pid) {
                Ok(_) => {
                    platform::println!(
                        "core.service: registered capability.service as service delegate"
                    );
                }
                Err(err) => {
                    platform::println!(
                        "core.service: capability delegate registration failed errno={}",
                        err.errno().unwrap_or(0)
                    );
                    platform::process::exit(1);
                }
            }
        }
        Err(err) => {
            platform::println!(
                "core.service: capability.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }

    loop {
        platform::thread::yield_now();
    }
}
