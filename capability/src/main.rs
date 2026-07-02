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

const DRIVERS_SERVICE_PATH: &str = "/system/services/drivers.service";
const DRIVERS_SERVICE_MANIFEST_PATH: &str = "/system/services/drivers.service.toml";

fn parse_capability_requires(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_caps = false;
    let mut collecting = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_caps = line == "[capabilities]";
            collecting = false;
            continue;
        }
        if !in_caps {
            continue;
        }
        if let Some((key, rest)) = line.split_once('=') {
            if key.trim() != "requires" {
                continue;
            }
            collecting = true;
            collect_capability_line(&mut out, rest);
            continue;
        }
        if collecting {
            collect_capability_line(&mut out, line);
        }
    }

    out
}

fn collect_capability_line(out: &mut Vec<String>, line: &str) {
    for part in line.split(',') {
        let item = part.trim().trim_matches(|ch| ch == '[' || ch == ']' || ch == '"');
        if !item.is_empty() {
            out.push(item.to_string());
        }
    }
}

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

fn spawn_drivers_service() -> Result<u64, mochi_user_syscall::SysError> {
    let manifest = platform::file::read_to_end_path(DRIVERS_SERVICE_MANIFEST_PATH)?;
    let text = core::str::from_utf8(&manifest)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = parse_capability_requires(text);
    platform::println!(
        "capability.service: parsed drivers.service manifest caps={}",
        caps.len()
    );
    let caps_nul = encode_nul_list(&caps);
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    let args = [logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    platform::service::spawn_manifest(
        DRIVERS_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("capability.service: start");
    match spawn_drivers_service() {
        Ok(pid) => {
            platform::println!("capability.service: drivers.service spawned pid={}", pid);
            match register_delegate_with_retry(platform::service::DELEGATE_DRIVER_SPAWN, pid) {
                Ok(_) => {
                    platform::println!("capability.service: registered drivers.service as driver delegate");
                }
                Err(err) => {
                    platform::println!(
                        "capability.service: delegate registration failed errno={}",
                        err.errno().unwrap_or(0)
                    );
                    platform::process::exit(1);
                }
            }
        }
        Err(err) => {
            platform::println!(
                "capability.service: drivers.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
    loop {
        platform::thread::yield_now();
    }
}
