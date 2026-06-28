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
    and rsp, -16
    call service_main
1:
    hlt
    jmp 1b
"#
);

const CAPABILITY_SERVICE_PATH: &str = "/system/services/capability.service";
const CAPABILITY_SERVICE_MANIFEST_PATH: &str = "/system/services/capability.service.toml";

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

fn spawn_capability_service() -> Result<u64, mochi_user_syscall::SysError> {
    let manifest = platform::file::read_to_end_path(CAPABILITY_SERVICE_MANIFEST_PATH)?;
    let text = core::str::from_utf8(&manifest)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = parse_capability_requires(text);
    let caps_nul = encode_nul_list(&caps);
    platform::service::spawn_manifest(
        CAPABILITY_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        None,
        Some(caps_nul.as_slice()),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main() -> ! {
    main();
    platform::process::exit(0)
}

fn main() {
    platform::println!("core.service: start");
    match spawn_capability_service() {
        Ok(pid) => {
            platform::println!("core.service: capability.service spawned pid={}", pid);
            match platform::service::register_delegate(
                platform::service::DELEGATE_SERVICE_SPAWN,
                pid,
            ) {
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
