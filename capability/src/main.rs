#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
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
const DRIVERS_PACKAGE_MANIFEST_PATH: &str = "/system/packages/drivers/manifest.toml";

#[derive(Default)]
struct PackageIndex {
    by_binary: BTreeMap<String, String>,
    duplicate: bool,
}

fn walk_package_tree(path: &str, out: &mut Vec<String>) {
    let Ok(entries) = platform::file::read_dir_names(path) else {
        return;
    };
    for name in entries {
        let child = alloc::format!("{}/{}", path.trim_end_matches('/'), name);
        if name == "manifest.toml" {
            out.push(child);
            continue;
        }
        walk_package_tree(&child, out);
    }
}

fn build_package_index() -> PackageIndex {
    let mut manifest_paths = Vec::new();
    walk_package_tree("/system/packages", &mut manifest_paths);
    let mut index = PackageIndex::default();
    for manifest_path in manifest_paths {
        let Some(manifest) = platform::package::read_manifest(&manifest_path) else {
            platform::println!("capability.service: invalid package manifest {}", manifest_path);
            continue;
        };
        for binary in manifest.binaries {
            if let Some(previous) = index
                .by_binary
                .insert(binary.path.clone(), manifest_path.clone())
            {
                platform::println!(
                    "capability.service: duplicate binary {} in {} and {}",
                    binary.path,
                    previous,
                    manifest_path
                );
                index.duplicate = true;
            }
        }
    }
    index
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

fn spawn_drivers_service(index: &PackageIndex) -> Result<u64, mochi_user_syscall::SysError> {
    if index.duplicate {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
    }
    let manifest_path = index
        .by_binary
        .get(DRIVERS_SERVICE_PATH)
        .cloned()
        .unwrap_or_else(|| DRIVERS_PACKAGE_MANIFEST_PATH.to_string());
    let manifest = platform::package::read_manifest(&manifest_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = manifest.binary_requires(DRIVERS_SERVICE_PATH).unwrap_or(&[]);
    platform::println!("capability.service: parsed drivers.service package caps={}", caps.len());
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
    let package_index = build_package_index();
    match spawn_drivers_service(&package_index) {
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
