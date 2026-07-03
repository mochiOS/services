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

const DRIVERS_PACKAGE_ID: &str = "org.mochios.drivers";
const SIGNATURE_PACKAGE_ID: &str = "org.mochios.signature";
const PACKAGE_PACKAGE_ID: &str = "org.mochios.package";
const RESOLVE_CAPS_OPCODE: u32 = 0x4341_5053;
const REPLY_OK: u64 = 0;

fn capability_reply(sender: u64, status: u64) {
    let _ = platform::ipc::reply(sender, &status.to_le_bytes());
}

#[derive(Default)]
struct PackageIndex {
    by_binary: BTreeMap<String, String>,
    by_package: BTreeMap<String, String>,
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
            platform::println!(
                "capability.service: invalid package manifest {}",
                manifest_path
            );
            continue;
        };
        if let Some(previous) = index
            .by_package
            .insert(manifest.package_id.clone(), manifest_path.clone())
        {
            platform::println!(
                "capability.service: duplicate package {} in {} and {}",
                manifest.package_id,
                previous,
                manifest_path
            );
            index.duplicate = true;
        }
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

fn is_known_capability(name: &str) -> bool {
    matches!(
        name,
        "fs.read.user.documents"
            | "fs.write.user.documents"
            | "fs.read.user.downloads"
            | "fs.write.user.downloads"
            | "fs.read.user.desktop"
            | "fs.write.user.desktop"
            | "fs.read.user.pictures"
            | "fs.write.user.pictures"
            | "fs.read.user.music"
            | "fs.write.user.music"
            | "fs.read.user.videos"
            | "fs.write.user.videos"
            | "fs.read.user"
            | "fs.write.user"
            | "fs.read.tmp"
            | "fs.write.tmp"
            | "fs.read.removable"
            | "fs.write.removable"
            | "fs.read.all"
            | "fs.write.all"
            | "net.connect"
            | "net.listen"
            | "net.raw"
            | "ipc.client"
            | "ipc.server"
            | "process.spawn"
            | "process.inspect"
            | "process.kill"
            | "window.create"
            | "window.overlay"
            | "window.capture"
            | "display.read"
            | "display.capture"
            | "input.keyboard"
            | "input.keyboard.global"
            | "input.pointer"
            | "input.pointer.global"
            | "input.gamepad"
            | "audio.playback"
            | "audio.record"
            | "clipboard.read"
            | "clipboard.write"
            | "notification.send"
            | "camera.access"
            | "microphone.access"
            | "location.access"
            | "bluetooth.access"
            | "usb.access"
            | "serial.access"
            | "power.shutdown"
            | "power.reboot"
            | "power.suspend"
            | "system.time.read"
            | "system.time.set"
            | "system.info.read"
            | "system.logs.read"
            | "package.install"
            | "package.remove"
            | "package.update"
            | "service.register"
            | "service.control"
            | "vm.create"
            | "vm.control"
            | "dma.allocate"
            | "memory.phys.map"
            | "memory.phys.translate"
            | "kernel.module.load"
            | "kernel.debug"
            | "device.gpu"
            | "device.audio"
            | "device.input"
            | "device.storage"
            | "device.net"
            | "account.self.read"
            | "account.self.modify"
            | "account.other.read"
            | "account.other.modify"
            | "settings.read"
            | "settings.write"
            | "capabilities.manage"
            | "unsandboxed"
            | "developer.debug"
            | "developer.profile"
            | "developer.tracing"
            | "signature.db.read"
            | "signature.db.write"
    )
}

fn validate_capabilities(
    binary_path: &str,
    caps: &[String],
) -> Result<(), mochi_user_syscall::SysError> {
    for cap in caps {
        if !is_known_capability(cap.as_str()) {
            platform::println!(
                "capability.service: unknown capability {} requested by {}",
                cap,
                binary_path
            );
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    Ok(())
}

fn binary_caps<'a>(
    manifest: &'a platform::package::PackageManifest,
    binary_path: &str,
) -> Result<&'a [String], mochi_user_syscall::SysError> {
    let caps = manifest
        .binary_requires(binary_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    validate_capabilities(binary_path, caps)?;
    Ok(caps)
}

fn service_binary_path(manifest: &platform::package::PackageManifest) -> Option<&str> {
    manifest
        .binaries
        .iter()
        .find(|binary| binary.kind.as_deref() == Some("service"))
        .map(|binary| binary.path.as_str())
}

fn package_manifest_by_id(
    index: &PackageIndex,
    package_id: &str,
) -> Result<platform::package::PackageManifest, mochi_user_syscall::SysError> {
    if let Some(manifest_path) = index.by_package.get(package_id) {
        return platform::package::read_manifest(manifest_path).ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        });
    }

    let Some(package_dir) = package_id.rsplit('.').next() else {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOENT as i64,
        ));
    };
    let fallback_path = alloc::format!("/system/packages/{}/manifest.toml", package_dir);
    let manifest = platform::package::read_manifest(&fallback_path).ok_or_else(|| {
        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64)
    })?;
    if manifest.package_id != package_id {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    Ok(manifest)
}

fn resolve_capabilities_for_path(
    binary_path: &str,
) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    let index = build_package_index();
    if index.duplicate {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let manifest_path = index
        .by_binary
        .get(binary_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let manifest = platform::package::read_manifest(manifest_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = binary_caps(&manifest, binary_path)?;
    Ok(caps.to_vec())
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

fn read_request_str(bytes: &[u8], len: u16) -> Result<&str, mochi_user_syscall::SysError> {
    let len = len as usize;
    if len > bytes.len() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    core::str::from_utf8(&bytes[..len])
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))
}

fn authorize_dynamic_capability(
    index: &PackageIndex,
    decision: platform::capability::CapabilityDecision,
    requester_thread: u64,
    request: &platform::capability::CapabilityRequest,
) -> Result<(), mochi_user_syscall::SysError> {
    if request.opcode != platform::capability::CAPABILITY_PROMPT_OPCODE
        || request.process_id == 0
        || requester_thread == 0
        || request.interactive == 0
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    if decision == platform::capability::CapabilityDecision::Deny {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    if request.capability_class != platform::capability::CapabilityClass::UserGrantable {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let executable = read_request_str(&request.executable.path, request.executable.path_len)?;
    if index.by_binary.contains_key(executable) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let capability = read_request_str(&request.capability, request.capability_len)?;
    if !is_known_capability(capability)
        || platform::capability::capability_from_string(capability)
            != platform::capability::CapabilityClass::UserGrantable
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    platform::syscall::call3(
        platform::syscall::SyscallNumber::CapTransfer,
        requester_thread,
        capability.as_ptr() as u64,
        capability.len() as u64,
    )
    .map(|_| ())
}

fn parse_decision_request(
    buf: &[u8],
) -> Result<platform::capability::CapabilityDecisionRequest, mochi_user_syscall::SysError> {
    if buf.len() < core::mem::size_of::<platform::capability::CapabilityDecisionRequest>() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let request = unsafe {
        core::ptr::read_unaligned(
            buf.as_ptr()
                .cast::<platform::capability::CapabilityDecisionRequest>(),
        )
    };
    if request.opcode != platform::capability::CAPABILITY_DECISION_OPCODE {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    Ok(request)
}

fn serve_capability_requests() -> ! {
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
    let index = build_package_index();
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
                .and_then(|path| resolve_capabilities_for_path(&path));
            reply_capabilities(sender, result);
            continue;
        }
        if opcode == platform::capability::CAPABILITY_DECISION_OPCODE {
            let status = parse_decision_request(slice)
                .and_then(|decision| {
                    authorize_dynamic_capability(
                        &index,
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
        capability_reply(sender, mochi_user_syscall::EINVAL);
    }
}

fn encode_spawn_args(items: &[String]) -> Vec<u8> {
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

fn spawn_service_by_package(
    index: &PackageIndex,
    package_id: &str,
) -> Result<u64, mochi_user_syscall::SysError> {
    if index.duplicate {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let manifest = package_manifest_by_id(index, package_id)?;
    let service_path = service_binary_path(&manifest)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let caps = binary_caps(&manifest, service_path)?;
    platform::println!(
        "capability.service: parsed {} caps={}",
        service_path,
        caps.len()
    );
    let caps_nul = encode_nul_list(&caps);
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    let args = [logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    platform::service::spawn_manifest(
        service_path,
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
    match spawn_service_by_package(&package_index, SIGNATURE_PACKAGE_ID) {
        Ok(pid) => {
            platform::println!("capability.service: signature.service spawned pid={}", pid);
        }
        Err(err) => {
            platform::println!(
                "capability.service: signature.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
    match spawn_service_by_package(&package_index, PACKAGE_PACKAGE_ID) {
        Ok(pid) => {
            platform::println!("capability.service: package.service spawned pid={}", pid);
        }
        Err(err) => {
            platform::println!(
                "capability.service: package.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
    match spawn_service_by_package(&package_index, DRIVERS_PACKAGE_ID) {
        Ok(pid) => {
            platform::println!("capability.service: drivers.service spawned pid={}", pid);
            match register_delegate_with_retry(platform::service::DELEGATE_DRIVER_SPAWN, pid) {
                Ok(_) => {
                    platform::println!(
                        "capability.service: registered drivers.service as driver delegate"
                    );
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
    serve_capability_requests();
}
