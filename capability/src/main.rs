#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::arch::global_asm;
use core::convert::TryInto;
use mochi_user_platform as platform;
use mochi_user_syscall as syscall;
use sha2::{Digest, Sha256};

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
const CAPABILITY_PACKAGE_ID: &str = "org.mochios.capability";
const RESOLVE_CAPS_OPCODE: u32 = 0x4341_5053;
const SPAWN_APP_OPCODE: u32 = 0x4150_5053;
const EXEC_MANIFEST_ENV_PREFIX: &str = "__MOCHI_EXEC_ENV=";
const REPLY_OK: u64 = 0;
const GRANTS_PATH: &str = "/system/policy/capability-grants.db";
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const FILE_MODE_644: u64 = 0o644;

#[repr(C)]
#[derive(Clone, Copy)]
struct SpawnAppRequestHeader {
    opcode: u32,
    shell_endpoint: u64,
    interactive: u8,
    reserved: [u8; 7],
}

#[derive(Default)]
struct AppPromptPolicy {
    interactive: BTreeSet<String>,
}

fn capability_reply(sender: u64, status: u64) {
    let _ = platform::ipc::reply(sender, &status.to_le_bytes());
}

fn stderr_line(message: &str) {
    let _ = platform::io::stderr(message.as_bytes());
    let _ = platform::io::stderr(b"\n");
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_toml_string_array(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    let inner = value.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let trimmed = item.trim();
        let unquoted = trimmed.strip_prefix('"')?.strip_suffix('"')?;
        out.push(unquoted.to_string());
    }
    Some(out)
}

fn load_app_prompt_policy(index: &PackageIndex) -> AppPromptPolicy {
    let Some(record) = index.by_package.get(CAPABILITY_PACKAGE_ID) else {
        return AppPromptPolicy::default();
    };
    let Ok(bytes) = platform::file::read_to_end_path(&record.manifest_path) else {
        return AppPromptPolicy::default();
    };
    let Ok(text) = core::str::from_utf8(&bytes) else {
        return AppPromptPolicy::default();
    };

    let mut policy = AppPromptPolicy::default();
    let mut section = "";
    let mut collecting = false;
    let mut array_body = String::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            collecting = false;
            array_body.clear();
            continue;
        }
        if collecting {
            if let Some(end) = line.find(']') {
                if !array_body.is_empty() {
                    array_body.push(' ');
                }
                array_body.push_str(line[..end].trim());
                if let Some(items) = parse_toml_string_array(&format!("[{}]", array_body)) {
                    for item in items {
                        if platform::capability::capability_from_string(item.as_str())
                            == platform::capability::CapabilityClass::UserGrantable
                        {
                            policy.interactive.insert(item);
                        }
                    }
                }
                collecting = false;
                array_body.clear();
                continue;
            }
            if !array_body.is_empty() {
                array_body.push(' ');
            }
            array_body.push_str(line);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if section != "prompt" || key.trim() != "interactive_capabilities" {
            continue;
        }
        let value = value.trim();
        if value.contains(']') {
            if let Some(items) = parse_toml_string_array(value) {
                for item in items {
                    if platform::capability::capability_from_string(item.as_str())
                        == platform::capability::CapabilityClass::UserGrantable
                    {
                        policy.interactive.insert(item);
                    }
                }
            }
        } else if let Some(start) = value.find('[') {
            collecting = true;
            array_body.clear();
            array_body.push_str(value[start + 1..].trim());
        }
    }

    policy
}

fn interactive_capability_policy(policy: &AppPromptPolicy, capability: &str) -> bool {
    policy.interactive.contains(capability)
}

fn current_process_id() -> Result<u64, mochi_user_syscall::SysError> {
    syscall::call0(syscall::SyscallNumber::GetPid)
}

fn prompt_shell_for_capability(
    shell_endpoint: u64,
    executable: &str,
    capability: &str,
    reason: &str,
) -> Result<(), mochi_user_syscall::SysError> {
    if shell_endpoint == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    if executable.len() > 256 || capability.len() > 64 || reason.len() > 128 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }

    let process_id = current_process_id()?;
    let mut request = platform::capability::CapabilityRequest {
        opcode: platform::capability::CAPABILITY_PROMPT_OPCODE,
        process_id,
        executable: platform::capability::ExecutableIdentity::default(),
        capability_class: platform::capability::CapabilityClass::UserGrantable,
        capability_len: capability.len() as u16,
        resource: platform::capability::ResourceDescriptor::default(),
        reason_len: reason.len() as u16,
        interactive: 1,
        decision_scope: 0,
        reserved0: 0,
        capability: [0; 64],
        reason: [0; 128],
    };
    request.executable.path_len = executable.len() as u16;
    request.executable.path[..executable.len()].copy_from_slice(executable.as_bytes());
    request.capability[..capability.len()].copy_from_slice(capability.as_bytes());
    request.reason[..reason.len()].copy_from_slice(reason.as_bytes());

    let mut reply = [0u8; 8];
    let msg = syscall::call5(
        syscall::SyscallNumber::IpcCall,
        shell_endpoint,
        (&request as *const platform::capability::CapabilityRequest) as u64,
        core::mem::size_of::<platform::capability::CapabilityRequest>() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    )?;
    if (msg & 0xffff_ffff) < 4 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let decision =
        u32::from_le_bytes(reply[..4].try_into().map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?);
    if decision == platform::capability::CapabilityDecision::AllowOnce as u32
        || decision == platform::capability::CapabilityDecision::AllowForProcess as u32
        || decision == platform::capability::CapabilityDecision::AllowPersistently as u32
        || decision == platform::capability::CapabilityDecision::AllowAllUserGrantable as u32
    {
        Ok(())
    } else {
        Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ))
    }
}

fn ensure_policy_dir() {
    let _ = platform::file::create_dir("/system", 0o755);
    let _ = platform::file::create_dir("/system/policy", 0o755);
}

fn write_file(path: &str, bytes: &[u8]) -> Result<(), mochi_user_syscall::SysError> {
    let fd = platform::file::openat_path(-100, path, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE_644)?;
    let mut written = 0usize;
    while written < bytes.len() {
        let n = platform::file::write(
            fd,
            bytes[written..].as_ptr() as u64,
            (bytes.len() - written) as u64,
        )? as usize;
        if n == 0 {
            let _ = platform::file::close(fd);
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EIO as i64,
            ));
        }
        written += n;
    }
    let _ = platform::file::close(fd);
    Ok(())
}

fn append_persistent_grant(
    executable: &str,
    digest: &[u8; 32],
    capability: &str,
    resource: Option<&str>,
    all_user_grantable: bool,
) -> Result<(), mochi_user_syscall::SysError> {
    ensure_policy_dir();
    let mut data = platform::file::read_to_end_path(GRANTS_PATH).unwrap_or_default();
    data.extend_from_slice(executable.as_bytes());
    data.push(b'\t');
    data.extend_from_slice(hex_digest(digest).as_bytes());
    data.push(b'\t');
    data.extend_from_slice(capability.as_bytes());
    data.push(b'\t');
    data.extend_from_slice(if all_user_grantable {
        b"all-user"
    } else {
        b"single"
    });
    data.push(b'\t');
    if let Some(resource) = resource {
        data.extend_from_slice(resource.as_bytes());
    }
    data.push(b'\n');
    write_file(GRANTS_PATH, &data)
}

fn transfer_user_grant(
    requester_thread: u64,
    capability: &str,
    executable: &str,
) -> Result<(), mochi_user_syscall::SysError> {
    let mut payload = Vec::with_capacity(capability.len() + 1 + executable.len());
    payload.extend_from_slice(capability.as_bytes());
    payload.push(0x1f);
    payload.extend_from_slice(executable.as_bytes());
    platform::syscall::call3(
        platform::syscall::SyscallNumber::CapTransfer,
        requester_thread,
        payload.as_ptr() as u64,
        payload.len() as u64,
    )
    .map(|_| ())
}

fn grant_db_matches(
    executable: &str,
    digest: &[u8; 32],
    capability: &str,
    resource: Option<&str>,
) -> bool {
    let Ok(data) = platform::file::read_to_end_path(GRANTS_PATH) else {
        return false;
    };
    let digest_hex = hex_digest(digest);
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(|b| *b == b'\t');
        let Some(path) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let Some(hash) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let Some(grant_cap) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let Some(scope) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let grant_resource = fields
            .next()
            .and_then(|v| core::str::from_utf8(v).ok())
            .unwrap_or("");
        if path != executable || hash != digest_hex {
            continue;
        }
        if scope == "all-user" {
            return true;
        }
        if scope == "single" && grant_cap == capability {
            let resource_matches = match resource {
                Some(resource) => grant_resource == resource,
                None => grant_resource.is_empty(),
            };
            if resource_matches {
                return true;
            }
        }
    }
    false
}

#[derive(Default)]
struct PackageIndex {
    by_binary: BTreeMap<String, PackageRecord>,
    by_package: BTreeMap<String, PackageRecord>,
    duplicate: bool,
}

#[derive(Clone)]
struct PackageRecord {
    manifest_path: String,
    manifest_hash: [u8; 32],
}

fn manifest_hash(path: &str) -> Result<[u8; 32], mochi_user_syscall::SysError> {
    let bytes = platform::file::read_to_end_path(path)?;
    let digest = Sha256::digest(&bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
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
        let Ok(hash) = manifest_hash(&manifest_path) else {
            platform::println!(
                "capability.service: failed to hash manifest {}",
                manifest_path
            );
            index.duplicate = true;
            continue;
        };
        let record = PackageRecord {
            manifest_path: manifest_path.clone(),
            manifest_hash: hash,
        };
        if let Some(previous) = index.by_package.get(&manifest.package_id) {
            if previous.manifest_hash != record.manifest_hash {
                platform::println!(
                    "capability.service: duplicate package {} in {} and {}",
                    manifest.package_id,
                    previous.manifest_path,
                    manifest_path
                );
                index.duplicate = true;
                continue;
            }
        } else {
            index
                .by_package
                .insert(manifest.package_id.clone(), record.clone());
        }
        for binary in manifest.binaries {
            if let Some(previous) = index.by_binary.get(&binary.path) {
                if previous.manifest_hash != record.manifest_hash {
                    platform::println!(
                        "capability.service: duplicate binary {} in {} and {}",
                        binary.path,
                        previous.manifest_path,
                        manifest_path
                    );
                    index.duplicate = true;
                }
            } else {
                index.by_binary.insert(binary.path.clone(), record.clone());
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
            | "window.decorate"
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

fn needs_app_prompt(policy: &AppPromptPolicy, capability: &str) -> bool {
    interactive_capability_policy(policy, capability)
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
        return platform::package::read_manifest(&manifest_path.manifest_path).ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        });
    }

    if let Some(package_dir) = package_id.rsplit('.').next() {
        let fallback_path = alloc::format!("/system/packages/{}/manifest.toml", package_dir);
        if let Some(manifest) = platform::package::read_manifest(&fallback_path) {
            if manifest.package_id == package_id {
                return Ok(manifest);
            }
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }

    Err(mochi_user_syscall::SysError::from_raw(
        mochi_user_syscall::ENOENT as i64,
    ))
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
    let manifest = platform::package::read_manifest(&manifest_path.manifest_path)
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

fn parse_nul_list(
    bytes: &[u8],
    max_items: usize,
) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    let mut out = Vec::new();
    for part in bytes.split(|byte| *byte == 0) {
        if part.is_empty() {
            continue;
        }
        let text = core::str::from_utf8(part).map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
        out.push(text.to_string());
        if out.len() > max_items {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    Ok(out)
}

fn spawn_application_from_manifest(
    index: &PackageIndex,
    policy: &AppPromptPolicy,
    sender: u64,
    buf: &[u8],
) -> Result<u64, mochi_user_syscall::SysError> {
    if buf.len() <= core::mem::size_of::<SpawnAppRequestHeader>() || index.duplicate {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    if platform::capability::check_thread(sender, "process.spawn")? == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let header = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<SpawnAppRequestHeader>()) };
    if header.opcode != SPAWN_APP_OPCODE {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let items = parse_nul_list(&buf[core::mem::size_of::<SpawnAppRequestHeader>()..], 64)?;
    let Some(entry_path) = items.first() else {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    };
    if !entry_path.starts_with('/') {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }

    let manifest_record = index
        .by_binary
        .get(entry_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let manifest = platform::package::read_manifest(&manifest_record.manifest_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let binary = manifest
        .binary(entry_path)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if binary.kind.as_deref() != Some("application") {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let caps = binary_caps(&manifest, entry_path)?;
    let mut prompted = false;
    for cap in caps {
        if platform::capability::capability_from_string(cap.as_str())
            != platform::capability::CapabilityClass::UserGrantable
        {
            continue;
        }
        if !needs_app_prompt(policy, cap) {
            continue;
        }
        prompted = true;
        if header.interactive == 0 || header.shell_endpoint == 0 {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
        prompt_shell_for_capability(header.shell_endpoint, entry_path, cap, "application launch")?;
    }
    if prompted {
        platform::println!(
            "capability.service: interactive app launch approved path={}",
            entry_path
        );
    }
    let caps_nul = encode_nul_list(&caps);
    let mut spawn_items = Vec::new();
    spawn_items.push(format!(
        "{}MOCHI_EXECUTABLE_PATH={}",
        EXEC_MANIFEST_ENV_PREFIX, entry_path
    ));
    spawn_items.push(format!(
        "{}MOCHI_SHELL_ENDPOINT={}",
        EXEC_MANIFEST_ENV_PREFIX, header.shell_endpoint
    ));
    spawn_items.push(format!(
        "{}MOCHI_STDIO_ENDPOINT={}",
        EXEC_MANIFEST_ENV_PREFIX, header.shell_endpoint
    ));
    spawn_items.push(format!(
        "{}MOCHI_PROMPT_MODE={}",
        EXEC_MANIFEST_ENV_PREFIX,
        if header.interactive == 0 {
            "deny"
        } else {
            "interactive"
        }
    ));
    spawn_items.extend(items[1..].iter().cloned());
    let args_nul = encode_nul_list(&spawn_items);
    platform::service::spawn_manifest(
        entry_path,
        platform::service::ROLE_APPLICATION,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
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
    let mut digest = [0u8; 32];
    let needs_digest = request.executable.digest != [0; 32]
        || matches!(
            decision,
            platform::capability::CapabilityDecision::AllowPersistently
                | platform::capability::CapabilityDecision::AllowAllUserGrantable
        );
    if needs_digest {
        let executable_bytes = platform::file::read_to_end_path(executable)?;
        let actual_digest = Sha256::digest(&executable_bytes);
        digest.copy_from_slice(&actual_digest);
        if request.executable.digest != [0; 32] && request.executable.digest != digest {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
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
    if let Some(record) = index.by_binary.get(executable) {
        let manifest =
            platform::package::read_manifest(&record.manifest_path).ok_or_else(|| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
        let declared_caps = binary_caps(&manifest, executable)?;
        if !declared_caps.iter().any(|cap| cap.as_str() == capability) {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
    }
    if matches!(
        decision,
        platform::capability::CapabilityDecision::AllowPersistently
            | platform::capability::CapabilityDecision::AllowAllUserGrantable
    ) {
        let resource = if request.resource.path_len == 0 {
            None
        } else {
            Some(read_request_str(
                &request.resource.path,
                request.resource.path_len,
            )?)
        };
        append_persistent_grant(
            executable,
            &digest,
            capability,
            resource,
            decision == platform::capability::CapabilityDecision::AllowAllUserGrantable,
        )?;
    }

    transfer_user_grant(requester_thread, capability, executable)
}

fn authorize_persistent_capability(
    index: &PackageIndex,
    requester_thread: u64,
    request: &platform::capability::CapabilityRequest,
) -> Result<(), mochi_user_syscall::SysError> {
    if request.opcode != platform::capability::CAPABILITY_PERSISTENT_QUERY_OPCODE
        || request.process_id == 0
        || requester_thread == 0
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
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
    let executable_bytes = platform::file::read_to_end_path(executable)?;
    let actual_digest = Sha256::digest(&executable_bytes);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&actual_digest);
    if request.executable.digest != [0; 32] && request.executable.digest != digest {
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
    let resource = if request.resource.path_len == 0 {
        None
    } else {
        Some(read_request_str(
            &request.resource.path,
            request.resource.path_len,
        )?)
    };
    if !grant_db_matches(executable, &digest, capability, resource) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    transfer_user_grant(requester_thread, capability, executable)
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

fn parse_persistent_query(
    buf: &[u8],
) -> Result<platform::capability::CapabilityRequest, mochi_user_syscall::SysError> {
    if buf.len() < core::mem::size_of::<platform::capability::CapabilityRequest>() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let request = unsafe {
        core::ptr::read_unaligned(
            buf.as_ptr()
                .cast::<platform::capability::CapabilityRequest>(),
        )
    };
    if request.opcode != platform::capability::CAPABILITY_PERSISTENT_QUERY_OPCODE {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    Ok(request)
}

fn serve_capability_requests(index: PackageIndex, app_prompt_policy: AppPromptPolicy) -> ! {
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
                .and_then(|path| resolve_capabilities_for_path(&path));
            reply_capabilities(sender, result);
            continue;
        }
        if opcode == SPAWN_APP_OPCODE {
            let result = spawn_application_from_manifest(&index, &app_prompt_policy, sender, slice);
            reply_spawn(sender, result);
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
        if opcode == platform::capability::CAPABILITY_PERSISTENT_QUERY_OPCODE {
            let status = parse_persistent_query(slice)
                .and_then(|request| authorize_persistent_capability(&index, sender, &request))
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
    let app_prompt_policy = load_app_prompt_policy(&package_index);
    match spawn_service_by_package(&package_index, SIGNATURE_PACKAGE_ID) {
        Ok(pid) => {
            platform::println!("capability.service: signature.service spawned pid={}", pid);
        }
        Err(err) => {
            stderr_line(&alloc::format!(
                "capability.service: signature.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
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
            stderr_line(&alloc::format!(
                "capability.service: package.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
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
                    stderr_line(&alloc::format!(
                        "capability.service: delegate registration failed errno={}",
                        err.errno().unwrap_or(0)
                    ));
                    platform::println!(
                        "capability.service: delegate registration failed errno={}",
                        err.errno().unwrap_or(0)
                    );
                    platform::process::exit(1);
                }
            }
        }
        Err(err) => {
            stderr_line(&alloc::format!(
                "capability.service: drivers.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            ));
            platform::println!(
                "capability.service: drivers.service spawn failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
    serve_capability_requests(package_index, app_prompt_policy);
}
