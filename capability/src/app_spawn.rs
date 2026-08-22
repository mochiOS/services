use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::dynamic_grant::prompt_shell_for_capability;
use crate::package_index::PackageIndex;
use crate::policy::{AppPromptPolicy, needs_app_prompt};
use crate::resolver::{binary_caps, encode_nul_list};

pub(crate) const SPAWN_APP_OPCODE: u32 = 0x4150_5053;
const EXEC_MANIFEST_ENV_PREFIX: &str = "__MOCHI_EXEC_ENV=";
const EXEC_MANIFEST_APP_ID_PREFIX: &str = "__MOCHI_EXEC_APP_ID=";

#[repr(C)]
#[derive(Clone, Copy)]
struct SpawnAppRequestHeader {
    opcode: u32,
    shell_endpoint: u64,
    interactive: u8,
    reserved: [u8; 7],
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

pub(crate) fn spawn_application_from_manifest(
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
        platform::logln!(
            "capability.service: interactive app launch approved path={}",
            entry_path
        );
    }
    let caps_nul = encode_nul_list(&caps);
    let mut spawn_items = Vec::new();
    spawn_items.push(format!(
        "{EXEC_MANIFEST_APP_ID_PREFIX}{}",
        manifest.package_id
    ));
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
    let args_nul = encode_spawn_args(&spawn_items);
    platform::service::spawn_manifest_for_requester(
        entry_path,
        platform::service::ROLE_APPLICATION,
        sender,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

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
