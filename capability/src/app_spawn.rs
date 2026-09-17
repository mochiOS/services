use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::dynamic_grant::{is_trusted_prompt_broker, prompt_shell_for_capability};
use crate::package_index::PackageIndex;
use crate::persistent_grant::{append_persistent_grant, has_persistent_grant};
use crate::policy::{AppPromptPolicy, needs_app_prompt};
use crate::resolver::{
    CapabilityDenyReason, application_identity, decide_binary_capabilities,
    authorize_spawn, encode_identity_args, encode_nul_list,
};

pub(crate) const SPAWN_APP_OPCODE: u32 = 0x4150_5053;
use mnu_abi::exec::ENVIRONMENT_PREFIX;

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

    let mut capability_decision =
        decide_binary_capabilities(&manifest, &manifest_record.manifest_path, entry_path)?;
    let requested_caps = capability_decision.requested.clone();
    let identity = application_identity(&manifest, &manifest_record.manifest_path)?;
    let requester_context = platform::process::thread_security_context(sender)?;
    let mut grant_context = mochi_user_syscall::ThreadSecurityContext::default();
    grant_context.effective_uid = requester_context.effective_uid;
    grant_context.effective_gid = requester_context.effective_gid;
    grant_context.subject_key_id = identity.subject_key_id;
    grant_context.provenance = identity.provenance as u8;
    let package_id = identity.package_id.as_bytes();
    let developer_id = identity.developer_id.as_bytes();
    if package_id.len() > grant_context.package_id.len()
        || developer_id.len() > grant_context.developer_id.len()
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    grant_context.package_id_len = package_id.len() as u16;
    grant_context.developer_id_len = developer_id.len() as u16;
    grant_context.package_id[..package_id.len()].copy_from_slice(package_id);
    grant_context.developer_id[..developer_id.len()].copy_from_slice(developer_id);
    let mut prompted = false;
    let mut user_allowed = Vec::new();
    for cap in &requested_caps {
        if platform::capability::capability_from_string(cap.as_str())
            != platform::capability::CapabilityClass::UserGrantable
        {
            user_allowed.push(cap.clone());
            continue;
        }
        if !needs_app_prompt(policy, cap) {
            user_allowed.push(cap.clone());
            continue;
        }
        if has_persistent_grant(&grant_context, cap, None) {
            user_allowed.push(cap.clone());
            continue;
        }
        prompted = true;
        if header.interactive == 0 || header.shell_endpoint == 0 {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
        if !is_trusted_prompt_broker(header.shell_endpoint) {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
        let decision = prompt_shell_for_capability(
            header.shell_endpoint,
            entry_path,
            cap,
            "application launch",
        )?;
        match decision {
            platform::capability::CapabilityDecision::AllowPersistently => {
                append_persistent_grant(&grant_context, cap, None, false)?;
            }
            platform::capability::CapabilityDecision::AllowAllUserGrantable => {
                append_persistent_grant(&grant_context, cap, None, true)?;
            }
            platform::capability::CapabilityDecision::AllowOnce
            | platform::capability::CapabilityDecision::AllowForProcess => {}
            platform::capability::CapabilityDecision::Deny => {
                return Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::EACCES as i64,
                ));
            }
        }
        user_allowed.push(cap.clone());
    }
    // A caller holding process.spawn delegates launch policy to this service;
    // it is not required to possess every capability of the application it
    // launches.  The earlier process.spawn check is therefore the explicit
    // caller ceiling for this path.
    let caller_allowed = requested_caps.clone();
    capability_decision =
        capability_decision.apply_runtime_constraints(&user_allowed, &caller_allowed);
    if !capability_decision.is_allowed() {
        platform::logln!(
            "capability.service: app launch denied path={} reason={:?} denied={:?}",
            entry_path,
            capability_decision.deny_reason,
            capability_decision.denied
        );
        let errno = if capability_decision.deny_reason
            == Some(CapabilityDenyReason::UnknownCapability)
        {
            mochi_user_syscall::EINVAL
        } else {
            mochi_user_syscall::EACCES
        };
        return Err(mochi_user_syscall::SysError::from_raw(errno as i64));
    }
    let caps = capability_decision.effective;
    if prompted {
        platform::logln!(
            "capability.service: interactive app launch approved path={}",
            entry_path
        );
    }
    let caps_nul = encode_nul_list(&caps);
    authorize_spawn(
        sender,
        entry_path,
        &identity,
        &caps,
        platform::service::ExecutionClass::Unprivileged,
    )?;
    let mut spawn_items = Vec::new();
    encode_identity_args(&identity, &mut spawn_items);
    spawn_items.push(format!(
        "{}MOCHI_EXECUTABLE_PATH={}",
        ENVIRONMENT_PREFIX, entry_path
    ));
    spawn_items.push(format!(
        "{}MOCHI_SHELL_ENDPOINT={}",
        ENVIRONMENT_PREFIX, header.shell_endpoint
    ));
    spawn_items.push(format!(
        "{}MOCHI_STDIO_ENDPOINT={}",
        ENVIRONMENT_PREFIX, header.shell_endpoint
    ));
    spawn_items.push(format!(
        "{}MOCHI_PROMPT_MODE={}",
        ENVIRONMENT_PREFIX,
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
        platform::service::ExecutionClass::Unprivileged,
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
