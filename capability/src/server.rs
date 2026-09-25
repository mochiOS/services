use alloc::string::String;
use alloc::vec::Vec;

use mochi_user_platform as platform;
use sha2::{Digest, Sha256};

use crate::app_spawn::{SPAWN_APP_OPCODE, spawn_application_from_manifest};
use crate::dynamic_grant::{authorize_dynamic_capability, is_trusted_prompt_broker};
use crate::persistent_grant::{authorize_persistent_capability, has_persistent_grant};
use crate::policy::needs_app_prompt;
use crate::resolver::{
    CapabilityDenyReason, application_identity, binary_caps, decide_binary_capabilities,
    authorize_spawn, encode_exec_authorization_args, encode_identity_args, encode_nul_list,
    resolve_capabilities_for_path,
};
use crate::state::CapabilityServiceState;

const REPLY_OK: u64 = 0;

fn capability_reply(sender: u64, status: u64) {
    let _ = platform::ipc::reply(sender, &status.to_le_bytes());
}

fn parse_decision_request(
    buf: &[u8],
) -> Result<platform::capability::CapabilityDecisionRequest, mochi_user_syscall::SysError> {
    platform::capability::decode_decision_request(buf)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))
}

fn reply_capabilities(sender: u64, result: Result<Vec<String>, mochi_user_syscall::SysError>) {
    let (status, capabilities) = match result {
        Ok(caps) => (REPLY_OK, encode_nul_list(&caps)),
        Err(err) => {
            let status = err.errno().unwrap_or(mochi_user_syscall::EIO);
            (status, Vec::new())
        }
    };
    let reply = platform::capability::encode_resolve_capabilities_reply(status, &capabilities);
    let _ = platform::ipc::reply(sender, &reply);
}

fn reply_execution_security(
    sender: u64,
    result: Result<(Vec<String>, Vec<String>), mochi_user_syscall::SysError>,
) {
    let (status, identity, capabilities) = match result {
        Ok((identity, capabilities)) => (
            REPLY_OK,
            encode_nul_list(&identity),
            encode_nul_list(&capabilities),
        ),
        Err(error) => (
            error.errno().unwrap_or(mochi_user_syscall::EIO),
            Vec::new(),
            Vec::new(),
        ),
    };
    let reply = platform::capability::encode_resolve_execution_security_reply(
        status,
        &identity,
        &capabilities,
    );
    match reply {
        Ok(reply) => {
            let _ = platform::ipc::reply(sender, &reply);
        }
        Err(_) => capability_reply(sender, mochi_user_syscall::EINVAL),
    }
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

fn parse_persistent_query(
    buf: &[u8],
) -> Result<platform::capability::CapabilityRequest, mochi_user_syscall::SysError> {
    platform::capability::decode_request(buf)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))
}

pub(crate) fn serve_capability_requests(mut state: CapabilityServiceState) -> ! {
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(err) => {
            platform::logln!(
                "capability.service: endpoint create failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    };
    platform::logln!("capability.service: ready");
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
        if opcode == platform::capability::RESOLVE_CAPABILITIES_OPCODE {
            let result = platform::capability::decode_resolve_capabilities_request(slice)
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                })
                .and_then(|path| resolve_capabilities_for_path(&state.package_index, path));
            reply_capabilities(sender, result);
            continue;
        }
        if opcode == platform::capability::RESOLVE_EXECUTION_SECURITY_OPCODE {
            let result = platform::capability::decode_resolve_execution_security_request(slice)
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                })
                .and_then(|(execution_class_raw, path)| {
                    let execution_class = platform::service::ExecutionClass::from_raw(
                        execution_class_raw,
                    )
                    .ok_or_else(|| {
                        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                    })?;
                    let record = state.package_index.by_binary.get(path).ok_or_else(|| {
                        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64)
                    })?;
                    let caps =
                        binary_caps(&record.manifest, &record.manifest_path, path)?.to_vec();
                    let identity =
                        application_identity(&record.manifest, &record.manifest_path)?;
                    let mut identity_items = Vec::new();
                    encode_identity_args(&identity, &mut identity_items);
                    authorize_spawn(sender, path, &identity, &caps, execution_class)?;
                    Ok((identity_items, caps))
                });
            reply_execution_security(sender, result);
            continue;
        }
        if opcode == platform::capability::AUTHORIZE_EXEC_OPCODE {
            let result = platform::capability::decode_authorize_exec_request(slice)
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
                })
                .and_then(|path| {
                    let record = state.package_index.by_binary.get(path).ok_or_else(|| {
                        mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64)
                    })?;
                    let mut capability_decision = decide_binary_capabilities(
                        &record.manifest,
                        &record.manifest_path,
                        path,
                    )?;
                    let identity =
                        application_identity(&record.manifest, &record.manifest_path)?;
                    let requester_context =
                        platform::process::thread_security_context(sender)?;
                    let package_id = identity.package_id.as_bytes();
                    let developer_id = identity.developer_id.as_bytes();
                    if package_id.len() > requester_context.package_id.len()
                        || developer_id.len() > requester_context.developer_id.len()
                    {
                        return Err(mochi_user_syscall::SysError::from_raw(
                            mochi_user_syscall::EINVAL as i64,
                        ));
                    }
                    let requester_package_len = requester_context.package_id_len as usize;
                    let requester_developer_len = requester_context.developer_id_len as usize;
                    let same_identity = requester_package_len <= requester_context.package_id.len()
                        && requester_developer_len <= requester_context.developer_id.len()
                        && &requester_context.package_id[..requester_package_len] == package_id
                        && &requester_context.developer_id[..requester_developer_len]
                            == developer_id
                        && requester_context.subject_key_id == identity.subject_key_id
                        && requester_context.provenance == identity.provenance as u8;
                    let mut target_context = mochi_user_syscall::ThreadSecurityContext::default();
                    target_context.effective_uid = requester_context.effective_uid;
                    target_context.effective_gid = requester_context.effective_gid;
                    target_context.package_id_len = package_id.len() as u16;
                    target_context.developer_id_len = developer_id.len() as u16;
                    target_context.package_id[..package_id.len()].copy_from_slice(package_id);
                    target_context.developer_id[..developer_id.len()]
                        .copy_from_slice(developer_id);
                    target_context.subject_key_id = identity.subject_key_id;
                    target_context.provenance = identity.provenance as u8;
                    let mut user_allowed = Vec::new();
                    let mut caller_allowed = Vec::new();
                    for capability in &capability_decision.requested {
                        let already_held =
                            platform::capability::check_thread(sender, capability) == Ok(1);
                        let user_grantable = platform::capability::capability_from_string(capability)
                            == platform::capability::CapabilityClass::UserGrantable;
                        let policy_allows = user_grantable
                            && !needs_app_prompt(&state.app_prompt_policy, capability);
                        let user_authorized = !user_grantable
                            || same_identity
                            || has_persistent_grant(&target_context, capability, None)
                            || policy_allows;

                        if already_held {
                            caller_allowed.push(capability.clone());
                        }
                        if user_authorized {
                            user_allowed.push(capability.clone());
                        }
                    }
                    capability_decision = capability_decision
                        .apply_runtime_constraints(&user_allowed, &caller_allowed);
                    if !capability_decision.is_allowed() {
                        platform::logln!(
                            "capability.service: exec denied path={} reason={:?} denied={:?}",
                            path,
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
                    let mut identity_items = Vec::new();
                    encode_identity_args(&identity, &mut identity_items);
                    let executable = platform::file::read_to_end_path(path)?;
                    let digest = Sha256::digest(&executable);
                    let mut digest_hex = String::with_capacity(64);
                    for byte in digest {
                        use core::fmt::Write;
                        let _ = write!(digest_hex, "{byte:02x}");
                    }
                    identity_items.push(alloc::format!(
                        "{}{digest_hex}",
                        mnu_abi::exec::EXECUTABLE_DIGEST_PREFIX
                    ));
                    identity_items.push(alloc::format!(
                        "{}{}",
                        mnu_abi::exec::EXEC_AUTHORIZATION_KIND_PREFIX,
                        mnu_abi::exec::EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE
                    ));
                    identity_items.push(alloc::format!(
                        "{}unprivileged",
                        mnu_abi::exec::EXEC_AUTHORIZATION_CLASS_PREFIX
                    ));
                    let identity_nul = encode_exec_authorization_args(&identity_items)?;
                    let caps_nul = encode_nul_list(&caps);
                    platform::service::authorize_exec_for_requester(
                        sender,
                        path,
                        &identity_nul,
                        &caps_nul,
                    )
                    .map(|_| ())
                });
            capability_reply(
                sender,
                result
                    .map(|_| REPLY_OK)
                    .unwrap_or_else(|error| error.errno().unwrap_or(mochi_user_syscall::EIO)),
            );
            continue;
        }
        if opcode == platform::capability::PACKAGE_INDEX_CHANGED_OPCODE {
            let status = if slice.len() != core::mem::size_of::<u32>() {
                mochi_user_syscall::EINVAL
            } else if platform::capability::check_thread(sender, "package.install") != Ok(1) {
                mochi_user_syscall::EACCES
            } else {
                state
                    .refresh_package_index()
                    .map(|_| REPLY_OK)
                    .unwrap_or_else(|error| error.errno().unwrap_or(mochi_user_syscall::EIO))
            };
            capability_reply(sender, status);
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
            let status = if !is_trusted_prompt_broker(sender) {
                mochi_user_syscall::EACCES
            } else {
                parse_decision_request(slice)
                    .and_then(|decision| {
                        authorize_dynamic_capability(
                            &state.package_index,
                            decision.decision,
                            decision.reserved,
                            &decision.request,
                        )
                    })
                    .map(|_| REPLY_OK)
                    .unwrap_or_else(|error| error.errno().unwrap_or(mochi_user_syscall::EIO))
            };
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
