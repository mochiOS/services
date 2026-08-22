use mochi_user_platform as platform;
use mochios_linux_portal_protocol::{
    Access, GRANT_RESPONSE_LEN, GrantDirectoryRequest, GrantDirectoryResponse,
    NETWORK_RESPONSE_LEN, Opcode, RequestNetworkRequest, RequestNetworkResponse, decode_opcode,
};
use mochios_permission_prompt_protocol::{MAX_MESSAGE_LEN, PromptRequest};

use crate::service_launcher;
use crate::session::ActiveSession;
use crate::spawn_support::errno;

#[derive(Clone, Copy)]
pub(crate) struct PermissionPromptProcess {
    process: u64,
    token: u64,
}

pub(crate) fn handle(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
    prompt_process: &mut Option<PermissionPromptProcess>,
) {
    match decode_opcode(request_bytes) {
        Ok(Opcode::GrantDirectory) => handle_directory(
            request_bytes,
            sender,
            session,
            logger_endpoint,
            prompt_process,
        ),
        Ok(Opcode::RequestNetwork) => handle_network(
            request_bytes,
            sender,
            session,
            logger_endpoint,
            prompt_process,
        ),
        _ => reply_invalid(request_bytes, sender),
    }
}

fn handle_directory(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
    prompt_process: &mut Option<PermissionPromptProcess>,
) {
    let request_id = request_bytes
        .get(8..16)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    let result = GrantDirectoryRequest::decode(request_bytes)
        .map_err(|_| mochi_user_syscall::EINVAL)
        .and_then(|request| {
            let session = session.ok_or(mochi_user_syscall::EPERM)?;
            authorize_request(sender, session, &request)?;
            prompt(logger_endpoint, prompt_process, &request)
        });
    let (status, grant_id) = match result {
        Ok(grant_id) => (0, grant_id),
        Err(error) => (-(error as i32), 0),
    };
    let response = GrantDirectoryResponse {
        request_id,
        status,
        grant_id,
    };
    let mut output = [0u8; GRANT_RESPONSE_LEN];
    if let Ok(length) = response.encode(&mut output) {
        let _ = platform::ipc::reply(sender, &output[..length]);
    }
}

fn handle_network(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
    prompt_process: &mut Option<PermissionPromptProcess>,
) {
    let request_id = request_id(request_bytes);
    let result = RequestNetworkRequest::decode(request_bytes)
        .map_err(|_| mochi_user_syscall::EINVAL)
        .and_then(|request| {
            let session = session.ok_or(mochi_user_syscall::EPERM)?;
            authorize_network(sender, session, &request)?;
            prompt_network(logger_endpoint, prompt_process, request.bundle_id)
        });
    let response = RequestNetworkResponse {
        request_id,
        status: result.map_or_else(|error| -(error as i32), |_| 0),
    };
    let mut output = [0u8; NETWORK_RESPONSE_LEN];
    if let Ok(length) = response.encode(&mut output) {
        let _ = platform::ipc::reply(sender, &output[..length]);
    }
}

fn authorize_network(
    sender: u64,
    session: ActiveSession,
    request: &RequestNetworkRequest<'_>,
) -> Result<(), u64> {
    let linux_pid = session.linux_pid.ok_or(mochi_user_syscall::EPERM)?;
    if request.session_id != session.id || Some(linux_pid) != sender_process(sender) {
        return Err(mochi_user_syscall::EPERM);
    }
    let user = user_for_uid(session.identity.uid).ok_or(mochi_user_syscall::EPERM)?;
    (request.user == user.name)
        .then_some(())
        .ok_or(mochi_user_syscall::EPERM)
}

fn prompt_network(
    logger_endpoint: u64,
    prompt_process: &mut Option<PermissionPromptProcess>,
    bundle_id: &str,
) -> Result<(), u64> {
    let application = application_name(bundle_id);
    platform::logln!("service-manager.service: network prompt application={application}");
    run_prompt(
        logger_endpoint,
        prompt_process,
        PromptRequest::Network {
            token: 1,
            application: &application,
        },
    )
}

fn reply_invalid(request: &[u8], sender: u64) {
    let response = RequestNetworkResponse {
        request_id: request_id(request),
        status: -(mochi_user_syscall::EINVAL as i32),
    };
    let mut output = [0u8; NETWORK_RESPONSE_LEN];
    if let Ok(length) = response.encode(&mut output) {
        let _ = platform::ipc::reply(sender, &output[..length]);
    }
}

fn request_id(bytes: &[u8]) -> u64 {
    bytes
        .get(8..16)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn authorize_request(
    sender: u64,
    session: ActiveSession,
    request: &GrantDirectoryRequest<'_>,
) -> Result<(), u64> {
    let linux_pid = session.linux_pid.ok_or(mochi_user_syscall::EPERM)?;
    if request.session_id != session.id || Some(linux_pid) != sender_process(sender) {
        return Err(mochi_user_syscall::EPERM);
    }
    let user = user_for_uid(session.identity.uid).ok_or(mochi_user_syscall::EPERM)?;
    if request.user != user.name {
        return Err(mochi_user_syscall::EPERM);
    }
    let home = alloc::format!("/home/{}", user.name);
    let in_home = request.path == home
        || request
            .path
            .strip_prefix(home.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'));
    let readable_system = request.path == "/applications"
        || request.path.starts_with("/applications/")
        || request.path == "/libraries"
        || request.path.starts_with("/libraries/");
    if (!in_home && !readable_system) || (request.access.writable() && !in_home) {
        return Err(mochi_user_syscall::EACCES);
    }
    if std::fs::metadata(request.path)
        .map(|metadata| !metadata.is_dir())
        .unwrap_or(true)
    {
        return Err(mochi_user_syscall::ENOENT);
    }
    Ok(())
}

fn prompt(
    logger_endpoint: u64,
    prompt_process: &mut Option<PermissionPromptProcess>,
    request: &GrantDirectoryRequest<'_>,
) -> Result<u64, u64> {
    let application = application_name(request.bundle_id);
    platform::logln!(
        "service-manager.service: portal prompt application={} path={}",
        application,
        request.path
    );
    run_prompt(
        logger_endpoint,
        prompt_process,
        PromptRequest::Directory {
            token: 1,
            application: &application,
            path: request.path,
            writable: request.access == Access::READ_WRITE,
        },
    )?;
    platform::service_ready::generate_token().map_err(errno)
}

pub(crate) fn prewarm(prompt_process: &mut Option<PermissionPromptProcess>, logger_endpoint: u64) {
    if prompt_process.is_some() {
        return;
    }
    let token = match platform::service_ready::generate_token() {
        Ok(token) => token,
        Err(error) => {
            platform::logln!(
                "service-manager.service: permission prompt token failed errno={}",
                errno(error)
            );
            return;
        }
    };
    *prompt_process = service_launcher::spawn_permission_prompt_server(logger_endpoint, token)
        .map_err(|error| {
            platform::logln!(
                "service-manager.service: permission prompt prewarm failed errno={}",
                errno(error)
            );
            error
        })
        .ok()
        .map(|process| PermissionPromptProcess { process, token });
}

fn run_prompt(
    logger_endpoint: u64,
    prompt_process: &mut Option<PermissionPromptProcess>,
    request: PromptRequest<'_>,
) -> Result<(), u64> {
    prewarm(prompt_process, logger_endpoint);
    let prompt = prompt_process.take().ok_or(mochi_user_syscall::EIO)?;
    let request = match request {
        PromptRequest::Network { application, .. } => PromptRequest::Network {
            token: prompt.token,
            application,
        },
        PromptRequest::Directory {
            application,
            path,
            writable,
            ..
        } => PromptRequest::Directory {
            token: prompt.token,
            application,
            path,
            writable,
        },
    };
    let mut encoded = [0u8; MAX_MESSAGE_LEN];
    let length = request
        .encode(&mut encoded)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
    let mut reply = [0u8; 4];
    let result = crate::spawn_support::call_with_wait(
        prompt.process,
        &encoded[..length],
        &mut reply,
    )
    .map_err(|error| {
        platform::logln!(
            "service-manager.service: permission prompt IPC failed process={} errno={}",
            prompt.process,
            errno(error)
        );
        errno(error)
    })
    .and_then(|message| {
        let length = (message & 0xffff_ffff) as usize;
        if length != reply.len() {
            platform::logln!(
                "service-manager.service: permission prompt reply invalid process={} bytes={}",
                prompt.process,
                length
            );
            return Err(mochi_user_syscall::EIO);
        }
        let status = i32::from_le_bytes(reply);
        platform::logln!(
            "service-manager.service: permission prompt reply process={} status={}",
            prompt.process,
            status
        );
        if status == 0 {
            Ok(())
        } else {
            Err(status.unsigned_abs() as u64)
        }
    });
    prewarm(prompt_process, logger_endpoint);
    result
}

fn application_name(bundle_id: &str) -> alloc::string::String {
    let manifest_path = alloc::format!("/system/packages/{bundle_id}/manifest.toml");
    platform::package::read_manifest(&manifest_path)
        .filter(|manifest| manifest.package_id == bundle_id)
        .map(|manifest| {
            if manifest.package_name.ends_with(".app") {
                manifest.package_name
            } else {
                alloc::format!("{}.app", manifest.package_name)
            }
        })
        .unwrap_or_else(|| "Application".to_owned())
}

fn sender_process(sender: u64) -> Option<u64> {
    platform::ipc::endpoint_owner_process(sender).ok()
}

fn user_for_uid(uid: u32) -> Option<mochios_user_database::UserRecord> {
    use mochios_user_database::{DATABASE_PATH, UserDatabase};
    let bytes = std::fs::read(DATABASE_PATH).ok()?;
    UserDatabase::parse(&bytes).ok()?.find_uid(uid).cloned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn access_policy_only_allows_writes_below_the_session_home() {
        let home = "/home/alice";
        assert!(
            "/home/alice/Develop"
                .strip_prefix(home)
                .is_some_and(|tail| tail.starts_with('/'))
        );
        assert!(
            !"/home/alice2"
                .strip_prefix(home)
                .is_some_and(|tail| tail.starts_with('/'))
        );
        assert!("/applications/Files.app".starts_with("/applications/"));
    }
}
