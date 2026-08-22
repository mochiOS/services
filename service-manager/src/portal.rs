use mochi_user_platform as platform;
use mochios_linux_portal_protocol::{
    Access, GRANT_RESPONSE_LEN, GrantDirectoryRequest, GrantDirectoryResponse,
    NETWORK_RESPONSE_LEN, Opcode, RequestNetworkRequest, RequestNetworkResponse, decode_opcode,
};

use crate::service_launcher;
use crate::session::ActiveSession;
use crate::spawn_support::errno;

const WAIT_NO_HANG: u64 = 1;
const PROMPT_TIMEOUT_TICKS: u64 = 30_000;

pub(crate) fn handle(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
) {
    match decode_opcode(request_bytes) {
        Ok(Opcode::GrantDirectory) => {
            handle_directory(request_bytes, sender, session, logger_endpoint)
        }
        Ok(Opcode::RequestNetwork) => {
            handle_network(request_bytes, sender, session, logger_endpoint)
        }
        _ => reply_invalid(request_bytes, sender),
    }
}

fn handle_directory(
    request_bytes: &[u8],
    sender: u64,
    session: Option<ActiveSession>,
    logger_endpoint: u64,
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
            prompt(logger_endpoint, &request)
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
) {
    let request_id = request_id(request_bytes);
    let result = RequestNetworkRequest::decode(request_bytes)
        .map_err(|_| mochi_user_syscall::EINVAL)
        .and_then(|request| {
            let session = session.ok_or(mochi_user_syscall::EPERM)?;
            authorize_network(sender, session, &request)?;
            prompt_network(logger_endpoint, request.bundle_id)
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

fn prompt_network(logger_endpoint: u64, application: &str) -> Result<(), u64> {
    platform::logln!("service-manager.service: network prompt application={application}");
    let process =
        service_launcher::spawn_network_prompt(logger_endpoint, application).map_err(errno)?;
    wait_for_prompt(process).map(|_| ())
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

fn prompt(logger_endpoint: u64, request: &GrantDirectoryRequest<'_>) -> Result<u64, u64> {
    platform::logln!(
        "service-manager.service: portal prompt application={} path={}",
        request.bundle_id,
        request.path
    );
    let process = service_launcher::spawn_portal_prompt(
        logger_endpoint,
        request.bundle_id,
        request.path,
        request.access == Access::READ_WRITE,
    )
    .map_err(errno)?;
    platform::logln!(
        "service-manager.service: portal prompt spawned process={}",
        process
    );
    wait_for_prompt(process)?;
    platform::service_ready::generate_token().map_err(errno)
}

fn wait_for_prompt(process: u64) -> Result<(), u64> {
    let started = platform::time::ticks().map_err(errno)?;
    loop {
        let mut exit_status = 0i32;
        match platform::process::wait(
            process as i64,
            core::ptr::addr_of_mut!(exit_status) as u64,
            WAIT_NO_HANG,
        ) {
            Ok(0) => {}
            Ok(_) if exit_status == 0 => {
                return Ok(());
            }
            Ok(_) => return Err(mochi_user_syscall::EACCES),
            Err(error) => return Err(errno(error)),
        }
        let now = platform::time::ticks().map_err(errno)?;
        if now.saturating_sub(started) >= PROMPT_TIMEOUT_TICKS {
            return Err(mochi_user_syscall::EAGAIN);
        }
        platform::thread::yield_now();
    }
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
