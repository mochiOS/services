use std::fmt::Write;

use mboot_protocol::{
    Destination, ErrorCode, KnownCommand, Message, STAGE_SHARED_CHUNK_LEN,
    STAGE_SHARED_CHUNK_MAGIC, decode_line, encode_to_string,
};
use mochi_user_platform as platform;

use crate::agent::{Agent, AgentError, ExternalRequestError, ReadyStage};
use crate::transport::TransportError;
use crate::transport::virtio::VirtioSerialTransport;

const STAGE_TOKEN_PREFIX: &str = "--mboot-stage-token=";
const RETRY_DELAY_MS: u64 = 1_000;
const POLL_DELAY_MS: u64 = 10;
const IPC_MESSAGE_LEN: usize = mboot_protocol::MAX_IPC_MESSAGE_LEN;

#[derive(Clone, Copy)]
struct PendingDeveloperRequest {
    sender: u64,
    request_id: u64,
}

#[derive(Clone, Copy)]
struct SharedStageMapping {
    address: u64,
    length: usize,
    owner: u64,
}

pub fn run() -> ! {
    let _ = platform::logger::init_from_env();
    let stage_token = std::env::args()
        .find_map(|argument| argument.strip_prefix(STAGE_TOKEN_PREFIX).map(str::to_owned))
        .and_then(|value| value.parse::<u64>().ok());
    let started = current_ticks();
    let boot_id = loop {
        if let Some(boot_id) = generate_boot_id() {
            break boot_id;
        }
        platform::logln!("mboot-agent.service: boot ID generation failed; retrying");
        let _ = platform::thread::sleep_milliseconds(RETRY_DELAY_MS);
    };
    let mut agent = Agent::new(env!("MOCHIOS_VERSION"), boot_id, started);
    let mut transport = None;
    let mut pending_developer_sender = None;
    let mut streaming_stage = false;
    let mut shared_stage_mapping = None;
    let mut initialization_error_reported = false;

    loop {
        receive_ipc_request(
            &mut agent,
            stage_token,
            &mut pending_developer_sender,
            &mut streaming_stage,
            &mut shared_stage_mapping,
        );
        if transport.is_none() {
            match VirtioSerialTransport::initialize() {
                Ok(initialized) => {
                    platform::logln!("mboot-agent.service: virtio control transport initialized");
                    transport = Some(initialized);
                    initialization_error_reported = false;
                }
                Err(error) => {
                    if !initialization_error_reported {
                        platform::logln!(
                            "mboot-agent.service: control transport unavailable error={:?}",
                            error
                        );
                        initialization_error_reported = true;
                    }
                    let _ = platform::thread::sleep_milliseconds(RETRY_DELAY_MS);
                    continue;
                }
            }
        }
        if let Some(active) = transport.as_mut() {
            match agent.tick(active, current_ticks()) {
                Ok(()) | Err(AgentError::Transport(TransportError::Disconnected)) => {}
                Err(AgentError::Transport(TransportError::WouldBlock)) => {}
                Err(AgentError::Transport(
                    TransportError::InvalidDevice | TransportError::Io(_),
                )) => {
                    platform::logln!(
                        "mboot-agent.service: control transport reset; reinitializing"
                    );
                    transport = None;
                }
                Err(error) => {
                    platform::logln!("mboot-agent.service: protocol error={:?}", error);
                }
            }
        }
        complete_developer_request(&mut agent, &mut pending_developer_sender);
        if streaming_stage || agent.external_request_pending() || pending_developer_sender.is_some()
        {
            platform::thread::yield_now();
        } else {
            let _ = platform::thread::sleep_milliseconds(POLL_DELAY_MS);
        }
    }
}

fn receive_ipc_request(
    agent: &mut Agent,
    expected_token: Option<u64>,
    pending_developer_sender: &mut Option<PendingDeveloperRequest>,
    streaming_stage: &mut bool,
    shared_stage_mapping: &mut Option<SharedStageMapping>,
) {
    if pending_developer_sender.is_some() {
        return;
    }
    if *streaming_stage && !agent.can_accept_external_event() {
        return;
    }
    let mut request = [0u8; IPC_MESSAGE_LEN];
    let received = match platform::ipc::try_wait(&mut request) {
        Ok(received) => received,
        Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => return,
        Err(_) => return,
    };
    let sender = received >> 32;
    let length = (received & 0xffff_ffff) as usize;
    let Some(message) = request.get(..length) else {
        reply_errno(sender, mochi_user_syscall::EINVAL);
        return;
    };
    if handle_shared_stage_ipc(
        agent,
        sender,
        message,
        streaming_stage,
        shared_stage_mapping,
    ) {
        return;
    }
    if let Ok((token, stage)) = platform::service_ready::decode_notification(message) {
        let status = (Some(token) == expected_token)
            .then_some(stage)
            .and_then(|stage| match stage {
                1 => Some(ReadyStage::Userspace),
                2 => Some(ReadyStage::Display),
                3 => Some(ReadyStage::Desktop),
                _ => None,
            })
            .map_or(-(mochi_user_syscall::EINVAL as i32), |stage| {
                agent
                    .mark_ready(stage)
                    .map_or(-(mochi_user_syscall::EINVAL as i32), |()| 0)
            });
        let _ = platform::ipc::reply(sender, &status.to_le_bytes());
        return;
    }
    let decoded = match decode_line(message) {
        Ok(decoded) => decoded,
        Err(_) => {
            reply_errno(sender, mochi_user_syscall::EINVAL);
            return;
        }
    };
    let client_request_id = decoded.request_id;
    match decoded.known_command() {
        Some(KnownCommand::LinuxStageChunk) => {
            *streaming_stage = true;
        }
        Some(KnownCommand::LinuxStageCommit | KnownCommand::LinuxStageCancel) => {
            *streaming_stage = false;
        }
        _ => {}
    }
    if decoded.known_command().is_some_and(is_linux_command) && !linux_service_owns_sender(sender) {
        reply_protocol_error(sender, client_request_id, ErrorCode::PermissionDenied);
        return;
    }
    if decoded.known_command().is_some_and(is_wifi_command)
        && platform::capability::check_thread(sender, "settings.write") != Ok(1)
    {
        reply_protocol_error(sender, client_request_id, ErrorCode::PermissionDenied);
        return;
    }
    if decoded.message_type == mboot_protocol::MessageType::Event {
        match agent.queue_external_event(decoded) {
            Ok(()) => {
                let _ = platform::ipc::reply(sender, &0i32.to_le_bytes());
            }
            Err(error) => reply_errno(sender, external_errno(error)),
        }
        return;
    }
    match agent.queue_external_request(decoded, current_ticks()) {
        Ok(()) => {
            *pending_developer_sender = Some(PendingDeveloperRequest {
                sender,
                request_id: client_request_id,
            });
        }
        Err(error) => reply_protocol_error(sender, request_id(message), external_error(error)),
    }
}

fn handle_shared_stage_ipc(
    agent: &mut Agent,
    sender: u64,
    message: &[u8],
    streaming_stage: &mut bool,
    mapping: &mut Option<SharedStageMapping>,
) -> bool {
    if message.len() == 16 && linux_service_owns_sender(sender) {
        let address = u64::from_le_bytes(message[..8].try_into().unwrap());
        let length = u64::from_le_bytes(message[8..16].try_into().unwrap());
        if address & 0xfff == 0
            && length > 0
            && let Ok(length) = usize::try_from(length)
        {
            *mapping = Some(SharedStageMapping {
                address,
                length,
                owner: sender,
            });
        }
        return true;
    }
    if message.len() != STAGE_SHARED_CHUNK_LEN || message[..8] != STAGE_SHARED_CHUNK_MAGIC {
        return false;
    }
    if !linux_service_owns_sender(sender) {
        reply_errno(sender, mochi_user_syscall::EACCES);
        return true;
    }
    let instance = u64::from_le_bytes(message[8..16].try_into().unwrap());
    let offset = u64::from_le_bytes(message[16..24].try_into().unwrap());
    let length = u64::from_le_bytes(message[24..32].try_into().unwrap());
    let Some(shared) = *mapping else {
        reply_errno(sender, mochi_user_syscall::EINVAL);
        return true;
    };
    let Ok(length) = usize::try_from(length) else {
        reply_errno(sender, mochi_user_syscall::EINVAL);
        return true;
    };
    if shared.owner != sender || length == 0 || length > shared.length {
        reply_errno(sender, mochi_user_syscall::EINVAL);
        return true;
    }
    let bytes = unsafe { std::slice::from_raw_parts(shared.address as *const u8, length) };
    match agent.queue_external_stage_bytes(instance, offset, bytes) {
        Ok(()) => {
            *streaming_stage = true;
            let _ = platform::ipc::reply(sender, &0i32.to_le_bytes());
        }
        Err(error) => reply_errno(sender, external_errno(error)),
    }
    true
}

fn is_wifi_command(command: KnownCommand) -> bool {
    matches!(
        command,
        KnownCommand::WifiStatus
            | KnownCommand::WifiScan
            | KnownCommand::WifiSetEnabled
            | KnownCommand::WifiConnect
            | KnownCommand::WifiDisconnect
    )
}

fn is_linux_command(command: KnownCommand) -> bool {
    matches!(
        command,
        KnownCommand::LinuxLaunch
            | KnownCommand::LinuxStageBegin
            | KnownCommand::LinuxStageChunk
            | KnownCommand::LinuxStageCommit
            | KnownCommand::LinuxStageCancel
            | KnownCommand::LinuxPortalReset
            | KnownCommand::LinuxPortalGrant
            | KnownCommand::LinuxPortalMkdir
            | KnownCommand::LinuxPortalFileBegin
            | KnownCommand::LinuxPortalFileChunk
            | KnownCommand::LinuxPortalFileCommit
            | KnownCommand::LinuxPortalFileCancel
            | KnownCommand::LinuxPortalRelease
            | KnownCommand::LinuxPortalExportBegin
            | KnownCommand::LinuxPortalExportEntry
            | KnownCommand::LinuxPortalExportChunk
            | KnownCommand::LinuxPortalExportEnd
            | KnownCommand::LinuxBundleLaunch
            | KnownCommand::LinuxWindows
            | KnownCommand::LinuxWindowInfo
            | KnownCommand::LinuxFrame
            | KnownCommand::LinuxInput
            | KnownCommand::LinuxConfigure
            | KnownCommand::LinuxClose
    )
}

fn linux_service_owns_sender(sender: u64) -> bool {
    let owner = platform::ipc::endpoint_owner_process(sender).ok();
    let linux_service = platform::process::find_by_name("linux.service").ok();
    owner.is_some() && owner == linux_service
}

fn complete_developer_request(
    agent: &mut Agent,
    pending_sender: &mut Option<PendingDeveloperRequest>,
) {
    let response = agent.take_external_response();
    if response.is_none() && agent.external_request_pending() {
        return;
    }
    let Some(pending) = pending_sender.take() else {
        return;
    };
    let Some(response) = response else {
        reply_protocol_error(pending.sender, pending.request_id, ErrorCode::InvalidState);
        return;
    };
    match encode_to_string(&response) {
        Ok(encoded) => {
            let _ = platform::ipc::reply(pending.sender, encoded.as_bytes());
        }
        Err(_) => reply_errno(pending.sender, mochi_user_syscall::EIO),
    }
}

fn reply_protocol_error(sender: u64, request_id: u64, error: ErrorCode) {
    if request_id == 0 {
        reply_errno(sender, mochi_user_syscall::EINVAL);
        return;
    }
    let response = Message::error(Destination::Mochios, request_id, error, Vec::new());
    match encode_to_string(&response) {
        Ok(encoded) => {
            let _ = platform::ipc::reply(sender, encoded.as_bytes());
        }
        Err(_) => reply_errno(sender, mochi_user_syscall::EIO),
    }
}

fn reply_errno(sender: u64, errno: u64) {
    let status = -(errno as i32);
    let _ = platform::ipc::reply(sender, &status.to_le_bytes());
}

fn external_error(error: ExternalRequestError) -> ErrorCode {
    match error {
        ExternalRequestError::NotNegotiated => ErrorCode::InvalidState,
        ExternalRequestError::Busy => ErrorCode::Busy,
        ExternalRequestError::InvalidRequest => ErrorCode::InvalidArgument,
        ExternalRequestError::Encode => ErrorCode::Internal,
    }
}

fn external_errno(error: ExternalRequestError) -> u64 {
    match error {
        ExternalRequestError::NotNegotiated | ExternalRequestError::Busy => {
            mochi_user_syscall::EAGAIN
        }
        ExternalRequestError::InvalidRequest => mochi_user_syscall::EINVAL,
        ExternalRequestError::Encode => mochi_user_syscall::EIO,
    }
}

fn request_id(message: &[u8]) -> u64 {
    decode_line(message).map_or(0, |message| message.request_id)
}

fn current_ticks() -> u64 {
    platform::time::ticks().unwrap_or(0)
}

fn generate_boot_id() -> Option<String> {
    let mut bytes = [0u8; 16];
    platform::random::fill(&mut bytes).ok()?;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    Some(output)
}
