use mochi_user_platform as platform;
use mochios_permission_prompt_protocol::{MAX_MESSAGE_LEN, PromptRequest};

const SERVER_ARGUMENT: &str = "--permission-prompt-server";
const TOKEN_ARGUMENT_PREFIX: &str = "--permission-prompt-token=";

pub(crate) fn requested() -> bool {
    std::env::args().any(|argument| argument == SERVER_ARGUMENT)
}

pub(crate) fn run() -> Result<(), viewkit::ViewKitError> {
    let expected_token = std::env::args()
        .find_map(|argument| {
            argument
                .strip_prefix(TOKEN_ARGUMENT_PREFIX)
                .and_then(|value| value.parse::<u64>().ok())
        })
        .filter(|token| *token != 0);
    let Some(target) = platform::service_ready::take_bootstrap_target() else {
        std::process::exit(1);
    };
    if expected_token.is_none() {
        std::process::exit(1);
    }
    let endpoint = platform::ipc::create_handle().unwrap_or_else(|_| std::process::exit(1));
    // The child owns RECEIVE. Only SEND and delegation rights leave it.
    let rights = platform::handle::HANDLE_RIGHT_SEND
        | platform::handle::HANDLE_RIGHT_TRANSFER
        | platform::handle::HANDLE_RIGHT_DUPLICATE;
    if platform::service_ready::notify_handle(target, 0, endpoint, rights).is_err() {
        let _ = platform::handle::close(endpoint);
        std::process::exit(1);
    }
    platform::logln!("secure-ui.service: permission prompt server ready");
    let mut request_bytes = [0u8; MAX_MESSAGE_LEN];
    let mut handles = platform::ipc::IpcObjectHandles::default();
    let received =
        platform::ipc::wait_object_handles(endpoint as u64, &mut request_bytes, &mut handles)
            .unwrap_or_else(|_| std::process::exit(1));
    let _ = platform::handle::close(endpoint);
    let unexpected_handles = handles.count != 0;
    for attached in handles
        .handles
        .iter()
        .take((handles.count as usize).min(handles.handles.len()))
    {
        if attached.handle != 0 {
            let _ = platform::handle::close(attached.handle);
        }
    }
    let sender = received >> 32;
    let length = (received & 0xffff_ffff) as usize;
    let request = request_bytes
        .get(..length)
        .and_then(|bytes| PromptRequest::decode(bytes).ok());
    let authorized = !unexpected_handles
        && request
            .as_ref()
            .zip(expected_token)
            .is_some_and(|(request, expected)| match request {
                PromptRequest::Network { token, .. }
                | PromptRequest::Directory { token, .. }
                | PromptRequest::Storage { token, .. } => *token == expected,
            });
    platform::logln!(
        "secure-ui.service: permission prompt request sender={} bytes={} authorized={}",
        sender,
        length,
        authorized
    );
    let decision = if authorized {
        request
            .map(|request| match request {
                PromptRequest::Network { application, .. } => {
                    platform::logln!(
                        "secure-ui.service: showing network prompt application={application}"
                    );
                    crate::network_prompt::decide(application.to_owned())
                }
                PromptRequest::Directory {
                    application,
                    path,
                    writable,
                    ..
                } => crate::portal_prompt::decide(crate::portal_prompt::PromptConfiguration {
                    application: application.to_owned(),
                    path: path.to_owned(),
                    writable,
                }),
                PromptRequest::Storage {
                    application,
                    action,
                    target,
                    ..
                } => crate::storage_prompt::decide(crate::storage_prompt::PromptConfiguration {
                    application: application.to_owned(),
                    action,
                    target: target.to_owned(),
                }),
            })
            .transpose()
    } else {
        Ok(None)
    };
    let (allowed, ui_error) = match decision {
        Ok(allowed) => (allowed.unwrap_or(false), None),
        Err(error) => {
            platform::logln!("secure-ui.service: permission prompt UI failed error={error}");
            (false, Some(error))
        }
    };
    let status = if ui_error.is_some() {
        mochi_user_syscall::EIO as i32
    } else if allowed {
        0i32
    } else {
        mochi_user_syscall::EACCES as i32
    };
    platform::logln!(
        "secure-ui.service: permission prompt completed allowed={} status={}",
        allowed,
        status
    );
    if let Err(error) = platform::ipc::reply(sender, &status.to_le_bytes()) {
        platform::logln!(
            "secure-ui.service: permission prompt reply failed errno={}",
            error.errno().unwrap_or(0)
        );
    }
    // Report rendering errors only after replying, so the caller cannot be
    // left waiting for a server which exits without answering its request.
    ui_error.map_or(Ok(()), Err)
}
