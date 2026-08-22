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
    platform::logln!("secure-ui.service: permission prompt server ready");
    let mut request_bytes = [0u8; MAX_MESSAGE_LEN];
    let received = match platform::ipc::try_wait(&mut request_bytes) {
        Ok(received) => received,
        Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => loop {
            match platform::ipc::try_wait(&mut request_bytes) {
                Ok(received) => break received,
                Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {
                    platform::thread::yield_now();
                }
                Err(_) => std::process::exit(1),
            }
        },
        Err(_) => std::process::exit(1),
    };
    let sender = received >> 32;
    let length = (received & 0xffff_ffff) as usize;
    let request = request_bytes
        .get(..length)
        .and_then(|bytes| PromptRequest::decode(bytes).ok());
    let authorized = request
        .as_ref()
        .zip(expected_token)
        .is_some_and(|(request, expected)| match request {
            PromptRequest::Network { token, .. } | PromptRequest::Directory { token, .. } => {
                *token == expected
            }
        });
    platform::logln!(
        "secure-ui.service: permission prompt request sender={} bytes={} authorized={}",
        sender,
        length,
        authorized
    );
    let allowed = if authorized {
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
            })
            .transpose()
            .map_err(|error| {
                platform::logln!("secure-ui.service: permission prompt UI failed error={error}");
                error
            })?
            .unwrap_or(false)
    } else {
        false
    };
    let status = if allowed {
        0i32
    } else {
        -(mochi_user_syscall::EACCES as i32)
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
    Ok(())
}
