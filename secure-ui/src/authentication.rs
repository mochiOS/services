use mochi_user_platform as platform;
use mochios_user_protocol::{
    Authenticate, AuthenticationResult, MAX_MESSAGE_LEN, Status, decode_opcode,
};

const USER_SERVICE_NAME: &str = "user.service";
const SERVICE_LOOKUP_ATTEMPTS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedUser {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) name: String,
    pub(crate) home: String,
    pub(crate) shell: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthenticationError {
    InvalidCredentials,
    ServiceUnavailable,
    Protocol,
}

pub(crate) fn authenticate(
    request_id: u64,
    name: &str,
    password: &[u8],
) -> Result<AuthenticatedUser, AuthenticationError> {
    let service = find_user_service().ok_or(AuthenticationError::ServiceUnavailable)?;
    let request = Authenticate {
        request_id,
        name,
        password,
    };
    let mut request_bytes = [0u8; MAX_MESSAGE_LEN];
    let request_len = request
        .encode(&mut request_bytes)
        .map_err(|_| AuthenticationError::Protocol)?;
    let mut reply = [0u8; MAX_MESSAGE_LEN];
    let call_result = platform::ipc::call(service, &request_bytes[..request_len], &mut reply);
    request_bytes[..request_len].fill(0);
    let result = call_result.map_err(|_| AuthenticationError::ServiceUnavailable)?;
    let reply_len = (result & 0xffff_ffff) as usize;
    if reply_len > reply.len() {
        return Err(AuthenticationError::Protocol);
    }
    let reply = &reply[..reply_len];
    match decode_opcode(reply).map_err(|_| AuthenticationError::Protocol)? {
        mochios_user_protocol::Opcode::AuthenticationResult => {
            let result =
                AuthenticationResult::decode(reply).map_err(|_| AuthenticationError::Protocol)?;
            if result.request_id != request_id {
                return Err(AuthenticationError::Protocol);
            }
            Ok(AuthenticatedUser {
                uid: result.uid,
                gid: result.gid,
                name: result.name.to_owned(),
                home: result.home.to_owned(),
                shell: result.shell.to_owned(),
            })
        }
        mochios_user_protocol::Opcode::Status => {
            let status = Status::decode(reply).map_err(|_| AuthenticationError::Protocol)?;
            if status.request_id != request_id {
                return Err(AuthenticationError::Protocol);
            }
            if status.status == -(mochi_user_syscall::EACCES as i32) {
                Err(AuthenticationError::InvalidCredentials)
            } else {
                Err(AuthenticationError::Protocol)
            }
        }
        _ => Err(AuthenticationError::Protocol),
    }
}

fn find_user_service() -> Option<u64> {
    for _ in 0..SERVICE_LOOKUP_ATTEMPTS {
        if let Ok(endpoint) = platform::process::find_by_name(USER_SERVICE_NAME)
            && endpoint != 0
        {
            return Some(endpoint);
        }
        platform::thread::yield_now();
    }
    None
}
