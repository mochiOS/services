use mochi_user_platform as platform;
use mochios_user_database::UserDatabase;
use mochios_user_protocol::{
    Authenticate, AuthenticationResult, MAX_CHUNK_LEN, MAX_MESSAGE_LEN, SnapshotChunk,
    SnapshotChunkRequest, SnapshotInfo, SnapshotRequest, Status, decode_opcode,
};

const USER_SERVICE_NAME: &str = "user.service";
const SERVICE_LOOKUP_ATTEMPTS: usize = 64;
const MAX_DATABASE_LEN: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoginUser {
    pub(crate) name: String,
    pub(crate) display_name: String,
}

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

pub(crate) fn list_users(request_id: u64) -> Result<Vec<LoginUser>, AuthenticationError> {
    let service = find_user_service().ok_or(AuthenticationError::ServiceUnavailable)?;
    let request = SnapshotRequest { request_id };
    let mut request_bytes = [0u8; MAX_MESSAGE_LEN];
    let request_len = request
        .encode(&mut request_bytes)
        .map_err(|_| AuthenticationError::Protocol)?;
    let mut reply = [0u8; MAX_MESSAGE_LEN];
    let reply_len = call(service, &request_bytes[..request_len], &mut reply)?;
    let info =
        SnapshotInfo::decode(&reply[..reply_len]).map_err(|_| AuthenticationError::Protocol)?;
    if info.request_id != request_id {
        return Err(AuthenticationError::Protocol);
    }
    let total_len = usize::try_from(info.total_len).map_err(|_| AuthenticationError::Protocol)?;
    if total_len == 0 || total_len > MAX_DATABASE_LEN {
        return Err(AuthenticationError::Protocol);
    }

    let mut database_bytes = Vec::with_capacity(total_len);
    while database_bytes.len() < total_len {
        let length = (total_len - database_bytes.len()).min(MAX_CHUNK_LEN);
        let request = SnapshotChunkRequest {
            request_id,
            offset: database_bytes.len() as u64,
            length: length as u32,
        };
        let request_len = request
            .encode(&mut request_bytes)
            .map_err(|_| AuthenticationError::Protocol)?;
        let reply_len = call(service, &request_bytes[..request_len], &mut reply)?;
        let chunk = SnapshotChunk::decode(&reply[..reply_len])
            .map_err(|_| AuthenticationError::Protocol)?;
        if chunk.request_id != request_id
            || chunk.generation != info.generation
            || chunk.offset != database_bytes.len() as u64
            || chunk.bytes.len() > total_len - database_bytes.len()
        {
            return Err(AuthenticationError::Protocol);
        }
        database_bytes.extend_from_slice(chunk.bytes);
    }

    let database =
        UserDatabase::parse(&database_bytes).map_err(|_| AuthenticationError::Protocol)?;
    Ok(database
        .users()
        .iter()
        .filter(|user| !user.locked)
        .map(|user| LoginUser {
            name: user.name.clone(),
            display_name: user.display_name.clone(),
        })
        .collect())
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

fn call(service: u64, request: &[u8], reply: &mut [u8]) -> Result<usize, AuthenticationError> {
    let result = platform::ipc::call(service, request, reply)
        .map_err(|_| AuthenticationError::ServiceUnavailable)?;
    let reply_len = (result & 0xffff_ffff) as usize;
    if reply_len > reply.len() {
        return Err(AuthenticationError::Protocol);
    }
    Ok(reply_len)
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
