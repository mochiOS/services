use mochi_user_platform as platform;
use mochios_user_database::{FIRST_REGULAR_UID, UserDatabase};
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

pub(crate) struct LoginUsers {
    pub(crate) users: Vec<LoginUser>,
    pub(crate) has_regular_account: bool,
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

pub(crate) fn list_users(request_id: u64) -> Result<LoginUsers, AuthenticationError> {
    let database = load_database(request_id)?;
    Ok(login_users(&database))
}

pub(crate) fn session_identity(
    request_id: u64,
    name: &str,
) -> Result<mochi_user_platform::service_ready::SessionIdentity, AuthenticationError> {
    let database = load_database(request_id)?;
    let user = database
        .users()
        .iter()
        .find(|user| user.name == name && user.uid >= FIRST_REGULAR_UID && !user.locked)
        .ok_or(AuthenticationError::InvalidCredentials)?;
    Ok(mochi_user_platform::service_ready::SessionIdentity {
        uid: user.uid,
        gid: user.gid,
    })
}

fn login_users(database: &UserDatabase) -> LoginUsers {
    let has_regular_account = database
        .users()
        .iter()
        .any(|user| user.uid >= FIRST_REGULAR_UID);
    let users = database
        .users()
        .iter()
        .filter(|user| user.uid >= FIRST_REGULAR_UID && !user.locked)
        .map(|user| LoginUser {
            name: user.name.clone(),
            display_name: user.display_name.clone(),
        })
        .collect();
    LoginUsers {
        users,
        has_regular_account,
    }
}

pub(crate) fn load_database(request_id: u64) -> Result<UserDatabase, AuthenticationError> {
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

    UserDatabase::parse(&database_bytes).map_err(|_| AuthenticationError::Protocol)
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

pub(crate) fn call(
    service: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<usize, AuthenticationError> {
    let result = platform::ipc::call(service, request, reply)
        .map_err(|_| AuthenticationError::ServiceUnavailable)?;
    let reply_len = (result & 0xffff_ffff) as usize;
    if reply_len > reply.len() {
        return Err(AuthenticationError::Protocol);
    }
    Ok(reply_len)
}

pub(crate) fn find_user_service() -> Option<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use mochios_user_database::UserRecord;

    #[test]
    fn root_only_database_requires_initial_setup() {
        let users = login_users(&UserDatabase::with_root());
        assert!(!users.has_regular_account);
        assert!(users.users.is_empty());
    }

    #[test]
    fn locked_regular_account_prevents_initial_setup_but_is_not_selectable() {
        let mut database = UserDatabase::with_root();
        assert!(
            database
                .add(UserRecord::regular(
                    "alice",
                    FIRST_REGULAR_UID,
                    FIRST_REGULAR_UID,
                ))
                .is_ok()
        );
        let users = login_users(&database);
        assert!(users.has_regular_account);
        assert!(users.users.is_empty());
    }

    #[test]
    fn unlocked_regular_account_is_selectable() {
        let mut database = UserDatabase::with_root();
        let mut alice = UserRecord::regular("alice", FIRST_REGULAR_UID, FIRST_REGULAR_UID);
        alice.display_name = "Alice".to_owned();
        alice.locked = false;
        assert!(database.add(alice).is_ok());
        let users = login_users(&database);
        assert!(users.has_regular_account);
        assert_eq!(users.users.len(), 1);
        assert_eq!(users.users[0].name, "alice");
        assert_eq!(users.users[0].display_name, "Alice");
    }
}
