use std::path::Path;
use zeroize::Zeroize;

use mochi_user_platform as platform;
use mochios_user_database::{DATABASE_PATH, UserDatabase, UserRecord};
use mochios_user_protocol::{
    AddUser, Authenticate, AuthenticationResult, MAX_CHUNK_LEN, MAX_MESSAGE_LEN, Opcode,
    RemoveUser, SetPassword, SnapshotChunk, SnapshotChunkRequest, SnapshotInfo, SnapshotRequest,
    Status, decode_opcode,
};
use user_service::{password, storage};
mod administrator;
mod public_endpoint;
mod administrator_authentication;
mod self_account;

const READ_CAPABILITY: &str = "account.other.read";
const MODIFY_CAPABILITY: &str = "account.other.modify";
const AUTHENTICATE_CAPABILITY: &str = "account.authenticate";

fn diagnostic(message: &str) {
    platform::logln!("{}", message);
    let _ = platform::io::stderr(message.as_bytes());
    let _ = platform::io::stderr(b"\n");
}

struct UserService {
    database: UserDatabase,
    generation: u64,
    healthy: bool,
    groups: mochios_user_database::groups::GroupDatabase,
    groups_healthy: bool,
    administrator_authentication: administrator_authentication::Limiter,
    own_password_limiter: self_account::Limiter,
}

impl UserService {
    fn load() -> std::io::Result<Self> {
        let database = storage::load(Path::new(DATABASE_PATH))?;
        let groups = user_service::public_groups::load(
            Path::new(mochios_user_database::groups::DATABASE_PATH),
            &database,
        )?;
        Ok(Self {
            database,
            groups,
            groups_healthy: true,
            generation: 1,
            healthy: true,
            administrator_authentication: administrator_authentication::Limiter::default(),
            own_password_limiter: self_account::Limiter::default(),
        })
    }

    fn save_candidate(&mut self, operation: &str, candidate: UserDatabase) -> Result<(), u64> {
        if !self.healthy {
            return Err(mochi_user_syscall::EIO);
        }
        storage::save(Path::new(DATABASE_PATH), &candidate).map_err(|error| {
            self.healthy=false;
            let status = error.status();
            diagnostic(&format!(
                "user.service: database save failed operation={} storage_operation={} status={} error={}",
                operation,
                error.operation(),
                status,
                error,
            ));
            i64::from(status) as u64
        })?;

        self.database = candidate;
        self.generation = self.generation.wrapping_add(1).max(1);
        Ok(())
    }

    fn reply_status(&self, sender: u64, request_id: u64, status: u64) {
        let status = user_service::status::wire_status(status);
        let response = Status {
            request_id,
            status,
            generation: self.generation,
        };
        let mut buffer = [0u8; mochios_user_protocol::STATUS_LEN];
        if let Ok(length) = response.encode(&mut buffer) {
            let _ = platform::ipc::reply(sender, &buffer[..length]);
        }
    }

    fn handle_snapshot_begin(&self, sender: u64, request: &[u8]) {
        let Ok(request) = SnapshotRequest::decode(request) else {
            self.reply_status(sender, 0, mochi_user_syscall::EINVAL);
            return;
        };
        let Ok(bytes) = public_endpoint::metadata(&self.database).encode() else {
            self.reply_status(sender, request.request_id, mochi_user_syscall::EIO);
            return;
        };
        let response = SnapshotInfo {
            request_id: request.request_id,
            total_len: bytes.len() as u64,
            generation: self.generation,
        };
        let mut buffer = [0u8; mochios_user_protocol::SNAPSHOT_INFO_LEN];
        if let Ok(length) = response.encode(&mut buffer) {
            let _ = platform::ipc::reply(sender, &buffer[..length]);
        }
    }

    fn handle_snapshot_chunk(&self, sender: u64, request: &[u8]) {
        let Ok(request) = SnapshotChunkRequest::decode(request) else {
            self.reply_status(sender, 0, mochi_user_syscall::EINVAL);
            return;
        };
        let Ok(bytes) = public_endpoint::metadata(&self.database).encode() else {
            self.reply_status(sender, request.request_id, mochi_user_syscall::EIO);
            return;
        };
        let offset = usize::try_from(request.offset).unwrap_or(usize::MAX);
        if offset >= bytes.len() {
            self.reply_status(
                sender,
                request.request_id,
                mochios_posix_protocol::STATUS_ERANGE as i64 as u64,
            );
            return;
        }
        let length = (request.length as usize)
            .min(MAX_CHUNK_LEN)
            .min(bytes.len() - offset);
        let response = SnapshotChunk {
            request_id: request.request_id,
            offset: request.offset,
            generation: self.generation,
            bytes: &bytes[offset..offset + length],
        };
        let mut buffer = [0u8; MAX_MESSAGE_LEN];
        if let Ok(length) = response.encode(&mut buffer) {
            let _ = platform::ipc::reply(sender, &buffer[..length]);
        }
    }

    fn handle_add(&mut self, sender: u64, request: &[u8]) {
        let Ok(request) = AddUser::decode(request) else {
            self.reply_status(sender, 0, mochi_user_syscall::EINVAL);
            return;
        };
        let user = match UserRecord::parse(request.encoded_record) {
            Ok(user) => user,
            Err(_) => {
                self.reply_status(sender, request.request_id, mochi_user_syscall::EINVAL);
                return;
            }
        };
        if !self.groups_healthy {
            self.reply_status(sender, request.request_id, mochi_user_syscall::EIO);
            return;
        }
        let mut groups = self.groups.clone();
        groups.prune_members(&self.database);
        let mut group_changed = match groups.ensure_private(&user) {
            Ok(changed) => changed,
            Err(_) => {
                self.reply_status(sender, request.request_id, mochi_user_syscall::EINVAL);
                return;
            }
        };
        if user.uid >= mochios_user_database::FIRST_REGULAR_UID
            && !self.database.users().iter().any(|user| user.uid >= mochios_user_database::FIRST_REGULAR_UID) {
            if groups.add_administrator(&user.name).is_err() {
                self.reply_status(sender, request.request_id, mochi_user_syscall::EIO);
                return;
            }
            group_changed = true;
        }
        let mut candidate = self.database.clone();
        if candidate.add(user).is_err() {
            self.reply_status(sender, request.request_id, mochi_user_syscall::EINVAL);
            return;
        }
        // A group may exist without an account. Publish a new private group
        // first; a failed account save leaves valid, unassigned metadata.
        if group_changed {
            if let Err(error) = user_service::public_groups::save(
                Path::new(mochios_user_database::groups::DATABASE_PATH),
                &groups,
            ) {
                self.groups_healthy = false;
                self.reply_status(sender, request.request_id, i64::from(error.status()) as u64);
                return;
            }
            self.groups = groups;
        }
        let status = self
            .save_candidate("add-user", candidate)
            .err()
            .unwrap_or(0);
        self.reply_status(sender, request.request_id, status);
    }

    fn handle_remove(&mut self, sender: u64, request: &[u8]) {
        let Ok(request) = RemoveUser::decode(request) else {
            self.reply_status(sender, 0, mochi_user_syscall::EINVAL);
            return;
        };
        let mut candidate = self.database.clone();
        if candidate.remove(request.name).is_err() {
            self.reply_status(sender, request.request_id, mochi_user_syscall::EINVAL);
            return;
        }
        let mut groups = self.groups.clone();
        if groups.remove_member(request.name) {
            if user_service::public_groups::save(Path::new(mochios_user_database::groups::DATABASE_PATH), &groups).is_err() {
                self.groups_healthy = false;
                self.reply_status(sender, request.request_id, mochi_user_syscall::EIO);
                return;
            }
            self.groups = groups;
        }
        let status = self
            .save_candidate("remove-user", candidate)
            .err()
            .unwrap_or(0);
        self.reply_status(sender, request.request_id, status);
    }

    fn handle_set_password(&mut self, sender: u64, request: &[u8]) {
        if !self.healthy {
            self.reply_status(sender, 0, mochi_user_syscall::EIO);
            return;
        }
        let Ok(request) = SetPassword::decode(request) else {
            self.reply_status(sender, 0, mochi_user_syscall::EINVAL);
            return;
        };
        self.replace_password(sender, request.request_id, request.name, request.password, || Ok(()));
    }

    fn replace_password(&mut self, sender: u64, request_id: u64, name: &str, password_bytes: &[u8], revalidate: impl Fn() -> Result<(), i32>) {
        let Some(existing) = self.database.find_name(name) else {
            self.reply_status(sender, request_id, mochi_user_syscall::ENOENT);
            return;
        };
        let password_hash = match password::hash(password_bytes) {
            Ok(password_hash) => password_hash,
            Err(_) => {
                self.reply_status(sender, request_id, mochi_user_syscall::EIO);
                return;
            }
        };
        if let Err(status) = revalidate() {
            self.reply_status(sender, request_id, i64::from(status) as u64);
            return;
        }
        // Publish both old/new encrypted key wrappers before changing the
        // account DB. A crash or failed save keeps the old login recoverable.
        let prepared = user_service::keychain::Connection::connect().and_then(|c| {
            c.prepare_password(
                existing.uid,
                &existing.password_hash,
                &password_hash,
                password_bytes,
            )
        });
        if prepared.is_err() {
            self.reply_status(sender, request_id, mochi_user_syscall::EIO);
            return;
        }
        let mut candidate = self.database.clone();
        let Some(user) = candidate.find_name_mut(&existing.name) else {
            self.reply_status(sender, request_id, mochi_user_syscall::ENOENT);
            return;
        };
        user.password_hash = password_hash;
        user.locked = false;
        if let Err(status) = revalidate() {
            self.reply_status(sender, request_id, i64::from(status) as u64);
            return;
        }
        let status = match self.save_candidate("set-password", candidate) {
            Ok(()) => 0,
            Err(status) => status,
        };
        if status == 0 {
            if let Some(user) = self.database.find_name(name) {
                // Initial account setup can proceed straight to session
                // activation without another password-entry screen.
                if user_service::keychain::Connection::connect()
                    .and_then(|c| c.verified_login(user.uid, &user.password_hash, password_bytes))
                    .is_err()
                {
                    diagnostic("user.service: password saved; keychain login handoff unavailable");
                }
            }
        }
        self.reply_status(sender, request_id, status);
    }

    fn handle_self_info(&self, client: &mochios_posix_client::Client<mochios_posix_client::SyscallEndpointTransport>, sender: u64, bytes: &[u8]) {
        let result = (|| {
            let request = mochios_user_protocol::self_account::Info::decode(bytes).map_err(|_| -22)?;
            let caller = self_account::capture(client, sender, false)?;
            let user = self.database.find_uid(caller.uid).filter(|_| self.healthy).ok_or(-13)?;
            let record = mochios_user_protocol::public_account::Record { uid: user.uid, gid: user.gid, name: &user.name, display_name: &user.display_name, home: &user.home, shell: &user.shell };
            let mut reply = [0; MAX_MESSAGE_LEN];
            let n = mochios_user_protocol::self_account::encode_info(request.request_id, record, &mut reply).map_err(|_| -5)?;
            platform::ipc::reply(sender, &reply[..n]).map_err(|_| -5)?;
            Ok::<_, i32>(())
        })();
        if let Err(status) = result { let id = mochios_user_protocol::self_account::Info::decode(bytes).map(|r| r.request_id).unwrap_or(0); self.reply_status(sender, id, i64::from(status) as u64); }
    }

    fn handle_change_own_password(&mut self, client: &mochios_posix_client::Client<mochios_posix_client::SyscallEndpointTransport>, sender: u64, bytes: &[u8]) {
        let result = (|| {
            let request = mochios_user_protocol::self_account::ChangePassword::decode(bytes).map_err(|_| -22)?;
            let caller = self_account::capture(client, sender, true)?;
            let now = platform::time::monotonic_nanoseconds().map_err(|_| -5)?;
            self.own_password_limiter.check(caller.uid, now)?;
            let user = self.database.find_uid(caller.uid).filter(|user| self.healthy && !user.locked).ok_or(-13)?;
            let verified = password::verify(request.current, &user.password_hash);
            let name = user.name.clone();
            if !verified { self.own_password_limiter.failed(caller.uid, now); return Err(-13); }
            caller.revalidate(client, sender)?;
            self.own_password_limiter.succeeded(caller.uid);
            self.replace_password(sender, request.request_id, &name, request.replacement, || caller.revalidate(client, sender));
            Ok::<_, i32>(())
        })();
        if let Err(status) = result { let id = mochios_user_protocol::self_account::ChangePassword::decode(bytes).map(|r| r.request_id).unwrap_or(0); self.reply_status(sender, id, i64::from(status) as u64); }
    }

    fn handle_authenticate(&self, sender: u64, request: &[u8]) {
        if !self.healthy {
            self.reply_status(sender, 0, mochi_user_syscall::EIO);
            return;
        }
        let Ok(request) = Authenticate::decode(request) else {
            platform::logln!("user.service: rejected malformed authentication request");
            self.reply_status(sender, 0, mochi_user_syscall::EINVAL);
            return;
        };
        let user = self.database.find_name(request.name);
        let stored_hash = match user {
            Some(user) if !user.locked => user.password_hash.as_str(),
            _ => "!",
        };
        let keychain = user_service::keychain::Connection::connect();
        let verified = password::verify(request.password, stored_hash);
        let Some(user) = user else {
            platform::logln!(
                "user.service: authentication denied request={} reason=unknown-user",
                request.request_id
            );
            self.reply_status(sender, request.request_id, mochi_user_syscall::EACCES);
            return;
        };
        if user.locked || !verified {
            platform::logln!(
                "user.service: authentication denied request={} reason={}",
                request.request_id,
                if user.locked { "locked" } else { "credential" }
            );
            self.reply_status(sender, request.request_id, mochi_user_syscall::EACCES);
            return;
        }
        // A keychain failure must not claim false authentication or prevent
        // account recovery. The vault stays unavailable without a valid proof.
        if keychain
            .and_then(|c| c.verified_login(user.uid, stored_hash, request.password))
            .is_err()
        {
            diagnostic("user.service: authenticated user; keychain handoff unavailable");
        }
        let response = AuthenticationResult {
            request_id: request.request_id,
            uid: user.uid,
            gid: user.gid,
            name: &user.name,
            home: &user.home,
            shell: &user.shell,
        };
        let mut buffer = [0u8; MAX_MESSAGE_LEN];
        match response.encode(&mut buffer) {
            Ok(length) => {
                platform::logln!(
                    "user.service: authentication accepted request={} response_bytes={}",
                    request.request_id,
                    length
                );
                let _ = platform::ipc::reply(sender, &buffer[..length]);
            }
            Err(_) => {
                platform::logln!(
                    "user.service: authentication response encode failed request={}",
                    request.request_id
                );
                self.reply_status(sender, request.request_id, mochi_user_syscall::EIO);
            }
        }
    }
}

fn main() {
    let _ = platform::logger::init_from_env();
    platform::logln!("user.service: start");
    let Some(ready_target) = platform::service_ready::take_bootstrap_target() else {
        diagnostic("user.service: missing ready target");
        platform::process::exit(1);
    };
    let mut service = match UserService::load() {
        Ok(service) => service,
        Err(error) => {
            diagnostic(&format!(
                "user.service: database load failed error={}",
                error
            ));
            let _ = platform::service_ready::notify(
                ready_target,
                user_service::status::io_status(&error),
            );
            platform::process::exit(1);
        }
    };
    if let Err(error) = administrator::protect_settings() {
        diagnostic(&format!("user.service: account settings protection failed: {error}"));
        let _ = platform::service_ready::notify(ready_target, -13);
        platform::process::exit(1);
    }
    let endpoint = match platform::ipc::create_handle() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            diagnostic(&format!(
                "user.service: endpoint create failed errno={}",
                error.errno().unwrap_or(0)
            ));
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    let posix = match mochios_posix_client::Client::from_syscall_launch_context() {
        Ok(client) => client,
        Err(_) => { diagnostic("user.service: missing POSIX session authority"); platform::process::exit(1); }
    };
    let (public_endpoint, public_view) = match public_endpoint::start(public_endpoint::Snapshot {
        database: public_endpoint::metadata(&service.database), groups: service.groups.clone(),
        healthy: service.healthy, groups_healthy: service.groups_healthy,
    }) {
        Ok(started) => started,
        Err(_) => { diagnostic("user.service: public account endpoint startup failed"); platform::process::exit(1); }
    };
    let rights = mochios_posix_protocol::ACCOUNT_ENDPOINT_RIGHTS;
    if platform::service_ready::notify_handle(ready_target, 0, public_endpoint, rights).is_err() {
        diagnostic("user.service: ready notification failed");
        platform::process::exit(1);
    }
    platform::logln!(
        "user.service: ready users={}",
        service.database.users().len()
    );
    let mut buffer = [0u8; MAX_MESSAGE_LEN];
    loop {
        buffer.zeroize();
        let message = match platform::ipc::wait(u64::from(endpoint), &mut buffer) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let request = &buffer[..length.min(buffer.len())];
        let opcode = decode_opcode(request);
        if opcode == Ok(Opcode::PublicGroupLookup) {
            let mut response = [0; MAX_MESSAGE_LEN];
            match user_service::public_groups::reply(
                &service.groups,
                service.groups_healthy,
                request,
                &mut response,
            ) {
                Ok(length) => {
                    let _ = platform::ipc::reply(sender, &response[..length]);
                }
                Err(status) => {
                    let id = mochios_user_protocol::public_group::decode_request(request)
                        .map(|(id, _)| id)
                        .unwrap_or(0);
                    service.reply_status(sender, id, i64::from(status) as u64);
                }
            }
            buffer.zeroize();
            continue;
        }
        if opcode == Ok(Opcode::PublicLookup) {
            let mut response = [0; MAX_MESSAGE_LEN];
            match user_service::public_accounts::reply(
                &service.database,
                service.healthy,
                request,
                &mut response,
            ) {
                Ok(length) => {
                    let _ = platform::ipc::reply(sender, &response[..length]);
                }
                Err(status) => {
                    let id = mochios_user_protocol::public_account::decode_request(request)
                        .map(|(id, _)| id)
                        .unwrap_or(0);
                    service.reply_status(sender, id, i64::from(status) as u64);
                }
            }
            buffer.zeroize();
            continue;
        }
        let required_capability = match opcode {
            Ok(Opcode::SnapshotBegin | Opcode::SnapshotChunk) => READ_CAPABILITY,
            Ok(Opcode::SelfInfo) => "account.self.read",
            Ok(Opcode::ChangeOwnPassword) => "account.self.modify",
            Ok(Opcode::AddUser | Opcode::RemoveUser | Opcode::SetPassword) => MODIFY_CAPABILITY,
            Ok(Opcode::Authenticate | Opcode::VerifyAdministrator) => AUTHENTICATE_CAPABILITY,
            _ => {
                service.reply_status(sender, 0, mochi_user_syscall::EINVAL);
                buffer.zeroize();
                continue;
            }
        };
        if platform::capability::check_thread(sender, required_capability) != Ok(1) {
            platform::logln!(
                "user.service: request denied missing capability={}",
                required_capability
            );
            service.reply_status(sender, 0, mochi_user_syscall::EACCES);
            buffer.zeroize();
            continue;
        }
        if required_capability == MODIFY_CAPABILITY && !administrator::permits(&posix, sender) {
            let request_id = match opcode {
                Ok(Opcode::AddUser) => AddUser::decode(request).map(|request| request.request_id).unwrap_or(0),
                Ok(Opcode::RemoveUser) => RemoveUser::decode(request).map(|request| request.request_id).unwrap_or(0),
                Ok(Opcode::SetPassword) => SetPassword::decode(request).map(|request| request.request_id).unwrap_or(0),
                _ => 0,
            };
            service.reply_status(sender, request_id, mochi_user_syscall::EACCES);
            buffer.zeroize();
            continue;
        }
        match opcode {
            Ok(Opcode::SnapshotBegin) => service.handle_snapshot_begin(sender, request),
            Ok(Opcode::SnapshotChunk) => service.handle_snapshot_chunk(sender, request),
            Ok(Opcode::AddUser) => service.handle_add(sender, request),
            Ok(Opcode::RemoveUser) => service.handle_remove(sender, request),
            Ok(Opcode::SetPassword) => service.handle_set_password(sender, request),
            Ok(Opcode::SelfInfo) => service.handle_self_info(&posix, sender, request),
            Ok(Opcode::ChangeOwnPassword) => service.handle_change_own_password(&posix, sender, request),
            Ok(Opcode::Authenticate) => service.handle_authenticate(sender, request),
            Ok(Opcode::VerifyAdministrator) => {
                let id = mochios_user_protocol::VerifyAdministrator::decode(request).map(|request| request.request_id).unwrap_or(0);
                let status = if service.healthy && service.groups_healthy {
                    service.administrator_authentication.verify(sender, request, &service.database, &service.groups).err().unwrap_or(0)
                } else { -5 };
                service.reply_status(sender, id, i64::from(status) as u64);
            }
            _ => service.reply_status(sender, 0, mochi_user_syscall::EINVAL),
        }
        let used_length = length.min(buffer.len());
        buffer[..used_length].zeroize();
        // Never hold this projection lock while querying POSIX or saving files.
        // Publish only metadata after the authoritative mutation has finished.
        if let Ok(mut view) = public_view.lock() {
            *view = public_endpoint::Snapshot {
                database: public_endpoint::metadata(&service.database), groups: service.groups.clone(),
                healthy: service.healthy, groups_healthy: service.groups_healthy,
            };
        } else { platform::process::exit(1); }
    }
}
