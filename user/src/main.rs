use std::path::Path;

use mochi_user_platform as platform;
use mochios_user_database::{DATABASE_PATH, UserDatabase, UserRecord};
use mochios_user_protocol::{
    AddUser, MAX_CHUNK_LEN, MAX_MESSAGE_LEN, Opcode, RemoveUser, SnapshotChunk,
    SnapshotChunkRequest, SnapshotInfo, SnapshotRequest, Status, decode_opcode,
};
use user_service::storage;

const READ_CAPABILITY: &str = "account.other.read";
const MODIFY_CAPABILITY: &str = "account.other.modify";

fn diagnostic(message: &str) {
    platform::println!("{}", message);
    let _ = platform::io::stderr(message.as_bytes());
    let _ = platform::io::stderr(b"\n");
}

struct UserService {
    database: UserDatabase,
    generation: u64,
}

impl UserService {
    fn load() -> std::io::Result<Self> {
        Ok(Self {
            database: storage::load(Path::new(DATABASE_PATH))?,
            generation: 1,
        })
    }

    fn save_candidate(&mut self, candidate: UserDatabase) -> Result<(), u64> {
        storage::save(Path::new(DATABASE_PATH), &candidate).map_err(errno)?;
        self.database = candidate;
        self.generation = self.generation.wrapping_add(1).max(1);
        Ok(())
    }

    fn reply_status(&self, sender: u64, request_id: u64, status: u64) {
        let status = if status == 0 {
            0
        } else {
            -(i32::try_from(status).unwrap_or(i32::MAX))
        };
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
        let Ok(bytes) = self.database.encode() else {
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
        let Ok(bytes) = self.database.encode() else {
            self.reply_status(sender, request.request_id, mochi_user_syscall::EIO);
            return;
        };
        let offset = usize::try_from(request.offset).unwrap_or(usize::MAX);
        if offset >= bytes.len() {
            self.reply_status(sender, request.request_id, mochi_user_syscall::ERANGE);
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
        let mut candidate = self.database.clone();
        if candidate.add(user).is_err() {
            self.reply_status(sender, request.request_id, mochi_user_syscall::EINVAL);
            return;
        }
        let status = self.save_candidate(candidate).err().unwrap_or(0);
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
        let status = self.save_candidate(candidate).err().unwrap_or(0);
        self.reply_status(sender, request.request_id, status);
    }
}

fn errno(error: std::io::Error) -> u64 {
    error
        .raw_os_error()
        .unwrap_or(mochi_user_syscall::EIO as i32) as u64
}

fn main() {
    let _ = platform::logger::init_from_env();
    platform::println!("user.service: start");
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
            let _ = platform::service_ready::notify(ready_target, -(errno(error) as i32));
            platform::process::exit(1);
        }
    };
    let endpoint = match platform::ipc::create() {
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
    if platform::service_ready::notify(ready_target, 0).is_err() {
        diagnostic("user.service: ready notification failed");
        platform::process::exit(1);
    }
    platform::println!(
        "user.service: ready users={}",
        service.database.users().len()
    );
    let mut buffer = [0u8; MAX_MESSAGE_LEN];
    loop {
        let message = match platform::ipc::wait(endpoint, &mut buffer) {
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
        let required_capability = match opcode {
            Ok(Opcode::SnapshotBegin | Opcode::SnapshotChunk) => READ_CAPABILITY,
            Ok(Opcode::AddUser | Opcode::RemoveUser) => MODIFY_CAPABILITY,
            _ => {
                service.reply_status(sender, 0, mochi_user_syscall::EINVAL);
                continue;
            }
        };
        if platform::capability::check_thread(sender, required_capability) != Ok(1) {
            service.reply_status(sender, 0, mochi_user_syscall::EACCES);
            continue;
        }
        match opcode {
            Ok(Opcode::SnapshotBegin) => service.handle_snapshot_begin(sender, request),
            Ok(Opcode::SnapshotChunk) => service.handle_snapshot_chunk(sender, request),
            Ok(Opcode::AddUser) => service.handle_add(sender, request),
            Ok(Opcode::RemoveUser) => service.handle_remove(sender, request),
            _ => service.reply_status(sender, 0, mochi_user_syscall::EINVAL),
        }
    }
}
