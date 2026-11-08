//! Read-only account projection has its own endpoint. POSIX may call it while
//! the mutation endpoint is waiting for POSIX credentials or durable I/O.
use mochi_user_platform as platform;
use mochios_user_database::{UserDatabase, groups::GroupDatabase};
use mochios_user_protocol::{MAX_MESSAGE_LEN, Opcode, Status, decode_opcode};
use std::sync::{Arc, Mutex, mpsc};

#[derive(Clone)]
pub struct Snapshot {
    pub database: UserDatabase,
    pub groups: GroupDatabase,
    pub healthy: bool,
    pub groups_healthy: bool,
}
pub type Shared = Arc<Mutex<Snapshot>>;

/// Hashes are never part of metadata snapshots, on either public endpoint.
pub fn metadata(database: &UserDatabase) -> UserDatabase {
    let mut result = database.clone();
    for user in database.users() {
        if let Some(record) = result.find_name_mut(&user.name) {
            record.password_hash = "!".into();
        }
    }
    result
}

pub fn start(snapshot: Snapshot) -> Result<(u32, Shared), i32> {
    let shared = Arc::new(Mutex::new(snapshot));
    let worker = Arc::clone(&shared);
    let (ready, startup) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("public-accounts".into())
        .spawn(move || {
            let endpoint = match platform::ipc::create_handle() {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = ready.send(Err(error.raw() as i32));
                    return;
                }
            };
            if ready.send(Ok(endpoint)).is_err() {
                return;
            }
            let mut request = [0; MAX_MESSAGE_LEN];
            let mut response = [0; MAX_MESSAGE_LEN];
            loop {
                let message = match platform::ipc::wait(u64::from(endpoint), &mut request) {
                    Ok(message) => message,
                    Err(_) => {
                        platform::thread::yield_now();
                        continue;
                    }
                };
                let sender = message >> 32;
                let bytes = &request[..(message as u32 as usize).min(request.len())];
                let request_id = match decode_opcode(bytes) {
                    Ok(Opcode::PublicLookup) => {
                        mochios_user_protocol::public_account::decode_request(bytes)
                            .map(|(id, _)| id)
                            .unwrap_or(0)
                    }
                    Ok(Opcode::PublicGroupLookup) => {
                        mochios_user_protocol::public_group::decode_request(bytes)
                            .map(|(id, _)| id)
                            .unwrap_or(0)
                    }
                    _ => 0,
                };
                let result =
                    worker
                        .lock()
                        .map_err(|_| -5)
                        .and_then(|view| match decode_opcode(bytes) {
                            Ok(Opcode::PublicLookup) => user_service::public_accounts::reply(
                                &view.database,
                                view.healthy,
                                bytes,
                                &mut response,
                            ),
                            Ok(Opcode::PublicGroupLookup) => user_service::public_groups::reply(
                                &view.groups,
                                view.groups_healthy,
                                bytes,
                                &mut response,
                            ),
                            _ => Err(-13),
                        });
                let length = result.unwrap_or_else(|status| {
                    Status {
                        request_id,
                        status,
                        generation: 0,
                    }
                    .encode(&mut response)
                    .unwrap_or(0)
                });
                let _ = platform::ipc::reply(sender, &response[..length]);
            }
        })
        .map_err(|_| -5)?;
    let endpoint = startup.recv().map_err(|_| -5)??;
    Ok((endpoint, shared))
}
