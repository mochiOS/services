#[cfg(target_os = "mochios")]
fn main() {
    use std::sync::Arc;

    use ext4plus::Ext4;
    use filesystem_service::ext4::Ext4Storage;
    use filesystem_service::platform_storage::{MochiDisk, find_data_partition};
    use filesystem_service::service::FilesystemService;
    use filesystem_service::storage::PartitionIo;
    use mochi_user_platform as platform;
    use mochios_filesystem_protocol as protocol;

    let _ = platform::logger::init_from_env();
    platform::logln!("filesystem.service: start");
    let Some(ready_target) = platform::service_ready::take_bootstrap_target() else {
        platform::logln!("filesystem.service: missing ready target");
        platform::process::exit(1);
    };
    let (first_lba, sector_count) = match find_data_partition(0) {
        Ok(range) => range,
        Err(error)
            if error.is_not_found()
                && platform::boot::system_slot()
                    .ok()
                    .is_none_or(|slot| slot == 0) =>
        {
            platform::logln!(
                "filesystem.service: legacy image has no Data partition; retaining CExt root"
            );
            let _ = platform::service_ready::notify(ready_target, 0);
            loop {
                platform::thread::yield_now();
            }
        }
        Err(error) => {
            platform::logln!("filesystem.service: Data partition discovery failed: {error}");
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    let partition = Arc::new(PartitionIo::new(MochiDisk::new(0), first_lba, sector_count));
    let storage = Ext4Storage::new(partition.clone());
    let fs = match Ext4::load_with_writer(Box::new(storage.clone()), Some(Box::new(storage))) {
        Ok(fs) => fs,
        Err(error) => {
            platform::logln!("filesystem.service: ext4 mount failed: {error}");
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    let legacy_endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => {
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    let endpoint = match platform::ipc::create_handle() {
        Ok(endpoint) => endpoint,
        Err(_) => {
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    let filesystem_id = match register_filesystem(legacy_endpoint) {
        Ok(filesystem_id) => filesystem_id,
        Err(_) => {
            platform::logln!("filesystem.service: registration failed");
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    const COMPATIBILITY_ROOT_FILESYSTEM_ID: u64 = 1;
    if mount_filesystem(COMPATIBILITY_ROOT_FILESYSTEM_ID, "/system", "/system").is_err() {
        platform::logln!("filesystem.service: System mount failed");
        let _ = platform::service_ready::notify(ready_target, -1);
        platform::process::exit(1);
    }
    if mount_filesystem(filesystem_id, "/", "/").is_err() {
        platform::logln!("filesystem.service: Data root mount failed");
        let _ = platform::service_ready::notify(ready_target, -1);
        platform::process::exit(1);
    }
    let mut service = FilesystemService::new(fs);
    let delegated_rights = platform::handle::HANDLE_RIGHT_SEND
        | platform::handle::HANDLE_RIGHT_DUPLICATE
        | platform::handle::HANDLE_RIGHT_TRANSFER;
    if platform::service_ready::notify_handle(ready_target, 0, endpoint, delegated_rights).is_err()
    {
        platform::process::exit(1);
    }
    platform::logln!("filesystem.service: ready");
    let mut request_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let mut response_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    loop {
        let mut attached = platform::ipc::IpcObjectHandles::default();
        let message = match platform::ipc::wait_object_handles(
            endpoint as u64,
            &mut request_bytes,
            &mut attached,
        ) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let request = &request_bytes[..length.min(request_bytes.len())];
        if request.starts_with(&mnu_abi::provider::MAGIC.to_le_bytes()) {
            let response_len = handle_provider_request(&mut service, request, &mut response_bytes);
            close_attached_handles(&attached);
            if let Some(response_len) = response_len {
                let _ = platform::ipc::reply(sender, &response_bytes[..response_len]);
            }
            continue;
        }
        let response = match protocol::decode(&request_bytes[..length.min(request_bytes.len())]) {
            Ok((header, payload)) => {
                if header.opcode == protocol::OP_OPEN_AT {
                    let base_open_id = if attached.count == 1 {
                        let directory = attached.handles[0];
                        let required = platform::handle::HANDLE_RIGHT_READ
                            | platform::handle::HANDLE_RIGHT_TRANSFER;
                        if directory.reserved != 0 || directory.rights & required != required {
                            None
                        } else {
                            platform::handle::identify_provider_object(directory.handle).ok()
                        }
                    } else if attached.count == 0 {
                        None
                    } else {
                        close_attached_handles(&attached);
                        let response = filesystem_service::service::Response {
                            header: protocol::Header {
                                opcode: protocol::OP_STATUS,
                                request_id: header.request_id,
                                status: -22,
                                ..protocol::Header::default()
                            },
                            payload: Vec::new(),
                        };
                        if let Ok(length) = protocol::encode(
                            response.header,
                            &response.payload,
                            &mut response_bytes,
                        ) {
                            let _ = platform::ipc::reply(sender, &response_bytes[..length]);
                        }
                        continue;
                    };
                    let result = service.open_at(header, payload, base_open_id);
                    close_attached_handles(&attached);
                    match result {
                        Ok(response) => {
                            let rights = open_handle_rights(header.flags);
                            let opened = match platform::handle::create_provider_object(
                                endpoint,
                                response.header.open_id,
                                rights,
                            ) {
                                Ok(opened) => opened,
                                Err(_) => {
                                    let _ = service.provider_close(response.header.open_id);
                                    let failed = filesystem_service::service::Response {
                                        header: protocol::Header {
                                            opcode: protocol::OP_STATUS,
                                            request_id: header.request_id,
                                            status: -5,
                                            ..protocol::Header::default()
                                        },
                                        payload: Vec::new(),
                                    };
                                    if let Ok(length) = protocol::encode(
                                        failed.header,
                                        &failed.payload,
                                        &mut response_bytes,
                                    ) {
                                        let _ =
                                            platform::ipc::reply(sender, &response_bytes[..length]);
                                    }
                                    continue;
                                }
                            };
                            if let Ok(length) = protocol::encode(
                                response.header,
                                &response.payload,
                                &mut response_bytes,
                            ) {
                                let mut outgoing = platform::ipc::IpcObjectHandles::default();
                                outgoing.count = 1;
                                outgoing.handles[0] = platform::ipc::IpcObjectHandle {
                                    handle: opened,
                                    reserved: 0,
                                    rights,
                                };
                                let sent = platform::ipc::reply_object_handles(
                                    sender,
                                    &response_bytes[..length],
                                    &outgoing,
                                );
                                if sent.is_err() {
                                    let _ = service.provider_close(response.header.open_id);
                                }
                            }
                            let _ = platform::handle::close(opened);
                            continue;
                        }
                        Err(error) => {
                            let failed = filesystem_service::service::Response {
                                header: protocol::Header {
                                    opcode: protocol::OP_STATUS,
                                    request_id: header.request_id,
                                    status: -error,
                                    ..protocol::Header::default()
                                },
                                payload: Vec::new(),
                            };
                            if let Ok(length) = protocol::encode(
                                failed.header,
                                &failed.payload,
                                &mut response_bytes,
                            ) {
                                let _ = platform::ipc::reply(sender, &response_bytes[..length]);
                            }
                            continue;
                        }
                    }
                } else if attached.count != 0 {
                    filesystem_service::service::Response {
                        header: protocol::Header {
                            opcode: protocol::OP_STATUS,
                            request_id: header.request_id,
                            status: -22,
                            ..protocol::Header::default()
                        },
                        payload: Vec::new(),
                    }
                } else {
                    if header.opcode == protocol::OP_SYNC {
                        if partition.flush().is_err() {
                            let response = filesystem_service::service::Response {
                                header: protocol::Header {
                                    opcode: protocol::OP_STATUS,
                                    request_id: header.request_id,
                                    mount_id: header.mount_id,
                                    status: -5,
                                    ..protocol::Header::default()
                                },
                                payload: Vec::new(),
                            };
                            if let Ok(length) = protocol::encode(
                                response.header,
                                &response.payload,
                                &mut response_bytes,
                            ) {
                                let _ = platform::ipc::reply(sender, &response_bytes[..length]);
                            }
                            continue;
                        }
                    }
                    service.handle(header, payload)
                }
            }
            Err(_) => filesystem_service::service::Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    status: -22,
                    ..protocol::Header::default()
                },
                payload: Vec::new(),
            },
        };
        close_attached_handles(&attached);
        if let Ok(length) =
            protocol::encode(response.header, &response.payload, &mut response_bytes)
        {
            let _ = platform::ipc::reply(sender, &response_bytes[..length]);
        }
    }
}

#[cfg(target_os = "mochios")]
fn open_handle_rights(flags: u32) -> u64 {
    use mochios_filesystem_protocol as protocol;
    let mut rights = mochi_user_platform::handle::HANDLE_RIGHT_DUPLICATE
        | mochi_user_platform::handle::HANDLE_RIGHT_TRANSFER;
    if flags & protocol::OPEN_AT_READ != 0 {
        rights |= mochi_user_platform::handle::HANDLE_RIGHT_READ;
    }
    if flags & protocol::OPEN_AT_WRITE != 0 {
        rights |= mochi_user_platform::handle::HANDLE_RIGHT_WRITE;
    }
    if flags & protocol::OPEN_AT_DIRECTORY == 0 {
        rights |= mochi_user_platform::handle::HANDLE_RIGHT_SEEK;
    }
    rights
}

#[cfg(target_os = "mochios")]
fn close_attached_handles(handles: &mochi_user_platform::ipc::IpcObjectHandles) {
    for attached in handles.handles.iter().take(handles.count as usize) {
        let _ = mochi_user_platform::handle::close(attached.handle);
    }
}

#[cfg(target_os = "mochios")]
fn handle_provider_request(
    service: &mut filesystem_service::service::FilesystemService,
    request: &[u8],
    response: &mut [u8],
) -> Option<usize> {
    use mnu_abi::provider;
    let (header, payload) = provider::RequestHeader::decode(request).ok()?;
    if header.opcode == provider::OP_RELEASE {
        let _ = service.provider_close(header.object_id);
        return None;
    }
    let result = match header.opcode {
        provider::OP_READ => service
            .provider_read(header.object_id, header.length as usize)
            .map(|data| (data.len() as u64, data)),
        provider::OP_WRITE => service
            .provider_write(header.object_id, payload)
            .map(|written| (written as u64, Vec::new())),
        provider::OP_SEEK => service
            .provider_seek(header.object_id, header.argument, header.basis)
            .map(|offset| (offset, Vec::new())),
        _ => Err(38),
    };
    let (status, value, data) = match result {
        Ok((value, data)) => (0, value, data),
        Err(errno) => (-(errno as i64), 0, Vec::new()),
    };
    provider::ResponseHeader {
        opcode: header.opcode,
        status,
        object_id: header.object_id,
        value,
        data_length: data.len() as u32,
    }
    .encode(&data, response)
    .ok()
}

#[cfg(target_os = "mochios")]
fn register_filesystem(endpoint: u64) -> Result<u64, ()> {
    let raw = unsafe {
        mochi_user_platform::syscall::syscall1(
            mochios_filesystem_protocol::SYS_FILESYSTEM_REGISTER,
            endpoint,
        )
    };
    syscall_result(raw)
}

#[cfg(target_os = "mochios")]
fn mount_filesystem(filesystem_id: u64, target: &str, source: &str) -> Result<u64, ()> {
    let raw = unsafe {
        mochi_user_platform::syscall::syscall5(
            mochios_filesystem_protocol::SYS_FILESYSTEM_MOUNT,
            filesystem_id,
            target.as_ptr() as u64,
            target.len() as u64,
            source.as_ptr() as u64,
            source.len() as u64,
        )
    };
    syscall_result(raw)
}

#[cfg(target_os = "mochios")]
fn syscall_result(raw: u64) -> Result<u64, ()> {
    if (raw as i64) < 0 { Err(()) } else { Ok(raw) }
}

#[cfg(not(target_os = "mochios"))]
fn main() {}
