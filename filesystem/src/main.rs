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
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => {
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    let filesystem_id = match register_filesystem(endpoint) {
        Ok(filesystem_id) => filesystem_id,
        Err(_) => {
            platform::logln!("filesystem.service: registration failed");
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    };
    for path in [
        "/bin",
        "/applications",
        "/libraries",
        "/home",
        "/var",
        "/tmp",
    ] {
        if mount_filesystem(filesystem_id, path, path).is_err() {
            platform::logln!("filesystem.service: mount failed: {path}");
            let _ = platform::service_ready::notify(ready_target, -1);
            platform::process::exit(1);
        }
    }
    let mut service = FilesystemService::new(fs);
    if platform::service_ready::notify(ready_target, 0).is_err() {
        platform::process::exit(1);
    }
    platform::logln!("filesystem.service: ready");
    let mut request_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let mut response_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    loop {
        let message = match platform::ipc::wait(endpoint, &mut request_bytes) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let response = match protocol::decode(&request_bytes[..length.min(request_bytes.len())]) {
            Ok((header, payload)) => {
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
            Err(_) => filesystem_service::service::Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    status: -22,
                    ..protocol::Header::default()
                },
                payload: Vec::new(),
            },
        };
        if let Ok(length) =
            protocol::encode(response.header, &response.payload, &mut response_bytes)
        {
            let _ = platform::ipc::reply(sender, &response_bytes[..length]);
        }
    }
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
    if (raw as i64) < 0 {
        Err(())
    } else {
        Ok(raw)
    }
}

#[cfg(not(target_os = "mochios"))]
fn main() {}
