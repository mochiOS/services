//! Dedicated native Provider endpoint: object IDs are interpreted only after
//! native delivery authentication or owner-endpoint identification of an
//! explicitly attached Handle. There is no PID/FD lookup facility.

use crate::shared_memory_native::{NativeBacking, NativeProviderBacking};
use mochi_user_platform as platform;
use mochios_posix_protocol::shared_memory as wire;
use posix_service::shared_memory_file::{Descriptions, handle_provider_request};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, Ordering},
};

const MAP_MAGIC: &[u8; 4] = b"SHMB";

pub fn start() -> Result<NativeProviderBacking, i64> {
    let descriptions = Arc::new(Mutex::new(Descriptions::new()));
    let worker_descriptions = Arc::clone(&descriptions);
    let startup = Arc::new(AtomicI64::new(0));
    let worker_startup = Arc::clone(&startup);
    std::thread::Builder::new()
        .name("posix-shm-provider".to_owned())
        .spawn(move || match platform::ipc::create_handle() {
            Ok(endpoint) => {
                worker_startup.store(i64::from(endpoint), Ordering::Release);
                run(endpoint, worker_descriptions);
            }
            Err(error) => worker_startup.store(error.raw(), Ordering::Release),
        })
        .map_err(|_| -5)?;
    loop {
        match startup.load(Ordering::Acquire) {
            0 => platform::thread::yield_now(),
            error if error < 0 => return Err(error),
            endpoint => {
                return Ok(NativeProviderBacking {
                    endpoint: u32::try_from(endpoint).map_err(|_| -5)?,
                    descriptions,
                });
            }
        }
    }
}

pub fn mapping(
    endpoint: u32,
    writable: bool,
    attachment: posix_service::AttachedObject<u32>,
) -> Result<posix_service::OpenedObject<u32>, i32> {
    let mut request = [0; 8];
    request[..4].copy_from_slice(MAP_MAGIC);
    request[4..].copy_from_slice(&u32::from(writable).to_le_bytes());
    let mut attachments = platform::ipc::IpcObjectHandles::default();
    attachments.count = 1;
    attachments.handles[0] = platform::ipc::IpcObjectHandle {
        handle: attachment.handle,
        reserved: 0,
        rights: attachment.rights,
    };
    let mut response = [0; 4];
    let outcome =
        platform::ipc::call_object_handles(endpoint, &request, &mut response, &mut attachments);
    let result = match outcome {
        Err(error) => Err(error.raw() as i32),
        Ok(length) if length as u32 != 4 || attachments.delivery_flags != 0 => Err(-5),
        Ok(_) => {
            let status = i32::from_le_bytes(response);
            if status != 0 {
                Err(status)
            } else if attachments.count == 1
                && attachments.handles[0].reserved == 0
                && attachments.handles[0].handle != 0
                && attachments.handles[0].rights == wire::mapping_rights(writable)
            {
                Ok(posix_service::OpenedObject {
                    handle: attachments.handles[0].handle,
                    rights: attachments.handles[0].rights,
                })
            } else {
                Err(-5)
            }
        }
    };
    // On transport failure the attachment array may still contain the original
    // borrowed request Handle. Only successful calls replace it with owned replies.
    if outcome.is_ok() && result.is_err() {
        for attachment in attachments.handles.iter().take(attachments.count as usize) {
            let _ = platform::handle::close(attachment.handle);
        }
    }
    result
}

fn run(endpoint: u32, descriptions: Arc<Mutex<Descriptions<u32>>>) -> ! {
    use mnu_abi::provider;
    let mut request = vec![0; provider::REQUEST_HEADER_LEN + provider::MAX_DATA_LEN];
    let mut response = vec![0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    loop {
        let mut attachments = platform::ipc::IpcObjectHandles::default();
        let message = match platform::ipc::wait_object_handles(
            u64::from(endpoint),
            &mut request,
            &mut attachments,
        ) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message as u32 as usize).min(request.len());
        let bytes = &request[..length];
        if bytes.starts_with(MAP_MAGIC) {
            let result = (|| {
                if bytes.len() != 8
                    || attachments.count != 1
                    || attachments.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
                {
                    return Err(-22);
                }
                let writable = match u32::from_le_bytes(bytes[4..].try_into().unwrap()) {
                    0 => false,
                    1 => true,
                    _ => return Err(-22),
                };
                let attached = attachments.handles[0];
                let required = mnu_abi::HANDLE_RIGHT_READ
                    | mnu_abi::HANDLE_RIGHT_CONTROL
                    | if writable {
                        mnu_abi::HANDLE_RIGHT_WRITE
                    } else {
                        0
                    };
                if attached.handle == 0
                    || attached.reserved != 0
                    || attached.rights & required != required
                {
                    return Err(-13);
                }
                let id = platform::handle::identify_provider_object(attached.handle)
                    .map_err(|error| error.raw() as i32)?;
                let manager = descriptions.lock().map_err(|_| -5)?;
                let backing = manager.mapping_backing(id, writable)?;
                platform::handle::duplicate(backing, wire::mapping_rights(writable))
                    .map_err(|error| error.raw() as i32)
            })();
            match result {
                Ok(handle) => {
                    let mut outgoing = platform::ipc::IpcObjectHandles::default();
                    outgoing.count = 1;
                    outgoing.handles[0] = platform::ipc::IpcObjectHandle {
                        handle,
                        reserved: 0,
                        rights: platform::handle::rights(handle).unwrap_or(0),
                    };
                    let _ =
                        platform::ipc::reply_object_handles(sender, &0i32.to_le_bytes(), &outgoing);
                    let _ = platform::handle::close(handle);
                }
                Err(error) => {
                    let _ = platform::ipc::reply(sender, &error.to_le_bytes());
                }
            }
        } else {
            let result = descriptions.lock().map_err(|_| -5).and_then(|mut manager| {
                handle_provider_request(
                    &mut manager,
                    bytes,
                    attachments.delivery_flags,
                    attachments.count,
                    &mut NativeBacking,
                    &mut response,
                )
            });
            match result {
                Ok(Some(length)) => {
                    let _ = platform::ipc::reply(sender, &response[..length]);
                }
                Ok(None) => (),
                Err(error) => platform::logln!(
                    "posix.service: shared-memory provider rejected request errno={}",
                    error
                ),
            }
        }
        for attachment in attachments.handles.iter().take(attachments.count as usize) {
            let _ = platform::handle::close(attachment.handle);
        }
    }
}
