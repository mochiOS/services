//! Owner-identified master provenance. No filesystem RPC on the PTY worker.
use crate::{pty::PtyManager, terminal_publication::Name};
use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
use mochios_filesystem_protocol::device_removal as wire;

pub const MAGIC: [u8; 4] = *b"PTYG";
pub const REQUEST: [u8; 8] = *b"PTYG\x01\0\0\0";
const MAX_REPLY: usize =
    8 + wire::HEADER_LEN + mochios_filesystem_protocol::device_namespace::MAX_NAME_LEN;

/// Positive wire errno. Identify only the received Handle with the native
/// owner-only operation, never a scalar supplied by the requester.
pub fn lookup(
    manager: &PtyManager,
    bytes: &[u8],
    objects: &IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i32>,
) -> Result<Name, i32> {
    if objects.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(13);
    }
    if bytes != REQUEST || objects.count != 1 {
        return Err(22);
    }
    let object = objects.handles[0];
    if object.handle == 0
        || object.reserved != 0
        || object.rights & crate::pty_grant::RIGHTS != crate::pty_grant::RIGHTS
    {
        return Err(13);
    }
    manager.master_name(identify(object.handle)?)
}

pub fn serve(
    manager: &std::sync::Mutex<PtyManager>,
    sender: u64,
    bytes: &[u8],
    objects: IpcObjectHandles,
) {
    use mochi_user_platform as platform;
    let result = manager.lock().map_err(|_| 5).and_then(|manager| {
        lookup(&manager, bytes, &objects, |handle| {
            platform::handle::identify_provider_object(handle).map_err(|error| {
                match error.native_error() {
                    Some(platform::syscall::NativeError::NotFound) => 9,
                    Some(
                        platform::syscall::NativeError::InvalidArgument
                        | platform::syscall::NativeError::AccessDenied,
                    ) => 22,
                    _ => -mochios_posix_protocol::status::normalize_failure(error.raw()),
                }
            })
        })
    });
    for (index, object) in objects
        .handles
        .iter()
        .take(objects.count as usize)
        .enumerate()
    {
        if object.handle != 0
            && !objects.handles[..index]
                .iter()
                .any(|old| old.handle == object.handle)
        {
            let _ = platform::handle::close(object.handle);
        }
    }
    let mut reply = [0; MAX_REPLY];
    let length = match result {
        Ok(name) => match wire::encode(
            wire::Request {
                device: name.device,
                node_id: name.node_id,
                name: &name.component,
            },
            &mut reply[8..],
        ) {
            Ok(length) => 8 + length,
            Err(_) => {
                reply[..8].copy_from_slice(&(-5i64).to_le_bytes());
                8
            }
        },
        Err(error) => {
            reply[..8].copy_from_slice(&(-i64::from(error)).to_le_bytes());
            8
        }
    };
    let _ = platform::ipc::reply(sender, &reply[..length]);
}

/// Negative wire status. Borrowed request references are not reply ownership;
/// malformed successful deliveries reclaim unexpected received Handles.
pub fn query_with(
    endpoint: u32,
    source: IpcObjectHandle,
    invoke: impl FnOnce(u32, &[u8], &mut [u8], &mut IpcObjectHandles) -> Result<u64, i32>,
    mut close: impl FnMut(u32),
) -> Result<Name, i32> {
    if endpoint == 0
        || source.handle == 0
        || source.reserved != 0
        || source.rights & crate::pty_grant::RIGHTS != crate::pty_grant::RIGHTS
    {
        return Err(-13);
    }
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        rights: crate::pty_grant::RIGHTS,
        ..source
    };
    let mut reply = [0; MAX_REPLY];
    let delivered = crate::filesystem_transport::call_native(&mut objects, |exchange| {
        invoke(endpoint, &REQUEST, &mut reply, exchange)
    })?;
    let result = (|| {
        let length = delivered as u32 as usize;
        if objects.count != 0 || objects.delivery_flags != 0 || length < 8 || length > reply.len() {
            return Err(-5);
        }
        let status = i64::from_le_bytes(reply[..8].try_into().unwrap());
        if status != 0 {
            return Err(
                if status < 0 && status >= -(i32::MAX as i64) && length == 8 {
                    status as i32
                } else {
                    -5
                },
            );
        }
        let identity = wire::decode(&reply[8..length]).map_err(|_| -5)?;
        Ok(Name {
            component: identity.name.to_vec(),
            device: identity.device,
            node_id: identity.node_id,
        })
    })();
    for (index, object) in objects
        .handles
        .iter()
        .take(objects.count as usize)
        .enumerate()
    {
        if object.handle != 0
            && !objects.handles[..index]
                .iter()
                .any(|old| old.handle == object.handle)
        {
            close(object.handle);
        }
    }
    result
}

pub fn query(endpoint: u32, source: IpcObjectHandle) -> Result<Name, i32> {
    use mochi_user_platform as platform;
    query_with(
        endpoint,
        source,
        |endpoint, bytes, reply, objects| {
            platform::ipc::call_object_handles(endpoint, bytes, reply, objects)
                .map_err(|error| mochios_posix_protocol::status::normalize_failure(error.raw()))
        },
        |handle| {
            let _ = platform::handle::close(handle);
        },
    )
}
