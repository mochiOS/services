//! Metadata-only transfer for an explicitly received PTY data Handle.
use crate::{
    OpenedObject,
    pty::{EACCES, EINVAL, EIO, PtyManager},
};
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol::device_metadata as wire;

fn metadata_rights(rights: u64) -> bool {
    rights & T != 0 && rights & !(C | T) == 0
}

/// Receiver-side errors are positive POSIX wire errno. Identity and rights
/// originate only in native identification and kernel attachment metadata.
pub fn lookup(
    manager: &PtyManager,
    bytes: &[u8],
    attached: &IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i32>,
) -> Result<OpenedObject<u32>, i32> {
    if attached.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(EACCES);
    }
    let request = wire::Request::decode(bytes).map_err(|status| -status)?;
    if attached.count != 1 {
        return Err(EINVAL);
    }
    let source = attached.handles[0];
    if source.handle == 0
        || source.reserved != 0
        || !metadata_rights(request.rights)
        || source.rights & request.rights != request.rights
    {
        return Err(EACCES);
    }
    let object = identify(source.handle)?;
    let handle = manager.duplicate_slave_metadata(object, source.rights, request.rights)?;
    Ok(OpenedObject {
        handle,
        rights: request.rights,
    })
}

/// Own received references and the temporary outgoing reference. A failed
/// reply must not leak a duplicate metadata Handle or retire the data open.
pub fn serve(
    manager: &std::sync::Mutex<PtyManager>,
    sender: u64,
    bytes: &[u8],
    attached: IpcObjectHandles,
) {
    use mochi_user_platform as platform;
    let result = manager.lock().map_err(|_| EIO).and_then(|manager| {
        lookup(&manager, bytes, &attached, |handle| {
            platform::handle::identify_provider_object(handle).map_err(|_| crate::pty::EBADF)
        })
    });
    for source in attached.handles.iter().take(attached.count as usize) {
        if source.handle != 0 {
            let _ = platform::handle::close(source.handle);
        }
    }
    match result {
        Ok(opened) => {
            let mut outgoing = IpcObjectHandles::default();
            outgoing.count = 1;
            outgoing.handles[0] = IpcObjectHandle {
                handle: opened.handle,
                reserved: 0,
                rights: opened.rights,
            };
            let _ = platform::ipc::reply_object_handles(sender, &0i64.to_le_bytes(), &outgoing);
            let _ = platform::handle::close(opened.handle);
        }
        Err(error) => {
            let _ = platform::ipc::reply(sender, &(-i64::from(error)).to_le_bytes());
        }
    }
}

/// Caller-side failures use negative POSIX wire status, not raw native errors.
pub fn query_with(
    endpoint: u32,
    source: IpcObjectHandle,
    rights: u64,
    invoke: impl FnOnce(u32, &[u8], &mut [u8], &mut IpcObjectHandles) -> Result<u64, i32>,
    mut close: impl FnMut(u32),
) -> Result<OpenedObject<u32>, i32> {
    if endpoint == 0
        || source.handle == 0
        || source.reserved != 0
        || !metadata_rights(rights)
        || source.rights & rights != rights
    {
        return Err(-EACCES);
    }
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle { rights, ..source };
    let mut response = [0; 8];
    // On native failure the buffer can still contain borrowed source handles.
    // call_native leaves reply cleanup empty unless installation succeeded.
    let delivered = crate::filesystem_transport::call_native(&mut objects, |exchange| {
        invoke(
            endpoint,
            &wire::Request { rights }.encode(),
            &mut response,
            exchange,
        )
    })?;
    let result = (|| {
        if delivered as u32 as usize != response.len() || objects.delivery_flags != 0 {
            return Err(-EIO);
        }
        let status = i64::from_le_bytes(response);
        if status != 0 {
            return Err(
                if status < 0 && status >= -(i32::MAX as i64) && objects.count == 0 {
                    status as i32
                } else {
                    -EIO
                },
            );
        }
        if objects.count != 1 {
            return Err(-EIO);
        }
        let object = objects.handles[0];
        if object.handle == 0 || object.reserved != 0 || object.rights != rights {
            return Err(-EIO);
        }
        Ok(OpenedObject {
            handle: object.handle,
            rights,
        })
    })();
    if result.is_err() {
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
    }
    result
}

pub fn query(
    endpoint: u32,
    source: IpcObjectHandle,
    rights: u64,
) -> Result<OpenedObject<u32>, i32> {
    use mochi_user_platform as platform;
    query_with(
        endpoint,
        source,
        rights,
        |endpoint, bytes, reply, objects| {
            platform::ipc::call_object_handles(endpoint, bytes, reply, objects)
                .map_err(|error| mochios_posix_protocol::status::normalize_failure(error.raw()))
        },
        |handle| {
            let _ = platform::handle::close(handle);
        },
    )
}
