//! A factory grant authorizes read-only metadata, never terminal data/mutation.
use crate::pty::{EACCES, EINVAL, EIO, PtyManager};
use mnu_abi::{HANDLE_RIGHT_TRANSFER, IPC_DELIVERY_ENDPOINT_HANDLE, IpcObjectHandles};
use mochios_filesystem_protocol::device_observation as wire;

pub fn observe(
    manager: &PtyManager,
    bytes: &[u8],
    attached: &IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i32>,
) -> Result<Vec<u8>, i32> {
    if attached.delivery_flags != IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(EACCES);
    }
    let request = wire::Request::decode(bytes).map_err(|status| -status)?;
    if attached.count != 1 {
        return Err(EINVAL);
    }
    let factory = attached.handles[0];
    if factory.handle == 0 || factory.reserved != 0 || factory.rights != HANDLE_RIGHT_TRANSFER {
        return Err(EACCES);
    }
    manager.observe_slave_factory(
        identify(factory.handle)?,
        request.selector,
        request.capacity as usize,
    )
}

/// Own incoming attachments; reply only with signed wire status and bytes.
pub fn serve(
    manager: &std::sync::Mutex<PtyManager>,
    sender: u64,
    bytes: &[u8],
    attached: IpcObjectHandles,
) {
    use mochi_user_platform as platform;
    let result = manager.lock().map_err(|_| EIO).and_then(|manager| {
        observe(&manager, bytes, &attached, |handle| {
            platform::handle::identify_provider_object(handle).map_err(|_| crate::pty::EBADF)
        })
    });
    for (index, object) in attached
        .handles
        .iter()
        .take(attached.count as usize)
        .enumerate()
    {
        if object.handle != 0
            && !attached.handles[..index]
                .iter()
                .any(|old| old.handle == object.handle)
        {
            let _ = platform::handle::close(object.handle);
        }
    }
    let mut reply = Vec::new();
    match result {
        Ok(payload) => {
            reply.extend_from_slice(&0i64.to_le_bytes());
            reply.extend_from_slice(&payload);
        }
        Err(error) => reply.extend_from_slice(&(-i64::from(error)).to_le_bytes()),
    }
    let _ = platform::ipc::reply(sender, &reply);
}
