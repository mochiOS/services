//! Mint a slave-open capability only from an explicitly received master Handle.
//! The native adapter owns incoming/outgoing references; this function borrows
//! the attachment and serializes bookkeeping and publication under its lock.
use crate::pty::{EACCES, EINVAL, EIO, PtyManager};
use mnu_abi::{
    HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_READ, HANDLE_RIGHT_TRANSFER,
    HANDLE_RIGHT_WAIT, HANDLE_RIGHT_WRITE, IPC_DELIVERY_ENDPOINT_HANDLE, IpcObjectHandles,
};

pub const FACTORY_RIGHTS: u64 = HANDLE_RIGHT_DUPLICATE | HANDLE_RIGHT_TRANSFER;
pub const MASTER_RIGHTS: u64 = HANDLE_RIGHT_READ
    | HANDLE_RIGHT_WRITE
    | HANDLE_RIGHT_WAIT
    | HANDLE_RIGHT_CONTROL
    | HANDLE_RIGHT_DUPLICATE
    | HANDLE_RIGHT_TRANSFER;

#[derive(Debug, PartialEq, Eq)]
pub struct PublishedFactory {
    pub handle: u32,
    pub rights: u64,
}

/// Consume received attachment references and reply with an attenuated factory.
/// Must run on the provider endpoint's owning thread. Kept outside target-only
/// main so the native adapter is also type-checked by host builds.
pub fn serve(
    manager: &std::sync::Mutex<PtyManager>,
    endpoint: u32,
    sender: u64,
    request: &[u8],
    attached: IpcObjectHandles,
) {
    use mochi_user_platform as platform;
    let result = manager.lock().map_err(|_| EIO).and_then(|mut manager| {
        create(
            &mut manager,
            request,
            &attached,
            |handle| {
                platform::handle::identify_provider_object(handle).map_err(|_| crate::pty::EBADF)
            },
            |object_id, rights| {
                platform::handle::create_provider_object(endpoint, object_id, rights).map_err(
                    |error| -mochios_posix_protocol::status::normalize_failure(error.raw()),
                )
            },
        )
    });
    for object in attached.handles.iter().take(attached.count as usize) {
        let _ = platform::handle::close(object.handle);
    }
    match result {
        Ok(factory) => {
            let mut outgoing = IpcObjectHandles::default();
            outgoing.count = 1;
            outgoing.handles[0] = mnu_abi::IpcObjectHandle {
                handle: factory.handle,
                reserved: 0,
                rights: factory.rights,
            };
            let _ = platform::ipc::reply_object_handles(sender, &0i64.to_le_bytes(), &outgoing);
            // A successful reply owns a reference. Otherwise final native
            // release reclaims bookkeeping; never close the caller's source.
            let _ = platform::handle::close(factory.handle);
        }
        Err(errno) => {
            let _ = platform::ipc::reply(sender, &(-i64::from(errno)).to_le_bytes());
        }
    }
}

/// `identify` must use the native owner-only ProviderObjectIdentify operation.
/// `publish` must create a native provider object on that same owner endpoint.
/// Callback errors use positive POSIX wire errno, like PtyManager operations.
pub fn create(
    manager: &mut PtyManager,
    request: &[u8],
    attached: &IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i32>,
    publish: impl FnOnce(u64, u64) -> Result<u32, i32>,
) -> Result<PublishedFactory, i32> {
    if attached.delivery_flags != IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(EACCES);
    }
    mochios_posix_protocol::pty_factory::decode(request).map_err(|status| -status)?;
    if attached.count != 1 {
        return Err(EINVAL);
    }
    let master = attached.handles[0];
    // A stripped controller must not regain data, wait, or mutation authority
    // by converting itself into a factory for unrestricted slave opens.
    if master.handle == 0 || master.reserved != 0 || master.rights & MASTER_RIGHTS != MASTER_RIGHTS
    {
        return Err(EACCES);
    }
    let master_object_id = identify(master.handle)?;
    let factory = manager.create_slave_factory(master_object_id)?;
    match publish(factory, FACTORY_RIGHTS) {
        Ok(handle) if handle != 0 => Ok(PublishedFactory {
            handle,
            rights: FACTORY_RIGHTS,
        }),
        result => {
            let _ = manager.release(factory);
            Err(result.err().unwrap_or(EIO))
        }
    }
}
