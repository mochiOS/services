//! Independent slave publication on the native provider's owning thread.
use crate::{
    OpenedObject,
    pty::{EACCES, EINVAL, EIO, PtyManager},
    filesystem_reference::Reference,
};
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as CONTROL, HANDLE_RIGHT_DUPLICATE as DUPLICATE,
    HANDLE_RIGHT_TRANSFER as TRANSFER, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol::device_open as wire;

/// All methods are local native operations, never peer RPC. `create` owns its
/// returned reference; failed initialization closes it before returning error.
pub trait Publisher {
    fn create(&mut self, object_id: u64, rights: u64) -> Result<u32, i32>;
    fn options(&mut self, handle: u32, options: u64) -> Result<(), i32>;
    fn signal(&mut self, object_id: u64, signals: u64) -> Result<(), i32>;
    fn close(&mut self, handle: u32);
}

/// Caller holds the manager lock through native creation and readiness
/// initialization, serializing this transaction with master close and data IO.
/// `adopt` consumes the received metadata reference even when it fails. That
/// slot is cleared first, so common incoming-reference cleanup cannot close it.
pub fn open(
    manager: &mut PtyManager,
    bytes: &[u8],
    attached: &mut IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i32>,
    adopt: impl FnOnce(IpcObjectHandle) -> Result<Reference, i32>,
    publisher: &mut impl Publisher,
) -> Result<OpenedObject<u32>, i32> {
    if attached.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(EACCES);
    }
    let request = wire::Request::decode(bytes).map_err(|status| -status)?;
    if request.rights & !crate::pty_factory::MASTER_RIGHTS != 0
        || request.rights & TRANSFER == 0
        || request.rights & (mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE) == 0
        || request.options & !mnu_abi::HANDLE_OPTION_NONBLOCKING != 0
    {
        return Err(EINVAL);
    }
    if attached.count != 2 {
        return Err(EINVAL);
    }
    let factory = attached.handles[0];
    let metadata = attached.handles[1];
    let required = DUPLICATE | TRANSFER;
    if factory.handle == 0
        || factory.reserved != 0
        || factory.rights & TRANSFER == 0
        || metadata.handle == 0
        || metadata.reserved != 0
        || metadata.rights & required != required
        || metadata.rights & !(required | CONTROL) != 0
    {
        return Err(EACCES);
    }
    let factory_id = identify(factory.handle)?;
    attached.handles[1] = IpcObjectHandle::default();
    let object_id = manager.open_slave_with_metadata(factory_id, adopt(metadata)?)?;
    let mut handle = None;
    let result = (|| {
        // CONTROL is retained only locally to initialize OFD options; the
        // reply is attenuated to exactly the admitted requested rights.
        let created = publisher.create(object_id, request.rights | CONTROL)?;
        if created == 0 {
            return Err(EIO);
        }
        handle = Some(created);
        publisher.options(created, request.options)?;
        for id in manager.signal_object_ids(object_id)? {
            publisher.signal(id, manager.signals(id)?)?;
        }
        Ok(OpenedObject {
            handle: created,
            rights: request.rights,
        })
    })();
    if result.is_err() {
        let affected = manager.signal_object_ids(object_id).unwrap_or_default();
        let _ = manager.release(object_id);
        if let Some(handle) = handle {
            publisher.close(handle);
        }
        // Opening the first slave clears the master's peer-closed signal.
        // Restore existing endpoints if initialization failed partway through.
        for id in affected {
            if let Ok(signals) = manager.signals(id) {
                let _ = publisher.signal(id, signals);
            }
        }
    }
    result
}

struct NativePublisher {
    endpoint: u32,
}
fn errno(error: mochi_user_platform::syscall::SysError) -> i32 {
    -mochios_posix_protocol::status::normalize_failure(error.raw())
}
impl Publisher for NativePublisher {
    fn create(&mut self, object_id: u64, rights: u64) -> Result<u32, i32> {
        mochi_user_platform::handle::create_provider_object(self.endpoint, object_id, rights)
            .map_err(errno)
    }
    fn options(&mut self, handle: u32, options: u64) -> Result<(), i32> {
        use mochi_user_platform::syscall;
        syscall::call2(
            syscall::SyscallNumber::HandleOptionsSet,
            u64::from(handle),
            options,
        )
        .map(|_| ())
        .map_err(errno)
    }
    fn signal(&mut self, object_id: u64, signals: u64) -> Result<(), i32> {
        mochi_user_platform::handle::signal_provider_object(
            object_id,
            signals,
            crate::pty::READINESS_SIGNALS & !signals,
        )
        .map_err(errno)
    }
    fn close(&mut self, handle: u32) {
        let _ = mochi_user_platform::handle::close(handle);
    }
}

/// Own all received references. The outgoing native object is never retained
/// by the filesystem to proxy IO; its holder calls the PTY provider directly.
pub fn serve(
    manager: &std::sync::Mutex<PtyManager>,
    endpoint: u32,
    sender: u64,
    request: &[u8],
    mut attached: IpcObjectHandles,
) {
    use mochi_user_platform as platform;
    let mut publisher = NativePublisher { endpoint };
    let result = manager.lock().map_err(|_| EIO).and_then(|mut manager| {
        open(
            &mut manager,
            request,
            &mut attached,
            |handle| {
                platform::handle::identify_provider_object(handle).map_err(|_| crate::pty::EBADF)
            },
            Reference::from_received,
            &mut publisher,
        )
    });
    for object in attached.handles.iter().take(attached.count as usize) {
        if object.handle != 0 {
            let _ = platform::handle::close(object.handle);
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
            publisher.close(opened.handle);
        }
        Err(error) => {
            let _ = platform::ipc::reply(sender, &(-i64::from(error)).to_le_bytes());
        }
    }
}
