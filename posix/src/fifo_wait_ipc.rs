//! FIFO notification adapter. Requests name no PID, FD or provider object ID:
//! the exact owning endpoint identifies only an explicitly attached Handle.
use crate::{
    OpenedObject,
    fifo::WaitCondition,
    fifo_manager::Manager,
    fifo_wait::{Registered, Waits},
};
use mnu_abi::{IpcObjectHandle, IpcObjectHandles};

pub const MAGIC: &[u8; 4] = b"FIWT";
pub const REQUEST_LEN: usize = 16;
pub const JOB_RIGHTS: u64 =
    mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
const DIRECTIONS: u64 = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE;

pub fn encode(condition: WaitCondition) -> Result<[u8; REQUEST_LEN], i32> {
    let (kind, length) = match condition {
        WaitCondition::Open => (0u16, 0),
        WaitCondition::Read => (1, 0),
        WaitCondition::Write(0) => return Err(-22),
        WaitCondition::Write(length) => (2, u64::try_from(length).map_err(|_| -22)?),
    };
    let mut request = [0; REQUEST_LEN];
    request[..4].copy_from_slice(MAGIC);
    request[4..6].copy_from_slice(&1u16.to_le_bytes());
    request[6..8].copy_from_slice(&kind.to_le_bytes());
    request[8..].copy_from_slice(&length.to_le_bytes());
    Ok(request)
}

fn decode(bytes: &[u8]) -> Result<WaitCondition, i32> {
    if bytes.len() != REQUEST_LEN || &bytes[..4] != MAGIC || bytes[4..6] != 1u16.to_le_bytes() {
        return Err(-22);
    }
    let kind = u16::from_le_bytes(bytes[6..8].try_into().map_err(|_| -22)?);
    let length = u64::from_le_bytes(bytes[8..].try_into().map_err(|_| -22)?);
    match (kind, length) {
        (0, 0) => Ok(WaitCondition::Open),
        (1, 0) => Ok(WaitCondition::Read),
        (2, 1..) => Ok(WaitCondition::Write(
            usize::try_from(length).map_err(|_| -22)?,
        )),
        _ => Err(-22),
    }
}

fn direction(condition: WaitCondition, rights: u64) -> Result<u64, i32> {
    let direction = rights & DIRECTIONS;
    let allowed = match condition {
        WaitCondition::Open => {
            direction == mnu_abi::HANDLE_RIGHT_READ || direction == mnu_abi::HANDLE_RIGHT_WRITE
        }
        WaitCondition::Read => direction == mnu_abi::HANDLE_RIGHT_READ,
        WaitCondition::Write(_) => direction == mnu_abi::HANDLE_RIGHT_WRITE,
    };
    if allowed { Ok(direction) } else { Err(-13) }
}

/// Until adoption, references remain in objects for the caller's cleanup.
/// Adoption consumes its sole slot even on error; H must close its local native
/// reference in Drop. After adoption, register owns H on every failure path.
/// identify must be the native exact-provider-endpoint operation, not a lookup
/// by a client supplied number. All callback errors are negative service status.
pub fn register_with<H>(
    manager: &Manager,
    waits: &mut Waits<H>,
    bytes: &[u8],
    objects: &mut IpcObjectHandles,
    identify: impl FnOnce(u32) -> Result<u64, i32>,
    adopt: impl FnOnce(IpcObjectHandle) -> Result<H, i32>,
    create: impl FnOnce(u64) -> Result<u32, i32>,
) -> Result<Registered, i32> {
    if objects.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(-13);
    }
    let condition = decode(bytes)?;
    if objects.count != 1 {
        return Err(-22);
    }
    let source = objects.handles[0];
    let required = direction(condition, source.rights)?;
    if source.handle == 0 || source.reserved != 0 || source.rights != required {
        return Err(-13);
    }
    let object = identify(source.handle)?;
    // Reject stale/foreign object IDs and wrong directions before adopting.
    manager.wait_target(object, condition)?;
    let source = std::mem::take(&mut objects.handles[0]);
    objects.count = 0;
    let lease = adopt(source)?;
    waits.register(manager, object, condition, lease, create)
}

pub struct NativeLease(u32);
impl Drop for NativeLease {
    fn drop(&mut self) {
        let _ = mochi_user_platform::handle::close(self.0);
    }
}

fn native_status(error: mochi_user_platform::syscall::SysError) -> i32 {
    mochios_posix_protocol::status::normalize_failure(error.raw())
}

fn close_received(objects: &IpcObjectHandles) {
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
            let _ = mochi_user_platform::handle::close(object.handle);
        }
    }
}

/// Called on the owning worker, serialized with data mutations and releases.
/// The native notification's last release, including failed publication,
/// retires the job. Never remove a job while a published notification can live.
pub fn serve(
    endpoint: u32,
    manager: &Manager,
    waits: &mut Waits<NativeLease>,
    sender: u64,
    bytes: &[u8],
    mut objects: IpcObjectHandles,
) {
    use mochi_user_platform as platform;
    let registered = register_with(
        manager,
        waits,
        bytes,
        &mut objects,
        |handle| platform::handle::identify_provider_object(handle).map_err(native_status),
        |source| Ok(NativeLease(source.handle)),
        |id| {
            platform::handle::create_provider_object(endpoint, id, JOB_RIGHTS)
                .map_err(native_status)
        },
    );
    close_received(&objects);
    let registered = match registered {
        Ok(job) => job,
        Err(error) => {
            let _ = platform::ipc::reply(sender, &error.to_le_bytes());
            return;
        }
    };
    let signaled = if registered.ready {
        platform::handle::signal_provider_object(
            registered.object_id,
            mnu_abi::HANDLE_SIGNAL_READABLE,
            0,
        )
        .map_err(native_status)
    } else {
        Ok(())
    };
    match signaled {
        Ok(()) => {
            let mut outgoing = IpcObjectHandles::default();
            outgoing.count = 1;
            outgoing.handles[0] = IpcObjectHandle {
                handle: registered.handle,
                reserved: 0,
                rights: JOB_RIGHTS,
            };
            let _ = platform::ipc::reply_object_handles(sender, &0i32.to_le_bytes(), &outgoing);
        }
        Err(error) => {
            let _ = platform::ipc::reply(sender, &error.to_le_bytes());
        }
    }
    let _ = platform::handle::close(registered.handle);
}

/// Borrow source and receive one WAIT-only notification authority. Returned
/// objects are owned only after successful native IPC; failed IPC must never
/// close the source reference still present in an in/out syscall buffer.
pub fn query_with(
    endpoint: u32,
    source: IpcObjectHandle,
    condition: WaitCondition,
    invoke: impl FnOnce(u32, &[u8], &mut [u8], &mut IpcObjectHandles) -> Result<u64, i32>,
    mut close: impl FnMut(u32),
) -> Result<OpenedObject<u32>, i32> {
    let required = direction(condition, source.rights)?;
    if endpoint == 0
        || source.handle == 0
        || source.reserved != 0
        || source.rights & mnu_abi::HANDLE_RIGHT_TRANSFER == 0
    {
        return Err(-13);
    }
    let bytes = encode(condition)?;
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        rights: required,
        ..source
    };
    let mut response = [0; 4];
    let delivered = crate::filesystem_transport::call_native(&mut objects, |objects| {
        invoke(endpoint, &bytes, &mut response, objects)
    })?;
    let result = (|| {
        if delivered as u32 != 4 || objects.delivery_flags != 0 {
            return Err(-5);
        }
        let status = i32::from_le_bytes(response);
        if status != 0 {
            return Err(if status < 0 && objects.count == 0 {
                status
            } else {
                -5
            });
        }
        if objects.count != 1 {
            return Err(-5);
        }
        let job = objects.handles[0];
        if job.handle == 0 || job.reserved != 0 || job.rights != JOB_RIGHTS {
            return Err(-5);
        }
        Ok(OpenedObject {
            handle: job.handle,
            rights: job.rights,
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
    condition: WaitCondition,
) -> Result<OpenedObject<u32>, i32> {
    query_with(
        endpoint,
        source,
        condition,
        |endpoint, bytes, reply, objects| {
            mochi_user_platform::ipc::call_object_handles(endpoint, bytes, reply, objects)
                .map_err(native_status)
        },
        |handle| {
            let _ = mochi_user_platform::handle::close(handle);
        },
    )
}
