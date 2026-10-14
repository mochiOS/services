//! Authenticated dispatcher-to-worker bridge for receive notifications.
use mochi_user_platform as platform;
use mochios_posix_protocol::socket as wire;
use posix_service::{
    AttachedObject, OpenedObject,
    socket::Streams,
    socket_receive_wait::{ReceiveWaits, object_id},
};

pub const MAGIC: &[u8; 4] = b"SORW";

pub fn register(
    endpoint: u32,
    socket: AttachedObject<u32>,
    minimum: u64,
) -> Result<OpenedObject<u32>, i32> {
    if socket.handle == 0
        || socket.rights & wire::receive_wait_socket_rights() != wire::receive_wait_socket_rights()
    {
        return Err(-13);
    }
    if minimum == 0 {
        return Err(-22);
    }
    let mut request = [0; 12];
    request[..4].copy_from_slice(MAGIC);
    request[4..].copy_from_slice(&minimum.to_le_bytes());
    let mut handles = platform::ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0] = platform::ipc::IpcObjectHandle {
        handle: socket.handle,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_READ,
    };
    let mut response = [0; 4];
    let received = posix_service::filesystem_transport::call_native(&mut handles, |native| {
        platform::ipc::call_object_handles(endpoint, &request, &mut response, native)
    })
    .map_err(|error| error.raw() as i32);
    let result = (|| {
        if received? as u32 != 4 || handles.delivery_flags != 0 {
            return Err(-5);
        }
        let status = i32::from_le_bytes(response);
        if status != 0 {
            return Err(if status < 0 && handles.count == 0 {
                status
            } else {
                -5
            });
        }
        if handles.count != 1 {
            return Err(-5);
        }
        let job = handles.handles[0];
        if job.handle == 0 || job.reserved != 0 || job.rights != wire::receive_wait_job_rights() {
            return Err(-5);
        }
        Ok(OpenedObject {
            handle: job.handle,
            rights: job.rights,
        })
    })();
    if result.is_err() {
        for (index, job) in handles
            .handles
            .iter()
            .take(handles.count as usize)
            .enumerate()
        {
            if job.handle != 0
                && !handles.handles[..index]
                    .iter()
                    .any(|old| old.handle == job.handle)
            {
                let _ = platform::handle::close(job.handle);
            }
        }
    }
    result
}

/// True transfers ownership of the sole received READ reference into the job;
/// false leaves it for the worker's common attachment cleanup on every error.
pub fn dispatch(
    endpoint: u32,
    service_process: u64,
    streams: &Streams,
    waits: &mut ReceiveWaits<u32>,
    sender: u64,
    bytes: &[u8],
    attachments: &platform::ipc::IpcObjectHandles,
) -> bool {
    let result = (|| {
        if attachments.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
            || platform::ipc::endpoint_owner_process(sender).ok() != Some(service_process)
        {
            return Err(-13);
        }
        if bytes.len() != 12 || attachments.count != 1 {
            return Err(-22);
        }
        let source = attachments.handles[0];
        if source.handle == 0 || source.reserved != 0 || source.rights != mnu_abi::HANDLE_RIGHT_READ
        {
            return Err(-13);
        }
        let socket = platform::handle::identify_provider_object(source.handle)
            .map_err(|e| e.raw() as i32)?;
        let minimum = u64::from_le_bytes(bytes[4..].try_into().map_err(|_| -22)?);
        let job = waits.start(streams, socket, minimum, source.handle)?;
        let prepared = object_id(job).and_then(|id| {
            platform::handle::create_provider_object(endpoint, id, wire::receive_wait_job_rights())
                .map_err(|e| e.raw() as i32)
        });
        let handle = match prepared {
            Ok(handle) => handle,
            Err(error) => {
                let _ = waits.release(job, |_| ());
                return Err(error);
            }
        };
        // Publication and the queue check are serialized with all queue writes.
        pump(streams, waits);
        let mut outgoing = platform::ipc::IpcObjectHandles::default();
        outgoing.count = 1;
        outgoing.handles[0] = platform::ipc::IpcObjectHandle {
            handle,
            reserved: 0,
            rights: wire::receive_wait_job_rights(),
        };
        let sent = platform::ipc::reply_object_handles(sender, &0i32.to_le_bytes(), &outgoing);
        if sent.is_err() {
            let _ = waits.release(job, |_| ());
        }
        let _ = platform::handle::close(handle);
        if sent.is_err() {
            return Err(-5);
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = platform::ipc::reply(sender, &error.to_le_bytes());
        return false;
    }
    true
}

pub fn pump(streams: &Streams, waits: &mut ReceiveWaits<u32>) {
    waits.pump(streams, |job| {
        if let Ok(id) = object_id(job) {
            if let Err(error) =
                platform::handle::signal_provider_object(id, mnu_abi::HANDLE_SIGNAL_READABLE, 0)
            {
                if error.raw() != -9 {
                    platform::logln!(
                        "posix.service: receive notification failed errno={}",
                        error.raw()
                    );
                }
            }
        }
    });
}
