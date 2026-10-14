//! Direct record requests require explicitly attached data authority. Knowing
//! the worker endpoint alone never authorizes access to any socket or buffer.

use mochi_user_platform as platform;
use mochios_posix_protocol::socket_record as wire;
use posix_service::{socket::Streams, socket_record_io, AttachedObject, OpenedObject};

pub fn endpoint_reference(endpoint: u32) -> Result<Vec<OpenedObject<u32>>, i32> {
    let mut result = Vec::new();
    result.try_reserve(1).map_err(|_| -12)?;
    let handle = platform::handle::duplicate(endpoint, wire::ENDPOINT_RIGHTS)
        .map_err(|error| error.raw() as i32)?;
    result.push(OpenedObject {
        handle,
        rights: wire::ENDPOINT_RIGHTS,
    });
    Ok(result)
}

pub fn dispatch(
    endpoint: u32,
    streams: &mut Streams,
    waits: &mut posix_service::socket_receive_wait::ReceiveWaits<u32>,
    routes: &mut posix_service::socket_route::Routes<u32>,
    sender: u64,
    bytes: &[u8],
    attachments: &platform::ipc::IpcObjectHandles,
) -> (Option<[u64; 2]>, bool) {
    if wire::Request::decode(bytes)
        .is_ok_and(|request| request.operation == wire::Operation::WaitSend)
    {
        return (
            None,
            register_send(endpoint, streams, waits, sender, bytes, attachments),
        );
    }
    let mut response = [0; wire::MAX_REPLY_LEN];
    let result = (|| {
        let request = wire::Request::decode(bytes).map_err(|_| -22)?;
        if attachments.count != 2 {
            return Err(-22);
        }
        let mut attached = [AttachedObject {
            handle: 0u32,
            rights: 0,
        }; 2];
        for (target, received) in attached.iter_mut().zip(&attachments.handles[..2]) {
            if received.reserved != 0 {
                return Err(-22);
            }
            *target = AttachedObject {
                handle: received.handle,
                rights: received.rights,
            };
        }
        let (socket, buffer) =
            socket_record_io::authorize(request, attachments.delivery_flags, &attached)?;
        // This syscall accepts the Provider object only on its exact owning
        // endpoint thread. A foreign Provider or numeric object ID is useless.
        let id = platform::handle::identify_provider_object(socket.handle)
            .map_err(|error| error.raw() as i32)?;
        if request.operation == wire::Operation::SendRoute {
            return routes.transfer(
                streams,
                posix_service::socket_route::job_id(id)?,
                request,
                &mut socket_record_io::NativeBuffer::borrowed(buffer.handle),
                &mut response,
            );
        }
        let affected = streams.affected(id)?;
        let length = streams.transfer_record(
            id,
            request,
            &mut socket_record_io::NativeBuffer::borrowed(buffer.handle),
            &mut response,
        )?;
        Ok((length, affected))
    })();
    match result {
        Ok((length, affected)) => {
            let _ = platform::ipc::reply(sender, &response[..length]);
            (Some(affected), false)
        }
        Err(error) => {
            let _ = platform::ipc::reply(sender, &i32::to_le_bytes(error));
            (None, false)
        }
    }
    // Both attachments remain owned by the worker's common cleanup.
}

fn register_send(
    endpoint: u32,
    streams: &Streams,
    waits: &mut posix_service::socket_receive_wait::ReceiveWaits<u32>,
    sender: u64,
    bytes: &[u8],
    attachments: &platform::ipc::IpcObjectHandles,
) -> bool {
    let result = (|| {
        let request = wire::Request::decode(bytes).map_err(|_| -22)?;
        if attachments.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
            return Err(-13);
        }
        if attachments.count != 1 {
            return Err(-22);
        }
        let source = attachments.handles[0];
        if source.handle == 0 || source.reserved != 0 || source.rights != request.socket_rights() {
            return Err(-13);
        }
        let socket = platform::handle::identify_provider_object(source.handle)
            .map_err(|error| error.raw() as i32)?;
        let job = waits.start_send(streams, socket, request.length as usize, source.handle)?;
        let prepared = posix_service::socket_receive_wait::object_id(job).and_then(|id| {
            platform::handle::create_provider_object(
                endpoint,
                id,
                mochios_posix_protocol::socket::receive_wait_job_rights(),
            )
            .map_err(|error| error.raw() as i32)
        });
        let handle = match prepared {
            Ok(handle) => handle,
            Err(error) => {
                let _ = waits.release(job, |_| ());
                return Err(error);
            }
        };
        super::socket_receive_wait_native::pump(streams, waits);
        let mut outgoing = platform::ipc::IpcObjectHandles::default();
        outgoing.count = 1;
        outgoing.handles[0] = platform::ipc::IpcObjectHandle {
            handle,
            reserved: 0,
            rights: mochios_posix_protocol::socket::receive_wait_job_rights(),
        };
        let sent = platform::ipc::reply_object_handles(sender, &0i32.to_le_bytes(), &outgoing);
        if sent.is_err() {
            let _ = waits.release(job, |_| ());
        }
        let _ = platform::handle::close(handle);
        sent.map(|_| ()).map_err(|_| -5)
    })();
    if let Err(error) = result {
        let _ = platform::ipc::reply(sender, &i32::to_le_bytes(error));
        false
    } else {
        true
    }
}
