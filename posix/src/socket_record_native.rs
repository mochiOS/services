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
    streams: &mut Streams,
    sender: u64,
    bytes: &[u8],
    attachments: &platform::ipc::IpcObjectHandles,
) -> Option<[u64; 2]> {
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
            Some(affected)
        }
        Err(error) => {
            let _ = platform::ipc::reply(sender, &i32::to_le_bytes(error));
            None
        }
    }
    // Both attachments remain owned by the worker's common cleanup.
}
