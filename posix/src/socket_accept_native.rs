//! Accept is control-plane IPC with an explicitly attached listener object.
//! Only the authenticated service dispatcher may nominate an accepting process.

use mochi_user_platform as platform;
use mochios_posix_protocol::socket as wire;
use posix_service::{AttachedObject, OpenedObject, PosixService, socket::Streams};
use std::sync::{Arc, Mutex};

pub const MAGIC: &[u8; 4] = b"SOAC";
const REQUEST_LEN: usize = 12 + wire::ACCEPT_LEN;

pub fn accept(
    endpoint: u32,
    process_id: u64,
    listener: AttachedObject<u32>,
    request: wire::Accept,
) -> Result<(OpenedObject<u32>, Vec<u8>), i32> {
    let required = wire::accept_listener_rights();
    if listener.handle == 0 || listener.rights & required != required {
        return Err(-13);
    }
    let mut bytes = [0; REQUEST_LEN];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4..12].copy_from_slice(&process_id.to_le_bytes());
    request.encode(&mut bytes[12..]).map_err(|_| -22)?;
    let mut handles = platform::ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0] = platform::ipc::IpcObjectHandle {
        handle: listener.handle,
        reserved: 0,
        rights: required,
    };
    let mut response = [0; 4 + wire::MAX_ADDRESS_LEN];
    let mut address = Vec::new();
    address
        .try_reserve(wire::MAX_ADDRESS_LEN)
        .map_err(|_| -12)?;
    let received = posix_service::filesystem_transport::call_native(&mut handles, |native| {
        platform::ipc::call_object_handles(endpoint, &bytes, &mut response, native)
    })
    .map_err(|error| error.raw() as i32);
    let result = (|| {
        let length = received? as u32 as usize;
        let response = response.get(..length).ok_or(-5)?;
        let status = i32::from_le_bytes(response.get(..4).ok_or(-5)?.try_into().map_err(|_| -5)?);
        if handles.delivery_flags != 0 {
            return Err(-5);
        }
        if status != 0 {
            return Err(if status < 0 && response.len() == 4 && handles.count == 0 {
                status
            } else {
                -5
            });
        }
        if handles.count != 1
            || handles.handles[0].handle == 0
            || handles.handles[0].reserved != 0
            || handles.handles[0].rights != wire::descriptor_rights()
        {
            return Err(-5);
        }
        wire::Address::decode(&response[4..]).map_err(|_| -5)?;
        address.extend_from_slice(&response[4..]);
        Ok((
            OpenedObject {
                handle: handles.handles[0].handle,
                rights: handles.handles[0].rights,
            },
            address,
        ))
    })();
    if result.is_err() {
        close_received(&handles);
    }
    result
}

fn close_received(handles: &platform::ipc::IpcObjectHandles) {
    for (index, entry) in handles
        .handles
        .iter()
        .take(handles.count as usize)
        .enumerate()
    {
        if entry.handle != 0
            && !handles.handles[..index]
                .iter()
                .any(|old| old.handle == entry.handle)
        {
            let _ = platform::handle::close(entry.handle);
        }
    }
}

/// Called only on the exact thread which owns the socket Provider endpoint.
pub fn dispatch(
    endpoint: u32,
    service_process: u64,
    state: &Arc<Mutex<PosixService<u32>>>,
    streams: &mut Streams,
    sender: u64,
    bytes: &[u8],
    attachments: &platform::ipc::IpcObjectHandles,
) -> Option<[u64; 2]> {
    let mut response = [0; 4 + wire::MAX_ADDRESS_LEN];
    let authorized: Result<_, i32> = (|| {
        if attachments.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
            || platform::ipc::endpoint_owner_process(sender).ok() != Some(service_process)
        {
            return Err(-13);
        }
        if bytes.len() != REQUEST_LEN || attachments.count != 1 {
            return Err(-22);
        }
        let attached = attachments.handles[0];
        if attached.handle == 0
            || attached.reserved != 0
            || attached.rights & wire::accept_listener_rights() != wire::accept_listener_rights()
        {
            return Err(-13);
        }
        let request = wire::Accept::decode(&bytes[12..]).map_err(|_| -22)?;
        let process_id = u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| -22)?);
        let credentials = {
            let state = state.lock().map_err(|_| -5)?;
            let peer = state.registered_peer(process_id).ok_or(-1)?;
            (peer.effective_uid, peer.effective_gid)
        };
        let listener = platform::handle::identify_provider_object(attached.handle)
            .map_err(|e| e.raw() as i32)?;
        let ticket = streams.begin_accept(listener)?;
        Ok((listener, ticket, credentials, request.options))
    })();
    let (listener, ticket, credentials, options) = match authorized {
        Ok(value) => value,
        Err(error) => {
            let _ = platform::ipc::reply(sender, &error.to_le_bytes());
            return None;
        }
    };
    let id = ticket.endpoint();
    let mut replied = false;
    let result: Result<[u64; 2], i32> = (|| {
        let address_len = streams
            .peer_address(id)?
            .encode(&mut response[4..])
            .map_err(|_| -5)?;
        let handle =
            platform::handle::create_provider_object(endpoint, id, wire::descriptor_rights())
                .map_err(|e| e.raw() as i32)?;
        let mut outgoing = platform::ipc::IpcObjectHandles::default();
        outgoing.count = 1;
        outgoing.handles[0] = platform::ipc::IpcObjectHandle {
            handle,
            reserved: 0,
            rights: wire::descriptor_rights(),
        };
        let sent =
            platform::ipc::reply_object_handles(sender, &response[..4 + address_len], &outgoing);
        if sent.is_err() {
            // Retire the failed object's identity before its final close queues
            // a native release. The connection/data remain in the accept queue.
            let rollback = streams.abort_accept(ticket);
            let _ = platform::handle::close(handle);
            rollback?;
            return Err(-5);
        }
        // No other socket request can execute on this worker before commit.
        replied = true;
        let committed = streams.commit_accept(ticket, credentials, options);
        let _ = platform::handle::close(handle);
        committed?;
        Ok([listener, id])
    })();
    match result {
        Ok(ids) => Some(ids),
        Err(error) => {
            if replied {
                platform::logln!(
                    "posix.service: accepted socket commit failed errno={}",
                    error
                );
                return None;
            }
            // A failed create has no Handle; a failed send already rolled back.
            if streams.options(id).is_ok() {
                let _ = streams.abort_accept(ticket);
            }
            let _ = platform::ipc::reply(sender, &error.to_le_bytes());
            None
        }
    }
}
