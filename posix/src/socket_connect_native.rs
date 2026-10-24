//! Dispatcher-to-Provider bridge. Only authenticated internal endpoint calls
//! may nominate session identity; socket authority is explicitly attached.

use mochi_user_platform as platform;
use mochios_posix_protocol::socket as wire;
use posix_service::{
    AttachedObject, OpenedObject, PosixService,
    socket::Streams,
    socket_binding::Bindings,
    socket_connect::{Connections, Started, object_id},
};
use std::sync::{Arc, Mutex};

pub const MAGIC: &[u8; 4] = b"SOCO";

pub fn connect(
    endpoint: u32,
    process_id: u64,
    socket: AttachedObject<u32>,
    address: wire::Address<'_>,
) -> Result<(Vec<OpenedObject<u32>>, Vec<u8>), i32> {
    let rights = wire::connect_socket_rights();
    if socket.handle == 0 || socket.rights & rights != rights {
        return Err(-13);
    }
    let mut request = [0; 12 + wire::MAX_ADDRESS_LEN];
    request[..4].copy_from_slice(MAGIC);
    request[4..12].copy_from_slice(&process_id.to_le_bytes());
    let length = address.encode(&mut request[12..]).map_err(|_| -22)?;
    let mut handles = platform::ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0] = platform::ipc::IpcObjectHandle {
        handle: socket.handle,
        reserved: 0,
        rights,
    };
    let mut response = [0; 4 + wire::CONNECT_REPLY_LEN];
    // No fallible allocation after receiving an owned job reference.
    let mut opened = Vec::new();
    opened.try_reserve(1).map_err(|_| -12)?;
    let mut payload = Vec::new();
    payload
        .try_reserve(wire::CONNECT_REPLY_LEN)
        .map_err(|_| -12)?;
    let received = posix_service::filesystem_transport::call_native(&mut handles, |native| {
        platform::ipc::call_object_handles(endpoint, &request[..12 + length], &mut response, native)
    })
    .map_err(|error| error.raw() as i32);
    let result = (|| {
        let response = response.get(..received? as u32 as usize).ok_or(-5)?;
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
        match wire::ConnectReply::decode(&response[4..]).map_err(|_| -5)? {
            wire::ConnectReply::Connected if handles.count == 0 => (),
            wire::ConnectReply::Waiting if handles.count == 1 => {
                let job = handles.handles[0];
                if job.handle == 0 || job.reserved != 0 || job.rights != wire::connect_job_rights()
                {
                    return Err(-5);
                }
                opened.push(OpenedObject {
                    handle: job.handle,
                    rights: job.rights,
                });
            }
            _ => return Err(-5),
        }
        payload.extend_from_slice(&response[4..]);
        Ok((opened, payload))
    })();
    if result.is_err() {
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
    result
}

pub fn dispatch(
    endpoint: u32,
    service_process: u64,
    state: &Arc<Mutex<PosixService<u32>>>,
    streams: &mut Streams,
    bindings: &Bindings<u32>,
    jobs: &mut Connections<u32>,
    inet: &mut posix_service::inet_socket::Registry<
        posix_service::inet_datagram_native::NetworkBackend,
    >,
    sender: u64,
    bytes: &[u8],
    attachments: &platform::ipc::IpcObjectHandles,
) -> Option<[u64; 3]> {
    let result = (|| {
        if attachments.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
            || platform::ipc::endpoint_owner_process(sender).ok() != Some(service_process)
        {
            return Err(-13);
        }
        if bytes.len() < 12 || attachments.count != 1 {
            return Err(-22);
        }
        let source = attachments.handles[0];
        if source.handle == 0
            || source.reserved != 0
            || source.rights & wire::connect_socket_rights() != wire::connect_socket_rights()
        {
            return Err(-13);
        }
        let address = wire::Address::decode(&bytes[12..]).map_err(|_| -22)?;
        let process_id = u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| -22)?);
        let client = platform::handle::identify_provider_object(source.handle)
            .map_err(|e| e.raw() as i32)?;
        if posix_service::inet_socket::is_inet(client) {
            {
                let state = state.lock().map_err(|_| -5)?;
                state.registered_peer(process_id).ok_or(-1)?;
            }
            let mut response = [0; 4 + wire::CONNECT_REPLY_LEN];
            wire::ConnectReply::Connected
                .encode(&mut response[4..])
                .map_err(|_| -5)?;
            inet.connect(client, address)?;
            let _ = platform::ipc::reply(sender, &response);
            return Ok(None);
        }
        let wire::Address::UnixPath(path) = address else {
            return Err(-95);
        };
        if streams.kind(client)? == wire::Kind::Datagram {
            let old_peer = streams.affected(client)?[1];
            let mut response = [0; 4 + wire::CONNECT_REPLY_LEN];
            wire::ConnectReply::Connected
                .encode(&mut response[4..])
                .map_err(|_| -5)?;
            let mut backend = super::socket_path_native::snapshot_process(state, process_id, path)?;
            let target = bindings.connect_datagram_path(streams, client, path, &mut backend)?;
            let _ = platform::ipc::reply(sender, &response);
            return Ok(Some([client, target, old_peer]));
        }
        let nonblocking = streams.options(client)? & wire::NONBLOCKING != 0;
        let mut backend = super::socket_path_native::snapshot_process(state, process_id, path)?;
        let started = jobs.start(streams, bindings, client, path, nonblocking, &mut backend)?;
        let mut response = [0; 4 + wire::CONNECT_REPLY_LEN];
        match started {
            Started::Connected { listener, accepted } => {
                wire::ConnectReply::Connected
                    .encode(&mut response[4..])
                    .map_err(|_| -5)?;
                let _ = platform::ipc::reply(sender, &response);
                Ok(Some([client, listener, accepted]))
            }
            Started::Waiting { job } => {
                let prepared = (|| {
                    wire::ConnectReply::Waiting
                        .encode(&mut response[4..])
                        .map_err(|_| -5)?;
                    platform::handle::create_provider_object(
                        endpoint,
                        object_id(job)?,
                        wire::connect_job_rights(),
                    )
                    .map_err(|error| error.raw() as i32)
                })();
                let handle = match prepared {
                    Ok(handle) => handle,
                    Err(error) => {
                        let _ = jobs.release(job, |handle| {
                            let _ = platform::handle::close(handle);
                        });
                        return Err(error);
                    }
                };
                let mut outgoing = platform::ipc::IpcObjectHandles::default();
                outgoing.count = 1;
                outgoing.handles[0] = platform::ipc::IpcObjectHandle {
                    handle,
                    reserved: 0,
                    rights: wire::connect_job_rights(),
                };
                let sent = platform::ipc::reply_object_handles(sender, &response, &outgoing);
                if sent.is_err() {
                    // Cancel before close can queue a late native release.
                    let _ = jobs.release(job, |handle| {
                        let _ = platform::handle::close(handle);
                    });
                }
                let _ = platform::handle::close(handle);
                if sent.is_err() {
                    return Err(-5);
                }
                Ok(Some([client, 0, 0]))
            }
        }
    })();
    match result {
        Ok(ids) => ids,
        Err(error) => {
            let _ = platform::ipc::reply(sender, &error.to_le_bytes());
            None
        }
    }
}

pub fn pump(streams: &mut Streams, bindings: &Bindings<u32>, jobs: &mut Connections<u32>) {
    let mut affected = [0; 2 * posix_service::socket::MAX_ENDPOINTS];
    let mut length = 0;
    jobs.pump(
        streams,
        bindings,
        |handle| {
            let _ = platform::handle::close(handle);
        },
        |job, client, result| {
            if let Ok(id) = object_id(job) {
                if let Err(error) =
                    platform::handle::signal_provider_object(id, mnu_abi::HANDLE_SIGNAL_READABLE, 0)
                {
                    if !super::socket_native::notification_is_retired(error.raw()) {
                        platform::logln!(
                            "posix.service: connect job signal failed status={}",
                            error.raw()
                        );
                    }
                }
            }
            affected[length] = client;
            length += 1;
            if let Ok((listener, _)) = result {
                affected[length] = listener;
                length += 1;
            }
        },
    );
    super::socket_native::signal(streams, jobs, affected[..length].iter().copied());
}
