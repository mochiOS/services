//! No process/FD lookup: every operation requires explicit IPC authority;
//! transactions are resolved only through ProviderObjectIdentify on this worker.
use mochi_user_platform as platform;
use mochios_posix_protocol::socket_transfer::{self as wire, Request};
use posix_service::{
    socket::Streams,
    socket_rights::Lease,
    socket_transfer::{Transfers, job_id, object_id},
};
fn close(handle: u32) {
    let _ = platform::handle::close(handle);
}

/// Returns a bit mask of received references whose ownership has been consumed,
/// including references closed by rollback. The common worker cleanup skips them.
/// The second result identifies descriptions whose send/receive readiness changed.
pub fn dispatch(
    endpoint: u32,
    streams: &mut Streams,
    transfers: &mut Transfers,
    routes: &mut posix_service::socket_route::Routes<u32>,
    sender: u64,
    bytes: &[u8],
    attachments: &platform::ipc::IpcObjectHandles,
) -> (u8, Option<[u64; 2]>) {
    let mut consumed = 0u8;
    let mut affected = None;
    let mut created = None;
    let mut replied = false;
    let result = (|| {
        if attachments.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
            return Err(-13);
        }
        let request = wire::decode(bytes).map_err(|error| match error {
            wire::Error::UnknownOperation => -38,
            _ => -22,
        })?;
        let count = attachments.count as usize;
        if count == 0 || count > mnu_abi::IPC_MAX_OBJECT_HANDLES {
            return Err(-22);
        }
        let attached = &attachments.handles[..count];
        for (index, item) in attached.iter().enumerate() {
            if item.handle == 0
                || item.reserved != 0
                || attached[..index]
                    .iter()
                    .any(|old| old.handle == item.handle)
            {
                return Err(-22);
            }
        }
        match request {
            Request::Begin {
                length,
                descriptors,
            } => {
                if count != 1 || attached[0].rights != mnu_abi::HANDLE_RIGHT_WRITE {
                    return Err(-13);
                }
                let socket = platform::handle::identify_provider_object(attached[0].handle)
                    .map_err(|error| error.raw() as i32)?;
                let id = if posix_service::socket_route::is_route(socket) {
                    transfers.start_route(
                        streams,
                        routes,
                        posix_service::socket_route::job_id(socket)?,
                        attached[0].handle,
                        length,
                        descriptors,
                        close,
                    )?
                } else {
                    transfers.start(
                        streams,
                        socket,
                        attached[0].handle,
                        length,
                        descriptors,
                        close,
                    )?
                };
                consumed |= 1;
                let handle = match object_id(id).and_then(|object| {
                    platform::handle::create_provider_object(endpoint, object, wire::RIGHTS)
                        .map_err(|error| error.raw() as i32)
                }) {
                    Ok(handle) => handle,
                    Err(error) => {
                        let _ = transfers.release(id);
                        return Err(error);
                    }
                };
                created = Some((id, handle));
                Ok(0u32)
            }
            Request::Append {
                offset,
                count: files,
                metadata,
            } => {
                if count != files as usize + 1
                    || attached[0].rights != mnu_abi::HANDLE_RIGHT_CONTROL
                {
                    return Err(-13);
                }
                let object = platform::handle::identify_provider_object(attached[0].handle)
                    .map_err(|error| error.raw() as i32)?;
                let id = job_id(object)?;
                transfers.progress(id)?;
                let mut leases = Vec::new();
                leases.try_reserve_exact(files as usize).map_err(|_| -12)?;
                for (index, item) in attached[1..].iter().enumerate() {
                    // Transient worker jobs are not POSIX file descriptions.
                    // Refuse retaining any such job, preventing staging cycles.
                    if platform::handle::identify_provider_object(item.handle)
                        .is_ok_and(|object| object > posix_service::socket::MAX_DESCRIPTION_ID)
                    {
                        return Err(-22);
                    }
                    consumed |= 1 << (index + 1);
                    let info = metadata[index].ok_or(-22)?;
                    leases.push(Lease::adopt(item.handle, item.rights, info, close)?);
                }
                transfers
                    .append(id, offset as usize, leases)
                    .map(|count| count as u32)
            }
            Request::Commit { offset } => {
                if count != 2
                    || attached[0].rights != mnu_abi::HANDLE_RIGHT_CONTROL
                    || attached[1].rights
                        != (mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP)
                {
                    return Err(-13);
                }
                let object = platform::handle::identify_provider_object(attached[0].handle)
                    .map_err(|error| error.raw() as i32)?;
                let (count, ids) = transfers.commit_with_routes(
                    streams,
                    routes,
                    job_id(object)?,
                    offset,
                    &mut posix_service::socket_record_io::NativeBuffer::borrowed(
                        attached[1].handle,
                    ),
                )?;
                affected = Some(ids);
                Ok(count as u32)
            }
            Request::Receive {
                offset,
                length,
                maximum_rights,
            }
            | Request::Peek {
                offset,
                length,
                maximum_rights,
            } => {
                let peek = matches!(request, Request::Peek { .. });
                if count != 2
                    || attached[0].rights != mnu_abi::HANDLE_RIGHT_READ
                    || attached[1].rights
                        != (mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_MAP)
                {
                    return Err(-13);
                }
                let socket = platform::handle::identify_provider_object(attached[0].handle)
                    .map_err(|error| error.raw() as i32)?;
                let ids = streams.affected(socket)?;
                let publish = |id, info: posix_service::socket_transfer::ReceiptInfo| {
                    let source = mochios_posix_protocol::socket::Address::decode(
                        info.record.source.encoded(),
                    )
                    .map_err(|_| -5)?;
                    let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
                    let reply = wire::ReceiveReply {
                        copied: info.record.copied as u32,
                        length: info.record.length as u32,
                        total_rights: info.total_rights as u16,
                        available_rights: info.available_rights as u16,
                        source,
                    };
                    let size = if peek {
                        reply.encode_peek(length, maximum_rights, &mut response)
                    } else {
                        reply.encode(length, maximum_rights, &mut response)
                    }
                    .map_err(|_| -5)?;
                    let mut outgoing = platform::ipc::IpcObjectHandles::default();
                    let handle = match id {
                        Some(id) => {
                            let handle = platform::handle::create_provider_object(
                                endpoint,
                                object_id(id)?,
                                wire::RIGHTS,
                            )
                            .map_err(|error| error.raw() as i32)?;
                            outgoing.count = 1;
                            outgoing.handles[0] = platform::ipc::IpcObjectHandle {
                                handle,
                                reserved: 0,
                                rights: wire::RIGHTS,
                            };
                            Some(handle)
                        }
                        None => None,
                    };
                    let result =
                        platform::ipc::reply_object_handles(sender, &response[..size], &outgoing);
                    if let Some(handle) = handle {
                        close(handle);
                    }
                    result.map_err(|error| error.raw() as i32)?;
                    replied = true;
                    Ok(())
                };
                let mut buffer =
                    posix_service::socket_record_io::NativeBuffer::borrowed(attached[1].handle);
                let (_, receipt) = if peek {
                    transfers.peek(
                        streams,
                        socket,
                        attached[0].handle,
                        offset,
                        length,
                        maximum_rights as usize,
                        close,
                        publish,
                        &mut buffer,
                    )
                } else {
                    transfers.receive(
                        streams,
                        socket,
                        attached[0].handle,
                        offset,
                        length,
                        maximum_rights as usize,
                        close,
                        publish,
                        &mut buffer,
                    )
                }?;
                if receipt.is_some() {
                    consumed |= 1;
                }
                // Peek changes neither queue capacity nor provider readiness.
                if !peek {
                    affected = Some(ids);
                }
                Ok(0)
            }
            Request::Deliver { offset, maximum } => {
                if count != 1 || attached[0].rights != mnu_abi::HANDLE_RIGHT_CONTROL {
                    return Err(-13);
                }
                let object = platform::handle::identify_provider_object(attached[0].handle)
                    .map_err(|error| error.raw() as i32)?;
                transfers
                    .deliver(
                        job_id(object)?,
                        offset as usize,
                        maximum as usize,
                        |leases| {
                            let mut outgoing = platform::ipc::IpcObjectHandles::default();
                            let mut metadata = [mochios_posix_protocol::InheritedFdMetadata {
                                kind: 5,
                                open_flags: 0,
                                descriptor_flags: 0,
                            };
                                mnu_abi::IPC_MAX_OBJECT_HANDLES];
                            outgoing.count = leases.len() as u32;
                            for (index, lease) in leases.iter().enumerate() {
                                metadata[index] = lease.metadata();
                                outgoing.handles[index] = platform::ipc::IpcObjectHandle {
                                    handle: lease.handle(),
                                    reserved: 0,
                                    rights: lease.rights(),
                                };
                            }
                            let mut response = [0; wire::MAX_DELIVERY_REPLY_LEN];
                            let size = wire::delivery_reply(
                                offset,
                                &metadata[..leases.len()],
                                &mut response,
                            )
                            .map_err(|_| -5)?;
                            platform::ipc::reply_object_handles(
                                sender,
                                &response[..size],
                                &outgoing,
                            )
                            .map_err(|error| error.raw() as i32)?;
                            replied = true;
                            Ok(())
                        },
                    )
                    .map(|count| count as u32)
            }
        }
    })();
    if let Some((id, handle)) = created {
        let mut outgoing = platform::ipc::IpcObjectHandles::default();
        outgoing.count = 1;
        outgoing.handles[0] = platform::ipc::IpcObjectHandle {
            handle,
            reserved: 0,
            rights: wire::RIGHTS,
        };
        if platform::ipc::reply_object_handles(sender, &0u32.to_le_bytes(), &outgoing).is_err() {
            let _ = transfers.release(id);
        }
        close(handle);
    } else if !replied {
        let bytes = match result {
            Ok(count) => count.to_le_bytes(),
            Err(error) => i32::to_le_bytes(error),
        };
        let _ = platform::ipc::reply(sender, &bytes);
    }
    (consumed, affected)
}

pub fn provider_request(
    transfers: &mut Transfers,
    sender: u64,
    request: mnu_abi::provider::RequestHeader,
    flags: u32,
    attachments: u32,
    response: &mut [u8],
) {
    use mnu_abi::provider;
    let authenticated = flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT && attachments == 0;
    if authenticated && request.opcode == provider::OP_RELEASE {
        if let Ok(id) = job_id(request.object_id) {
            let _ = transfers.release(id);
        }
        return;
    }
    let status = if !authenticated { -13 } else { -95 };
    if let Ok(length) = (provider::ResponseHeader {
        opcode: request.opcode,
        object_id: request.object_id,
        status,
        value: 0,
        data_length: 0,
    })
    .encode(&[], response)
    {
        let _ = platform::ipc::reply(sender, &response[..length]);
    }
}
