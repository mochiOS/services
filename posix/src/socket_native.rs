//! Socket objects owned by a dedicated native Provider endpoint thread.

use mochi_user_platform as platform;
use mochios_posix_protocol::socket as wire;
use posix_service::{
    PosixService,
    socket::Streams,
    socket_provider::{handle_provider_request, native_signals},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, Ordering},
};

const CREATE_MAGIC: &[u8; 4] = b"SOPA";
const CREATE_SINGLE_MAGIC: &[u8; 4] = b"SOCR";
const CREATE_LEN: usize = 12 + wire::CREATE_LEN;

pub fn start(service: Arc<Mutex<PosixService<u32>>>) -> Result<u32, i64> {
    let startup = Arc::new(AtomicI64::new(0));
    let worker_startup = Arc::clone(&startup);
    std::thread::Builder::new()
        .name("posix-socket-provider".to_owned())
        .spawn(move || {
            let result = platform::ipc::create_handle().and_then(|endpoint| {
                platform::process::current_execution_identity()
                    .map(|identity| (endpoint, identity.process_id))
            });
            match result {
                Ok((endpoint, process_id)) => {
                    worker_startup.store(i64::from(endpoint), Ordering::Release);
                    run(endpoint, process_id, service);
                }
                Err(error) => worker_startup.store(error.raw(), Ordering::Release),
            }
        })
        .map_err(|_| -5)?;
    loop {
        match startup.load(Ordering::Acquire) {
            0 => platform::thread::yield_now(),
            error if error < 0 => return Err(error),
            endpoint => return u32::try_from(endpoint).map_err(|_| -5),
        }
    }
}

/// Called by the service dispatcher only after kernel sender authentication.
/// Never hold the service state mutex across this RPC.
pub fn create(
    endpoint: u32,
    process_id: u64,
    create: wire::Create,
    pair: bool,
    factory: Option<posix_service::AttachedObject<u32>>,
) -> Result<Vec<posix_service::OpenedObject<u32>>, i32> {
    let mut request = [0; CREATE_LEN];
    request[..4].copy_from_slice(if pair {
        CREATE_MAGIC
    } else {
        CREATE_SINGLE_MAGIC
    });
    request[4..12].copy_from_slice(&process_id.to_le_bytes());
    create.encode(&mut request[12..]).map_err(|_| -22)?;
    let mut attachments = platform::ipc::IpcObjectHandles::default();
    if let Some(factory) = factory {
        let rights = wire::inet_factory_rights();
        if factory.handle == 0 || factory.rights & rights != rights {
            return Err(-13);
        }
        attachments.count = 1;
        attachments.handles[0] = platform::ipc::IpcObjectHandle {
            handle: factory.handle,
            reserved: 0,
            rights,
        };
    }
    let mut opened = Vec::new();
    opened
        .try_reserve_exact(if pair { 2 } else { 1 })
        .map_err(|_| -12)?;
    let mut response = [0; 4];
    let length =
        posix_service::filesystem_transport::call_native(&mut attachments, |attachments| {
            platform::ipc::call_object_handles(endpoint, &request, &mut response, attachments)
        })
        .map_err(|error| mochios_posix_protocol::status::normalize_failure(error.raw()))?;
    let result = (|| {
        if length as u32 != 4 || attachments.delivery_flags != 0 {
            return Err(-5);
        }
        let status = i32::from_le_bytes(response);
        if status != 0 {
            return Err(status);
        }
        let count = if pair { 2 } else { 1 };
        if attachments.count as usize != count
            || attachments.handles[..count].iter().any(|attachment| {
                attachment.handle == 0
                    || attachment.reserved != 0
                    || attachment.rights != wire::descriptor_rights()
            })
        {
            return Err(-5);
        }
        for attachment in &attachments.handles[..count] {
            opened.push(posix_service::OpenedObject {
                handle: attachment.handle,
                rights: attachment.rights,
            });
        }
        Ok(opened)
    })();
    if result.is_err() {
        for attached in attachments.handles.iter().take(attachments.count as usize) {
            let _ = platform::handle::close(attached.handle);
        }
    }
    result
}

pub(super) fn signal(
    streams: &Streams,
    jobs: &posix_service::socket_connect::Connections<u32>,
    ids: impl IntoIterator<Item = u64>,
) {
    const SIGNALS: u64 = mnu_abi::HANDLE_SIGNAL_READABLE
        | mnu_abi::HANDLE_SIGNAL_WRITABLE
        | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
    for id in ids
        .into_iter()
        .flat_map(|id| std::iter::once(id).chain(streams.record_observers(id)))
    {
        if let Ok(ready) = streams.readiness(id) {
            let set = if jobs.is_pending(id) {
                0
            } else {
                native_signals(ready)
            };
            if let Err(error) = platform::handle::signal_provider_object(id, set, SIGNALS & !set) {
                // A final close can race notification; no remaining observer.
                if !notification_is_retired(error.raw()) {
                    platform::logln!(
                        "posix.service: socket readiness failed status={}",
                        error.raw()
                    );
                }
            }
        }
    }
}

pub(super) fn notification_is_retired(raw: i64) -> bool {
    // Callers supply validated local IDs and constant supported signal masks.
    // InvalidArgument therefore means the last reference was already closed,
    // not a zero-readiness result or a reason to retry a foreign namespace.
    mnu_abi::status::Error::from_raw(raw as u64) == Some(mnu_abi::status::Error::InvalidArgument)
}

fn run(endpoint: u32, service_process: u64, service: Arc<Mutex<PosixService<u32>>>) -> ! {
    use mnu_abi::provider;
    let mut streams = Streams::new();
    let mut inet = posix_service::inet_socket::Registry::<
        posix_service::inet_datagram_native::NetworkBackend,
    >::new();
    let mut tcp = super::socket_tcp_native::Registry::new();
    let mut bindings = posix_service::socket_binding::Bindings::new();
    let mut jobs = posix_service::socket_connect::Connections::new();
    let mut receive_waits = posix_service::socket_receive_wait::ReceiveWaits::new();
    let mut routes = posix_service::socket_route::Routes::new();
    let mut transfers = posix_service::socket_transfer::Transfers::new(1024);
    let mut request = vec![0; provider::REQUEST_HEADER_LEN + provider::MAX_DATA_LEN];
    let mut response = vec![0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    let mut gc_deadline = 0;
    let mut gc_clock_error_reported = false;
    loop {
        // A final external close does not destroy a queue-only cycle, so no
        // OP_RELEASE would arrive to wake an ordinary IPC wait. Use the existing
        // native endpoint readiness wait with a bounded GC deadline only while
        // ancillary records exist. Normal socket traffic has no extra wait.
        if streams.has_ancillary_records() {
            match platform::time::monotonic_nanoseconds() {
                Ok(now) => {
                    gc_clock_error_reported = false;
                    if now >= gc_deadline {
                        gc_deadline = now.saturating_add(super::socket_gc_native::INTERVAL_NS);
                        match super::socket_gc_native::collect(&mut streams) {
                            Ok(ids) => signal(&streams, &jobs, ids),
                            // A retired Provider's release may still be queued.
                            // Failed observations never authorize queue deletion.
                            Err(-9 | -11) => (),
                            Err(error) => platform::logln!(
                                "posix.service: socket cycle observation failed errno={}",
                                error
                            ),
                        }
                        super::socket_receive_wait_native::pump(&streams, &mut receive_waits);
                        super::socket_route_native::pump(&streams, &routes);
                    }
                }
                Err(error) => {
                    // Keep ordinary IPC available if the clock fails. Do not
                    // collect using a fabricated timestamp or spin/log-flood.
                    if !gc_clock_error_reported {
                        platform::logln!(
                            "posix.service: socket GC clock failed errno={}",
                            error.raw()
                        );
                        gc_clock_error_reported = true;
                    }
                }
            }
        } else {
            gc_deadline = 0;
        }
        inet.pump(|id, set| {
            let all = mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_WRITABLE
                | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            platform::handle::signal_provider_object(id, set, all & !set)
                .map_err(|error| mochios_posix_protocol::status::normalize_failure(error.raw()))
        });
        super::socket_tcp_native::pump(&mut tcp);
        let mut watches = [mnu_abi::HandleWaitItem::default(); mnu_abi::HANDLE_WAIT_MANY_MAX_ITEMS];
        watches[0] = mnu_abi::HandleWaitItem {
            handle: endpoint,
            interests: mnu_abi::HANDLE_SIGNAL_READABLE,
            ..Default::default()
        };
        let mut count = 1;
        let mut overflow = false;
        inet.watches(|handle, interests| {
            if count < watches.len() {
                watches[count] = mnu_abi::HandleWaitItem {
                    handle,
                    interests,
                    ..Default::default()
                };
                count += 1;
            } else {
                overflow = true;
            }
        });
        tcp.watches(|handle, interests| {
            if count < watches.len() {
                watches[count] = mnu_abi::HandleWaitItem {
                    handle,
                    interests,
                    ..Default::default()
                };
                count += 1;
            } else {
                overflow = true;
            }
        });
        if count > 1 || gc_deadline != 0 {
            let mut deadline = if gc_deadline != 0 {
                gc_deadline
            } else {
                mnu_abi::HANDLE_WAIT_INFINITE
            };
            if overflow {
                let Ok(now) = platform::time::monotonic_nanoseconds() else {
                    platform::thread::yield_now();
                    continue;
                };
                deadline = deadline.min(now.saturating_add(10_000_000));
            }
            match platform::process::wait_many(&mut watches[..count], deadline) {
                Ok(0) => (),
                Ok(_) => continue,
                Err(error) => {
                    if error.native_error() != Some(mnu_abi::status::Error::NotReady) {
                        platform::thread::yield_now();
                    }
                    continue;
                }
            }
        }
        let mut attachments = platform::ipc::IpcObjectHandles::default();
        let message = match platform::ipc::wait_object_handles(
            u64::from(endpoint),
            &mut request,
            &mut attachments,
        ) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let bytes = &request[..(message as u32 as usize).min(request.len())];
        let mut retained_receive_source = false;
        let mut consumed_attachments = 0u8;
        if bytes.starts_with(&mochios_posix_protocol::socket_transfer::MAGIC) {
            let (consumed, affected) = super::socket_transfer_native::dispatch(
                endpoint,
                &mut streams,
                &mut transfers,
                &mut routes,
                sender,
                bytes,
                &attachments,
            );
            consumed_attachments = consumed;
            if let Some(ids) = affected {
                signal(&streams, &jobs, ids);
            }
        } else if bytes.starts_with(&mochios_posix_protocol::socket_route::MAGIC) {
            retained_receive_source = super::socket_route_native::prepare(
                endpoint,
                &service,
                &streams,
                &bindings,
                &mut routes,
                sender,
                bytes,
                &attachments,
            );
        } else if bytes.starts_with(&mochios_posix_protocol::socket_record::REQUEST_MAGIC) {
            let (affected, retained) = super::socket_record_native::dispatch(
                endpoint,
                &mut streams,
                &mut inet,
                &mut receive_waits,
                &mut routes,
                sender,
                bytes,
                &attachments,
            );
            retained_receive_source = retained;
            if let Some(ids) = affected {
                signal(&streams, &jobs, ids);
            }
        } else if bytes.starts_with(super::socket_receive_wait_native::MAGIC) {
            retained_receive_source = super::socket_receive_wait_native::dispatch(
                endpoint,
                service_process,
                &streams,
                &mut receive_waits,
                sender,
                bytes,
                &attachments,
            );
        } else if bytes.starts_with(super::socket_connect_native::MAGIC) {
            if let Some(ids) = super::socket_connect_native::dispatch(
                endpoint,
                service_process,
                &service,
                &mut streams,
                &bindings,
                &mut jobs,
                &mut inet,
                &mut tcp,
                &mut retained_receive_source,
                sender,
                bytes,
                &attachments,
            ) {
                signal(&streams, &jobs, ids);
            }
        } else if bytes.starts_with(super::socket_accept_native::MAGIC) {
            if let Some(ids) = super::socket_accept_native::dispatch(
                endpoint,
                service_process,
                &service,
                &mut streams,
                &mut tcp,
                sender,
                bytes,
                &attachments,
            ) {
                signal(&streams, &jobs, ids);
            }
        } else if bytes.starts_with(CREATE_MAGIC) || bytes.starts_with(CREATE_SINGLE_MAGIC) {
            let pair = bytes.starts_with(CREATE_MAGIC);
            let count = if pair { 2 } else { 1 };
            let result = (|| {
                // Only the authenticated service dispatcher may nominate a process.
                if bytes.len() != CREATE_LEN
                    || attachments.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
                {
                    return Err(-22);
                }
                if platform::ipc::endpoint_owner_process(sender).ok() != Some(service_process) {
                    return Err(-13);
                }
                let process_id = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
                let create = wire::Create::decode(&bytes[12..]).map_err(|_| -22)?;
                let inet_create = create.domain == wire::Domain::Ipv4
                    && matches!(create.kind, wire::Kind::Datagram | wire::Kind::Stream)
                    && !pair;
                if (!inet_create && attachments.count != 0)
                    || (inet_create && attachments.count != 1)
                {
                    return Err(-13);
                }
                let ids = if inet_create {
                    let source = attachments.handles[0];
                    if source.handle == 0
                        || source.reserved != 0
                        || source.rights != wire::inet_factory_rights()
                    {
                        return Err(-13);
                    }
                    let (network, credentials) = {
                        let state = service.lock().map_err(|_| -5)?;
                        let peer = state.registered_peer(process_id).ok_or(-1)?;
                        (
                            state.network_endpoint().ok_or(-6)?,
                            (peer.effective_uid, peer.effective_gid),
                        )
                    };
                    consumed_attachments = 1;
                    let factory = posix_service::OpenedObject {
                        handle: source.handle,
                        rights: source.rights,
                    };
                    if create.kind == wire::Kind::Stream {
                        let backend = posix_service::inet_stream_native::NetworkBackend::new(
                            network, factory,
                        )?;
                        backend.validate()?;
                        let socket = posix_service::inet_stream::Stream::new(backend, create)?;
                        [tcp.insert(socket, credentials)?, 0]
                    } else {
                        let backend = posix_service::inet_datagram_native::NetworkBackend::new(
                            network, factory,
                        )?;
                        backend.validate()?;
                        let socket = posix_service::inet_datagram::Datagram::new(backend, create)?;
                        [inet.insert(socket)?, 0]
                    }
                } else {
                    let state = service.lock().map_err(|_| -5)?;
                    let peer = state.registered_peer(process_id).ok_or(-1)?;
                    if pair {
                        state.create_socket_pair(peer, create, &mut streams)?
                    } else {
                        [state.create_socket(peer, create, &mut streams)?, 0]
                    }
                };
                let mut handles = [0; 2];
                for (index, id) in ids.into_iter().take(count).enumerate() {
                    match platform::handle::create_provider_object(
                        endpoint,
                        id,
                        wire::descriptor_rights(),
                    ) {
                        Ok(handle) => handles[index] = handle,
                        Err(error) => {
                            for handle in handles {
                                if handle != 0 {
                                    let _ = platform::handle::close(handle);
                                }
                            }
                            for id in ids.into_iter().take(count) {
                                if posix_service::inet_stream_socket::is_stream(id) {
                                    let _ = tcp.remove(id);
                                } else if posix_service::inet_socket::is_inet(id) {
                                    let _ = inet.remove(id);
                                } else {
                                    let _ = streams.release(id);
                                }
                            }
                            return Err(error.raw() as i32);
                        }
                    }
                }
                if posix_service::inet_stream_socket::is_stream(ids[0]) {
                    super::socket_tcp_native::pump(&mut tcp);
                } else if inet_create {
                    if let Err(error) = platform::handle::signal_provider_object(
                        ids[0],
                        mnu_abi::HANDLE_SIGNAL_WRITABLE,
                        mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
                    ) {
                        let _ = inet.remove(ids[0]);
                        let _ = platform::handle::close(handles[0]);
                        return Err(mochios_posix_protocol::status::normalize_failure(
                            error.raw(),
                        ));
                    }
                } else {
                    signal(&streams, &jobs, ids);
                }
                Ok(handles)
            })();
            match result {
                Ok(handles) => {
                    let mut outgoing = platform::ipc::IpcObjectHandles::default();
                    outgoing.count = count as u32;
                    for (slot, handle) in outgoing
                        .handles
                        .iter_mut()
                        .zip(handles.into_iter().take(count))
                    {
                        *slot = platform::ipc::IpcObjectHandle {
                            handle,
                            reserved: 0,
                            rights: wire::descriptor_rights(),
                        };
                    }
                    if platform::ipc::reply_object_handles(sender, &0i32.to_le_bytes(), &outgoing)
                        .is_err()
                    {
                        for handle in handles.into_iter().take(count) {
                            if let Ok(id) = platform::handle::identify_provider_object(handle) {
                                if posix_service::inet_stream_socket::is_stream(id) {
                                    let _ = tcp.remove(id);
                                } else if posix_service::inet_socket::is_inet(id) {
                                    let _ = inet.remove(id);
                                }
                            }
                        }
                    }
                    for handle in handles.into_iter().take(count) {
                        let _ = platform::handle::close(handle);
                    }
                }
                Err(error) => {
                    let _ = platform::ipc::reply(sender, &error.to_le_bytes());
                }
            }
        } else {
            let decoded = provider::RequestHeader::decode(bytes).ok();
            let native = attachments.delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
                && attachments.count == 0;
            let released_observers = decoded
                .filter(|(header, _)| native && header.opcode == provider::OP_RELEASE)
                .and_then(|(header, _)| streams.release_observers(header.object_id).ok());
            if let Some((header, payload)) = decoded {
                if posix_service::inet_stream_socket::is_stream(header.object_id)
                    || posix_service::inet_stream_socket::is_job(header.object_id)
                {
                    let result = tcp.dispatch(
                        bytes,
                        attachments.delivery_flags,
                        attachments.count,
                        &mut response,
                    );
                    // Publish drained levels before completing the native request.
                    super::socket_tcp_native::pump(&mut tcp);
                    match result {
                        Ok(Some(n)) => {
                            let _ = platform::ipc::reply(sender, &response[..n]);
                        }
                        Ok(None) | Err(-9) if native && header.opcode == provider::OP_RELEASE => (),
                        Err(error) => platform::logln!(
                            "posix.service: TCP Provider request rejected status={}",
                            error
                        ),
                        _ => (),
                    }
                    for object in attachments.handles.iter().take(attachments.count as usize) {
                        let _ = platform::handle::close(object.handle);
                    }
                    continue;
                }
                if posix_service::inet_socket::is_inet(header.object_id) {
                    match inet.dispatch(
                        bytes,
                        attachments.delivery_flags,
                        attachments.count,
                        &mut response,
                    ) {
                        Ok(Some(n)) => {
                            let _ = platform::ipc::reply(sender, &response[..n]);
                        }
                        Ok(None) | Err(-9) if native && header.opcode == provider::OP_RELEASE => (),
                        Err(error) => platform::logln!(
                            "posix.service: UDP Provider request rejected status={}",
                            error
                        ),
                        _ => (),
                    }
                    for object in attachments.handles.iter().take(attachments.count as usize) {
                        let _ = platform::handle::close(object.handle);
                    }
                    continue;
                }
                if posix_service::socket_transfer::job_id(header.object_id).is_ok() {
                    super::socket_transfer_native::provider_request(
                        &mut transfers,
                        sender,
                        header,
                        attachments.delivery_flags,
                        attachments.count,
                        &mut response,
                    );
                    for attached in attachments.handles.iter().take(attachments.count as usize) {
                        let _ = platform::handle::close(attached.handle);
                    }
                    continue;
                }
                if posix_service::socket_route::is_route(header.object_id) {
                    super::socket_route_native::provider_request(
                        &mut routes,
                        sender,
                        header,
                        attachments.delivery_flags,
                        attachments.count,
                        &mut response,
                    );
                    for attached in attachments.handles.iter().take(attachments.count as usize) {
                        let _ = platform::handle::close(attached.handle);
                    }
                    continue;
                }
                if posix_service::socket_receive_wait::job_id(header.object_id).is_ok() {
                    let result = receive_waits.handle_provider_request(
                        bytes,
                        attachments.delivery_flags,
                        attachments.count,
                        |source| {
                            let _ = platform::handle::close(source);
                        },
                    );
                    // Only final release is exposed. Other requests must get a
                    // bounded error reply rather than leaving IPC callers hung.
                    if let Err(error) = result
                        && !(native
                            && header.opcode == provider::OP_RELEASE
                            && error == -9
                            && attachments.count == 0)
                    {
                        if let Ok(length) = (provider::ResponseHeader {
                            opcode: header.opcode,
                            status: i64::from(error),
                            object_id: header.object_id,
                            value: 0,
                            data_length: 0,
                        })
                        .encode(&[], &mut response)
                        {
                            let _ = platform::ipc::reply(sender, &response[..length]);
                        }
                    }
                    for attached in attachments.handles.iter().take(attachments.count as usize) {
                        let _ = platform::handle::close(attached.handle);
                    }
                    continue;
                }
                if header.object_id & posix_service::socket_connect::JOB_OBJECT_TAG != 0 {
                    let client = posix_service::socket_connect::job_id(header.object_id)
                        .and_then(|id| jobs.client(id))
                        .ok();
                    match jobs.handle_provider_request(
                        bytes,
                        attachments.delivery_flags,
                        attachments.count,
                        &mut response,
                        |handle| {
                            let _ = platform::handle::close(handle);
                        },
                    ) {
                        Ok(Some(length)) => {
                            let _ = platform::ipc::reply(sender, &response[..length]);
                        }
                        Ok(None) => {
                            if let Some(client) = client {
                                signal(&streams, &jobs, [client]);
                            }
                        }
                        Err(-9) if native && header.opcode == provider::OP_RELEASE => (),
                        Err(error) => {
                            platform::logln!("posix.service: connect job rejected errno={}", error)
                        }
                    }
                    for attached in attachments.handles.iter().take(attachments.count as usize) {
                        let _ = platform::handle::close(attached.handle);
                    }
                    super::socket_connect_native::pump(&mut streams, &bindings, &mut jobs);
                    continue;
                }
                if native
                    && jobs.is_pending(header.object_id)
                    && header.opcode == provider::OP_CONTROL
                    && header.basis == wire::CONTROL_READINESS
                    && payload.is_empty()
                    && header.length == 4
                {
                    if let Ok(length) = (provider::ResponseHeader {
                        opcode: header.opcode,
                        object_id: header.object_id,
                        status: 0,
                        value: 4,
                        data_length: 4,
                    })
                    .encode(&[0; 4], &mut response)
                    {
                        let _ = platform::ipc::reply(sender, &response[..length]);
                    }
                    continue;
                }
                if native
                    && header.opcode == provider::OP_CONTROL
                    && (header.basis == wire::CONTROL_BIND
                        || header.basis == wire::CONTROL_LISTEN
                        || (header.basis == wire::CONTROL_LOCAL_ADDRESS
                            && bindings.address(header.object_id).is_some()))
                {
                    match super::socket_path_native::control(
                        &mut streams,
                        &mut bindings,
                        &service,
                        sender,
                        header,
                        payload,
                        &mut response,
                    ) {
                        Ok(length) => {
                            if header.basis == wire::CONTROL_LISTEN {
                                if let Ok(ids) = streams.affected(header.object_id) {
                                    signal(&streams, &jobs, ids);
                                }
                            }
                            let _ = platform::ipc::reply(sender, &response[..length]);
                        }
                        Err(error) => platform::logln!(
                            "posix.service: socket path control failed errno={}",
                            error
                        ),
                    }
                    super::socket_connect_native::pump(&mut streams, &bindings, &mut jobs);
                    continue;
                }
                if native && header.opcode == provider::OP_RELEASE {
                    bindings.release_with(header.object_id, |handle| {
                        let _ = platform::handle::close(handle);
                    });
                }
            }
            let affected = provider::RequestHeader::decode(bytes)
                .ok()
                .and_then(|(header, _)| streams.affected(header.object_id).ok());
            let result = handle_provider_request(
                &mut streams,
                bytes,
                attachments.delivery_flags,
                attachments.count,
                &mut response,
            );
            if let Some(ids) = affected {
                signal(&streams, &jobs, ids);
            }
            if let Some(observers) = released_observers {
                signal(&streams, &jobs, observers.iter());
            }
            match result {
                Ok(Some(length)) => {
                    let _ = platform::ipc::reply(sender, &response[..length]);
                }
                Ok(None) => (),
                // Rollback of failed object creation may enqueue a late release.
                Err(-9)
                    if provider::RequestHeader::decode(bytes)
                        .is_ok_and(|(header, _)| header.opcode == provider::OP_RELEASE)
                        && attachments.delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
                        && attachments.count == 0 =>
                {
                    ()
                }
                Err(error) => platform::logln!(
                    "posix.service: socket provider rejected request errno={}",
                    error
                ),
            }
        }
        consumed_attachments |= u8::from(retained_receive_source);
        for (index, attached) in attachments
            .handles
            .iter()
            .take(attachments.count as usize)
            .enumerate()
        {
            if consumed_attachments & (1 << index) == 0 {
                let _ = platform::handle::close(attached.handle);
            }
        }
        super::socket_connect_native::pump(&mut streams, &bindings, &mut jobs);
        super::socket_receive_wait_native::pump(&streams, &mut receive_waits);
        super::socket_route_native::pump(&streams, &routes);
    }
}
