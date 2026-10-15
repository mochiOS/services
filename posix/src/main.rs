#![cfg_attr(target_os = "mochios", feature(allocator_api))]

#[cfg(target_os = "mochios")]
mod process_control;

#[cfg(target_os = "mochios")]
mod resource_policy_native;

#[cfg(target_os = "mochios")]
mod named_semaphore_native;

#[cfg(target_os = "mochios")]
mod shared_memory_native;

#[cfg(target_os = "mochios")]
mod shared_memory_provider;

#[cfg(target_os = "mochios")]
mod socket_native;

#[cfg(target_os = "mochios")]
mod socket_path_native;

#[cfg(target_os = "mochios")]
mod socket_accept_native;

#[cfg(target_os = "mochios")]
mod socket_connect_native;

#[cfg(target_os = "mochios")]
mod socket_receive_wait_native;

#[cfg(target_os = "mochios")]
mod socket_record_native;

#[cfg(target_os = "mochios")]
mod socket_route_native;
#[cfg(target_os = "mochios")]
mod socket_transfer_native;
#[cfg(target_os = "mochios")]
mod socket_gc_native;

#[cfg(target_os = "mochios")]
const PTY_SYNC_MAGIC: [u8; 4] = *b"PTYS";

#[cfg(target_os = "mochios")]
const PTY_IDENTIFY_MAGIC: [u8; 4] = *b"PTYI";

#[cfg(target_os = "mochios")]
const PTY_WAKE_MAGIC: [u8; 4] = *b"PTYW";

#[cfg(target_os = "mochios")]
fn main() {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use mochi_user_platform as platform;
    use mochios_filesystem_protocol as filesystem_protocol;
    use mochios_posix_protocol as protocol;
    use posix_service::{AttachedObject, PosixService};

    let _ = platform::logger::init_from_env();
    platform::logln!("posix.service: start");
    let Some(ready_target) = platform::service_ready::take_bootstrap_target() else {
        platform::logln!("posix.service: missing ready target");
        platform::process::exit(1);
    };
    let endpoint_handle = match platform::ipc::create_handle() {
        Ok(handle) => handle,
        Err(error) => {
            platform::logln!(
                "posix.service: endpoint handle creation failed errno={}",
                error.raw()
            );
            platform::process::exit(1);
        }
    };
    let ptys = Arc::new(Mutex::new(posix_service::pty::PtyManager::new()));
    let mut shared_memory_backend = match shared_memory_provider::start() {
        Ok(backend) => backend,
        Err(error) => {
            platform::logln!("posix.service: shared-memory provider startup failed errno={}", error);
            platform::process::exit(1);
        }
    };
    let service_state = Arc::new(Mutex::new(PosixService::new()));
    let socket_endpoint = match socket_native::start(Arc::clone(&service_state)) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            platform::logln!("posix.service: socket provider startup failed errno={}", error);
            platform::process::exit(1);
        }
    };
    let provider_endpoint_handle = match start_pty_provider(
        Arc::clone(&ptys),
        Arc::clone(&service_state),
        endpoint_handle,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            platform::logln!("posix.service: provider worker failed errno={}", error);
            platform::process::exit(1);
        }
    };
    let delegated_rights = platform::handle::HANDLE_RIGHT_SEND
        | platform::handle::HANDLE_RIGHT_DUPLICATE
        | platform::handle::HANDLE_RIGHT_TRANSFER;
    let service_process_id = match platform::process::current_execution_identity() {
        Ok(context) => context.process_id,
        Err(error) => {
            platform::logln!(
                "posix.service: current execution identity failed errno={}",
                error.raw()
            );
            platform::process::exit(1);
        }
    };

    let mut service = service_state.lock().unwrap();
    let bootstrap = platform::handle::inherited(protocol::BOOTSTRAP_PROCESS_HANDLE_KEY)
        .and_then(|handle| {
            let required =
                platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL;
            if platform::handle::rights(handle)? != required {
                return Err(platform::syscall::SysError::from_raw(-22));
            }
            platform::process::handle_status(handle).map(|status| (handle, status.process_id))
        });
    match bootstrap {
        Ok((handle, process_id)) => {
            // Userspace boot policy, never copied from kernel UID/GID fields.
            if let Err(error) = service.initialize_bootstrap_process(
                posix_service::AuthenticatedProcess { handle, process_id },
                0,
                0,
                &[],
            ) {
                platform::logln!("posix.service: bootstrap registration failed errno={error}");
                platform::process::exit(1);
            }
        }
        Err(error) => {
            platform::logln!(
                "posix.service: missing or invalid bootstrap process errno={}",
                error.raw()
            );
            platform::process::exit(1);
        }
    }
    let filesystem_endpoint =
        match platform::handle::inherited(filesystem_protocol::CONTROL_HANDLE_KEY) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                platform::logln!(
                    "posix.service: missing filesystem endpoint errno={}",
                    error.raw()
                );
                platform::process::exit(1);
            }
        };
    let mut filesystem = RuntimeFilesystem {
        endpoint: filesystem_endpoint,
    };
    let mut processes = RuntimeProcesses;
    if let Err(error) =
        platform::service_ready::notify_handle(ready_target, 0, endpoint_handle, delegated_rights)
    {
        platform::logln!(
            "posix.service: endpoint publication failed errno={}",
            error.raw()
        );
        platform::process::exit(1);
    }
    platform::logln!("posix.service: endpoint ready");
    drop(service);
    let mut pending_waits = Vec::new();
    let mut pending_signal_waits = Vec::new();
    let mut signal_threads = BTreeMap::new();
    // Native ThreadHandles are not yet wait-many targets. Observe their
    // lifecycle periodically, not by scanning every handle on every RPC.
    let mut thread_sweep_deadline_ms = 0;
    let mut cpu_sweep_deadline_ms = 0;
    let mut request_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let mut response_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    loop {
        let mut service = service_state.lock().unwrap();
        if let Err(error) = service.refresh_child_exit_notifications(&mut processes) {
            platform::logln!(
                "posix.service: child lifecycle refresh failed errno={}",
                error
            );
        }
        if let Err(error) = service.reap_abandoned_forks(&mut filesystem, &mut processes) {
            platform::logln!(
                "posix.service: abandoned fork cleanup failed errno={}",
                error
            );
        }
        if let Err(error) = service.reap_orphans(&mut filesystem, &mut processes) {
            platform::logln!("posix.service: orphan reap pending errno={}", error);
        }
        if let Err(error) = service.reap_discarded_children(&mut filesystem, &mut processes) {
            platform::logln!(
                "posix.service: discarded child reap pending errno={}",
                error
            );
        }
        let cpu_deadline = if service.has_finite_cpu_limits() {
            let now = match platform::time::monotonic_milliseconds() {
                Ok(now) => now,
                Err(error) => {
                    platform::logln!(
                        "posix.service: CPU budget clock failed errno={}",
                        error.raw()
                    );
                    platform::thread::yield_now();
                    continue;
                }
            };
            if now >= cpu_sweep_deadline_ms {
                if let Err(error) = service.enforce_cpu_limits(&mut processes) {
                    platform::logln!(
                        "posix.service: CPU budget observation failed errno={}",
                        error
                    );
                }
                cpu_sweep_deadline_ms =
                    now.saturating_add(posix_service::cpu_limit::SWEEP_INTERVAL_MS);
            }
            cpu_sweep_deadline_ms.saturating_mul(1_000_000)
        } else {
            cpu_sweep_deadline_ms = 0;
            platform::syscall::HANDLE_WAIT_INFINITE
        };
        deliver_process_resume_notifications(&mut service);
        complete_pending_signal_waits(&mut pending_signal_waits, &mut service);
        complete_pending_waits(
            &mut pending_waits,
            &mut service,
            &mut filesystem,
            &mut processes,
        );
        deliver_signal_notifications(&mut service, &mut signal_threads);
        let deadline = if signal_threads.is_empty() {
            platform::syscall::HANDLE_WAIT_INFINITE
        } else {
            let now = match platform::time::monotonic_milliseconds() {
                Ok(now) => now,
                Err(error) => {
                    platform::logln!(
                        "posix.service: thread lifecycle clock failed errno={}",
                        error.raw()
                    );
                    platform::thread::yield_now();
                    continue;
                }
            };
            if now >= thread_sweep_deadline_ms {
                reap_signal_threads(&mut service, &mut signal_threads);
                thread_sweep_deadline_ms = now.saturating_add(1_000);
            }
            if signal_threads.is_empty() {
                platform::syscall::HANDLE_WAIT_INFINITE
            } else {
                thread_sweep_deadline_ms.saturating_mul(1_000_000)
            }
        };
        let deadline = pending_signal_waits
            .iter()
            .filter_map(|wait: &PendingSignalWait| wait.deadline)
            .fold(deadline.min(cpu_deadline), u64::min);
        let lifecycle_handles = service.child_lifecycle_handles();
        drop(service);
        match wait_for_request_or_child(endpoint_handle, lifecycle_handles, deadline) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                platform::logln!("posix.service: lifecycle wait failed errno={}", error);
                platform::thread::yield_now();
                continue;
            }
        }
        let mut received_handles = platform::ipc::IpcObjectHandles::default();
        let message = match platform::ipc::wait_object_handles(
            endpoint_handle as u64,
            &mut request_bytes,
            &mut received_handles,
        ) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let attached_count = (received_handles.count as usize).min(received_handles.handles.len());
        let attachments_valid = attached_count == received_handles.count as usize
            && received_handles
                .handles
                .iter()
                .take(attached_count)
                .all(|attachment| attachment.handle != 0 && attachment.reserved == 0);
        let attachments: Vec<AttachedObject<u32>> = received_handles
            .handles
            .iter()
            .take(attached_count)
            .map(|attachment| AttachedObject {
                handle: attachment.handle,
                rights: attachment.rights,
            })
            .collect();
        let sender_process = platform::ipc::endpoint_owner_process(sender).ok();
        let peer = sender_process.and_then(|process_id| {
            let service = service_state.lock().ok()?;
            service.registered_peer(process_id)
        });
        let decoded = request_bytes
            .get(..length)
            .and_then(|bytes| protocol::decode(bytes).ok());
        // Do not hold POSIX state across provider RPC: concurrent terminal I/O
        // must be able to acquire that same state to authorize its caller.
        let identified_terminal = if attachments_valid
            && attachments.len() == 1
            && attachments[0].rights == platform::handle::HANDLE_RIGHT_TRANSFER
            && decoded.is_some_and(|(header, _)| matches!(
                header.opcode,
                protocol::OP_TERMINAL_ACQUIRE | protocol::OP_TERMINAL_RELEASE
                    | protocol::OP_TERMINAL_GET_FOREGROUND | protocol::OP_TERMINAL_SET_FOREGROUND
            ))
        {
            Some(identify_pty_terminal(
                provider_endpoint_handle,
                attachments[0].handle,
            ))
        } else {
            None
        };
        let opened_pty = if peer.is_some()
            && attachments_valid
            && attachments.is_empty()
            && decoded.is_some_and(|(header, payload)| {
                header.opcode == protocol::OP_PTY_OPEN && header.flags == 0 && payload.is_empty()
            })
        {
            Some(open_pty_response(
                &ptys,
                provider_endpoint_handle,
                decoded.unwrap().0.request_id,
            ))
        } else {
            None
        };
        let opened_socket = if let (Some(peer), Some((header, payload)), true) =
            (peer, decoded, attachments_valid)
        {
            if matches!(
                header.opcode,
                protocol::OP_SOCKET_CREATE
                    | protocol::OP_SOCKET_PAIR
                    | protocol::OP_SOCKET_ACCEPT
                    | protocol::OP_SOCKET_CONNECT
                    | protocol::OP_SOCKET_RECEIVE_WAIT
                    | protocol::OP_SOCKET_RECORD_ENDPOINT
            ) {
                let result = if header.flags != 0 || header.status != 0 {
                    Err(-22)
                } else if header.opcode == protocol::OP_SOCKET_RECORD_ENDPOINT {
                    if !attachments.is_empty() || !payload.is_empty() {
                        Err(-22)
                    } else {
                        socket_record_native::endpoint_reference(socket_endpoint)
                            .map(|handles| (handles, Vec::new()))
                    }
                } else if header.opcode == protocol::OP_SOCKET_RECEIVE_WAIT {
                    if attachments.len() != 1 || payload.len() != 8 {
                        Err(-22)
                    } else {
                        let mut handles = Vec::new();
                        match handles.try_reserve(1) {
                            Err(_) => Err(-12),
                            Ok(()) => socket_receive_wait_native::register(
                                socket_endpoint,
                                attachments[0],
                                u64::from_le_bytes(payload.try_into().unwrap()),
                            )
                            .map(|handle| {
                                handles.push(handle);
                                (handles, Vec::new())
                            }),
                        }
                    }
                } else if header.opcode == protocol::OP_SOCKET_CONNECT {
                    if attachments.len() != 1 {
                        Err(-22)
                    } else {
                        protocol::socket::Address::decode(payload)
                            .map_err(|_| -22)
                            .and_then(|address| {
                                socket_connect_native::connect(
                                    socket_endpoint,
                                    peer.process_id,
                                    attachments[0],
                                    address,
                                )
                            })
                    }
                } else if header.opcode == protocol::OP_SOCKET_ACCEPT {
                    if attachments.len() != 1 {
                        Err(-22)
                    } else {
                        protocol::socket::Accept::decode(payload)
                            .map_err(|_| -22)
                            .and_then(|request| {
                                let mut handles = Vec::new();
                                handles.try_reserve(1).map_err(|_| -12)?;
                                let (opened, address) = socket_accept_native::accept(
                                    socket_endpoint,
                                    peer.process_id,
                                    attachments[0],
                                    request,
                                )?;
                                handles.push(opened);
                                Ok((handles, address))
                            })
                    }
                } else if !attachments.is_empty() {
                    Err(-22)
                } else {
                    protocol::socket::Create::decode(payload)
                        .map_err(|_| -22)
                        .and_then(|create| {
                            socket_native::create(
                                socket_endpoint,
                                peer.process_id,
                                create,
                                header.opcode == protocol::OP_SOCKET_PAIR,
                            )
                        })
                        .map(|handles| (handles, Vec::new()))
                };
                Some(match result {
                    Ok((handles, payload)) => {
                        let mut response = status_response(header.request_id, 0);
                        response.header.payload_len = payload.len() as u32;
                        response.payload = payload;
                        posix_service::ObjectResponse { response, handles }
                    }
                    Err(error) => posix_service::ObjectResponse {
                        response: status_response(header.request_id, error),
                        handles: Vec::new(),
                    },
                })
            } else {
                None
            }
        } else {
            None
        };
        let mut service = service_state.lock().unwrap();
        if attachments_valid
            && attachments.is_empty()
            && sender_process == Some(service_process_id)
            && request_bytes.get(..length) == Some(&PTY_WAKE_MAGIC[..])
        {
            continue;
        }
        let mut retained_handle = None;
        let object_response = match (peer, decoded, attachments_valid) {
            (Some(_), Some((header, _)), true)
                if matches!(
                    header.opcode,
                    protocol::OP_SOCKET_CREATE
                        | protocol::OP_SOCKET_PAIR
                        | protocol::OP_SOCKET_ACCEPT
                        | protocol::OP_SOCKET_CONNECT
                        | protocol::OP_SOCKET_RECEIVE_WAIT
                        | protocol::OP_SOCKET_RECORD_ENDPOINT
                ) => {
                opened_socket
            }
            (Some(_peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_SHARED_MEMORY_BACKING =>
            {
                let result = if header.flags != 0 || header.status != 0
                    || payload.len() != 4 || attachments.len() != 1 {
                    Err(-22)
                } else {
                    match u32::from_le_bytes(payload.try_into().unwrap()) {
                        0 => shared_memory_provider::mapping(shared_memory_backend.endpoint, false, attachments[0]),
                        1 => shared_memory_provider::mapping(shared_memory_backend.endpoint, true, attachments[0]),
                        _ => Err(-22),
                    }
                };
                Some(match result {
                    Ok(opened) => posix_service::ObjectResponse {
                        response: status_response(header.request_id, 0), handles: vec![opened],
                    },
                    Err(error) => posix_service::ObjectResponse {
                        response: status_response(header.request_id, error), handles: Vec::new(),
                    },
                })
            }
            (Some(peer), Some((header, payload)), true)
                if matches!(header.opcode, protocol::OP_SHARED_MEMORY_OPEN | protocol::OP_SHARED_MEMORY_UNLINK) =>
            {
                Some(service.handle_shared_memory(peer, header, payload, &attachments,
                    &mut shared_memory_backend))
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_RESOURCE_POLICY =>
            {
                Some(service.handle_resource_policy(peer, header, payload, &attachments,
                    &mut resource_policy_native::NativeFactory))
            }
            (Some(peer), Some((header, payload)), true)
                if matches!(header.opcode, protocol::OP_SEMAPHORE_OPEN | protocol::OP_SEMAPHORE_UNLINK) =>
            {
                Some(service.handle_named_semaphore(peer, header, payload, &attachments,
                    &mut named_semaphore_native::NativeBacking))
            }
            (Some(peer), Some((header, payload)), true)
                if matches!(
                    header.opcode,
                    protocol::OP_SIGNAL_THREAD_MASK
                        | protocol::OP_SIGNAL_THREAD_DEQUEUE
                        | protocol::OP_SIGNAL_THREAD_PENDING
                        | protocol::OP_SIGNAL_THREAD_RAISE
                        | protocol::OP_SIGNAL_THREAD_FAULT
                        | protocol::OP_SIGNAL_DELIVERY_ORIGIN
                        | protocol::OP_SIGNAL_THREAD_EPOCH
                        | protocol::OP_SIGNAL_IMAGE_STARTED
                )
                    && attachments.is_empty() =>
            {
                let response = match platform::ipc::endpoint_execution_identity(sender) {
                    Ok(identity) => {
                        service.handle_thread_signal_request(peer, identity, header, payload)
                    }
                    Err(_) => invalid_response(header.request_id),
                };
                Some(posix_service::ObjectResponse {
                    response,
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_PTY_OPEN
                    && header.flags == 0
                    && payload.is_empty()
                    && attachments.is_empty() =>
            {
                Some(if service.session(peer.process_id).is_some() {
                    opened_pty.unwrap()
                } else {
                    posix_service::ObjectResponse {
                        response: invalid_response(header.request_id),
                        handles: Vec::new(),
                    }
                })
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_PROCESS_SESSION_INFO
                    && header.flags == 0
                    && payload.is_empty()
                    && attachments.len() == 1 =>
            {
                let response = match inspect_sender_process(&service, peer, attachments[0]) {
                    Ok(payload) => posix_service::Response {
                        header: protocol::Header {
                            opcode: protocol::OP_STATUS,
                            request_id: header.request_id,
                            payload_len: payload.len() as u32,
                            ..Default::default()
                        },
                        payload,
                    },
                    Err(status) => status_response(header.request_id, status),
                };
                Some(posix_service::ObjectResponse {
                    response,
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_PROCESS_INITIALIZE
                    && header.flags == 0
                    && attachments.len() == 1 =>
            {
                let status = initialize_sender_process(&mut service, peer, attachments[0], payload);
                if status.is_ok() {
                    retained_handle = Some(attachments[0].handle);
                }
                Some(posix_service::ObjectResponse {
                    response: match status {
                        Ok(()) => success_response(header.request_id),
                        Err(status) => status_response(header.request_id, status),
                    },
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_PROCESS_LAUNCHED
                    && header.flags == 0
                    && payload.is_empty()
                    && attachments.len() == 2 =>
            {
                let status = adopt_launched_child(
                    &mut service,
                    peer,
                    attachments[0],
                    attachments[1],
                    &mut filesystem,
                );
                if status.is_ok() {
                    retained_handle = Some(attachments[1].handle);
                }
                Some(posix_service::ObjectResponse {
                    response: match status {
                        Ok(()) => success_response(header.request_id),
                        Err(status) => status_response(header.request_id, status),
                    },
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if matches!(
                    header.opcode,
                    protocol::OP_PROCESS_TREE_TERMINATE | protocol::OP_PROCESS_TREE_RECLAIM
                ) && header.flags == 0
                    && payload.is_empty()
                    && attachments.len() == 1 =>
            {
                let status =
                    process_control::authenticated_tree_root(attachments[0]).and_then(|root| {
                        if header.opcode == protocol::OP_PROCESS_TREE_TERMINATE {
                            service.begin_launched_tree_termination(peer, root, &mut processes)
                        } else {
                            service.reclaim_launched_tree(
                                peer,
                                root,
                                &mut filesystem,
                                &mut processes,
                            )
                        }
                    });
                Some(posix_service::ObjectResponse {
                    response: match status {
                        Ok(()) => success_response(header.request_id),
                        Err(status) => status_response(header.request_id, status),
                    },
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_PROCESS_LAUNCH_ABORT
                    && header.flags == 0
                    && payload.is_empty()
                    && attachments.len() == 1 =>
            {
                let status = if attachments[0].rights != platform::handle::HANDLE_RIGHT_WAIT {
                    Err(posix_service::STATUS_EINVAL)
                } else {
                    platform::process::handle_status(attachments[0].handle)
                        .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5))
                        .and_then(|status| {
                            service.abort_launched_child(
                                peer,
                                posix_service::AuthenticatedProcess {
                                    handle: attachments[0].handle,
                                    process_id: status.process_id,
                                },
                                &mut filesystem,
                                &mut processes,
                            )
                        })
                };
                Some(posix_service::ObjectResponse {
                    response: match status {
                        Ok(()) => success_response(header.request_id),
                        Err(status) => status_response(header.request_id, status),
                    },
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if matches!(
                    header.opcode,
                    protocol::OP_TERMINAL_ACQUIRE
                        | protocol::OP_TERMINAL_RELEASE
                        | protocol::OP_TERMINAL_GET_FOREGROUND
                        | protocol::OP_TERMINAL_SET_FOREGROUND
                ) && attachments.len() == 1
                    && attachments[0].rights == platform::handle::HANDLE_RIGHT_TRANSFER =>
            {
                let response =
                    match identified_terminal.unwrap() {
                        Ok(terminal_id) => {
                            match platform::ipc::endpoint_execution_identity(sender) {
                                Ok(identity) => service.handle_terminal(
                                    peer, identity, header, payload, terminal_id,
                                ),
                                Err(_) => invalid_response(header.request_id),
                            }
                        }
                        Err(status) => status_response(header.request_id, status),
                    };
                Some(posix_service::ObjectResponse {
                    response,
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_SIGNAL_THREAD_SEND
                    && header.flags == 0
                    && attachments.len() == 1 =>
            {
                let attached = attachments[0];
                let required =
                    platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL;
                let result = if attached.rights & required != required {
                    Err(protocol::STATUS_EPERM)
                } else {
                    platform::ipc::endpoint_execution_identity(sender)
                        .map_err(|_| protocol::STATUS_EPERM)
                        .and_then(|identity| {
                            platform::thread::handle_status(attached.handle)
                                .map_err(|error| error.raw() as i32)
                                .and_then(|target| {
                                    service.send_thread_signal(peer, identity, target, attached.rights, payload)
                                })
                        })
                };
                Some(posix_service::ObjectResponse {
                    response: match result {
                        Ok(()) => success_response(header.request_id),
                        Err(error) => status_response(header.request_id, error),
                    },
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_SIGNAL_THREAD_REGISTER
                    && header.flags == 0
                    && payload.is_empty()
                    && attachments.len() == 1 =>
            {
                let thread = attachments[0];
                let status = platform::thread::handle_status(thread.handle).ok();
                // Inspect only the kernel-authenticated sender endpoint; never
                // import kernel credentials or reinterpret its number as a TID.
                let sender_context = platform::ipc::endpoint_execution_identity(sender)
                    .ok()
                    .filter(|context| context.process_id == peer.process_id);
                let registered_thread = sender_context.as_ref().zip(status.as_ref())
                    .filter(|(context, status)| {
                        posix_service::signal_thread_registration_matches(
                            context,
                            status,
                            thread.rights,
                        )
                    })
                    .map(|(context, _)| context.thread_id);
                if let Some(thread_id) = registered_thread {
                    if let Some(previous) = signal_threads.insert(
                        thread_id,
                        RegisteredSignalThread {
                            process_id: peer.process_id,
                            handle: thread.handle,
                        },
                    ) {
                        let _ = platform::handle::close(previous.handle);
                    }
                    retained_handle = Some(thread.handle);
                    Some(posix_service::ObjectResponse {
                        response: success_response(header.request_id),
                        handles: Vec::new(),
                    })
                } else {
                    Some(posix_service::ObjectResponse {
                        response: invalid_response(header.request_id),
                        handles: Vec::new(),
                    })
                }
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_PROCESS_STOPPED
                    && header.flags == 0
                    && attachments.is_empty() =>
            {
                let status = service
                    .report_process_stopped(peer, payload, &mut processes)
                    .map(|_| protocol::STATUS_OK)
                    .unwrap_or_else(|status| status);
                Some(posix_service::ObjectResponse {
                    response: status_response(header.request_id, status),
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if header.opcode == protocol::OP_PROCESS_SIGNALED
                    && header.flags == 0
                    && attachments.is_empty() =>
            {
                let status = service
                    .report_process_signaled(peer, payload, &mut processes)
                    .map(|_| protocol::STATUS_OK)
                    .unwrap_or_else(|status| status);
                Some(posix_service::ObjectResponse {
                    response: status_response(header.request_id, status),
                    handles: Vec::new(),
                })
            }
            (Some(peer), Some((header, payload)), true)
                if matches!(
                    header.opcode,
                    protocol::OP_SIGNAL_THREAD_WAIT_INFO | protocol::OP_SIGNAL_THREAD_TIMED_WAIT
                )
                    && header.flags == 0
                    && attachments.is_empty() =>
            {
                let parsed = if header.opcode == protocol::OP_SIGNAL_THREAD_TIMED_WAIT {
                    protocol::signal_wait::decode_timed_request(payload)
                        .map(|(mask, epoch, deadline)| (mask, epoch, Some(deadline)))
                } else {
                    protocol::decode_signal_wait_request(payload)
                        .map(|(mask, epoch)| (mask, epoch, None))
                }
                .map_err(|_| posix_service::STATUS_EINVAL)
                .and_then(|(mask, epoch, deadline)| {
                    let identity = platform::ipc::endpoint_execution_identity(sender)
                        .map_err(|_| protocol::STATUS_EPERM)?;
                    Ok((identity, mask, epoch, deadline))
                });
                let result = parsed.and_then(|(identity, mask, epoch, deadline)| {
                    // Bound deferred requests and disallow duplicates before
                    // consuming any signal, including malicious async sends.
                    if pending_signal_waits.len() >= 1024
                        || pending_signal_waits.iter().any(|wait: &PendingSignalWait| {
                            wait.identity == identity
                        })
                    {
                        return Err(protocol::STATUS_EAGAIN);
                    }
                    let now = if deadline.is_some() {
                        platform::time::monotonic_nanoseconds().map_err(|_| protocol::STATUS_EIO)?
                    } else {
                        0
                    };
                    match service.poll_wait_signal_info(peer, identity, mask, epoch, deadline, now) {
                        Ok(None) => {
                            pending_signal_waits.push(PendingSignalWait {
                                sender,
                                peer,
                                identity,
                                request_id: header.request_id,
                                mask,
                                epoch,
                                deadline,
                            });
                            Ok(None)
                        }
                        result => result,
                    }
                });
                match result {
                    Ok(None) => None,
                    result => Some(posix_service::ObjectResponse {
                        response: signal_wait_response(
                            header.request_id,
                            result.map(|signal| signal.unwrap()),
                        ),
                        handles: Vec::new(),
                    }),
                }
            }
            (Some(peer), Some((header, payload)), true)
                if matches!(
                    header.opcode,
                    protocol::OP_WAIT_CHILD | protocol::OP_WAIT_CHILD_GUARDED
                )
                    && header.flags == 0
                    && attachments.is_empty() =>
            {
                let parsed = if header.opcode == protocol::OP_WAIT_CHILD_GUARDED {
                    protocol::decode_guarded_wait_request(payload)
                        .map_err(|_| posix_service::STATUS_EINVAL)
                        .and_then(|(request, epoch)| {
                            let identity = platform::ipc::endpoint_execution_identity(sender)
                                .map_err(|_| posix_service::STATUS_EINVAL)?;
                            Ok((request, Some((identity, epoch))))
                        })
                } else {
                    protocol::decode_wait_request(payload)
                        .map(|request| (request, None))
                        .map_err(|_| posix_service::STATUS_EINVAL)
                };
                match parsed {
                    Ok((request, guard)) => {
                        let validated = match guard {
                            Some((identity, epoch)) => {
                                service.validate_wait_delivery_epoch(peer, identity, epoch)
                            }
                            None => Ok(()),
                        };
                        match validated.and_then(|()| {
                            service.wait_child(peer, request, &mut filesystem, &mut processes)
                        }) {
                            Err(protocol::STATUS_EAGAIN) => {
                                pending_waits.push(PendingWait {
                                    sender,
                                    peer,
                                    request_id: header.request_id,
                                    request,
                                    guard,
                                });
                                None
                            }
                            response => Some(posix_service::ObjectResponse {
                                response: wait_response(header.request_id, response),
                                handles: Vec::new(),
                            }),
                        }
                    }
                    Err(error) => Some(posix_service::ObjectResponse {
                        response: wait_response(header.request_id, Err(error)),
                        handles: Vec::new(),
                    }),
                }
            }
            (Some(peer), Some((header, payload)), true)
                if matches!(
                    header.opcode,
                    protocol::OP_PROCESS_SPAWNED | protocol::OP_FORK_COMMIT
                ) && header.flags == 0
                    && header.status == 0
                    && attachments.len() == 1 =>
            {
                match adopt_sender_child(
                    &mut service,
                    peer,
                    attachments[0],
                    (header.opcode == protocol::OP_PROCESS_SPAWNED).then_some(payload),
                    (header.opcode == protocol::OP_FORK_COMMIT).then_some(payload),
                    &mut filesystem,
                ) {
                    Ok(()) => {
                        retained_handle = Some(attachments[0].handle);
                        Some(posix_service::ObjectResponse {
                            response: success_response(header.request_id),
                            handles: Vec::new(),
                        })
                    }
                    Err(status) => {
                        let mut response = invalid_response(header.request_id);
                        response.header.status = status;
                        Some(posix_service::ObjectResponse {
                            response,
                            handles: Vec::new(),
                        })
                    }
                }
            }
            (Some(peer), Some((header, payload)), true) => {
                Some(service.handle_objects(peer, header, payload, &attachments, &mut filesystem))
            }
            (_, Some((header, _)), _) => Some(posix_service::ObjectResponse {
                response: invalid_response(header.request_id),
                handles: Vec::new(),
            }),
            _ => Some(posix_service::ObjectResponse {
                response: invalid_response(0),
                handles: Vec::new(),
            }),
        };
        for attachment in received_handles.handles.iter().take(attached_count) {
            if Some(attachment.handle) != retained_handle {
                let _ = platform::handle::close(attachment.handle);
            }
        }
        let Some(object_response) = object_response else {
            continue;
        };
        let prepared_fork = if decoded
            .is_some_and(|(header, _)| header.opcode == protocol::OP_FORK_PREPARE)
            && object_response.response.header.status == 0
        {
            peer.zip(protocol::fork::decode_token(&object_response.response.payload).ok())
        } else {
            None
        };
        let reply_queued = if let Ok(response_len) = protocol::encode(
            object_response.response.header,
            &object_response.response.payload,
            &mut response_bytes,
        ) {
            if object_response.handles.is_empty() {
                platform::ipc::reply(sender, &response_bytes[..response_len]).is_ok()
            } else {
                let mut outgoing = platform::ipc::IpcObjectHandles::default();
                outgoing.count = object_response.handles.len() as u32;
                for (slot, opened) in outgoing
                    .handles
                    .iter_mut()
                    .zip(object_response.handles.iter())
                {
                    *slot = platform::ipc::IpcObjectHandle {
                        handle: opened.handle,
                        reserved: 0,
                        rights: opened.rights,
                    };
                }
                platform::ipc::reply_object_handles(
                    sender,
                    &response_bytes[..response_len],
                    &outgoing,
                )
                .is_ok()
            }
        } else {
            false
        };
        // Enqueue success is not a client acknowledgment. Unacknowledged
        // preparations remain bounded and are also reclaimed on owner exit.
        if !reply_queued {
            if let Some((peer, token)) = prepared_fork {
                let _ = service.cancel_fork(peer, token, &mut filesystem);
            }
        }
        for opened in object_response.handles {
            let _ = platform::handle::close(opened.handle);
        }
    }
}

#[cfg(target_os = "mochios")]
fn start_pty_provider(
    ptys: std::sync::Arc<std::sync::Mutex<posix_service::pty::PtyManager>>,
    service: std::sync::Arc<std::sync::Mutex<posix_service::PosixService<u32>>>,
    control_endpoint: u32,
) -> Result<u32, i64> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use mochi_user_platform as platform;

    let startup = Arc::new(AtomicI64::new(0));
    let worker_startup = Arc::clone(&startup);
    std::thread::Builder::new()
        .name("posix-pty-provider".to_owned())
        .spawn(move || {
            let endpoint = match platform::ipc::create_handle() {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    worker_startup.store(error.raw(), Ordering::Release);
                    return;
                }
            };
            let identity = match platform::process::current_execution_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    worker_startup.store(error.raw(), Ordering::Release);
                    return;
                }
            };
            worker_startup.store(i64::from(endpoint), Ordering::Release);
            run_pty_provider(endpoint, control_endpoint, ptys, service, identity.process_id);
        })
        .map_err(|_| -5)?;
    loop {
        match startup.load(Ordering::Acquire) {
            0 => platform::thread::yield_now(),
            value if value < 0 => return Err(value),
            value => return u32::try_from(value).map_err(|_| -5),
        }
    }
}

#[cfg(target_os = "mochios")]
fn run_pty_provider(
    endpoint: u32,
    control_endpoint: u32,
    ptys: std::sync::Arc<std::sync::Mutex<posix_service::pty::PtyManager>>,
    service: std::sync::Arc<std::sync::Mutex<posix_service::PosixService<u32>>>,
    service_process_id: u64,
) -> ! {
    use mnu_abi::provider;
    use mochi_user_platform as platform;

    let mut request = vec![0u8; provider::REQUEST_HEADER_LEN + provider::MAX_DATA_LEN];
    let mut response = vec![0u8; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    loop {
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
        let length = (message & 0xffff_ffff) as usize;
        let request_length = length.min(request.len());
        let count = (attachments.count as usize).min(attachments.handles.len());
        if request[..request_length] == PTY_IDENTIFY_MAGIC {
            let status = if attachments.count == 1
                && count == 1
                && attachments.handles[0].handle != 0
                && attachments.handles[0].reserved == 0
            {
                platform::handle::identify_provider_object(attachments.handles[0].handle)
                    .map_err(|_| 9)
                    .and_then(|object_id| {
                        ptys.lock()
                            .map_err(|_| 5)
                            .and_then(|manager| manager.slave_terminal_id(object_id))
                    })
                    .and_then(|terminal_id| i64::try_from(terminal_id).map_err(|_| 22))
                    .unwrap_or_else(|errno| -(i64::from(errno)))
            } else {
                -22
            };
            for attachment in attachments.handles.iter().take(count) {
                let _ = platform::handle::close(attachment.handle);
            }
            let _ = platform::ipc::reply(sender, &status.to_le_bytes());
            continue;
        }
        for attachment in attachments.handles.iter().take(count) {
            let _ = platform::handle::close(attachment.handle);
        }
        if request[..request_length].starts_with(&PTY_SYNC_MAGIC) {
            let identity = platform::ipc::endpoint_execution_identity(sender).ok();
            let status = handle_pty_sync_request(
                &ptys,
                &request[..request_length],
                identity,
                service_process_id,
                attachments.count,
            );
            let _ = platform::ipc::reply(sender, &status.to_le_bytes());
            continue;
        }
        let decoded_provider = provider::RequestHeader::decode(&request[..request_length]).ok();
        if attachments.delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
            if let Some((header, _)) = decoded_provider {
                if let Ok(length) = (provider::ResponseHeader {
                    opcode: header.opcode,
                    object_id: header.object_id,
                    status: -13,
                    value: 0,
                    data_length: 0,
                })
                .encode(&[], &mut response)
                {
                    let _ = platform::ipc::reply(sender, &response[..length]);
                }
            }
            continue;
        }
        let access = decoded_provider.as_ref().and_then(|(header, _)| {
            ptys.lock().ok()?.job_control_access(*header)
        });
        let mut policy = if access.is_some() {
            service.lock().ok()
        } else {
            None
        };
        if let Some((terminal_id, reading, stop_write)) = access {
            let status = platform::ipc::endpoint_execution_identity(sender)
                .map_err(|_| -13)
                .and_then(|identity| {
                    policy.as_mut().ok_or(-5)?.authorize_terminal_io(
                        identity, terminal_id, reading, stop_write,
                    )
                });
            if let Err(status) = status {
                // The mutation and signal enqueue are serialized with all
                // session/group/mask changes. Wake the owner after unlocking;
                // never synchronously call it while it may identify a PTY.
                drop(policy);
                let _ = platform::ipc::send(u64::from(control_endpoint), &PTY_WAKE_MAGIC);
                if let Some((header, _)) = decoded_provider {
                    if let Ok(length) = (provider::ResponseHeader {
                        opcode: header.opcode,
                        object_id: header.object_id,
                        status: i64::from(status),
                        value: 0,
                        data_length: 0,
                    }).encode(&[], &mut response) {
                        let _ = platform::ipc::reply(sender, &response[..length]);
                    }
                }
                continue;
            }
        }
        let (response_len, signal_states, terminal_signals) = if let Ok(mut manager) = ptys.lock() {
            let object_ids = provider::RequestHeader::decode(&request[..request_length])
                .ok()
                .and_then(|(header, _)| manager.object_ids(header.object_id).ok());
            let response_len = posix_service::pty::handle_provider_request(
                &mut manager,
                &request[..request_length],
                &mut response,
            );
            let signal_states = object_ids
                .map(|ids| ids.map(|object_id| (object_id, manager.signals(object_id).ok())));
            let mut terminal_signals = Vec::new();
            while let Some(signal) = manager.take_terminal_signal() {
                terminal_signals.push(signal);
            }
            (response_len, signal_states, terminal_signals)
        } else {
            (None, None, Vec::new())
        };
        drop(policy);
        for signal in terminal_signals {
            let _ = notify_terminal_signal(&service, control_endpoint, signal);
        }
        if let Some(signal_states) = signal_states {
            for (object_id, signals) in signal_states {
                if let Some(signals) = signals {
                    let _ = platform::handle::signal_provider_object(
                        object_id,
                        signals,
                        posix_service::pty::READINESS_SIGNALS & !signals,
                    );
                }
            }
        }
        if let Some(response_len) = response_len {
            let _ = platform::ipc::reply(sender, &response[..response_len]);
        }
    }
}

#[cfg(target_os = "mochios")]
fn notify_terminal_signal(
    state: &std::sync::Mutex<posix_service::PosixService<u32>>,
    control_endpoint: u32,
    event: posix_service::pty::TerminalSignal,
) -> Result<(), i32> {
    use mochi_user_platform as platform;

    {
        // Events originate in the provider-owned PTY manager, never in an
        // external request's self-reported terminal ID or process identity.
        let mut service = state.lock().map_err(|_| -5)?;
        if event.signal == mochios_posix_protocol::SIGNAL_HUP {
            service.hangup_terminal(event.terminal_id)?;
        } else {
            service.signal_terminal_foreground_group(event.terminal_id, event.signal)?;
        }
    }
    platform::ipc::send(u64::from(control_endpoint), &PTY_WAKE_MAGIC)
        .map(|_| ())
        .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5))
}

#[cfg(target_os = "mochios")]
fn identify_pty_terminal(endpoint: u32, terminal: u32) -> Result<u64, i32> {
    use mochi_user_platform as platform;

    let mut attachments = platform::ipc::IpcObjectHandles::default();
    attachments.count = 1;
    attachments.handles[0] = platform::ipc::IpcObjectHandle {
        handle: terminal,
        reserved: 0,
        rights: platform::handle::HANDLE_RIGHT_TRANSFER,
    };
    let mut response = [0u8; 8];
    let message = platform::ipc::call_object_handles(
        endpoint,
        &PTY_IDENTIFY_MAGIC,
        &mut response,
        &mut attachments,
    )
    .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5))?;
    let returned_count = (attachments.count as usize).min(attachments.handles.len());
    for attachment in attachments.handles.iter().take(returned_count) {
        if attachment.handle != 0 {
            let _ = platform::handle::close(attachment.handle);
        }
    }
    if attachments.count != 0 || message & 0xffff_ffff != response.len() as u64 {
        return Err(-5);
    }
    let value = i64::from_le_bytes(response);
    if value <= 0 {
        return Err(i32::try_from(value).unwrap_or(-5));
    }
    u64::try_from(value).map_err(|_| -5)
}

#[cfg(target_os = "mochios")]
fn handle_pty_sync_request(
    ptys: &std::sync::Mutex<posix_service::pty::PtyManager>,
    request: &[u8],
    sender: Option<mnu_abi::ExecutionIdentity>,
    service_process_id: u64,
    attached_count: u32,
) -> i64 {
    use mochi_user_platform as platform;

    let pair = match posix_service::pty::authorize_sync_request(
        request,
        sender,
        service_process_id,
        attached_count,
    ) {
        Ok(pair) => pair,
        Err(error) => return -(i64::from(error)),
    };
    let master = pair.master_object_id;
    let slave = pair.slave_object_id;
    let manager = match ptys.lock() {
        Ok(manager) => manager,
        Err(_) => return -5,
    };
    if manager.object_ids(master) != Ok([master, slave]) {
        return -9;
    }
    for object_id in [master, slave] {
        let signals = match manager.signals(object_id) {
            Ok(signals) => signals,
            Err(errno) => return -(i64::from(errno)),
        };
        if let Err(error) = platform::handle::signal_provider_object(
            object_id,
            signals,
            posix_service::pty::READINESS_SIGNALS & !signals,
        ) {
            return error.raw();
        }
    }
    0
}

#[cfg(target_os = "mochios")]
fn sync_pty_provider(endpoint: u32, pair: posix_service::pty::PtyPair) -> Result<(), i32> {
    use mochi_user_platform as platform;

    let mut request = [0u8; 20];
    request[..4].copy_from_slice(&PTY_SYNC_MAGIC);
    request[4..12].copy_from_slice(&pair.master_object_id.to_le_bytes());
    request[12..20].copy_from_slice(&pair.slave_object_id.to_le_bytes());
    let mut response = [0u8; 8];
    let message = platform::ipc::call(u64::from(endpoint), &request, &mut response)
        .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5))?;
    if message & 0xffff_ffff != response.len() as u64 {
        return Err(-5);
    }
    let status = i64::from_le_bytes(response);
    if status == 0 {
        Ok(())
    } else {
        Err(i32::try_from(status).unwrap_or(-5))
    }
}

#[cfg(target_os = "mochios")]
fn open_pty_response(
    ptys: &std::sync::Mutex<posix_service::pty::PtyManager>,
    endpoint: u32,
    request_id: u64,
) -> posix_service::ObjectResponse<u32> {
    use mochi_user_platform as platform;

    let pair = match ptys.lock().unwrap().open() {
        Ok(pair) => pair,
        Err(status) => {
            return posix_service::ObjectResponse {
                response: status_response(request_id, -status),
                handles: Vec::new(),
            };
        }
    };
    let rights = platform::handle::HANDLE_RIGHT_READ
        | platform::handle::HANDLE_RIGHT_WRITE
        | platform::handle::HANDLE_RIGHT_WAIT
        | platform::handle::HANDLE_RIGHT_CONTROL
        | platform::handle::HANDLE_RIGHT_DUPLICATE
        | platform::handle::HANDLE_RIGHT_TRANSFER;
    let master =
        match platform::handle::create_provider_object(endpoint, pair.master_object_id, rights) {
            Ok(handle) => handle,
            Err(error) => {
                ptys.lock().unwrap().discard(pair);
                return posix_service::ObjectResponse {
                    response: status_response(request_id, i32::try_from(error.raw()).unwrap_or(-5)),
                    handles: Vec::new(),
                };
            }
        };
    let slave =
        match platform::handle::create_provider_object(endpoint, pair.slave_object_id, rights) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = platform::handle::close(master);
                ptys.lock().unwrap().discard(pair);
                return posix_service::ObjectResponse {
                    response: status_response(request_id, i32::try_from(error.raw()).unwrap_or(-5)),
                    handles: Vec::new(),
                };
            }
        };
    if let Err(status) = sync_pty_provider(endpoint, pair) {
        let _ = platform::handle::close(master);
        let _ = platform::handle::close(slave);
        ptys.lock().unwrap().discard(pair);
        return posix_service::ObjectResponse {
            response: status_response(request_id, status),
            handles: Vec::new(),
        };
    }
    posix_service::ObjectResponse {
        response: success_response(request_id),
        handles: vec![
            posix_service::OpenedObject {
                handle: master,
                rights,
            },
            posix_service::OpenedObject {
                handle: slave,
                rights,
            },
        ],
    }
}

#[cfg(target_os = "mochios")]
#[derive(Clone, Copy)]
struct RegisteredSignalThread {
    process_id: u64,
    handle: u32,
}

#[cfg(target_os = "mochios")]
fn signal_thread_terminated(
    service: &mut posix_service::PosixService<u32>,
    thread_id: u64,
    thread: RegisteredSignalThread,
) -> bool {
    use mochi_user_platform as platform;

    let status = platform::thread::handle_status(thread.handle)
        .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5));
    match service.retire_signal_thread(
        mnu_abi::ExecutionIdentity {
            process_id: thread.process_id,
            thread_id,
        },
        status,
    ) {
        Ok(terminated) => terminated,
        Err(error) => {
            platform::logln!("posix.service: thread lifecycle observation failed errno={error}");
            false
        }
    }
}

#[cfg(target_os = "mochios")]
fn reap_signal_threads(
    service: &mut posix_service::PosixService<u32>,
    threads: &mut std::collections::BTreeMap<u64, RegisteredSignalThread>,
) {
    threads.retain(|&thread_id, thread| {
        if signal_thread_terminated(service, thread_id, *thread) {
            !close_retired_signal_thread(thread_id, *thread)
        } else {
            true
        }
    });
}

#[cfg(target_os = "mochios")]
fn close_retired_signal_thread(thread_id: u64, thread: RegisteredSignalThread) -> bool {
    use mochi_user_platform as platform;

    if let Err(error) = platform::handle::close(thread.handle) {
        if error.raw() != -(platform::syscall::EBADF as i64) {
            platform::logln!(
                "posix.service: retired thread handle close failed errno={}",
                error.raw()
            );
            return false;
        }
    }
    let _ = platform::logger::write_status_fmt(format_args!(
        "posix.service: reclaimed signal thread pid={} tid={}\n",
        thread.process_id, thread_id
    ));
    true
}

#[cfg(target_os = "mochios")]
fn deliver_signal_notifications(
    service: &mut posix_service::PosixService<u32>,
    threads: &mut std::collections::BTreeMap<u64, RegisteredSignalThread>,
) {
    use mochi_user_platform as platform;

    let targets: Vec<_> = service.thread_signal_notification_threads().collect();
    for (process_id, thread_id) in targets {
        let Some(thread) = threads.get(&thread_id).copied() else {
            continue;
        };
        if thread.process_id != process_id {
            continue;
        }
        if platform::thread::interrupt(thread.handle, 0).is_ok() {
            service.acknowledge_thread_signal_notification(process_id, thread_id);
        } else if signal_thread_terminated(service, thread_id, thread)
            && close_retired_signal_thread(thread_id, thread)
        {
            threads.remove(&thread_id);
        }
    }

    let processes: Vec<u64> = service.signal_notification_processes().collect();
    for process_id in processes {
        let mut delivered = false;
        let mut stale = Vec::new();
        for (&thread_id, thread) in threads.iter() {
            if thread.process_id != process_id {
                continue;
            }
            match platform::thread::interrupt(thread.handle, 0) {
                Ok(()) => delivered = true,
                Err(_) if signal_thread_terminated(service, thread_id, *thread) => {
                    stale.push(thread_id)
                }
                Err(_) => {}
            }
        }
        for thread_id in stale {
            if let Some(thread) = threads.get(&thread_id).copied() {
                if close_retired_signal_thread(thread_id, thread) {
                    threads.remove(&thread_id);
                }
            }
        }
        if delivered {
            service.acknowledge_signal_notification(process_id);
        }
    }
}

#[cfg(target_os = "mochios")]
fn deliver_process_resume_notifications(service: &mut posix_service::PosixService<u32>) {
    use mochi_user_platform as platform;

    let processes: Vec<u64> = service.process_resume_notification_processes().collect();
    for process_id in processes {
        let Some(handle) = service.process_handle(process_id) else {
            service.acknowledge_process_resume_notification(process_id);
            continue;
        };
        if platform::process::resume_handle(handle).is_ok() {
            service.acknowledge_process_resume_notification(process_id);
        }
    }
}

#[cfg(target_os = "mochios")]
#[derive(Clone, Copy)]
struct PendingSignalWait {
    sender: u64,
    peer: posix_service::PeerIdentity,
    identity: mnu_abi::ExecutionIdentity,
    request_id: u64,
    mask: u64,
    epoch: u64,
    deadline: Option<u64>,
}

#[cfg(target_os = "mochios")]
fn complete_pending_signal_waits(
    pending: &mut Vec<PendingSignalWait>,
    service: &mut posix_service::PosixService<u32>,
) {
    use mochi_user_platform as platform;
    use mochios_posix_protocol as protocol;

    let mut index = 0;
    while index < pending.len() {
        let wait = pending[index];
        let result = if wait.deadline.is_some() {
            platform::time::monotonic_nanoseconds().map_err(|_| protocol::STATUS_EIO)
        } else {
            Ok(0)
        }
        .and_then(|now| {
            service.poll_wait_signal_info(
                wait.peer, wait.identity, wait.mask, wait.epoch, wait.deadline, now,
            )
        });
        let result = match result {
            Ok(None) => {
                index += 1;
                continue;
            }
            result => result.map(|accepted| accepted.unwrap()),
        };
        let response = signal_wait_response(wait.request_id, result);
        let mut bytes = vec![0; protocol::HEADER_LEN + protocol::signal_wait::LEN];
        if let Ok(length) = protocol::encode(response.header, &response.payload, &mut bytes) {
            let _ = platform::ipc::reply(wait.sender, &bytes[..length]);
        }
        pending.swap_remove(index);
    }
}

#[cfg(target_os = "mochios")]
fn signal_wait_response(
    request_id: u64,
    result: Result<mochios_posix_protocol::signal_wait::Accepted, i32>,
) -> posix_service::Response {
    use mochios_posix_protocol as protocol;
    match result {
        Ok(accepted) => {
            let mut payload = vec![0; protocol::signal_wait::LEN];
            if protocol::signal_wait::encode(accepted, &mut payload).is_err() {
                return status_response(request_id, protocol::STATUS_EIO);
            }
            posix_service::Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    request_id,
                    payload_len: payload.len() as u32,
                    ..Default::default()
                },
                payload,
            }
        }
        Err(error) => status_response(request_id, error),
    }
}

#[cfg(target_os = "mochios")]
#[derive(Clone, Copy)]
struct PendingWait {
    sender: u64,
    peer: posix_service::PeerIdentity,
    request_id: u64,
    request: mochios_posix_protocol::WaitRequest,
    guard: Option<(mnu_abi::ExecutionIdentity, u64)>,
}

#[cfg(target_os = "mochios")]
fn complete_pending_waits(
    pending: &mut Vec<PendingWait>,
    service: &mut posix_service::PosixService<u32>,
    filesystem: &mut RuntimeFilesystem,
    processes: &mut RuntimeProcesses,
) {
    use mochi_user_platform as platform;
    use mochios_posix_protocol as protocol;

    let mut index = 0;
    while index < pending.len() {
        let wait = pending[index];
        let validated = match wait.guard {
            Some((identity, epoch)) => {
                service.validate_wait_delivery_epoch(wait.peer, identity, epoch)
            }
            None => Ok(()),
        };
        let result = validated
            .and_then(|()| service.wait_child(wait.peer, wait.request, filesystem, processes));
        if result == Err(protocol::STATUS_EAGAIN) {
            index += 1;
            continue;
        }
        let response = wait_response(wait.request_id, result);
        let mut bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
        if let Ok(length) = protocol::encode(response.header, &response.payload, &mut bytes) {
            let _ = platform::ipc::reply(wait.sender, &bytes[..length]);
        }
        pending.swap_remove(index);
    }
}

#[cfg(target_os = "mochios")]
fn wait_for_request_or_child(
    endpoint: u32,
    lifecycle_handles: Vec<u32>,
    deadline: u64,
) -> Result<bool, i64> {
    use mochi_user_platform::{process, syscall};

    let mut items = Vec::new();
    items.push(syscall::HandleWaitItem {
        handle: endpoint,
        interests: syscall::HANDLE_SIGNAL_READABLE,
        ..syscall::HandleWaitItem::default()
    });
    for handle in lifecycle_handles {
        items.push(syscall::HandleWaitItem {
            handle,
            interests: syscall::HANDLE_SIGNAL_TERMINATED,
            ..syscall::HandleWaitItem::default()
        });
    }
    match process::wait_many(&mut items, deadline) {
        Ok(index) => Ok(index == 0),
        Err(error)
            if deadline != syscall::HANDLE_WAIT_INFINITE
                && error.raw() == -(syscall::EAGAIN as i64) =>
        {
            Ok(false)
        }
        Err(error) => Err(error.raw()),
    }
}

#[cfg(target_os = "mochios")]
fn initialize_sender_process(
    service: &mut posix_service::PosixService<u32>,
    peer: posix_service::PeerIdentity,
    process: posix_service::AttachedObject<u32>,
    payload: &[u8],
) -> Result<(), i32> {
    use mochi_user_platform as platform;
    let required = platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL;
    if process.rights != required {
        return Err(posix_service::STATUS_EINVAL);
    }
    let status = platform::process::handle_status(process.handle)
        .map_err(|error| error.errno().map_or(-5, |errno| -(errno as i32)))?;
    let mut groups = [0; mochios_posix_protocol::MAX_SUPPLEMENTARY_GROUPS];
    let (uid, gid, count) = mochios_posix_protocol::decode_spawn_credentials(payload, &mut groups)
        .map_err(|_| posix_service::STATUS_EINVAL)?;
    service.initialize_process(
        peer,
        posix_service::AuthenticatedProcess {
            handle: process.handle,
            process_id: status.process_id,
        },
        uid,
        gid,
        &groups[..count],
    )
}

#[cfg(target_os = "mochios")]
fn inspect_sender_process(
    service: &posix_service::PosixService<u32>,
    peer: posix_service::PeerIdentity,
    process: posix_service::AttachedObject<u32>,
) -> Result<Vec<u8>, i32> {
    use mochi_user_platform as platform;
    if process.rights != platform::handle::HANDLE_RIGHT_WAIT {
        return Err(posix_service::STATUS_EINVAL);
    }
    let status =
        platform::process::handle_status(process.handle).map_err(|error| error.raw() as i32)?;
    service.inspect_process_session(
        peer,
        posix_service::AuthenticatedProcess {
            handle: process.handle,
            process_id: status.process_id,
        },
    )
}

#[cfg(target_os = "mochios")]
fn adopt_sender_child(
    service: &mut posix_service::PosixService<u32>,
    peer: posix_service::PeerIdentity,
    process: posix_service::AttachedObject<u32>,
    credentials: Option<&[u8]>,
    preparation: Option<&[u8]>,
    filesystem: &mut RuntimeFilesystem,
) -> Result<(), i32> {
    use mochi_user_platform as platform;

    let required_rights =
        platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL;
    if process.rights != required_rights {
        return Err(posix_service::STATUS_EINVAL);
    }
    let status =
        platform::process::handle_status(process.handle).map_err(|error| error.raw() as i32)?;
    if let Some(preparation) = preparation {
        let token = mochios_posix_protocol::fork::decode_token(preparation)
            .map_err(|_| posix_service::STATUS_EINVAL)?;
        let child = posix_service::validate_fork_child(process, status)?;
        return service.commit_fork(peer, token, child);
    }
    let process = posix_service::AuthenticatedProcess {
        handle: process.handle,
        process_id: status.process_id,
    };
    if let Some(credentials) = credentials {
        let mut groups = [0; mochios_posix_protocol::MAX_SUPPLEMENTARY_GROUPS];
        let (uid, gid, count) =
            mochios_posix_protocol::decode_spawn_credentials(credentials, &mut groups)
                .map_err(|_| posix_service::STATUS_EINVAL)?;
        service.adopt_spawned_child(peer, process, uid, gid, &groups[..count], filesystem)
    } else {
        service.adopt_child(peer, process, filesystem)
    }
}

#[cfg(target_os = "mochios")]
fn adopt_launched_child(
    service: &mut posix_service::PosixService<u32>,
    peer: posix_service::PeerIdentity,
    requester: posix_service::AttachedObject<u32>,
    child: posix_service::AttachedObject<u32>,
    filesystem: &mut RuntimeFilesystem,
) -> Result<(), i32> {
    use mochi_user_platform as platform;
    if requester.rights != platform::handle::HANDLE_RIGHT_WAIT
        || child.rights
            != platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL
    {
        return Err(posix_service::STATUS_EINVAL);
    }
    let parent_status =
        platform::process::handle_status(requester.handle).map_err(|error| error.raw() as i32)?;
    let child_status =
        platform::process::handle_status(child.handle).map_err(|error| error.raw() as i32)?;
    if parent_status.state == platform::process::PROCESS_STATE_EXITED
        || child_status.state == platform::process::PROCESS_STATE_EXITED
    {
        return Err(mochios_posix_protocol::STATUS_ESRCH);
    }
    service.adopt_launched_child(
        peer,
        posix_service::AuthenticatedProcess {
            handle: requester.handle,
            process_id: parent_status.process_id,
        },
        posix_service::AuthenticatedProcess {
            handle: child.handle,
            process_id: child_status.process_id,
        },
        filesystem,
    )
}

#[cfg(target_os = "mochios")]
fn invalid_response(request_id: u64) -> posix_service::Response {
    status_response(request_id, posix_service::STATUS_EINVAL)
}

#[cfg(target_os = "mochios")]
fn status_response(request_id: u64, status: i32) -> posix_service::Response {
    posix_service::Response {
        header: mochios_posix_protocol::Header {
            opcode: mochios_posix_protocol::OP_STATUS,
            request_id,
            status,
            ..mochios_posix_protocol::Header::default()
        },
        payload: Vec::new(),
    }
}

#[cfg(target_os = "mochios")]
fn success_response(request_id: u64) -> posix_service::Response {
    posix_service::Response {
        header: mochios_posix_protocol::Header {
            opcode: mochios_posix_protocol::OP_STATUS,
            request_id,
            status: mochios_posix_protocol::STATUS_OK,
            ..mochios_posix_protocol::Header::default()
        },
        payload: Vec::new(),
    }
}

#[cfg(target_os = "mochios")]
fn wait_response(
    request_id: u64,
    result: Result<mochios_posix_protocol::WaitResult, i32>,
) -> posix_service::Response {
    use mochios_posix_protocol as protocol;

    match result {
        Ok(result) => {
            let mut payload = vec![0u8; protocol::WAIT_RESULT_LEN];
            if protocol::encode_wait_result(result, &mut payload).is_err() {
                return invalid_response(request_id);
            }
            posix_service::Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    request_id,
                    payload_len: payload.len() as u32,
                    status: protocol::STATUS_OK,
                    ..protocol::Header::default()
                },
                payload,
            }
        }
        Err(status) => posix_service::Response {
            header: protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id,
                status,
                ..protocol::Header::default()
            },
            payload: Vec::new(),
        },
    }
}

#[cfg(target_os = "mochios")]
struct RuntimeFilesystem {
    endpoint: mochi_user_platform::handle::Handle,
}

#[cfg(target_os = "mochios")]
struct RuntimeProcesses;

#[cfg(target_os = "mochios")]
impl posix_service::ProcessBackend<u32> for RuntimeProcesses {
    fn execution_usage(&mut self, process: u32) -> Result<mnu_abi::ProcessExecutionUsage, i32> {
        mochi_user_platform::process::execution_usage(Some(process))
            .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5))
    }

    fn status(&mut self, process: u32) -> Result<posix_service::ProcessLifecycle, i32> {
        use mochi_user_platform as platform;

        let status = platform::process::handle_status(process)
            .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5))?;
        if status.state == platform::syscall::PROCESS_STATE_EXITED {
            Ok(posix_service::ProcessLifecycle::Exited {
                exit_code: status.exit_code,
            })
        } else {
            Ok(posix_service::ProcessLifecycle::Running)
        }
    }

    fn suspend(&mut self, process: u32) -> Result<(), i32> {
        mochi_user_platform::process::suspend_handle(process)
            .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5))
    }

    fn terminate(&mut self, process: u32, exit_code: u64) -> Result<(), i32> {
        mochi_user_platform::process::terminate_handle(process, exit_code)
            .map_err(|error| i32::try_from(error.raw()).unwrap_or(-5))
    }

    fn release(&mut self, process: u32) {
        let _ = mochi_user_platform::handle::close(process);
    }
}

#[cfg(target_os = "mochios")]
type FilesystemMutationRequest = (
    mochios_filesystem_protocol::Header,
    Vec<u8>,
    mochi_user_platform::ipc::IpcObjectHandles,
);

#[cfg(target_os = "mochios")]
impl RuntimeFilesystem {
    fn open_request(
        &self,
        request: &posix_service::PreparedOpen,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<FilesystemMutationRequest, i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;

        let mut flags = filesystem::OPEN_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::OPEN_AT_BASE_ATTACHED;
        }
        for (source, target) in [
            (posix::OPEN_READ, filesystem::OPEN_AT_READ),
            (posix::OPEN_WRITE, filesystem::OPEN_AT_WRITE),
            (posix::OPEN_CREATE, filesystem::OPEN_AT_CREATE),
            (posix::OPEN_EXCLUSIVE, filesystem::OPEN_AT_EXCLUSIVE),
            (posix::OPEN_TRUNCATE, filesystem::OPEN_AT_TRUNCATE),
            (posix::OPEN_APPEND, filesystem::OPEN_AT_APPEND),
            (posix::OPEN_NONBLOCK, filesystem::OPEN_AT_NONBLOCK),
            (posix::OPEN_DIRECTORY, filesystem::OPEN_AT_DIRECTORY),
            (posix::OPEN_NOFOLLOW, filesystem::OPEN_AT_NOFOLLOW),
        ] {
            if request.options & source != 0 {
                flags |= target;
            }
        }
        let header = filesystem::Header {
            opcode: filesystem::OP_OPEN_AT,
            request_id: 1,
            flags,
            mode: request.mode,
            ..filesystem::Header::default()
        };
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        let header = filesystem::Header {
            length: payload.len() as u32,
            ..header
        };
        let handles = Self::path_handles(paths)?;
        Ok((header, payload, handles))
    }

    fn truncate_handle_request(
        &self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
        length: u64,
        growth_ceiling: u64,
    ) -> Result<FilesystemMutationRequest, i32> {
        use mochios_filesystem_protocol as filesystem;

        Ok((
            filesystem::Header {
                opcode: filesystem::OP_TRUNCATE_HANDLE,
                request_id: 6,
                offset: length,
                node_id: growth_ceiling,
                flags: filesystem::TRUNCATE_GROWTH_BOUNDED,
                ..filesystem::Header::default()
            },
            Vec::new(),
            file_handle_with_rights(file, mnu_abi::HANDLE_RIGHT_WRITE)?,
        ))
    }

    fn truncate_path_request(
        &self,
        request: &posix_service::PreparedTruncate,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<FilesystemMutationRequest, i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut flags = filesystem::TRUNCATE_AT_ROOT_ATTACHED | filesystem::TRUNCATE_GROWTH_BOUNDED;
        if paths.base.is_some() {
            flags |= filesystem::TRUNCATE_AT_BASE_ATTACHED;
        }
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        Ok((
            filesystem::Header {
                opcode: filesystem::OP_TRUNCATE_AT,
                request_id: 13,
                open_id: request.length,
                node_id: request.growth_ceiling,
                length: payload.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            payload,
            Self::path_handles(paths)?,
        ))
    }

    fn mutation_call(
        &self,
        (mut header, payload, mut handles): FilesystemMutationRequest,
        ticket: Option<posix_service::AttachedObject<u32>>,
        success_objects: usize,
    ) -> Result<Option<posix_service::OpenedObject<u32>>, posix_service::MutationError<u32>> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;
        use posix_service::{
            MutationError, OpenedObject,
            filesystem_transport::{MutationReply, mutation_status},
        };
        header.flags |= filesystem::MUTATION_ADMISSION;
        if let Some(ticket) = ticket {
            if ticket.handle == 0
                || ticket.rights != posix_service::mutation_admission::TICKET_RIGHTS
            {
                return Err(MutationError::Failed(-13));
            }
            let index = handles.count as usize;
            if index >= handles.handles.len() {
                return Err(MutationError::Failed(-22));
            }
            handles.handles[index] = platform::ipc::IpcObjectHandle {
                handle: ticket.handle,
                reserved: 0,
                rights: ticket.rights,
            };
            handles.count += 1;
            header.flags |= filesystem::MUTATION_ADMISSION_ATTACHED;
        }
        let mut request = vec![0; filesystem::HEADER_LEN + payload.len()];
        let length = filesystem::encode(header, &payload, &mut request).map_err(|_| -22)?;
        let mut reply = [0; filesystem::HEADER_LEN];
        if !self
            .call(&request[..length], &mut reply, &mut handles)
            .is_ok_and(|result| result as u32 as usize == filesystem::HEADER_LEN)
        {
            close_runtime_handles(&handles);
            return Err(MutationError::Failed(-5));
        }
        let result = filesystem::decode(&reply)
            .map_err(|_| -5)
            .and_then(|(response, payload)| {
                mutation_status(
                    response,
                    header.request_id,
                    payload,
                    &handles,
                    success_objects,
                )
            });
        match result {
            Ok(kind) => {
                let object = (handles.count == 1).then(|| OpenedObject {
                    handle: handles.handles[0].handle,
                    rights: handles.handles[0].rights,
                });
                // Returned references now belong to the response, not cleanup.
                match kind {
                    MutationReply::Ready => Ok(object),
                    MutationReply::Wait => Err(MutationError::Wait(object.ok_or(-5)?)),
                }
            }
            Err(status) => {
                close_runtime_handles(&handles);
                Err(MutationError::Failed(status))
            }
        }
    }

    fn call(
        &self,
        request: &[u8],
        reply: &mut [u8],
        handles: &mut mochi_user_platform::ipc::IpcObjectHandles,
    ) -> mochi_user_platform::syscall::SysResult<u64> {
        posix_service::filesystem_transport::call_native(handles, |exchanged| {
            mochi_user_platform::ipc::call_object_handles(self.endpoint, request, reply, exchanged)
        })
    }

    fn credential_payload(
        effective_uid: u32,
        effective_gid: u32,
        supplementary_groups: &[u32],
        payload: &[u8],
    ) -> Result<Vec<u8>, i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut encoded = vec![0u8; filesystem::CREDENTIALS_MAX_LEN + payload.len()];
        let length = filesystem::encode_credentials_payload(
            effective_uid,
            effective_gid,
            supplementary_groups,
            payload,
            &mut encoded,
        )
        .map_err(|_| -22)?;
        encoded.truncate(length);
        Ok(encoded)
    }

    fn flags_call(
        &self,
        header: mochios_filesystem_protocol::Header,
        mut handles: mochi_user_platform::ipc::IpcObjectHandles,
    ) -> Result<u32, i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut request = [0u8; filesystem::HEADER_LEN];
        let request_len = filesystem::encode(header, &[], &mut request).map_err(|_| -22)?;
        let mut response = [0u8; filesystem::HEADER_LEN];
        if self
            .call(&request[..request_len], &mut response, &mut handles)
            .is_err()
        {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let (response, payload) = match filesystem::decode(&response) {
            Ok(decoded) => decoded,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        if handles.count != 0
            || response.opcode != filesystem::OP_STATUS
            || !payload.is_empty()
            || response.status != 0
        {
            close_runtime_handles(&handles);
            return Err(if response.status < 0 {
                response.status
            } else {
                -5
            });
        }
        Ok(response.flags)
    }

    fn empty_call(
        &self,
        header: mochios_filesystem_protocol::Header,
        payload: &[u8],
        mut handles: mochi_user_platform::ipc::IpcObjectHandles,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut request = vec![0u8; filesystem::HEADER_LEN + payload.len()];
        let request_len = filesystem::encode(header, payload, &mut request).map_err(|_| -22)?;
        let mut response = [0u8; filesystem::HEADER_LEN];
        if !self
            .call(&request[..request_len], &mut response, &mut handles)
            .is_ok_and(|result| result as u32 as usize == filesystem::HEADER_LEN)
        {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let (response, payload) = match filesystem::decode(&response) {
            Ok(decoded) => decoded,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        let status = posix_service::filesystem_transport::metadata_status(
            response,
            header.request_id,
            payload,
            handles.count as usize,
            0,
        );
        close_runtime_handles(&handles);
        status?;
        Ok(())
    }

    fn payload_call(
        &self,
        header: mochios_filesystem_protocol::Header,
        payload: &[u8],
        mut handles: mochi_user_platform::ipc::IpcObjectHandles,
    ) -> Result<Vec<u8>, i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut request = vec![0u8; filesystem::HEADER_LEN + payload.len()];
        let request_len = filesystem::encode(header, payload, &mut request).map_err(|_| -22)?;
        let mut response = vec![0u8; filesystem::HEADER_LEN + filesystem::MAX_PATH_LEN];
        if self
            .call(&request[..request_len], &mut response, &mut handles)
            .is_err()
        {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let (response, payload) = match filesystem::decode(&response) {
            Ok(decoded) => decoded,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        if handles.count != 0 {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        if response.opcode != filesystem::OP_STATUS || response.status != 0 {
            return Err(if response.status < 0 {
                response.status
            } else {
                -5
            });
        }
        Ok(payload.to_vec())
    }

    fn status_call(
        &self,
        header: mochios_filesystem_protocol::Header,
        payload: &[u8],
        mut handles: mochi_user_platform::ipc::IpcObjectHandles,
    ) -> Result<mochios_filesystem_protocol::NodeStatus, i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut request = vec![0u8; filesystem::HEADER_LEN + payload.len()];
        let request_len = filesystem::encode(header, payload, &mut request).map_err(|_| -22)?;
        let mut response = vec![0u8; filesystem::HEADER_LEN + filesystem::NODE_STATUS_LEN];
        if self
            .call(&request[..request_len], &mut response, &mut handles)
            .is_err()
        {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let (response, payload) = match filesystem::decode(&response) {
            Ok(decoded) => decoded,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        if handles.count != 0 {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        if response.opcode != filesystem::OP_STATUS || response.status != 0 {
            return Err(if response.status < 0 {
                response.status
            } else {
                -5
            });
        }
        filesystem::decode_node_status(payload).map_err(|_| -5)
    }

    fn open_call(
        &self,
        header: mochios_filesystem_protocol::Header,
        path: &[u8],
        mut handles: mochi_user_platform::ipc::IpcObjectHandles,
    ) -> Result<posix_service::OpenedObject<mochi_user_platform::handle::Handle>, i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut request = vec![0u8; filesystem::HEADER_LEN + path.len()];
        let request_len = filesystem::encode(header, path, &mut request).map_err(|_| -22)?;
        let mut reply = vec![0u8; filesystem::HEADER_LEN];
        if !self
            .call(&request[..request_len], &mut reply, &mut handles)
            .is_ok_and(|result| result as u32 as usize == filesystem::HEADER_LEN)
        {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let (response, payload) = match filesystem::decode(&reply) {
            Ok(decoded) => decoded,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        if let Err(error) = posix_service::filesystem_transport::metadata_status(
            response,
            header.request_id,
            payload,
            handles.count as usize,
            1,
        ) {
            close_runtime_handles(&handles);
            return Err(error);
        }
        if handles.count != 1 || handles.handles[0].reserved != 0 {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let opened = handles.handles[0];
        Ok(posix_service::OpenedObject {
            handle: opened.handle,
            rights: opened.rights,
        })
    }

    fn path_handles(
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<mochi_user_platform::ipc::IpcObjectHandles, i32> {
        use mochi_user_platform as platform;

        let required =
            platform::handle::HANDLE_RIGHT_READ | platform::handle::HANDLE_RIGHT_TRANSFER;
        let mut handles = platform::ipc::IpcObjectHandles::default();
        for object in [Some(paths.root), paths.base].into_iter().flatten() {
            if object.rights & required != required {
                return Err(-13);
            }
            let index = handles.count as usize;
            handles.handles[index] = platform::ipc::IpcObjectHandle {
                handle: object.handle,
                reserved: 0,
                rights: required,
            };
            handles.count += 1;
        }
        Ok(handles)
    }

    fn rename_path_handles(
        paths: posix_service::RenamePathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<mochi_user_platform::ipc::IpcObjectHandles, i32> {
        use mochi_user_platform as platform;

        let required =
            platform::handle::HANDLE_RIGHT_READ | platform::handle::HANDLE_RIGHT_TRANSFER;
        let mut handles = platform::ipc::IpcObjectHandles::default();
        for object in [Some(paths.root), paths.old_base, paths.new_base]
            .into_iter()
            .flatten()
        {
            if object.rights & required != required {
                return Err(-13);
            }
            let index = handles.count as usize;
            handles.handles[index] = platform::ipc::IpcObjectHandle {
                handle: object.handle,
                reserved: 0,
                rights: required,
            };
            handles.count += 1;
        }
        Ok(handles)
    }
}

#[cfg(target_os = "mochios")]
fn single_file_handle(
    file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
) -> Result<mochi_user_platform::ipc::IpcObjectHandles, i32> {
    file_handle_with_rights(file, 0)
}

#[cfg(target_os = "mochios")]
fn file_handle_with_rights(
    file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    rights: u64,
) -> Result<mochi_user_platform::ipc::IpcObjectHandles, i32> {
    use mochi_user_platform as platform;
    let required = rights | platform::handle::HANDLE_RIGHT_TRANSFER;
    if file.rights & required != required {
        return Err(-13);
    }
    let mut handles = platform::ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0] = platform::ipc::IpcObjectHandle {
        handle: file.handle,
        reserved: 0,
        rights: required,
    };
    Ok(handles)
}

#[cfg(target_os = "mochios")]
fn controlled_file_handle(
    file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
) -> Result<mochi_user_platform::ipc::IpcObjectHandles, i32> {
    file_handle_with_rights(file, mnu_abi::HANDLE_RIGHT_CONTROL)
}

#[cfg(target_os = "mochios")]
impl posix_service::FilesystemBackend<mochi_user_platform::handle::Handle> for RuntimeFilesystem {
    fn open_session_root(
        &mut self,
        effective_uid: u32,
        effective_gid: u32,
        supplementary_groups: &[u32],
    ) -> Result<posix_service::SessionDirectories<mochi_user_platform::handle::Handle>, i32> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;

        let payload =
            Self::credential_payload(effective_uid, effective_gid, supplementary_groups, b"/")?;
        let open_root = || {
            self.open_call(
                filesystem::Header {
                    opcode: filesystem::OP_OPEN_AT,
                    request_id: 1,
                    length: payload.len() as u32,
                    flags: filesystem::OPEN_AT_SEARCH | filesystem::OPEN_AT_DIRECTORY,
                    ..filesystem::Header::default()
                },
                &payload,
                platform::ipc::IpcObjectHandles::default(),
            )
        };
        let root = open_root()?;
        let cwd = match open_root() {
            Ok(cwd) => cwd,
            Err(status) => {
                let _ = platform::handle::close(root.handle);
                return Err(status);
            }
        };
        Ok(posix_service::SessionDirectories {
            root: posix_service::AttachedObject {
                handle: root.handle,
                rights: root.rights,
            },
            cwd: posix_service::AttachedObject {
                handle: cwd.handle,
                rights: cwd.rights,
            },
        })
    }

    fn open_at(
        &mut self,
        request: &posix_service::PreparedOpen,
        paths: posix_service::PathObjects<u32>,
    ) -> Result<posix_service::OpenedObject<u32>, i32> {
        let (header, payload, handles) = self.open_request(request, paths)?;
        self.open_call(header, &payload, handles)
            .map_err(posix_service::mutation_filesystem_status)
    }

    fn open_at_admitted(
        &mut self,
        request: &posix_service::PreparedOpen,
        paths: posix_service::PathObjects<u32>,
        ticket: Option<posix_service::AttachedObject<u32>>,
    ) -> Result<posix_service::OpenedObject<u32>, posix_service::MutationError<u32>> {
        self.mutation_call(self.open_request(request, paths)?, ticket, 1)?
            .ok_or(posix_service::MutationError::Failed(-5))
    }

    fn open_directory_at(
        &mut self,
        request: &posix_service::PreparedStat,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<posix_service::OpenedObject<mochi_user_platform::handle::Handle>, i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut flags = filesystem::OPEN_AT_ROOT_ATTACHED
            | filesystem::OPEN_AT_DIRECTORY
            | filesystem::OPEN_AT_SEARCH;
        if paths.base.is_some() {
            flags |= filesystem::OPEN_AT_BASE_ATTACHED;
        }
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        self.open_call(
            filesystem::Header {
                opcode: filesystem::OP_OPEN_AT,
                request_id: 21,
                length: payload.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            &payload,
            Self::path_handles(paths)?,
        )
    }

    fn stat_at(
        &mut self,
        request: &posix_service::PreparedStat,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<mochios_posix_protocol::FileStatus, i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;
        let mut flags = filesystem::STAT_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::STAT_AT_BASE_ATTACHED;
        }
        if request.flags & posix::STAT_NOFOLLOW != 0 {
            flags |= filesystem::STAT_AT_NOFOLLOW;
        }
        let handles = Self::path_handles(paths)?;
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        let status = self.status_call(
            filesystem::Header {
                opcode: filesystem::OP_STAT_AT,
                request_id: 2,
                length: payload.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            &payload,
            handles,
        )?;
        filesystem_status_to_posix(status)
    }

    fn fstat(
        &mut self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) -> Result<mochios_posix_protocol::FileStatus, i32> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;

        if file.rights & platform::handle::HANDLE_RIGHT_TRANSFER == 0 {
            return Err(-13);
        }
        let mut handles = platform::ipc::IpcObjectHandles::default();
        handles.count = 1;
        handles.handles[0] = platform::ipc::IpcObjectHandle {
            handle: file.handle,
            reserved: 0,
            rights: platform::handle::HANDLE_RIGHT_TRANSFER,
        };
        let status = self.status_call(
            filesystem::Header {
                opcode: filesystem::OP_STAT_HANDLE,
                request_id: 3,
                ..filesystem::Header::default()
            },
            &[],
            handles,
        )?;
        filesystem_status_to_posix(status)
    }

    fn ftruncate(
        &mut self,
        file: posix_service::AttachedObject<u32>,
        length: u64,
        growth_ceiling: u64,
    ) -> Result<(), i32> {
        let (header, payload, handles) =
            self.truncate_handle_request(file, length, growth_ceiling)?;
        self.empty_call(header, &payload, handles)
            .map_err(posix_service::truncate_filesystem_status)
    }

    fn ftruncate_admitted(
        &mut self,
        file: posix_service::AttachedObject<u32>,
        length: u64,
        growth_ceiling: u64,
        ticket: Option<posix_service::AttachedObject<u32>>,
    ) -> Result<(), posix_service::MutationError<u32>> {
        self.mutation_call(
            self.truncate_handle_request(file, length, growth_ceiling)?,
            ticket,
            0,
        )
        .map(|_| ())
        .map_err(|error| error.map_status(posix_service::truncate_filesystem_status))
    }

    fn fchmod(
        &mut self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
        mode: u32,
        effective_uid: u32,
        effective_gid: u32,
        supplementary_groups: &[u32],
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;

        let payload =
            Self::credential_payload(effective_uid, effective_gid, supplementary_groups, &[])?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_CHMOD_HANDLE,
                request_id: 18,
                length: payload.len() as u32,
                mode,
                ..filesystem::Header::default()
            },
            &payload,
            controlled_file_handle(file)?,
        )
    }

    fn fchown(
        &mut self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
        uid: u32,
        gid: u32,
        effective_uid: u32,
        effective_gid: u32,
        supplementary_groups: &[u32],
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;

        let payload =
            Self::credential_payload(effective_uid, effective_gid, supplementary_groups, &[])?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_CHOWN_HANDLE,
                request_id: 19,
                node_id: u64::from(uid) | (u64::from(gid) << 32),
                length: payload.len() as u32,
                ..filesystem::Header::default()
            },
            &payload,
            controlled_file_handle(file)?,
        )
    }

    fn fsync(
        &mut self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;

        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_SYNC_HANDLE,
                request_id: 7,
                ..filesystem::Header::default()
            },
            &[],
            single_file_handle(file)?,
        )
    }

    fn get_status_flags(
        &mut self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) -> Result<u32, i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;

        let flags = self.flags_call(
            filesystem::Header {
                opcode: filesystem::OP_GET_FLAGS_HANDLE,
                request_id: 8,
                ..filesystem::Header::default()
            },
            single_file_handle(file)?,
        )?;
        let mut result = 0;
        if flags & filesystem::OPEN_STATUS_APPEND != 0 {
            result |= posix::OPEN_APPEND;
        }
        if flags & filesystem::OPEN_STATUS_NONBLOCK != 0 {
            result |= posix::OPEN_NONBLOCK;
        }
        Ok(result)
    }

    fn set_status_flags(
        &mut self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
        flags: u32,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;

        let mut filesystem_flags = 0;
        if flags & posix::OPEN_APPEND != 0 {
            filesystem_flags |= filesystem::OPEN_STATUS_APPEND;
        }
        if flags & posix::OPEN_NONBLOCK != 0 {
            filesystem_flags |= filesystem::OPEN_STATUS_NONBLOCK;
        }
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_SET_FLAGS_HANDLE,
                request_id: 9,
                flags: filesystem_flags,
                ..filesystem::Header::default()
            },
            &[],
            controlled_file_handle(file)?,
        )
    }

    fn update_status_flags(
        &mut self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
        mask: u32,
        flags: u32,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;
        let translate = |flags: u32| {
            (if flags & mochios_posix_protocol::OPEN_APPEND != 0 {
                filesystem::OPEN_STATUS_APPEND
            } else {
                0
            }) | (if flags & mochios_posix_protocol::OPEN_NONBLOCK != 0 {
                filesystem::OPEN_STATUS_NONBLOCK
            } else {
                0
            })
        };
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_UPDATE_FLAGS_HANDLE,
                request_id: 10,
                flags: translate(flags),
                length: 4,
                ..filesystem::Header::default()
            },
            &translate(mask).to_le_bytes(),
            controlled_file_handle(file)?,
        )
    }

    fn mkdir_at(
        &mut self,
        request: &posix_service::PreparedMkdir,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut flags = filesystem::MKDIR_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::MKDIR_AT_BASE_ATTACHED;
        }
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_MKDIR_AT,
                request_id: 10,
                length: payload.len() as u32,
                flags,
                mode: request.mode,
                ..filesystem::Header::default()
            },
            &payload,
            Self::path_handles(paths)?,
        )
    }

    fn unlink_at(
        &mut self,
        request: &posix_service::PreparedUnlink,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;

        let mut flags = filesystem::UNLINK_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::UNLINK_AT_BASE_ATTACHED;
        }
        if request.flags & posix::UNLINK_REMOVE_DIRECTORY != 0 {
            flags |= filesystem::UNLINK_AT_REMOVE_DIRECTORY;
        }
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_UNLINK_AT,
                request_id: 11,
                length: payload.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            &payload,
            Self::path_handles(paths)?,
        )
    }

    fn rename_at(
        &mut self,
        request: &posix_service::PreparedRename,
        paths: posix_service::RenamePathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut flags = filesystem::RENAME_AT_ROOT_ATTACHED;
        if paths.old_base.is_some() {
            flags |= filesystem::RENAME_AT_OLD_BASE_ATTACHED;
        }
        if paths.new_base.is_some() {
            flags |= filesystem::RENAME_AT_NEW_BASE_ATTACHED;
        }
        let old_length = u32::try_from(request.old_path.len()).map_err(|_| -22)?;
        let mut operation = Vec::with_capacity(request.old_path.len() + request.new_path.len());
        operation.extend_from_slice(request.old_path.as_bytes());
        operation.extend_from_slice(request.new_path.as_bytes());
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            &operation,
        )?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_RENAME_AT,
                request_id: 12,
                length: payload.len() as u32,
                flags,
                mode: old_length,
                ..filesystem::Header::default()
            },
            &payload,
            Self::rename_path_handles(paths)?,
        )
    }

    fn link_at(
        &mut self,
        request: &posix_service::PreparedLink,
        paths: posix_service::RenamePathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;

        let mut flags = filesystem::LINK_AT_ROOT_ATTACHED;
        if paths.old_base.is_some() {
            flags |= filesystem::LINK_AT_OLD_BASE_ATTACHED;
        }
        if paths.new_base.is_some() {
            flags |= filesystem::LINK_AT_NEW_BASE_ATTACHED;
        }
        if request.flags & posix::LINK_FOLLOW_SOURCE != 0 {
            flags |= filesystem::LINK_AT_FOLLOW_SOURCE;
        }
        let old_length = u32::try_from(request.old_path.len()).map_err(|_| -22)?;
        let mut operation = Vec::with_capacity(request.old_path.len() + request.new_path.len());
        operation.extend_from_slice(request.old_path.as_bytes());
        operation.extend_from_slice(request.new_path.as_bytes());
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            &operation,
        )?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_LINK_AT,
                request_id: 20,
                length: payload.len() as u32,
                flags,
                mode: old_length,
                ..filesystem::Header::default()
            },
            &payload,
            Self::rename_path_handles(paths)?,
        )
    }

    fn truncate_at(
        &mut self,
        request: &posix_service::PreparedTruncate,
        paths: posix_service::PathObjects<u32>,
    ) -> Result<(), i32> {
        let (header, payload, handles) = self.truncate_path_request(request, paths)?;
        self.empty_call(header, &payload, handles)
            .map_err(posix_service::truncate_filesystem_status)
    }

    fn truncate_at_admitted(
        &mut self,
        request: &posix_service::PreparedTruncate,
        paths: posix_service::PathObjects<u32>,
        ticket: Option<posix_service::AttachedObject<u32>>,
    ) -> Result<(), posix_service::MutationError<u32>> {
        self.mutation_call(self.truncate_path_request(request, paths)?, ticket, 0)
            .map(|_| ())
            .map_err(|error| error.map_status(posix_service::truncate_filesystem_status))
    }

    fn symlink_at(
        &mut self,
        request: &posix_service::PreparedSymlink,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut flags = filesystem::SYMLINK_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::SYMLINK_AT_BASE_ATTACHED;
        }
        let target_length = u32::try_from(request.target.len()).map_err(|_| -22)?;
        let mut operation = Vec::with_capacity(request.target.len() + request.link_path.len());
        operation.extend_from_slice(request.target.as_bytes());
        operation.extend_from_slice(request.link_path.as_bytes());
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            &operation,
        )?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_SYMLINK_AT,
                request_id: 14,
                length: payload.len() as u32,
                flags,
                mode: target_length,
                ..filesystem::Header::default()
            },
            &payload,
            Self::path_handles(paths)?,
        )
    }

    fn readlink_at(
        &mut self,
        request: &posix_service::PreparedReadlink,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<Vec<u8>, i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut flags = filesystem::READLINK_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::READLINK_AT_BASE_ATTACHED;
        }
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        self.payload_call(
            filesystem::Header {
                opcode: filesystem::OP_READLINK_AT,
                request_id: 15,
                length: payload.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            &payload,
            Self::path_handles(paths)?,
        )
    }

    fn chmod_at(
        &mut self,
        request: &posix_service::PreparedChmod,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;

        let mut flags = filesystem::CHMOD_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::CHMOD_AT_BASE_ATTACHED;
        }
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_CHMOD_AT,
                request_id: 16,
                length: payload.len() as u32,
                flags,
                mode: request.mode,
                ..filesystem::Header::default()
            },
            &payload,
            Self::path_handles(paths)?,
        )
    }

    fn chown_at(
        &mut self,
        request: &posix_service::PreparedChown,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;

        let mut flags = filesystem::CHOWN_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::CHOWN_AT_BASE_ATTACHED;
        }
        if request.flags & posix::CHOWN_NOFOLLOW != 0 {
            flags |= filesystem::CHOWN_AT_NOFOLLOW;
        }
        let payload = Self::credential_payload(
            request.effective_uid,
            request.effective_gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_CHOWN_AT,
                request_id: 17,
                node_id: u64::from(request.uid) | (u64::from(request.gid) << 32),
                length: payload.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            &payload,
            Self::path_handles(paths)?,
        )
    }

    fn access_at(
        &mut self,
        request: &posix_service::PreparedAccess,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;
        let mut flags = filesystem::ACCESS_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::ACCESS_AT_BASE_ATTACHED;
        }
        for (source, target) in [
            (posix::ACCESS_READ, filesystem::ACCESS_AT_READ),
            (posix::ACCESS_WRITE, filesystem::ACCESS_AT_WRITE),
            (posix::ACCESS_EXECUTE, filesystem::ACCESS_AT_EXECUTE),
        ] {
            if request.modes & source != 0 {
                flags |= target;
            }
        }
        if request.flags & posix::ACCESS_NOFOLLOW != 0 {
            flags |= filesystem::ACCESS_AT_NOFOLLOW;
        }
        let handles = Self::path_handles(paths)?;
        let payload = Self::credential_payload(
            request.uid,
            request.gid,
            &request.supplementary_groups,
            request.path.as_bytes(),
        )?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_ACCESS_AT,
                request_id: 4,
                length: payload.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            &payload,
            handles,
        )
    }

    fn retain_object(
        &mut self,
        object: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) -> Result<posix_service::AttachedObject<mochi_user_platform::handle::Handle>, i32> {
        use mochi_user_platform as platform;

        if object.rights & platform::handle::HANDLE_RIGHT_DUPLICATE == 0 {
            return Err(-13);
        }
        let handle = platform::handle::duplicate(object.handle, object.rights)
            .map_err(|error| -(i32::try_from(error.raw().unsigned_abs()).unwrap_or(i32::MAX)))?;
        Ok(posix_service::AttachedObject {
            handle,
            rights: object.rights,
        })
    }

    fn release_object(
        &mut self,
        object: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) {
        let _ = mochi_user_platform::handle::close(object.handle);
    }

    fn directory_path(
        &mut self,
        root: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
        directory: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) -> Result<Vec<u8>, i32> {
        use mochios_filesystem_protocol as filesystem;

        let header = filesystem::Header {
            opcode: filesystem::OP_PATH_HANDLE,
            request_id: 5,
            ..filesystem::Header::default()
        };
        let mut request = [0u8; filesystem::HEADER_LEN];
        let request_len = filesystem::encode(header, &[], &mut request).map_err(|_| -22)?;
        let mut response = vec![0u8; filesystem::MAX_MESSAGE_LEN];
        let mut handles = Self::path_handles(posix_service::PathObjects {
            root,
            base: Some(directory),
        })?;
        let received = match self.call(&request[..request_len], &mut response, &mut handles) {
            Ok(received) => received,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        close_runtime_handles(&handles);
        let length = (received & 0xffff_ffff) as usize;
        let bytes = response.get(..length).ok_or(-5)?;
        let (response, payload) = filesystem::decode(bytes).map_err(|_| -5)?;
        if response.opcode != filesystem::OP_STATUS || response.status != 0 {
            return Err(if response.status == 0 {
                -5
            } else {
                response.status
            });
        }
        Ok(payload.to_vec())
    }
}

#[cfg(target_os = "mochios")]
fn filesystem_status_to_posix(
    status: mochios_filesystem_protocol::NodeStatus,
) -> Result<mochios_posix_protocol::FileStatus, i32> {
    use mochios_filesystem_protocol as filesystem;

    let file_type = match status.kind {
        filesystem::NODE_TYPE_REGULAR => 0o100000,
        filesystem::NODE_TYPE_DIRECTORY => 0o040000,
        filesystem::NODE_TYPE_SYMLINK => 0o120000,
        filesystem::NODE_TYPE_SOCKET => 0o140000,
        filesystem::NODE_TYPE_SPECIAL => 0o020000,
        _ => return Err(-5),
    };
    Ok(mochios_posix_protocol::FileStatus {
        device: status.device,
        inode: status.node_id,
        mode: file_type | (status.mode & 0o7777),
        link_count: status.link_count,
        uid: status.uid,
        gid: status.gid,
        special_device: status.special_device,
        size: i64::try_from(status.size).map_err(|_| -75)?,
        block_size: i64::from(status.block_size),
        blocks: i64::try_from(status.blocks).map_err(|_| -75)?,
        access_time_seconds: i64::try_from(status.access_time_seconds).map_err(|_| -75)?,
        access_time_nanoseconds: i64::from(status.access_time_nanoseconds),
        modification_time_seconds: i64::try_from(status.modification_time_seconds)
            .map_err(|_| -75)?,
        modification_time_nanoseconds: i64::from(status.modification_time_nanoseconds),
        change_time_seconds: i64::try_from(status.change_time_seconds).map_err(|_| -75)?,
        change_time_nanoseconds: i64::from(status.change_time_nanoseconds),
    })
}

#[cfg(target_os = "mochios")]
fn close_runtime_handles(handles: &mochi_user_platform::ipc::IpcObjectHandles) {
    for handle in handles.handles.iter().take(handles.count as usize) {
        let _ = mochi_user_platform::handle::close(handle.handle);
    }
}

#[cfg(not(target_os = "mochios"))]
fn main() {}
