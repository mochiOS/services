//! Dedicated FIFO owner in posix.service. It retains one FS authority, accepts
//! admitted opens only from this service's authenticated native endpoints, and
//! handles native data, metadata and one-shot notification requests in order.
use mnu_abi::{IpcObjectHandle, IpcObjectHandles, provider};
use mochi_user_platform as platform;
use mochios_filesystem_protocol as fs;
use posix_service::{
    OpenedObject,
    fifo::Access,
    fifo_manager::{FilesystemScope, Manager},
    fifo_open_ipc as wire,
    fifo_wait::{Waits, is_notification},
    fifo_wait_ipc,
    filesystem_reference::Reference,
    pty_metadata_ipc,
};

fn status(error: platform::syscall::SysError) -> i32 {
    mochios_posix_protocol::status::normalize_failure(error.raw())
}
fn metadata_identity(handle: u32) -> Result<u64, i32> {
    platform::handle::identify_provider_object(handle)
        .map_err(|error| pty_metadata_ipc::identity_error(error.raw()))
}
fn close_objects(objects: &IpcObjectHandles) {
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
            let _ = platform::handle::close(object.handle);
        }
    }
}

struct Local(u32);
impl Drop for Local {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.0);
    }
}

pub struct Worker {
    endpoint: u32,
    thread: Option<std::thread::JoinHandle<()>>,
}
pub struct Registered {
    pub object: OpenedObject<u32>,
    pub ready: bool,
}

impl Worker {
    pub fn start(filesystem: u32) -> Result<Self, i32> {
        // Bind this owner's scope to an actually retained authority. Replacing
        // the FS endpoint requires a fresh worker/scope, never number reuse.
        let authority = Local(
            platform::handle::duplicate(
                filesystem,
                mnu_abi::HANDLE_RIGHT_SEND | mnu_abi::HANDLE_RIGHT_TRANSFER,
            )
            .map_err(status)?,
        );
        let (sender, receiver) = std::sync::mpsc::channel::<Result<u32, i32>>();
        let thread = std::thread::Builder::new()
            .name("posix-fifo-provider".into())
            .spawn(move || {
                let init = (|| {
                    let scope = FilesystemScope::new()?;
                    let process = platform::process::current_execution_identity()
                        .map_err(status)?
                        .process_id;
                    let endpoint = platform::ipc::create_handle().map_err(status)?;
                    Ok((endpoint, process, scope))
                })();
                match init {
                    Ok((endpoint, process, scope)) => {
                        let _authority = authority;
                        if sender.send(Ok(endpoint)).is_ok() {
                            run(endpoint, process, scope);
                        }
                        let _ = platform::handle::close(endpoint);
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                    }
                }
            })
            .map_err(|_| -5)?;
        let endpoint = receiver.recv().map_err(|_| -5)??;
        Ok(Self {
            endpoint,
            thread: Some(thread),
        })
    }

    pub fn endpoint(&self) -> u32 {
        self.endpoint
    }

    /// Consumes the original retained FS attachment on every path. Caller must
    /// have validated it against a successful call on this worker's FS authority.
    /// Success registers data; ready=false is NOT a completed blocking open.
    pub fn register(
        endpoint: u32,
        header: fs::Header,
        payload: &[u8],
        objects: IpcObjectHandles,
        access: Access,
        nonblocking: bool,
    ) -> Result<Registered, i32> {
        let result = (|| {
            if objects.delivery_flags != 0 {
                return Err(-5);
            }
            posix_service::fifo_inode::validate_reply(
                header,
                header.request_id,
                payload,
                &objects,
            )?;
            let request = wire::encode(header, payload, access, nonblocking)?;
            let mut received = objects;
            received.delivery_flags = 0;
            let mut response = [0; 8];
            let native =
                posix_service::filesystem_transport::call_native(&mut received, |native| {
                    platform::ipc::call_object_handles(endpoint, &request, &mut response, native)
                        .map_err(status)
                })?;
            let result = (|| {
                if native as u32 != 8 || received.delivery_flags != 0 {
                    return Err(-5);
                }
                let code = i32::from_le_bytes(response[..4].try_into().map_err(|_| -5)?);
                let ready = u32::from_le_bytes(response[4..].try_into().map_err(|_| -5)?);
                if code != 0 {
                    return Err(if code < 0 && received.count == 0 && ready == 0 {
                        code
                    } else {
                        -5
                    });
                }
                if ready > 1 || received.count != 1 {
                    return Err(-5);
                }
                let object = received.handles[0];
                if object.handle == 0
                    || object.reserved != 0
                    || object.rights != wire::data_rights(access)
                {
                    return Err(-5);
                }
                Ok(Registered {
                    object: OpenedObject {
                        handle: object.handle,
                        rights: object.rights,
                    },
                    ready: ready != 0,
                })
            })();
            if result.is_err() {
                close_objects(&received);
            }
            result
        })();
        close_objects(&objects);
        result
    }

    /// Orderly service shutdown only when no data or notification leases live.
    /// EBUSY leaves the worker and its authority available, without revocation.
    pub fn shutdown(&mut self) -> Result<(), i32> {
        let mut response = [0; 8];
        let mut objects = IpcObjectHandles::default();
        let native = posix_service::filesystem_transport::call_native(&mut objects, |objects| {
            platform::ipc::call_object_handles(self.endpoint, wire::STOP, &mut response, objects)
                .map_err(status)
        })?;
        close_objects(&objects);
        if native as u32 != 8 || objects.count != 0 || response[4..] != [0; 4] {
            return Err(-5);
        }
        let result = i32::from_le_bytes(response[..4].try_into().map_err(|_| -5)?);
        if result != 0 {
            return Err(result);
        }
        self.thread.take().ok_or(-9)?.join().map_err(|_| -5)?;
        Ok(())
    }
}

fn trusted(sender: u64, objects: &IpcObjectHandles, process: u64) -> bool {
    objects.delivery_flags == mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
        && platform::ipc::endpoint_owner_process(sender).ok() == Some(process)
}
fn signal(id: u64, signals: u64) -> Result<(), i32> {
    let mask = mnu_abi::HANDLE_SIGNAL_READABLE
        | mnu_abi::HANDLE_SIGNAL_WRITABLE
        | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
    match platform::handle::signal_provider_object(id, signals, mask & !signals) {
        Ok(()) => Ok(()),
        Err(error) if super::socket_native::notification_is_retired(error.raw()) => Ok(()),
        Err(error) => Err(status(error)),
    }
}
fn reply(sender: u64, code: i32, ready: bool) {
    let mut response = [0; 8];
    response[..4].copy_from_slice(&code.to_le_bytes());
    response[4..].copy_from_slice(&u32::from(ready).to_le_bytes());
    let _ = platform::ipc::reply(sender, &response);
}

/// Complete an admitted pathname open without keeping the dispatcher asleep.
/// Pending registrations return their data and notification as owned references.
pub fn open(
    endpoint: u32,
    header: fs::Header,
    payload: &[u8],
    objects: IpcObjectHandles,
    access: Access,
    nonblocking: bool,
    append: bool,
) -> Result<posix_service::OpenCompletion<u32>, i32> {
    let registered = Worker::register(endpoint, header, payload, objects, access, nonblocking)?;
    if append {
        let bytes =
            fs::description_flags::encode_update(fs::OPEN_STATUS_APPEND, fs::OPEN_STATUS_APPEND)
                .ok_or(-22)?;
        let update = platform::syscall::call6(
            mnu_abi::SyscallNumber::HandleControl,
            u64::from(registered.object.handle),
            fs::description_flags::UPDATE,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
        )
        .map_err(status);
        if update != Ok(0) {
            let _ = platform::handle::close(registered.object.handle);
            return Err(update.err().unwrap_or(-5));
        }
    }
    if registered.ready {
        return Ok(posix_service::OpenCompletion::Ready(registered.object));
    }
    let source = IpcObjectHandle {
        handle: registered.object.handle,
        reserved: 0,
        rights: registered.object.rights,
    };
    match fifo_wait_ipc::query(endpoint, source, posix_service::fifo::WaitCondition::Open) {
        Ok(notification) => Ok(posix_service::OpenCompletion::FifoPending {
            data: registered.object,
            notification,
        }),
        Err(error) => {
            let _ = platform::handle::close(registered.object.handle);
            Err(error)
        }
    }
}
fn run(endpoint: u32, process: u64, scope: FilesystemScope) {
    let mut manager = Manager::default();
    let mut waits = Waits::default();
    let mut request = vec![0; provider::REQUEST_HEADER_LEN + provider::MAX_DATA_LEN];
    let mut response = vec![0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    loop {
        let mut objects = IpcObjectHandles::default();
        let native = match platform::ipc::wait_object_handles(
            u64::from(endpoint),
            &mut request,
            &mut objects,
        ) {
            Ok(native) => native,
            Err(error) => {
                platform::logln!("posix.service: FIFO receive failed status={}", error.raw());
                return;
            }
        };
        let length = native as u32 as usize;
        let sender = native >> 32;
        let Some(bytes) = request.get(..length) else {
            close_objects(&objects);
            reply(sender, -22, false);
            continue;
        };
        if bytes == wire::STOP {
            let code = if !trusted(sender, &objects, process) {
                -13
            } else if objects.count != 0 {
                -22
            } else if !manager.is_empty() || !waits.is_empty() {
                -16
            } else {
                0
            };
            close_objects(&objects);
            reply(sender, code, false);
            if code == 0 {
                return;
            }
            continue;
        }
        if bytes.starts_with(wire::MAGIC) {
            let result = wire::admit_with(
                scope,
                trusted(sender, &objects, process),
                bytes,
                &mut objects,
                Reference::from_received,
            )
            .and_then(|(admitted, nonblocking)| {
                manager.open(
                    admitted,
                    nonblocking,
                    |id, rights, options| {
                        let handle = platform::handle::create_provider_object(endpoint, id, rights)
                            .map_err(status)?;
                        if let Err(error) = platform::syscall::call2(
                            mnu_abi::SyscallNumber::HandleOptionsSet,
                            u64::from(handle),
                            options,
                        ) {
                            let _ = platform::handle::close(handle);
                            return Err(status(error));
                        }
                        Ok(handle)
                    },
                    |handle| {
                        let _ = platform::handle::close(handle);
                    },
                )
            });
            close_objects(&objects);
            match result {
                Ok(opened) => {
                    let prepared = (|| {
                        manager.visit_signals(opened.channel, signal)?;
                        waits.pump(&manager, opened.channel, |id| {
                            signal(id, mnu_abi::HANDLE_SIGNAL_READABLE)
                        })?;
                        manager
                            .readiness(opened.object_id)
                            .map(|ready| ready.open_ready)
                    })();
                    match prepared {
                        Ok(ready) => {
                            let mut outgoing = IpcObjectHandles::default();
                            outgoing.count = 1;
                            outgoing.handles[0] = IpcObjectHandle {
                                handle: opened.handle,
                                reserved: 0,
                                rights: opened.rights,
                            };
                            let mut response = [0; 8];
                            response[4..].copy_from_slice(&u32::from(ready).to_le_bytes());
                            let _ =
                                platform::ipc::reply_object_handles(sender, &response, &outgoing);
                        }
                        Err(error) => reply(sender, error, false),
                    }
                    let _ = platform::handle::close(opened.handle);
                }
                Err(error) => reply(sender, error, false),
            }
            continue;
        }
        if bytes.starts_with(fifo_wait_ipc::MAGIC) {
            fifo_wait_ipc::serve(endpoint, &manager, &mut waits, sender, bytes, objects);
            continue;
        }
        if bytes.starts_with(&fs::device_metadata::MAGIC) {
            let result = pty_metadata_ipc::lookup_with(
                bytes,
                &objects,
                metadata_identity,
                |id, source, rights| {
                    manager
                        .duplicate_metadata(id, source, rights)
                        .map_err(|error| -error)
                },
            );
            pty_metadata_ipc::reply_metadata(sender, result, objects);
            continue;
        }
        let header = provider::RequestHeader::decode(bytes)
            .ok()
            .map(|(header, _)| header);
        let result = match header {
            Some(header) if is_notification(header.object_id) => waits
                .handle_provider_request(bytes, objects.delivery_flags, objects.count)
                .map(|_| None),
            Some(_) => manager
                .handle_provider_request(
                    bytes,
                    objects.delivery_flags,
                    objects.count,
                    &mut response,
                )
                .map(|dispatch| {
                    if let Some(key) = dispatch.changed {
                        // Queue changes have committed. A notification failure
                        // cannot replace the completed I/O result or lose progress.
                        if let Err(error) = manager.visit_signals(key, signal) {
                            platform::logln!(
                                "posix.service: FIFO readiness failed status={}",
                                error
                            );
                        }
                        if let Err(error) = waits.pump(&manager, key, |id| {
                            signal(id, mnu_abi::HANDLE_SIGNAL_READABLE)
                        }) {
                            platform::logln!(
                                "posix.service: FIFO notification failed status={}",
                                error
                            );
                        }
                    }
                    dispatch.reply_length
                }),
            None => Err(-22),
        };
        close_objects(&objects);
        match result {
            Ok(Some(length)) => {
                let _ = platform::ipc::reply(sender, &response[..length]);
            }
            Ok(None) => (),
            Err(error) => {
                // Native release is fire-and-forget. Endpoint requests always
                // receive an explicit error, never leave an IPC caller asleep.
                if objects.delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
                    if let Some(header) = header {
                        if header.opcode != provider::OP_RELEASE {
                            if let Ok(length) = (provider::ResponseHeader {
                                opcode: header.opcode,
                                object_id: header.object_id,
                                status: i64::from(error),
                                value: 0,
                                data_length: 0,
                            })
                            .encode(&[], &mut response)
                            {
                                let _ = platform::ipc::reply(sender, &response[..length]);
                            }
                        }
                    }
                    platform::logln!("posix.service: FIFO dispatch failed status={}", error);
                } else {
                    reply(sender, error, false);
                }
            }
        }
    }
}
