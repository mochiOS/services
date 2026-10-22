//! Slave names are filesystem policy, not kernel/provider object names.
//! A lease queues cleanup on final master release; it never makes FS RPC
//! while terminal state is locked or the FS worker awaits a slave factory.
use crate::{OpenedObject, PeerIdentity, pty::PtyManager};
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_SEND as S,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochi_user_platform as platform;
use mochios_filesystem_protocol as wire;
use std::sync::{Arc, Mutex, mpsc};

#[derive(Debug)]
pub struct Name {
    pub component: Vec<u8>,
    pub device: u64,
    pub node_id: u64,
}

#[derive(Debug)]
pub struct Lease {
    name: Option<Name>,
    retire: mpsc::Sender<Name>,
}
impl Lease {
    /// Only service-owned records obtained from successful registration belong
    /// here. This constructor is not reachable through a client wire request.
    pub fn new(name: Name, retire: mpsc::Sender<Name>) -> Self {
        Self {
            name: Some(name),
            retire,
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(name) = self.name.take()
            && self.retire.send(name).is_err()
        {
            platform::logln!("posix.service: terminal cleanup worker stopped");
        }
    }
}

/// Run only on the cleanup worker, never on the provider or under POSIX state.
/// Missing/replaced names are already retired. Other errors remain queued;
/// a failed name must not indefinitely prevent cleanup of other terminals.
pub fn retire(
    receiver: mpsc::Receiver<Name>,
    mut remove: impl FnMut(&Name) -> Result<(), i32>,
    mut report: impl FnMut(&Name, i32),
) {
    let mut pending = std::collections::VecDeque::new();
    loop {
        if pending.is_empty() {
            match receiver.recv() {
                Ok(name) => pending.push_back((name, false)),
                Err(_) => return,
            }
        }
        for name in receiver.try_iter().take(64) {
            pending.push_back((name, false));
        }
        // Examine the batch once. Failed entries go to the next round, not
        // straight back into this loop or a synchronous provider retry.
        for _ in 0..pending.len() {
            let (name, reported) = pending.pop_front().unwrap();
            match remove(&name) {
                Ok(()) | Err(-2) | Err(-116) => {}
                Err(error) => {
                    if !reported {
                        report(&name, error);
                    }
                    pending.push_back((name, true));
                }
            }
        }
        if !pending.is_empty() {
            // Back off even after channel disconnection, retaining cleanup
            // authority until the pending names can actually be retired.
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

/// Validate a metadata-only reply and reclaim unexpected *received* objects.
/// Request attachments remain borrowed even when native IPC fails.
pub fn status_with(
    header: wire::Header,
    payload: &[u8],
    mut objects: IpcObjectHandles,
    invoke: impl FnOnce(&[u8], &mut [u8], &mut IpcObjectHandles) -> Result<u64, i32>,
    mut close: impl FnMut(u32),
) -> Result<wire::NodeStatus, i32> {
    let mut request = vec![0; wire::HEADER_LEN + payload.len()];
    let length = wire::encode(header, payload, &mut request).map_err(|_| -22)?;
    let mut reply = vec![0; wire::HEADER_LEN + wire::NODE_STATUS_LEN];
    let delivered = crate::filesystem_transport::call_native(&mut objects, |exchange| {
        invoke(&request[..length], &mut reply, exchange)
    })?;
    let result = (|| {
        if objects.count != 0 || objects.delivery_flags != 0 {
            return Err(-5);
        }
        let (response, payload) =
            crate::filesystem_transport::reply_frame(&reply, delivered, header.request_id)?;
        if response.flags != 0 {
            return Err(-5);
        }
        if response.status != 0 {
            return Err(response.status);
        }
        if payload.len() != wire::NODE_STATUS_LEN {
            return Err(-5);
        }
        wire::decode_node_status(payload).map_err(|_| -5)
    })();
    for (index, object) in objects
        .handles
        .iter()
        .take(objects.count as usize)
        .enumerate()
    {
        if object.handle != 0
            && !objects.handles[..index]
                .iter()
                .any(|o| o.handle == object.handle)
        {
            close(object.handle);
        }
    }
    result
}

struct Connections {
    parent: u32,
    filesystem: u32,
    provider: u32,
}
impl Drop for Connections {
    fn drop(&mut self) {
        for handle in [self.parent, self.filesystem, self.provider] {
            if handle != 0 {
                let _ = platform::handle::close(handle);
            }
        }
    }
}
impl Connections {
    fn call(
        &self,
        opcode: u16,
        payload: &[u8],
        factory: Option<OpenedObject<u32>>,
    ) -> Result<wire::NodeStatus, i32> {
        let mut objects = IpcObjectHandles::default();
        objects.count = 1;
        objects.handles[0] = IpcObjectHandle {
            handle: self.parent,
            reserved: 0,
            rights: C | T,
        };
        if let Some(factory) = factory {
            objects.count = 3;
            objects.handles[1] = IpcObjectHandle {
                handle: self.provider,
                reserved: 0,
                rights: S,
            };
            objects.handles[2] = IpcObjectHandle {
                handle: factory.handle,
                reserved: 0,
                rights: T,
            };
        }
        status_with(
            wire::Header {
                opcode,
                request_id: 72,
                length: payload.len() as u32,
                ..Default::default()
            },
            payload,
            objects,
            |request, reply, objects| {
                platform::ipc::call_object_handles(self.filesystem, request, reply, objects)
                    .map_err(|error| mochios_posix_protocol::status::normalize_failure(error.raw()))
            },
            |handle| {
                let _ = platform::handle::close(handle);
            },
        )
    }
}

pub struct Publisher {
    connections: Arc<Connections>,
    retire: mpsc::Sender<Name>,
    process_id: u64,
}
impl Publisher {
    /// Own attenuated duplicates so the worker does not borrow caller-local
    /// references. The caller retains its original bootstrap authorities.
    pub fn start(
        parent: OpenedObject<u32>,
        filesystem: u32,
        provider: u32,
        process_id: u64,
    ) -> Result<Self, i32> {
        if parent.handle == 0 || parent.rights & (C | D | T) != C | D | T || process_id == 0 {
            return Err(-13);
        }
        let mut connections = Connections {
            parent: 0,
            filesystem: 0,
            provider: 0,
        };
        let duplicate = |handle, rights| {
            platform::handle::duplicate(handle, rights)
                .map_err(|error| mochios_posix_protocol::status::normalize_failure(error.raw()))
        };
        connections.parent = duplicate(parent.handle, C | T)?;
        connections.filesystem = duplicate(filesystem, S)?;
        connections.provider = duplicate(provider, S | T)?;
        let connections = Arc::new(connections);
        let worker = connections.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("posix-pty-cleanup".into())
            .spawn(move || {
                retire(
                    receiver,
                    |name| {
                        let mut payload =
                            vec![0; wire::device_removal::HEADER_LEN + name.component.len()];
                        let length = wire::device_removal::encode(
                            wire::device_removal::Request {
                                device: name.device,
                                node_id: name.node_id,
                                name: &name.component,
                            },
                            &mut payload,
                        )
                        .map_err(|_| -22)?;
                        worker
                            .call(
                                wire::OP_DEVICE_NODE_REMOVE_IF_SAME,
                                &payload[..length],
                                None,
                            )
                            .map(|_| ())
                    },
                    |name, error| {
                        platform::logln!(
                            "posix.service: terminal node cleanup failed inode={} errno={error}",
                            name.node_id
                        );
                    },
                );
            })
            .map_err(|_| -5)?;
        Ok(Self {
            connections,
            retire: sender,
            process_id,
        })
    }

    fn register(
        &self,
        master: u64,
        peer: PeerIdentity,
        factory: OpenedObject<u32>,
    ) -> Result<Lease, i32> {
        register_with(
            self.process_id,
            master,
            peer,
            self.retire.clone(),
            |payload| {
                self.connections.call(
                    wire::OP_DEVICE_NODE_REGISTER_EXTERNAL,
                    payload,
                    Some(factory),
                )
            },
        )
    }
}

/// Apply service-owned naming/ownership policy. `peer` is a snapshot of the
/// registered POSIX environment, not client-supplied request credentials.
pub fn register_with(
    process_id: u64,
    master: u64,
    peer: PeerIdentity,
    retire: mpsc::Sender<Name>,
    call: impl FnOnce(&[u8]) -> Result<wire::NodeStatus, i32>,
) -> Result<Lease, i32> {
    if process_id == 0 || master == 0 {
        return Err(-22);
    }
    // Process identity separates restarted providers; per-provider object
    // identity separates live masters. EEXIST never replaces another node.
    let component = format!("{process_id}-{master}").into_bytes();
    let mut payload = vec![0; wire::device_registration::HEADER_LEN + component.len()];
    let length = wire::device_registration::encode(
        wire::device_registration::Request {
            // No dedicated trusted tty group policy exists yet. Do not give
            // every member of the creator's primary group terminal injection
            // authority merely because that group is recorded as owner gid.
            mode: 0o600,
            uid: peer.effective_uid,
            gid: peer.effective_gid,
            special_device: master,
            name: &component,
        },
        &mut payload,
    )
    .map_err(|_| -22)?;
    let status = call(&payload[..length])?;
    if status.node_id == 0 || status.kind != wire::NODE_TYPE_SPECIAL {
        return Err(-5);
    }
    Ok(Lease::new(
        Name {
            component,
            device: status.device,
            node_id: status.node_id,
        },
        retire,
    ))
}

/// Only the service's just-created pair is accepted here, never client-supplied
/// inline IDs. No terminal lock is held across native publication or FS RPC.
pub fn publish_created_pair(
    manager: &Mutex<PtyManager>,
    endpoint: u32,
    pair: crate::pty::PtyPair,
    publisher: &Publisher,
    peer: PeerIdentity,
) -> Result<(), i32> {
    let object = manager
        .lock()
        .map_err(|_| -5)?
        .create_slave_factory(pair.master_object_id)
        .map_err(|error| -error)?;
    let factory = match platform::handle::create_provider_object(endpoint, object, D | T) {
        Ok(handle) => handle,
        Err(error) => {
            if let Ok(mut manager) = manager.lock() {
                let _ = manager.release(object);
            }
            return Err(mochios_posix_protocol::status::normalize_failure(
                error.raw(),
            ));
        }
    };
    let lease = publisher.register(
        pair.master_object_id,
        peer,
        OpenedObject {
            handle: factory,
            rights: D | T,
        },
    );
    // Registration installed its own references, or failed. Never retain an
    // extra factory lifetime locally, and never retire the FS-owned reference.
    let _ = platform::handle::close(factory);
    let lease = lease?;
    manager
        .lock()
        .map_err(|_| -5)?
        .attach_slave_name(pair.master_object_id, lease)
        .map_err(|error| -error)
}
