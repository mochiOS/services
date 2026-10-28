//! TCP factories and resources. Only native-authenticated object delivery or
//! explicit validated Handle attachments authorize operations after acquire.
use crate::stream::{Transport, Socket};
use alloc::vec::Vec;
use mnu_abi::provider;
use mochi_user_platform as platform;
use mochios_net_device_protocol::stream as wire;
const FACTORY_TAG: u64 = 4 << 60;
const RESOURCE_TAG: u64 = 6 << 60;
const TAG_MASK: u64 = 15 << 60;
const ID_LIMIT: u64 = 1 << 60;
const LIMIT: usize = 64;
const FACTORY_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
const RESOURCE_RIGHTS: u64 = FACTORY_RIGHTS
    | mnu_abi::HANDLE_RIGHT_READ
    | mnu_abi::HANDLE_RIGHT_WRITE
    | mnu_abi::HANDLE_RIGHT_WAIT;
const SIGNALS: u64 = mnu_abi::HANDLE_SIGNAL_READABLE
    | mnu_abi::HANDLE_SIGNAL_WRITABLE
    | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
struct Factory {
    id: u64,
    scopes: u32,
}
struct Resource {
    id: u64,
    socket: Socket,
    scopes: u32,
}
pub(crate) struct Server {
    endpoint: Option<u32>,
    next: u64,
    factories: Vec<Factory>,
    resources: Vec<Resource>,
}
impl Server {
    pub(crate) fn new(endpoint: Option<u32>) -> Self {
        Self {
            endpoint,
            next: 1,
            factories: Vec::new(),
            resources: Vec::new(),
        }
    }
    fn id(&mut self, tag: u64) -> Result<u64, i32> {
        if self.next >= ID_LIMIT {
            return Err(-24);
        }
        let id = tag | self.next;
        self.next += 1;
        Ok(id)
    }
    fn attached(&self, handles: &platform::ipc::IpcObjectHandles) -> Result<u64, i32> {
        if handles.count != 1
            || !matches!(
                handles.delivery_flags,
                0 | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
            )
        {
            return Err(-13);
        }
        let h = handles.handles[0];
        if h.handle == 0 || h.reserved != 0 || h.rights != mnu_abi::HANDLE_RIGHT_CONTROL {
            return Err(-13);
        }
        platform::handle::identify_provider_object(h.handle).map_err(|_| -13)
    }
    fn factory_scope(&self, handles: &platform::ipc::IpcObjectHandles) -> Result<u32, i32> {
        let id = self.attached(handles)?;
        self.factories
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.scopes)
            .ok_or(-13)
    }
    fn issue_factory(&mut self, scopes: u32) -> Result<(u64, u32), i32> {
        if self.factories.len() >= LIMIT {
            return Err(-24);
        }
        self.factories.try_reserve(1).map_err(|_| -12)?;
        let id = self.id(FACTORY_TAG)?;
        let h =
            platform::handle::create_provider_object(self.endpoint.ok_or(-5)?, id, FACTORY_RIGHTS)
                .map_err(|_| -5)?;
        self.factories.push(Factory { id, scopes });
        Ok((id, h))
    }
    fn issue_resource(
        &mut self,
        source: Option<u64>,
        scopes: u32,
        now: u64,
        backend: &mut Transport,
    ) -> Result<(u64, u32), i32> {
        if self.resources.len() >= LIMIT {
            return Err(-24);
        }
        self.resources.try_reserve(1).map_err(|_| -12)?;
        let id = self.id(RESOURCE_TAG)?;
        // Allocate the native reference before consuming a queued accept.
        let h = platform::handle::create_provider_object(self.endpoint.ok_or(-5)?, id, RESOURCE_RIGHTS)
            .map_err(|_| -5)?;
        let opened = match source {
            None => backend.open(),
            Some(listener) => {
                let r = self.resources.iter().find(|r| r.id == listener).ok_or(-13);
                match r {
                    Ok(r) => backend.accept(r.socket),
                    Err(e) => Err(e),
                }
            }
        };
        let socket = match opened {
            Ok(s) => s,
            Err(e) => {
                let _ = platform::handle::close(h);
                return Err(e);
            }
        };
        if platform::handle::signal_provider_object(id, 0, SIGNALS).is_err() {
            backend.release(socket, now);
            let _ = platform::handle::close(h);
            return Err(-5);
        }
        self.resources.push(Resource { id, socket, scopes });
        Ok((id, h))
    }
    fn remove(&mut self, id: u64, now: u64, backend: &mut Transport) {
        self.factories.retain(|f| f.id != id);
        if let Some(i) = self.resources.iter().position(|r| r.id == id) {
            backend.release(self.resources.swap_remove(i).socket, now);
        }
    }
    pub(crate) fn pump(&mut self, now: u64, backend: &mut Transport) {
        backend.advance(now, || platform::service_ready::generate_token().ok());
        for r in &self.resources {
            let set = match backend.status(r.socket) {
                Ok(s) => {
                    let mut set = 0;
                    if s.readable {
                        set |= mnu_abi::HANDLE_SIGNAL_READABLE;
                    }
                    if s.writable {
                        set |= mnu_abi::HANDLE_SIGNAL_WRITABLE;
                    }
                    if s.peer_closed {
                        set |= mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
                    }
                    set
                }
                Err(_) => SIGNALS,
            };
            let _ = platform::handle::signal_provider_object(r.id, set, SIGNALS & !set);
        }
    }
    pub(crate) fn dispatch(
        &mut self,
        sender: u64,
        bytes: &[u8],
        handles: &platform::ipc::IpcObjectHandles,
        now: u64,
        backend: &mut Transport,
    ) -> bool {
        if bytes.starts_with(b"NTCP") {
            let op = bytes
                .get(6..8)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .unwrap_or(0);
            let result = (|| {
                let op = wire::operation(bytes).map_err(|_| -22)?;
                match op {
                    wire::ACQUIRE => {
                        let scopes = wire::scopes(bytes).map_err(|_| -22)?;
                        if handles.count != 0
                            || !matches!(
                                handles.delivery_flags,
                                0 | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
                            )
                        {
                            return Err(-13);
                        }
                        for (bit, name) in [
                            (wire::CONNECT_SCOPE, "net.connect"),
                            (wire::LISTEN_SCOPE, "net.listen"),
                        ] {
                            if scopes & bit != 0
                                && platform::capability::check_thread(sender, name) != Ok(1)
                            {
                                return Err(-13);
                            }
                        }
                        self.issue_factory(scopes).map(Some)
                    }
                    wire::DERIVE => {
                        let requested = wire::scopes(bytes).map_err(|_| -22)?;
                        let source = self.factory_scope(handles)?;
                        if requested & source != requested {
                            return Err(-13);
                        }
                        self.issue_factory(requested).map(Some)
                    }
                    wire::VALIDATE if bytes.len() == 8 => {
                        self.factory_scope(handles)?;
                        Ok(None)
                    }
                    wire::OPEN if bytes.len() == 8 => {
                        let scopes = self.factory_scope(handles)?;
                        self.issue_resource(None, scopes, now, backend).map(Some)
                    }
                    wire::ACCEPT if bytes.len() == 8 => {
                        let id = self.attached(handles)?;
                        if !self
                            .resources
                            .iter()
                            .any(|r| r.id == id && r.scopes & wire::LISTEN_SCOPE != 0)
                        {
                            return Err(-13);
                        }
                        self.issue_resource(Some(id), 0, now, backend).map(Some)
                    }
                    wire::VALIDATE | wire::OPEN | wire::ACCEPT => Err(-22),
                    _ => Err(-38),
                }
            })();
            let mut response = [0; wire::REPLY_LEN];
            match result {
                Ok(Some((id, h))) => {
                    wire::reply(op, 0, &mut response).unwrap();
                    let mut attached = platform::ipc::IpcObjectHandles::default();
                    attached.count = 1;
                    attached.handles[0] = platform::ipc::IpcObjectHandle {
                        handle: h,
                        reserved: 0,
                        rights: if id & TAG_MASK == FACTORY_TAG {
                            FACTORY_RIGHTS
                        } else {
                            RESOURCE_RIGHTS
                        },
                    };
                    self.pump(now, backend);
                    if platform::ipc::reply_object_handles(sender, &response, &attached).is_err() {
                        self.remove(id, now, backend);
                    }
                    let _ = platform::handle::close(h);
                }
                outcome => {
                    wire::reply(op, outcome.err().unwrap_or(0), &mut response).unwrap();
                    let _ = platform::ipc::reply(sender, &response);
                }
            }
            return true;
        }
        let Ok((header, input)) = provider::RequestHeader::decode(bytes) else {
            return false;
        };
        if !matches!(header.object_id & TAG_MASK, FACTORY_TAG | RESOURCE_TAG) {
            return false;
        }
        let native =
            handles.count == 0 && handles.delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
        if native && header.opcode == provider::OP_RELEASE {
            self.remove(header.object_id, now, backend);
            return true;
        }
        let mut data = [0; provider::MAX_DATA_LEN];
        let result = (|| {
            if !native {
                return Err(-13);
            }
            if header.object_id & TAG_MASK == FACTORY_TAG {
                let f = self
                    .factories
                    .iter()
                    .find(|f| f.id == header.object_id)
                    .ok_or(-9)?;
                if header.opcode != provider::OP_CONTROL || header.basis != wire::QUERY_LIMITS {
                    return Err(-95);
                }
                if !input.is_empty() || header.length != wire::LIMITS_LEN as u32 {
                    return Err(-22);
                }
                let n = wire::Limits {
                    scopes: f.scopes,
                    minimum_port: 1024,
                    routes: wire::ROUTE_LOOPBACK
                        | if backend.has_interface() {
                            wire::ROUTE_INTERFACE
                        } else {
                            0
                        },
                }
                .encode(&mut data)
                .map_err(|_| -5)?;
                return Ok((n as u64, n));
            }
            let r = self
                .resources
                .iter()
                .find(|r| r.id == header.object_id)
                .ok_or(-9)?;
            let socket = r.socket;
            match header.opcode {
                provider::OP_MEMORY_OBJECT => Ok((0, 0)),
                provider::OP_READ | provider::OP_READ_AT => {
                    if header.basis != 0 {
                        return Err(-22);
                    }
                    backend
                        .receive(
                            socket,
                            header.opcode == provider::OP_READ_AT,
                            data.get_mut(..header.length as usize).ok_or(-22)?,
                        )
                        .map(|n| (n as u64, n))
                }
                provider::OP_WRITE => backend.send(socket, input).map(|n| (n as u64, 0)),
                provider::OP_QUERY => {
                    if !input.is_empty() {
                        return Err(-22);
                    }
                    match header.basis {
                        wire::LOCAL | wire::PEER if header.length == wire::ENDPOINT_LEN as u32 => {
                            let e = if header.basis == wire::LOCAL {
                                backend.local(socket)?
                            } else {
                                backend.peer(socket)?
                            };
                            let n = e.encode(&mut data).map_err(|_| -5)?;
                            Ok((n as u64, n))
                        }
                        wire::STATUS if header.length == wire::STATUS_LEN as u32 => {
                            let s = backend.status(socket)?;
                            let flags = u32::from(s.readable) * wire::READABLE
                                | u32::from(s.writable) * wire::WRITABLE
                                | u32::from(s.peer_closed) * wire::PEER_CLOSED
                                | u32::from(s.connecting) * wire::CONNECTING;
                            let n = wire::Observation {
                                flags,
                                error: s.error,
                            }
                            .encode(&mut data)
                            .map_err(|_| -5)?;
                            Ok((n as u64, n))
                        }
                        _ => Err(-95),
                    }
                }
                provider::OP_CONTROL => match header.basis {
                    wire::BIND | wire::CONNECT
                        if input.len() == wire::ENDPOINT_LEN && header.length == 0 =>
                    {
                        let e = wire::Endpoint::decode(input).map_err(|_| -22)?;
                        if header.basis == wire::BIND {
                            if e.port != 0 && e.port < 1024 {
                                return Err(-13);
                            }
                            backend.bind(socket, e)?;
                        } else {
                            if r.scopes & wire::CONNECT_SCOPE == 0 {
                                return Err(-13);
                            }
                            backend.connect(socket, e, || {
                                platform::service_ready::generate_token().ok()
                            })?;
                        }
                        Ok((0, 0))
                    }
                    wire::LISTEN if input.len() == 4 && header.length == 0 => {
                        if r.scopes & wire::LISTEN_SCOPE == 0 {
                            return Err(-13);
                        }
                        backend.listen(
                            socket,
                            u32::from_le_bytes(input.try_into().unwrap()) as usize,
                        )?;
                        Ok((0, 0))
                    }
                    wire::SHUTDOWN if input.len() == 4 && header.length == 0 => {
                        let flags = u32::from_le_bytes(input.try_into().unwrap());
                        if flags == 0 || flags & !(wire::READ_SHUTDOWN | wire::WRITE_SHUTDOWN) != 0 {
                            return Err(-22);
                        }
                        backend.shutdown(
                            socket,
                            flags & wire::READ_SHUTDOWN != 0,
                            flags & wire::WRITE_SHUTDOWN != 0,
                        )?;
                        Ok((0, 0))
                    }
                    wire::TAKE_ERROR if input.is_empty() && header.length == 4 => {
                        data[..4].copy_from_slice(&backend.take_error(socket)?.to_le_bytes());
                        Ok((4, 4))
                    }
                    wire::CANCEL_CONNECT if input.is_empty() && header.length == 4 => {
                        data[..4]
                            .copy_from_slice(&u32::from(backend.cancel_connect(socket)?).to_le_bytes());
                        Ok((4, 4))
                    }
                    _ => Err(-95),
                },
                _ => Err(-95),
            }
        })();
        let (status, value, n) = match result {
            Ok((v, n)) => (0, v, n),
            Err(e) => (e, 0, 0),
        };
        let mut response = [0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
        let n = provider::ResponseHeader {
            opcode: header.opcode,
            status: i64::from(status),
            object_id: header.object_id,
            value,
            data_length: n as u32,
        }
        .encode(&data[..n], &mut response)
        .unwrap();
        self.pump(now, backend);
        let _ = platform::ipc::reply(sender, &response[..n]);
        true
    }
}
