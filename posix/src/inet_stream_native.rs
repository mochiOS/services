//! TCP description adapter. Both factory authority and transport resources
//! are explicit owned native references; the trusted endpoint is pinned too.
use super::{
    OpenedObject,
    inet_datagram::Endpoint,
    inet_stream::{Backend, Observation},
};
use mochi_user_platform as platform;
use mochios_net_device_protocol::stream as wire;
const RESOURCE_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ
    | mnu_abi::HANDLE_RIGHT_WRITE
    | mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_WAIT
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub struct NetworkBackend {
    endpoint: u32,
    factory: Option<u32>,
}
fn failure(e: platform::syscall::SysError) -> i32 {
    mochios_posix_protocol::status::normalize_failure(e.raw())
}
fn native(e: Endpoint) -> wire::Endpoint {
    wire::Endpoint {
        address: e.address,
        port: e.port,
    }
}
fn posix(e: wire::Endpoint) -> Endpoint {
    Endpoint {
        address: e.address,
        port: e.port,
    }
}
impl NetworkBackend {
    /// Consumes factory, including on failure. endpoint is borrowed only for
    /// this call: a restricted duplicate pins its identity for the backend.
    pub fn new(endpoint: u32, factory: OpenedObject<u32>) -> Result<Self, i32> {
        let required = mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER;
        let result = (|| {
            if endpoint == 0
                || factory.handle == 0
                || factory.handle == endpoint
                || factory.rights & required != required
            {
                return Err(-13);
            }
            platform::handle::duplicate(
                endpoint,
                mochios_posix_protocol::network::endpoint_rights(),
            )
            .map_err(failure)
        })();
        match result {
            Ok(endpoint) => Ok(Self {
                endpoint,
                factory: Some(factory.handle),
            }),
            Err(e) => {
                if factory.handle != 0 && factory.handle != endpoint {
                    let _ = platform::handle::close(factory.handle);
                }
                Err(e)
            }
        }
    }
    fn call(
        &self,
        operation: u16,
        source: u32,
        returned_rights: Option<u64>,
    ) -> Result<Option<u32>, i32> {
        let mut objects = platform::ipc::IpcObjectHandles::default();
        objects.count = 1;
        objects.handles[0] = platform::ipc::IpcObjectHandle {
            handle: source,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_CONTROL,
        };
        let mut response = [0; wire::REPLY_LEN];
        let native = super::filesystem_transport::call_native(&mut objects, |objects| {
            platform::ipc::call_object_handles(
                self.endpoint,
                &wire::header(operation),
                &mut response,
                objects,
            )
        })
        .map_err(failure);
        let result = (|| {
            let count = native? as u32 as usize;
            if objects.delivery_flags != 0 {
                return Err(-5);
            }
            let status =
                wire::status(operation, response.get(..count).ok_or(-5)?).map_err(|_| -5)?;
            if status != 0 {
                if objects.count != 0 {
                    return Err(-5);
                }
                return Err(status);
            }
            let Some(rights) = returned_rights else {
                return if objects.count == 0 {
                    Ok(None)
                } else {
                    Err(-5)
                };
            };
            if objects.count != 1 {
                return Err(-5);
            }
            let h = objects.handles[0];
            if h.handle == 0
                || h.handle == source
                || h.handle == self.endpoint
                || h.reserved != 0
                || h.rights != rights
            {
                return Err(-5);
            }
            Ok(Some(h.handle))
        })();
        if result.is_err() {
            for (i, h) in objects
                .handles
                .iter()
                .take(objects.count as usize)
                .enumerate()
            {
                if h.handle != 0
                    && h.handle != source
                    && h.handle != self.endpoint
                    && !objects.handles[..i]
                        .iter()
                        .any(|old| old.handle == h.handle)
                {
                    let _ = platform::handle::close(h.handle);
                }
            }
        }
        result
    }
    pub fn validate(&self) -> Result<(), i32> {
        self.call(wire::VALIDATE, self.factory.ok_or(-13)?, None)
            .map(|_| ())
    }
    fn control(&self, h: u32, tag: u64, input: &[u8], out: &mut [u8]) -> Result<(), i32> {
        if platform::handle::control(h, tag, input, out).map_err(failure)? != out.len() {
            return Err(-5);
        }
        Ok(())
    }
    fn endpoint(&self, h: u32, tag: u64) -> Result<Endpoint, i32> {
        let mut bytes = [0; wire::ENDPOINT_LEN];
        if platform::handle::query(h, tag, &[], &mut bytes).map_err(failure)? != bytes.len() {
            return Err(-5);
        }
        wire::Endpoint::decode(&bytes).map(posix).map_err(|_| -5)
    }
}
impl Backend for NetworkBackend {
    type Handle = u32;
    fn open(&mut self) -> Result<u32, i32> {
        self.call(wire::OPEN, self.factory.ok_or(-13)?, Some(RESOURCE_RIGHTS))
            .map(|h| h.unwrap())
    }
    fn close(&mut self, h: u32) {
        let _ = platform::handle::close(h);
    }
    fn local(&mut self, h: u32) -> Result<Endpoint, i32> {
        self.endpoint(h, wire::LOCAL)
    }
    fn peer(&mut self, h: u32) -> Result<Endpoint, i32> {
        self.endpoint(h, wire::PEER)
    }
    fn bind(&mut self, h: u32, e: Endpoint) -> Result<(), i32> {
        let mut bytes = [0; wire::ENDPOINT_LEN];
        native(e).encode(&mut bytes).map_err(|_| -22)?;
        self.control(h, wire::BIND, &bytes, &mut [])
    }
    fn connect(&mut self, h: u32, e: Endpoint) -> Result<(), i32> {
        let mut bytes = [0; wire::ENDPOINT_LEN];
        native(e).encode(&mut bytes).map_err(|_| -22)?;
        self.control(h, wire::CONNECT, &bytes, &mut [])
    }
    fn listen(&mut self, h: u32, backlog: usize) -> Result<(), i32> {
        let backlog = u32::try_from(backlog).map_err(|_| -22)?;
        self.control(h, wire::LISTEN, &backlog.to_le_bytes(), &mut [])
    }
    fn cancel_connect(&mut self, h: u32) -> Result<bool, i32> {
        let mut bytes = [0; 4];
        self.control(h, wire::CANCEL_CONNECT, &[], &mut bytes)?;
        match u32::from_le_bytes(bytes) {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(-5),
        }
    }
    fn accept(&mut self, h: u32) -> Result<(Self, u32), i32> {
        // Allocate the endpoint reference before consuming a ready accept.
        let endpoint = platform::handle::duplicate(
            self.endpoint,
            mochios_posix_protocol::network::endpoint_rights(),
        )
        .map_err(failure)?;
        match self.call(wire::ACCEPT, h, Some(RESOURCE_RIGHTS)) {
            Ok(Some(h)) => Ok((
                Self {
                    endpoint,
                    factory: None,
                },
                h,
            )),
            result => {
                let _ = platform::handle::close(endpoint);
                Err(result.err().unwrap_or(-5))
            }
        }
    }
    fn observe(&mut self, h: u32) -> Result<Observation, i32> {
        let mut bytes = [0; wire::STATUS_LEN];
        if platform::handle::query(h, wire::STATUS, &[], &mut bytes).map_err(failure)?
            != bytes.len()
        {
            return Err(-5);
        }
        let s = wire::Observation::decode(&bytes).map_err(|_| -5)?;
        Ok(Observation {
            readable: s.flags & wire::READABLE != 0,
            writable: s.flags & wire::WRITABLE != 0,
            peer_closed: s.flags & wire::PEER_CLOSED != 0,
            connecting: s.flags & wire::CONNECTING != 0,
            error: s.error,
        })
    }
    fn take_error(&mut self, h: u32) -> Result<i32, i32> {
        let mut bytes = [0; 4];
        self.control(h, wire::TAKE_ERROR, &[], &mut bytes)?;
        let e = i32::from_le_bytes(bytes);
        if !(-4095..=0).contains(&e) {
            return Err(-5);
        }
        Ok(e)
    }
    fn send(&mut self, h: u32, bytes: &[u8]) -> Result<usize, i32> {
        let n = platform::handle::write(h, bytes).map_err(failure)?;
        if n > bytes.len() {
            return Err(-5);
        }
        Ok(n)
    }
    fn receive(&mut self, h: u32, peek: bool, bytes: &mut [u8]) -> Result<usize, i32> {
        let result = if peek {
            platform::handle::read_at(h, bytes, 0)
        } else {
            platform::handle::read(h, bytes)
        };
        let n = result.map_err(failure)?;
        if n > bytes.len() {
            return Err(-5);
        }
        Ok(n)
    }
    fn shutdown(&mut self, h: u32, read: bool, write: bool) -> Result<(), i32> {
        let flags = u32::from(read) * wire::READ_SHUTDOWN | u32::from(write) * wire::WRITE_SHUTDOWN;
        self.control(h, wire::SHUTDOWN, &flags.to_le_bytes(), &mut [])
    }
}
impl Drop for NetworkBackend {
    fn drop(&mut self) {
        if let Some(h) = self.factory {
            let _ = platform::handle::close(h);
        }
        let _ = platform::handle::close(self.endpoint);
    }
}
