//! Native network packet adapter for the POSIX socket worker. No endpoint
//! discovery or ambient-capability impersonation: the caller transfers a
//! factory reference explicitly. FD labels never reach network.service.
use super::OpenedObject;
use super::inet_datagram::{Backend, Endpoint, Received};
use mochi_user_platform as platform;
use mochios_net_device_protocol::{datagram as packet, datagram_authority as authority};

pub struct NetworkBackend {
    endpoint: u32,
    factory: u32,
}
fn failure(error: platform::syscall::SysError) -> i32 {
    mochios_posix_protocol::status::normalize_failure(error.raw())
}
fn native(endpoint: Endpoint) -> packet::Endpoint {
    packet::Endpoint {
        address: endpoint.address,
        port: endpoint.port,
    }
}
fn posix(endpoint: packet::Endpoint) -> Endpoint {
    Endpoint {
        address: endpoint.address,
        port: endpoint.port,
    }
}
impl NetworkBackend {
    /// Takes ownership of factory, including on failure. endpoint is borrowed
    /// from the worker's inherited table and must outlive this backend.
    pub fn new(endpoint: u32, factory: OpenedObject<u32>) -> Result<Self, i32> {
        let required = mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER;
        if endpoint == 0 || factory.handle == 0 || factory.rights & required != required {
            if factory.handle != 0 {
                let _ = platform::handle::close(factory.handle);
            }
            return Err(-13);
        }
        Ok(Self {
            endpoint,
            factory: factory.handle,
        })
    }
    /// Authenticate at the trusted network endpoint, never by invoking an
    /// arbitrary attached Provider that could block the shared socket worker.
    pub fn validate(&self) -> Result<(), i32> {
        let mut objects = platform::ipc::IpcObjectHandles::default();
        objects.count = 1;
        objects.handles[0] = platform::ipc::IpcObjectHandle {
            handle: self.factory,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_CONTROL,
        };
        let mut response = [0; authority::REPLY_LEN];
        let n = super::filesystem_transport::call_native(&mut objects, |objects| {
            platform::ipc::call_object_handles(
                self.endpoint,
                &authority::VALIDATE,
                &mut response,
                objects,
            )
        })
        .map_err(failure)? as u32 as usize;
        let status = authority::status_for(3, response.get(..n).ok_or(-5)?).map_err(|_| -5);
        let valid = objects.count == 0 && objects.delivery_flags == 0;
        for (index, object) in objects
            .handles
            .iter()
            .take(objects.count as usize)
            .enumerate()
        {
            if object.handle != 0
                && object.handle != self.factory
                && !objects.handles[..index]
                    .iter()
                    .any(|old| old.handle == object.handle)
            {
                let _ = platform::handle::close(object.handle);
            }
        }
        if !valid {
            return Err(-5);
        }
        match status? {
            0 => Ok(()),
            error => Err(error),
        }
    }
    fn control(&self, handle: u32, tag: u64, input: &[u8], output: &mut [u8]) -> Result<(), i32> {
        let n = platform::handle::control(handle, tag, input, output).map_err(failure)?;
        if n != output.len() {
            return Err(-5);
        }
        Ok(())
    }
    fn endpoint(&self, handle: u32, tag: u64, input: &[u8]) -> Result<Endpoint, i32> {
        let mut bytes = [0; packet::ENDPOINT_LEN];
        self.control(handle, tag, input, &mut bytes)?;
        packet::Endpoint::decode(&bytes).map(posix).map_err(|_| -5)
    }
}
impl Backend for NetworkBackend {
    type Handle = u32;
    fn open(&mut self, local: Endpoint) -> Result<u32, i32> {
        let mut request = [0; 16];
        packet::open(native(local), &mut request).map_err(|_| -22)?;
        let mut response = [0; authority::REPLY_LEN];
        let mut attached = platform::ipc::IpcObjectHandles::default();
        attached.count = 1;
        attached.handles[0] = platform::ipc::IpcObjectHandle {
            handle: self.factory,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_CONTROL,
        };
        let result = platform::ipc::call_object_handles(
            self.endpoint,
            &request,
            &mut response,
            &mut attached,
        )
        .map_err(failure);
        let outcome = (|| {
            let n = result? as u32 as usize;
            if attached.delivery_flags != 0 || n > response.len() {
                return Err(-5);
            }
            let status =
                authority::status_for(packet::OPEN_OPCODE, &response[..n]).map_err(|_| -5)?;
            if status != 0 {
                return Err(status);
            }
            let rights = mnu_abi::HANDLE_RIGHT_READ
                | mnu_abi::HANDLE_RIGHT_WRITE
                | mnu_abi::HANDLE_RIGHT_CONTROL
                | mnu_abi::HANDLE_RIGHT_WAIT
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER;
            if attached.count != 1 {
                return Err(-5);
            }
            let object = attached.handles[0];
            if object.handle == 0
                || object.handle == self.factory
                || object.reserved != 0
                || object.rights != rights
            {
                return Err(-5);
            }
            Ok(object.handle)
        })();
        if outcome.is_err() {
            // Failed native calls may leave the borrowed outgoing entries in
            // place. Close only distinct received references, never factory.
            for (index, object) in attached
                .handles
                .iter()
                .take(attached.count as usize)
                .enumerate()
            {
                if object.handle != 0
                    && object.handle != self.factory
                    && !attached.handles[..index]
                        .iter()
                        .any(|old| old.handle == object.handle)
                {
                    let _ = platform::handle::close(object.handle);
                }
            }
        }
        outcome
    }
    fn close(&mut self, handle: u32) {
        let _ = platform::handle::close(handle);
    }
    fn local(&mut self, handle: u32) -> Result<Endpoint, i32> {
        self.endpoint(handle, packet::LOCAL, &[])
    }
    fn source(&mut self, handle: u32, destination: Endpoint) -> Result<Endpoint, i32> {
        let mut bytes = [0; 8];
        native(destination).encode(&mut bytes).map_err(|_| -22)?;
        self.endpoint(handle, packet::SOURCE, &bytes)
    }
    fn set_peer(&mut self, handle: u32, peer: Option<Endpoint>) -> Result<(), i32> {
        let mut bytes = [0; 8];
        native(peer.unwrap_or(Endpoint::UNSPECIFIED))
            .encode(&mut bytes)
            .map_err(|_| -22)?;
        self.control(handle, packet::SET_PEER, &bytes, &mut [])
    }
    fn send(&mut self, handle: u32, destination: Endpoint, payload: &[u8]) -> Result<(), i32> {
        if payload.len() > packet::MAX_PAYLOAD {
            return Err(-90);
        }
        let mut frame = [0; packet::ENDPOINT_LEN + packet::MAX_PAYLOAD];
        let n = packet::send(Some(native(destination)), payload, &mut frame).map_err(|_| -22)?;
        if platform::handle::write(handle, &frame[..n]).map_err(failure)? != n {
            return Err(-5);
        }
        Ok(())
    }
    fn receive(&mut self, handle: u32, peek: bool, output: &mut [u8]) -> Result<Received, i32> {
        let mut frame = [0; packet::RECEIVE_HEADER_LEN + packet::MAX_PAYLOAD];
        let capacity = packet::RECEIVE_HEADER_LEN + output.len().min(packet::MAX_PAYLOAD);
        let count = if peek {
            platform::handle::read_at(handle, &mut frame[..capacity], 0)
        } else {
            platform::handle::read(handle, &mut frame[..capacity])
        }
        .map_err(failure)?;
        let record = packet::decode_received(frame.get(..count).ok_or(-5)?).map_err(|_| -5)?;
        output[..record.payload.len()].copy_from_slice(record.payload);
        Ok(Received {
            source: posix(record.source),
            copied: record.payload.len(),
            original: record.original_length,
        })
    }
    fn signals(&mut self, handle: u32) -> Result<u64, i32> {
        let mut items = [mnu_abi::HandleWaitItem {
            handle,
            interests: mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_WRITABLE
                | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
            ..Default::default()
        }];
        match platform::process::wait_many(&mut items, 0) {
            Ok(_) => Ok(items[0].observed),
            Err(error)
                if error.native_error() == Some(platform::syscall::NativeError::NotReady) =>
            {
                Ok(0)
            }
            Err(error) => Err(failure(error)),
        }
    }
    fn maximum_payload(&self) -> usize {
        packet::MAX_PAYLOAD
    }
}
impl Drop for NetworkBackend {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.factory);
    }
}
