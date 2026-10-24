//! Native packet objects. Only attached factory authority may create a binding;
//! later requests are authenticated by the kernel's Provider delivery metadata.
use super::{LIMIT, Server, TAG};
use crate::datagram::Backend;
use alloc::{collections::VecDeque, vec::Vec};
use mnu_abi::provider;
use mochi_user_platform as platform;
use mochios_net_device_protocol::{datagram as wire, datagram_authority as authority};
use mochios_network_stack::UdpSocketId;
const PACKET_TAG: u64 = 2 << 60;
const RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ
    | mnu_abi::HANDLE_RIGHT_WRITE
    | mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_WAIT
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
const SIGNALS: u64 = mnu_abi::HANDLE_SIGNAL_READABLE
    | mnu_abi::HANDLE_SIGNAL_WRITABLE
    | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
const TRANSMIT_LIMIT: usize = 8;
struct Pending {
    destination: wire::Endpoint,
    payload: Vec<u8>,
}
pub(super) struct Row {
    id: u64,
    socket: UdpSocketId,
    pending: VecDeque<Pending>,
    error: i32,
}
impl Server {
    pub(crate) fn dispatch_datagram(
        &mut self,
        sender: u64,
        bytes: &[u8],
        handles: &platform::ipc::IpcObjectHandles,
        backend: &mut impl Backend,
        _now: u64,
    ) -> bool {
        if bytes.get(..8) == Some(&[b'N', b'U', b'D', b'P', 1, 0, 2, 0]) {
            let result = (|| {
                let local = wire::decode_open(bytes).map_err(|_| -22)?;
                if handles.count != 1
                    || !matches!(
                        handles.delivery_flags,
                        0 | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
                    )
                {
                    return Err(-13);
                }
                let source = handles.handles[0];
                if source.handle == 0
                    || source.reserved != 0
                    || source.rights != mnu_abi::HANDLE_RIGHT_CONTROL
                {
                    return Err(-13);
                }
                let factory =
                    platform::handle::identify_provider_object(source.handle).map_err(|_| -13)?;
                if !self.live.contains(&factory) {
                    return Err(-13);
                }
                if local.port != 0 && local.port < 1024 {
                    return Err(-13);
                }
                if self.packets.len() == LIMIT || self.next >= TAG {
                    return Err(-24);
                }
                let endpoint = *self.endpoint.as_ref().map_err(|_| -5)?;
                self.packets.try_reserve(1).map_err(|_| -12)?;
                let socket = backend.bind(local)?;
                let id = PACKET_TAG | self.next;
                self.next += 1;
                let created =
                    platform::handle::create_provider_object(endpoint, id, RIGHTS).map_err(|_| -5);
                let handle = match created {
                    Ok(h) => h,
                    Err(e) => {
                        backend.release(socket);
                        return Err(e);
                    }
                };
                if platform::handle::signal_provider_object(
                    id,
                    mnu_abi::HANDLE_SIGNAL_WRITABLE,
                    SIGNALS & !mnu_abi::HANDLE_SIGNAL_WRITABLE,
                )
                .is_err()
                {
                    backend.release(socket);
                    let _ = platform::handle::close(handle);
                    return Err(-5);
                }
                self.packets.push(Row {
                    id,
                    socket,
                    pending: VecDeque::new(),
                    error: 0,
                });
                Ok((id, handle))
            })();
            let mut response = [0; authority::REPLY_LEN];
            match result {
                Ok((id, handle)) => {
                    authority::reply_for(wire::OPEN_OPCODE, 0, &mut response).unwrap();
                    let mut attached = platform::ipc::IpcObjectHandles::default();
                    attached.count = 1;
                    attached.handles[0] = platform::ipc::IpcObjectHandle {
                        handle,
                        reserved: 0,
                        rights: RIGHTS,
                    };
                    if platform::ipc::reply_object_handles(sender, &response, &attached).is_err() {
                        if let Some(i) = self.packets.iter().position(|r| r.id == id) {
                            backend.release(self.packets.swap_remove(i).socket);
                        }
                    }
                    let _ = platform::handle::close(handle);
                }
                Err(error) => {
                    authority::reply_for(wire::OPEN_OPCODE, error, &mut response).unwrap();
                    let _ = platform::ipc::reply(sender, &response);
                }
            }
            return true;
        }
        let Ok((header, input)) = provider::RequestHeader::decode(bytes) else {
            return false;
        };
        if header.object_id & (15 << 60) != PACKET_TAG {
            return false;
        }
        let native =
            handles.delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT && handles.count == 0;
        if native && header.opcode == provider::OP_RELEASE {
            if let Some(i) = self.packets.iter().position(|r| r.id == header.object_id) {
                backend.release(self.packets.swap_remove(i).socket);
            }
            return true;
        }
        let mut data = [0; provider::MAX_DATA_LEN];
        let result = (|| {
            if !native {
                return Err(-13);
            }
            let row = self
                .packets
                .iter_mut()
                .find(|r| r.id == header.object_id)
                .ok_or(-9)?;
            let socket = row.socket;
            match header.opcode {
                provider::OP_READ | provider::OP_READ_AT => {
                    if header.basis != 0 {
                        return Err(-22);
                    }
                    if row.error != 0 {
                        return Err(core::mem::take(&mut row.error));
                    }
                    backend
                        .receive(
                            socket,
                            header.opcode == provider::OP_READ_AT,
                            &mut data[..header.length as usize],
                        )
                        .map(|n| (n as u64, n))
                }
                provider::OP_WRITE => {
                    if input.len() > 8 + wire::MAX_PAYLOAD {
                        return Err(-90);
                    }
                    let (destination, payload) = wire::decode_send(input).map_err(|_| -22)?;
                    let destination = backend.destination(socket, destination)?;
                    if row.error != 0 {
                        return Err(core::mem::take(&mut row.error));
                    }
                    if row.pending.len() == TRANSMIT_LIMIT {
                        return Err(-11);
                    }
                    let mut owned = Vec::new();
                    owned.try_reserve_exact(payload.len()).map_err(|_| -12)?;
                    owned.extend_from_slice(payload);
                    row.pending.try_reserve(1).map_err(|_| -12)?;
                    row.pending.push_back(Pending {
                        destination,
                        payload: owned,
                    });
                    Ok((input.len() as u64, 0))
                }
                provider::OP_MEMORY_OBJECT => Ok((0, 0)),
                provider::OP_CONTROL => match header.basis {
                    wire::TAKE_STATUS if input.is_empty() && header.length == 4 => {
                        data[..4].copy_from_slice(&core::mem::take(&mut row.error).to_le_bytes());
                        Ok((4, 4))
                    }
                    wire::LOCAL | wire::PEER
                        if input.is_empty() && header.length == wire::ENDPOINT_LEN as u32 =>
                    {
                        let value = if header.basis == wire::LOCAL {
                            backend.local(socket)?
                        } else {
                            backend.peer(socket)?.unwrap_or(wire::Endpoint {
                                address: [0; 4],
                                port: 0,
                            })
                        };
                        let n = value.encode(&mut data).map_err(|_| -5)?;
                        Ok((n as u64, n))
                    }
                    wire::SET_PEER if input.len() == wire::ENDPOINT_LEN && header.length == 0 => {
                        let peer = wire::Endpoint::decode(input).map_err(|_| -22)?;
                        backend
                            .set_peer(socket, if peer.unspecified() { None } else { Some(peer) })?;
                        Ok((0, 0))
                    }
                    _ => Err(-95),
                },
                _ => Err(-95),
            }
        })();
        let (status, value, length) = match result {
            Ok((value, n)) => (0, value, n),
            Err(status) => (status, 0, 0),
        };
        let mut response = [0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
        let n = provider::ResponseHeader {
            opcode: header.opcode,
            status: i64::from(status),
            object_id: header.object_id,
            value,
            data_length: length as u32,
        }
        .encode(&data[..length], &mut response)
        .unwrap();
        let _ = platform::ipc::reply(sender, &response[..n]);
        true
    }
    pub(crate) fn pump_datagrams(&mut self, backend: &mut impl Backend, now: u64) {
        // Bound each loop's work and retain a complete record on transport
        // backpressure. A later peer change cannot redirect queued records.
        for row in &mut self.packets {
            for _ in 0..TRANSMIT_LIMIT {
                let Some(packet) = row.pending.front() else {
                    break;
                };
                match backend.send(row.socket, Some(packet.destination), &packet.payload, now) {
                    Ok(()) => {
                        row.pending.pop_front();
                    }
                    Err(-11) => break,
                    Err(error) => {
                        row.pending.pop_front();
                        if row.error == 0 {
                            row.error = error;
                        }
                    }
                }
            }
        }
        for row in &self.packets {
            let set = match backend.readable(row.socket) {
                Ok(readable) => {
                    let mut set = 0;
                    if readable || row.error != 0 {
                        set |= mnu_abi::HANDLE_SIGNAL_READABLE;
                    }
                    if row.pending.len() < TRANSMIT_LIMIT || row.error != 0 {
                        set |= mnu_abi::HANDLE_SIGNAL_WRITABLE;
                    }
                    set
                }
                Err(_) => SIGNALS,
            };
            let _ = platform::handle::signal_provider_object(row.id, set, SIGNALS & !set);
        }
    }
}
