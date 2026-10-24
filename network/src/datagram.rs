//! Packet backend shared by configured interfaces and no-device loopback.
//! Transport bounds and network policy stay in user space, outside mnu.
use mochios_net_device_protocol::datagram as wire;
use mochios_network_stack::{PacketError, UdpDatagram, UdpEndpoint, UdpSocketId, UdpSocketTable};
pub(crate) fn table_error(error: PacketError) -> i32 {
    match error {
        PacketError::Capacity => -24,
        PacketError::Mismatch => -98,
        _ => -22,
    }
}
pub(crate) trait Backend {
    fn sockets(&self) -> &UdpSocketTable;
    fn sockets_mut(&mut self) -> &mut UdpSocketTable;
    fn interface_address(&self) -> Option<[u8; 4]>;
    fn transmit(
        &mut self,
        source_port: u16,
        destination: wire::Endpoint,
        payload: &[u8],
        now: u64,
    ) -> Result<(), i32>;
    fn bind(&mut self, local: wire::Endpoint) -> Result<UdpSocketId, i32> {
        if local.address != [0; 4]
            && local.address[0] != 127
            && self.interface_address() != Some(local.address)
        {
            return Err(-99);
        }
        self.sockets_mut()
            .bind_endpoint(local.address, local.port)
            .map_err(table_error)
    }
    fn local(&self, id: UdpSocketId) -> Result<wire::Endpoint, i32> {
        let e = self.sockets().local_endpoint(id).map_err(|_| -9)?;
        Ok(wire::Endpoint {
            address: e.address,
            port: e.port,
        })
    }
    fn peer(&self, id: UdpSocketId) -> Result<Option<wire::Endpoint>, i32> {
        Ok(self
            .sockets()
            .peer(id)
            .map_err(|_| -9)?
            .map(|e| wire::Endpoint {
                address: e.address,
                port: e.port,
            }))
    }
    fn set_peer(&mut self, id: UdpSocketId, peer: Option<wire::Endpoint>) -> Result<(), i32> {
        if peer.is_some_and(|e| e.port == 0 || e.address == [0; 4]) {
            return Err(-22);
        }
        self.sockets_mut()
            .set_peer(
                id,
                peer.map(|e| UdpEndpoint {
                    address: e.address,
                    port: e.port,
                }),
            )
            .map_err(|_| -9)
    }
    fn destination(
        &self,
        id: UdpSocketId,
        peer: Option<wire::Endpoint>,
    ) -> Result<wire::Endpoint, i32> {
        let local = self.local(id)?;
        let peer = peer.or(self.peer(id)?).ok_or(-89)?;
        if peer.port == 0 || peer.address == [0; 4] {
            return Err(-22);
        }
        if peer.address[0] != 127 {
            let address = self.interface_address().ok_or(-6)?;
            if local.address != [0; 4] && local.address != address {
                return Err(-99);
            }
        }
        Ok(peer)
    }
    fn send(
        &mut self,
        id: UdpSocketId,
        peer: Option<wire::Endpoint>,
        payload: &[u8],
        now: u64,
    ) -> Result<(), i32> {
        if payload.len() > wire::MAX_PAYLOAD {
            return Err(-90);
        }
        let peer = self.destination(id, peer)?;
        let local = self.local(id)?;
        if peer.address[0] == 127 {
            let source = if local.address == [0; 4] {
                [127, 0, 0, 1]
            } else {
                local.address
            };
            // Datagram delivery is not guaranteed. Full or unmatched remote
            // queues drop packets without creating receiver backpressure.
            match self.sockets_mut().enqueue(
                source,
                peer.address,
                UdpDatagram {
                    source_port: local.port,
                    destination_port: peer.port,
                    payload,
                },
            ) {
                Ok(()) | Err(PacketError::Mismatch | PacketError::Capacity) => Ok(()),
                Err(_) => Err(-5),
            }
        } else {
            self.transmit(local.port, peer, payload, now)
        }
    }
    fn receive(&mut self, id: UdpSocketId, peek: bool, output: &mut [u8]) -> Result<usize, i32> {
        if output.len() < wire::RECEIVE_HEADER_LEN {
            return Err(-22);
        }
        let packet = self.sockets().peek_for(id).map_err(|_| -9)?.ok_or(-11)?;
        let n = wire::received(
            wire::Endpoint {
                address: packet.source_address,
                port: packet.source_port,
            },
            &packet.payload,
            output,
        )
        .map_err(|_| -5)?;
        if !peek {
            self.sockets_mut().receive_for(id).map_err(|_| -9)?;
        }
        Ok(n)
    }
    fn release(&mut self, id: UdpSocketId) {
        self.sockets_mut().unbind_endpoint(id);
    }
    fn readable(&self, id: UdpSocketId) -> Result<bool, i32> {
        self.sockets()
            .queued_for(id)
            .map(|n| n != 0)
            .map_err(|_| -9)
    }
}
pub(crate) struct Loopback {
    udp: UdpSocketTable,
}
impl Loopback {
    pub(crate) fn new() -> Self {
        Self {
            udp: UdpSocketTable::new(8, 8, wire::MAX_PAYLOAD),
        }
    }
}
impl Backend for Loopback {
    fn sockets(&self) -> &UdpSocketTable {
        &self.udp
    }
    fn sockets_mut(&mut self) -> &mut UdpSocketTable {
        &mut self.udp
    }
    fn interface_address(&self) -> Option<[u8; 4]> {
        None
    }
    fn transmit(&mut self, _: u16, _: wire::Endpoint, _: &[u8], _: u64) -> Result<(), i32> {
        Err(-6)
    }
}
