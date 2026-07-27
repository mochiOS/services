use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::driver::DriverClient;
use mochi_user_platform as platform;
use mochios_net_device_protocol::{InterfaceInfo, StackStatistics};
use mochios_network_stack::{
    ARP_LEN, ARP_REPLY, ARP_REQUEST, ArpCache, ArpEntry, ArpPacket, BROADCAST_MAC,
    DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DhcpClient, DhcpMessageType, DhcpState, ETHERTYPE_ARP,
    ETHERTYPE_IPV4, EchoPacket, EthernetHeader, Ipv4Config, Ipv4Header, PacketError, UdpDatagram,
    UdpSocketTable, decode_reply, encode_request, next_hop,
};

const ARP_TTL: u64 = 60_000;
const RETRY_TICKS: u64 = 1_000;
const MAX_RETRIES: u8 = 5;
const UDP_SOCKET_LIMIT: usize = 8;
const UDP_QUEUE_LIMIT: usize = 8;
const UDP_PAYLOAD_LIMIT: usize = 1_472;
const PENDING_IPV4_LIMIT: usize = 8;
const ICMP_IDENTIFIER: u16 = 0x4d4f;

struct PendingIpv4 {
    next_hop: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    payload: Vec<u8>,
}

pub(crate) struct NetworkStack {
    driver: DriverClient,
    info: InterfaceInfo,
    config: Option<Ipv4Config>,
    dhcp: DhcpClient,
    udp: UdpSocketTable,
    arp: ArpCache,
    stats: StackStatistics,
    ready: Option<platform::service_ready::Target>,
    last_dhcp_send: u64,
    arp_pending: Option<[u8; 4]>,
    arp_last: u64,
    arp_retries: u8,
    pending_ipv4: VecDeque<PendingIpv4>,
    next_ip_id: u16,
    ping_sequence: u16,
    ping_sent: Option<([u8; 4], u16, u64)>,
    ping_reply: Option<([u8; 4], u16, u64)>,
}
impl NetworkStack {
    pub(crate) fn new(
        mut driver: DriverClient,
        ready: Option<platform::service_ready::Target>,
        xid: u32,
    ) -> Result<Self, u64> {
        let info = driver.info()?;
        let mut udp = UdpSocketTable::new(UDP_SOCKET_LIMIT, UDP_QUEUE_LIMIT, UDP_PAYLOAD_LIMIT);
        udp.bind(DHCP_CLIENT_PORT)
            .map_err(|_| mochi_user_syscall::EINVAL)?;
        Ok(Self {
            driver,
            info,
            config: None,
            dhcp: DhcpClient::new(xid, info.mac),
            udp,
            arp: ArpCache::new(32),
            stats: StackStatistics::default(),
            ready,
            last_dhcp_send: 0,
            arp_pending: None,
            arp_last: 0,
            arp_retries: 0,
            pending_ipv4: VecDeque::with_capacity(PENDING_IPV4_LIMIT),
            next_ip_id: 1,
            ping_sequence: 1,
            ping_sent: None,
            ping_reply: None,
        })
    }
    pub(crate) fn start(&mut self, now: u64) -> Result<(), u64> {
        self.dhcp.begin(now);
        self.send_dhcp(DhcpMessageType::Discover, now)
    }
    pub(crate) const fn info(&self) -> InterfaceInfo {
        self.info
    }
    pub(crate) const fn statistics(&self) -> StackStatistics {
        self.stats
    }
    pub(crate) fn tick(&mut self, now: u64) {
        let previous_dhcp_state = self.dhcp.state;
        self.dhcp.tick(now);
        if previous_dhcp_state != DhcpState::Failed && self.dhcp.state == DhcpState::Failed {
            self.stats.dhcp_failures = self.stats.dhcp_failures.saturating_add(1);
            self.config = None;
        }
        if matches!(
            self.dhcp.state,
            DhcpState::Selecting
                | DhcpState::Requesting
                | DhcpState::Renewing
                | DhcpState::Rebinding
        ) && now.saturating_sub(self.last_dhcp_send) >= RETRY_TICKS
        {
            let kind = if self.dhcp.state == DhcpState::Selecting {
                DhcpMessageType::Discover
            } else {
                DhcpMessageType::Request
            };
            if self.send_dhcp(kind, now).is_err() {
                self.stats.tx_errors += 1
            }
        }
        if let Some(ip) = self.arp_pending
            && now.saturating_sub(self.arp_last) >= RETRY_TICKS
        {
            if self.arp_retries >= MAX_RETRIES {
                self.arp_pending = None;
                self.drop_pending_for(ip);
            } else {
                let _ = self.send_arp_request(ip, now);
            }
        }
    }
    pub(crate) fn poll_receive(&mut self, now: u64) -> Result<bool, u64> {
        let Some(frame) = self.driver.receive()? else {
            return Ok(false);
        };
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += frame.len() as u64;
        if let Err(error) = self.handle_frame(&frame, now) {
            self.stats.rx_dropped += 1;
            if error == PacketError::InvalidChecksum {
                self.stats.ipv4_checksum_errors += 1
            }
        }
        Ok(true)
    }
    fn handle_frame(&mut self, frame: &[u8], now: u64) -> Result<(), PacketError> {
        let (header, payload) = EthernetHeader::decode(frame)?;
        if !header.accepted_for(self.info.mac) {
            return Err(PacketError::Mismatch);
        }
        match header.ethertype {
            ETHERTYPE_ARP => self.handle_arp(header.source, payload, now),
            ETHERTYPE_IPV4 => self.handle_ipv4(payload, now),
            _ => Err(PacketError::Unsupported),
        }
    }
    fn handle_arp(
        &mut self,
        ethernet_source: [u8; 6],
        payload: &[u8],
        now: u64,
    ) -> Result<(), PacketError> {
        let packet = ArpPacket::decode(payload)?;
        if packet.sender_mac != ethernet_source {
            return Err(PacketError::Mismatch);
        }
        let config = self.config.ok_or(PacketError::Mismatch)?;
        if packet.sender_ip == [0; 4]
            || packet.target_ip != config.address
            || (packet.operation == ARP_REPLY && packet.target_mac != self.info.mac)
        {
            return Err(PacketError::Mismatch);
        }
        self.arp.insert(ArpEntry {
            ip: packet.sender_ip,
            mac: packet.sender_mac,
            expires_at: now.saturating_add(ARP_TTL),
        });
        if packet.operation == ARP_REPLY && self.arp_pending == Some(packet.sender_ip) {
            self.arp_pending = None;
            platform::println!(
                "network.service: gateway ARP resolved ip={}.{}.{}.{} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                packet.sender_ip[0],
                packet.sender_ip[1],
                packet.sender_ip[2],
                packet.sender_ip[3],
                packet.sender_mac[0],
                packet.sender_mac[1],
                packet.sender_mac[2],
                packet.sender_mac[3],
                packet.sender_mac[4],
                packet.sender_mac[5]
            );
            self.flush_pending(packet.sender_ip, packet.sender_mac);
        }
        if packet.operation == ARP_REQUEST && packet.target_ip == config.address {
            let reply = ArpPacket {
                operation: ARP_REPLY,
                sender_mac: self.info.mac,
                sender_ip: config.address,
                target_mac: packet.sender_mac,
                target_ip: packet.sender_ip,
            };
            self.send_arp(reply, packet.sender_mac)
                .map_err(|_| PacketError::Capacity)?;
        }
        Ok(())
    }
    fn handle_ipv4(&mut self, payload: &[u8], now: u64) -> Result<(), PacketError> {
        let (header, payload) = Ipv4Header::decode(payload)?;
        if header.protocol == 17 {
            let udp = UdpDatagram::decode(header.source, header.destination, payload)?;
            self.udp.enqueue(header.source, header.destination, udp)?;
            if let Some(packet) = self.udp.receive(DHCP_CLIENT_PORT)
                && packet.source_port == DHCP_SERVER_PORT
            {
                return self.handle_dhcp(&packet.payload, now);
            }
        } else if header.protocol == 1
            && self.config.is_some_and(|c| c.address == header.destination)
        {
            let echo = EchoPacket::decode(payload)?;
            if echo.reply {
                self.stats.icmp_echo_replies += 1;
                if let Some((target, sequence, sent)) = self.ping_sent
                    && target == header.source
                    && sequence == echo.sequence
                    && echo.identifier == ICMP_IDENTIFIER
                {
                    let rtt = now.saturating_sub(sent);
                    self.ping_reply = Some((target, sequence, rtt));
                    self.ping_sent = None;
                    platform::println!(
                        "network.service: ICMP Echo Reply from {}.{}.{}.{} seq={} rtt={}ms",
                        target[0],
                        target[1],
                        target[2],
                        target[3],
                        sequence,
                        rtt
                    );
                }
            } else {
                self.stats.icmp_echo_requests += 1;
                self.send_echo_reply(header.source, echo, now)
                    .map_err(|_| PacketError::Capacity)?
            }
        }
        Ok(())
    }
    fn handle_dhcp(&mut self, payload: &[u8], now: u64) -> Result<(), PacketError> {
        let message = decode_reply(payload, self.dhcp.xid, self.info.mac)?;
        match message.message_type {
            DhcpMessageType::Offer => {
                if self.dhcp.state != DhcpState::Selecting {
                    return Err(PacketError::Mismatch);
                }
                platform::println!("network.service: DHCPOFFER received");
                self.dhcp.accept(message, now)?;
                self.send_dhcp(DhcpMessageType::Request, now)
                    .map_err(|_| PacketError::Capacity)
            }
            DhcpMessageType::Ack => {
                self.dhcp.accept(message, now)?;
                let offer = message.offer;
                self.config = Some(Ipv4Config {
                    address: offer.address,
                    subnet_mask: offer.subnet_mask,
                    gateway: offer.gateway,
                    dns: offer.dns,
                });
                self.stats.dhcp_successes = self.stats.dhcp_successes.saturating_add(1);
                platform::println!("network.service: DHCPACK received");
                platform::println!(
                    "network.service: configured ip={}.{}.{}.{} mask={}.{}.{}.{} gateway={}.{}.{}.{} dns={}.{}.{}.{}",
                    offer.address[0],
                    offer.address[1],
                    offer.address[2],
                    offer.address[3],
                    offer.subnet_mask[0],
                    offer.subnet_mask[1],
                    offer.subnet_mask[2],
                    offer.subnet_mask[3],
                    offer.gateway[0],
                    offer.gateway[1],
                    offer.gateway[2],
                    offer.gateway[3],
                    offer.dns[0],
                    offer.dns[1],
                    offer.dns[2],
                    offer.dns[3]
                );
                if let Some(target) = self.ready.take() {
                    let _ = platform::service_ready::notify(target, 0);
                }
                self.send_echo(offer.gateway, now)
                    .map_err(|_| PacketError::Capacity)
            }
            DhcpMessageType::Nak => {
                self.dhcp.accept(message, now)?;
                self.stats.dhcp_failures = self.stats.dhcp_failures.saturating_add(1);
                self.config = None;
                Err(PacketError::Mismatch)
            }
            _ => Err(PacketError::Mismatch),
        }
    }
    fn send_dhcp(&mut self, kind: DhcpMessageType, now: u64) -> Result<(), u64> {
        let mut dhcp = [0u8; 320];
        let selected = self.dhcp.offer;
        let n = encode_request(
            kind,
            self.dhcp.xid,
            self.info.mac,
            selected.map(|o| o.address),
            selected.map(|o| o.server),
            &mut dhcp,
        )
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        let mut udp = [0u8; 340];
        let n = UdpDatagram {
            source_port: DHCP_CLIENT_PORT,
            destination_port: DHCP_SERVER_PORT,
            payload: &dhcp[..n],
        }
        .encode([0; 4], [255; 4], &mut udp)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        self.send_ipv4([255; 4], 17, &udp[..n], BROADCAST_MAC)?;
        self.last_dhcp_send = now;
        self.stats.dhcp_attempts += 1;
        platform::println!(
            "network.service: DHCP{} sent",
            if kind == DhcpMessageType::Discover {
                "DISCOVER"
            } else {
                "REQUEST"
            }
        );
        Ok(())
    }
    fn send_arp(&mut self, packet: ArpPacket, destination: [u8; 6]) -> Result<(), u64> {
        let mut arp = [0; ARP_LEN];
        let n = packet
            .encode(&mut arp)
            .map_err(|_| mochi_user_syscall::EINVAL)?;
        let mut frame = [0u8; 64];
        let n = EthernetHeader {
            destination,
            source: self.info.mac,
            ethertype: ETHERTYPE_ARP,
        }
        .encode(&arp[..n], &mut frame)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        self.transmit(&frame[..n])
    }
    fn send_arp_request(&mut self, target: [u8; 4], now: u64) -> Result<(), u64> {
        let source = self.config.map(|c| c.address).unwrap_or([0; 4]);
        self.send_arp(
            ArpPacket {
                operation: ARP_REQUEST,
                sender_mac: self.info.mac,
                sender_ip: source,
                target_mac: [0; 6],
                target_ip: target,
            },
            BROADCAST_MAC,
        )?;
        self.stats.arp_requests += 1;
        self.arp_pending = Some(target);
        self.arp_last = now;
        self.arp_retries = self.arp_retries.saturating_add(1);
        Ok(())
    }
    fn resolve(&mut self, target: [u8; 4], now: u64) -> Result<Option<[u8; 6]>, u64> {
        if let Some(mac) = self.arp.lookup(target, now) {
            self.stats.arp_cache_hits += 1;
            Ok(Some(mac))
        } else {
            self.stats.arp_cache_misses += 1;
            self.arp_retries = 0;
            self.send_arp_request(target, now)?;
            Ok(None)
        }
    }

    fn send_routed_ipv4(
        &mut self,
        destination: [u8; 4],
        protocol: u8,
        payload: &[u8],
        now: u64,
    ) -> Result<(), u64> {
        let config = self.config.ok_or(mochi_user_syscall::ENXIO)?;
        let hop = next_hop(config, destination).ok_or(mochi_user_syscall::ENXIO)?;
        if let Some(mac) = self.resolve(hop, now)? {
            return self.send_ipv4(destination, protocol, payload, mac);
        }
        if self.pending_ipv4.len() >= PENDING_IPV4_LIMIT {
            self.stats.tx_dropped = self.stats.tx_dropped.saturating_add(1);
            return Err(mochi_user_syscall::EAGAIN);
        }
        self.pending_ipv4.push_back(PendingIpv4 {
            next_hop: hop,
            destination,
            protocol,
            payload: payload.to_vec(),
        });
        Ok(())
    }

    fn flush_pending(&mut self, next_hop: [u8; 4], mac: [u8; 6]) {
        let count = self.pending_ipv4.len();
        for _ in 0..count {
            let Some(packet) = self.pending_ipv4.pop_front() else {
                break;
            };
            if packet.next_hop == next_hop {
                if self
                    .send_ipv4(packet.destination, packet.protocol, &packet.payload, mac)
                    .is_err()
                {
                    self.stats.tx_dropped = self.stats.tx_dropped.saturating_add(1);
                }
            } else {
                self.pending_ipv4.push_back(packet);
            }
        }
    }

    fn drop_pending_for(&mut self, next_hop: [u8; 4]) {
        let before = self.pending_ipv4.len();
        self.pending_ipv4
            .retain(|packet| packet.next_hop != next_hop);
        self.stats.tx_dropped = self
            .stats
            .tx_dropped
            .saturating_add(before.saturating_sub(self.pending_ipv4.len()) as u64);
    }
    fn send_ipv4(
        &mut self,
        destination: [u8; 4],
        protocol: u8,
        payload: &[u8],
        mac: [u8; 6],
    ) -> Result<(), u64> {
        let source = self.config.map(|c| c.address).unwrap_or([0; 4]);
        let mut ip = [0u8; 1500];
        let n = Ipv4Header {
            source,
            destination,
            protocol,
            ttl: 64,
            identification: self.next_ip_id,
        }
        .encode(payload, &mut ip)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        self.next_ip_id = self.next_ip_id.wrapping_add(1);
        let mut frame = [0u8; 1514];
        let n = EthernetHeader {
            destination: mac,
            source: self.info.mac,
            ethertype: ETHERTYPE_IPV4,
        }
        .encode(&ip[..n], &mut frame)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        self.transmit(&frame[..n])
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), u64> {
        match self.driver.transmit(frame) {
            Ok(()) => {
                self.stats.tx_packets += 1;
                self.stats.tx_bytes += frame.len() as u64;
                Ok(())
            }
            Err(e) => {
                self.stats.tx_errors += 1;
                Err(e)
            }
        }
    }
    fn send_echo(&mut self, target: [u8; 4], now: u64) -> Result<(), u64> {
        let sequence = self.ping_sequence;
        self.ping_sequence = self.ping_sequence.wrapping_add(1);
        let mut icmp = [0u8; 32];
        let n = EchoPacket {
            reply: false,
            identifier: ICMP_IDENTIFIER,
            sequence,
            payload: b"mochiOS",
        }
        .encode(&mut icmp)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        self.send_routed_ipv4(target, 1, &icmp[..n], now)?;
        self.ping_sent = Some((target, sequence, now));
        Ok(())
    }
    fn send_echo_reply(
        &mut self,
        target: [u8; 4],
        echo: EchoPacket<'_>,
        now: u64,
    ) -> Result<(), u64> {
        let mut icmp = [0u8; 1500];
        let n = EchoPacket {
            reply: true,
            identifier: echo.identifier,
            sequence: echo.sequence,
            payload: echo.payload,
        }
        .encode(&mut icmp)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        self.send_routed_ipv4(target, 1, &icmp[..n], now)
    }
    pub(crate) fn ping(&mut self, target: [u8; 4], started: u64) -> Result<u64, u64> {
        self.ping_reply = None;
        self.send_echo(target, started)?;
        let deadline = started.saturating_add(3_000);
        loop {
            let now = platform::time::ticks().map_err(|e| e.raw().unsigned_abs())?;
            self.tick(now);
            while self.poll_receive(now)? {}
            if let Some((address, _, rtt)) = self.ping_reply
                && address == target
            {
                return Ok(rtt);
            }
            if self.ping_sent.is_none() {
                let _ = self.send_echo(target, now);
            }
            if now >= deadline {
                return Err(mochi_user_syscall::EAGAIN);
            }
            platform::thread::yield_now()
        }
    }
    pub(crate) fn driver_statistics(
        &mut self,
    ) -> Result<mochios_net_device_protocol::DeviceStatistics, u64> {
        self.driver.statistics()
    }
}
