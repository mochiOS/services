use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::driver::DriverClient;
use mochi_user_platform as platform;
use mochios_net_device_protocol::{InterfaceInfo, StackStatistics};
use mochios_network_stack::{
    ARP_LEN, ARP_REPLY, ARP_REQUEST, ArpCache, ArpEntry, ArpPacket, BROADCAST_MAC,
    DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_MAX_MESSAGE_LEN, DNS_PORT, DhcpClient, DhcpMessageType,
    DhcpState, DnsCache, DnsError, DnsErrorKind, DnsName, DnsResponseCode, DnsRetry,
    DnsRetryAction, ETHERTYPE_ARP, ETHERTYPE_IPV4, EchoPacket, EthernetHeader, Ipv4Config,
    Ipv4Header, PacketError, TCP_PROTOCOL, TcpConnection, TcpConnectionError, TcpConnectionTable,
    TcpReceiveResult, TcpSegment, TcpState, TcpTransmit, TcpTuple, UdpDatagram, UdpSocketTable,
    decode_dns_response, decode_reply, encode_dns_query, encode_request, next_hop,
    parse_ipv4_literal,
};

const ARP_TTL: u64 = 60_000;
const RETRY_TICKS: u64 = 1_000;
const MAX_RETRIES: u8 = 5;
const UDP_SOCKET_LIMIT: usize = 8;
const UDP_QUEUE_LIMIT: usize = 8;
const UDP_PAYLOAD_LIMIT: usize = 1_472;
const PENDING_IPV4_LIMIT: usize = 8;
const DNS_CACHE_LIMIT: usize = 32;
const DNS_RETRY_DELAY: u64 = 500;
const DNS_RETRY_LIMIT: u8 = 3;
const TCP_CONNECTION_LIMIT: usize = 16;
const TCP_SEND_BUFFER_LIMIT: usize = 16 * 1024;
const TCP_RECEIVE_BUFFER_LIMIT: usize = 16 * 1024;
const TCP_RETRANSMIT_TIMEOUT: u64 = 500;
const TCP_RETRY_LIMIT: u8 = 5;
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
    dns_cache: DnsCache,
    tcp: TcpConnectionTable,
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
            dns_cache: DnsCache::new(DNS_CACHE_LIMIT),
            tcp: TcpConnectionTable::new(TCP_CONNECTION_LIMIT),
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
        for (handle, owner) in self.tcp.keys() {
            let _ = self.drive_tcp(handle, owner, now);
        }
        self.tcp.remove_closed();
    }
    pub(crate) fn poll_receive(&mut self, now: u64) -> Result<bool, u64> {
        let frame = match self.driver.receive() {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(false),
            Err(errno) => {
                self.interface_failed();
                return Err(errno);
            }
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
        } else if header.protocol == TCP_PROTOCOL
            && self
                .config
                .is_some_and(|config| config.address == header.destination)
        {
            return self.handle_tcp(header, payload, now);
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

    fn handle_tcp(
        &mut self,
        header: Ipv4Header,
        payload: &[u8],
        now: u64,
    ) -> Result<(), PacketError> {
        let segment = match TcpSegment::decode(header.source, header.destination, payload) {
            Ok(segment) => segment,
            Err(PacketError::InvalidChecksum) => {
                self.stats.tcp_checksum_errors = self.stats.tcp_checksum_errors.saturating_add(1);
                return Err(PacketError::Mismatch);
            }
            Err(error) => return Err(error),
        };
        let tuple = TcpTuple {
            local_address: header.destination,
            local_port: segment.destination_port,
            remote_address: header.source,
            remote_port: segment.source_port,
        };
        self.stats.tcp_segments_received = self.stats.tcp_segments_received.saturating_add(1);
        let received = {
            let connection = self
                .tcp
                .find_tuple_mut(tuple)
                .ok_or(PacketError::Mismatch)?;
            connection.on_segment(&segment, now).map(|result| {
                let acknowledgment = matches!(
                    result,
                    TcpReceiveResult::Acknowledge
                        | TcpReceiveResult::DuplicateSegment
                        | TcpReceiveResult::OutOfOrder
                )
                .then(|| connection.acknowledgment());
                (result, acknowledgment)
            })
        };
        let (result, acknowledgment) = match received {
            Ok(received) => received,
            Err(TcpConnectionError::ReceiveBufferFull) => {
                self.stats.tcp_receive_drops = self.stats.tcp_receive_drops.saturating_add(1);
                return Err(PacketError::Capacity);
            }
            Err(_) => return Err(PacketError::Mismatch),
        };
        if result == TcpReceiveResult::Reset {
            self.stats.tcp_resets = self.stats.tcp_resets.saturating_add(1);
        }
        if segment.flags
            & (mochios_network_stack::TCP_FLAG_SYN | mochios_network_stack::TCP_FLAG_ACK)
            == mochios_network_stack::TCP_FLAG_SYN | mochios_network_stack::TCP_FLAG_ACK
            && result == TcpReceiveResult::Acknowledge
        {
            platform::println!("network.service: TCP SYN+ACK received");
        }
        if let Some(acknowledgment) = acknowledgment {
            self.send_tcp(tuple, acknowledgment, now)
                .map_err(|_| PacketError::Capacity)?;
        }
        Ok(())
    }

    fn interface_failed(&mut self) {
        self.config = None;
        self.arp_pending = None;
        self.pending_ipv4.clear();
        self.tcp.abort_all();
        self.tcp.clear();
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

    pub(crate) fn resolve_ipv4(
        &mut self,
        hostname: &str,
        started: u64,
        timeout: u64,
        random: u64,
    ) -> Result<([u8; 4], bool), u64> {
        if let Some(address) = parse_ipv4_literal(hostname) {
            return Ok((address, false));
        }
        let name = DnsName::parse(hostname).map_err(dns_errno)?;
        let dns_server = self
            .config
            .map(|config| config.dns)
            .filter(|address| *address != [0; 4])
            .ok_or(mochi_user_syscall::ENXIO)?;
        if let Some(address) = self.dns_cache.lookup(&name, started) {
            self.stats.dns_cache_hits = self.stats.dns_cache_hits.saturating_add(1);
            return Ok((address, true));
        }
        self.stats.dns_cache_misses = self.stats.dns_cache_misses.saturating_add(1);
        let source_port = self.udp.bind(0).map_err(|_| mochi_user_syscall::EAGAIN)?;
        let result = self.resolve_dns_query(
            &name,
            dns_server,
            source_port,
            random as u16,
            started,
            timeout,
        );
        self.udp.unbind(source_port);
        result.map(|address| (address, false))
    }

    fn resolve_dns_query(
        &mut self,
        name: &DnsName,
        dns_server: [u8; 4],
        source_port: u16,
        transaction_id: u16,
        started: u64,
        timeout: u64,
    ) -> Result<[u8; 4], u64> {
        let mut query = [0u8; DNS_MAX_MESSAGE_LEN];
        let query_length = encode_dns_query(transaction_id, name, &mut query).map_err(dns_errno)?;
        let mut retry = DnsRetry::new(started, timeout, DNS_RETRY_DELAY, DNS_RETRY_LIMIT);
        loop {
            let now = platform::time::ticks().map_err(|error| error.raw().unsigned_abs())?;
            match retry.poll(now) {
                DnsRetryAction::Send => {
                    self.send_udp(
                        source_port,
                        DNS_PORT,
                        dns_server,
                        &query[..query_length],
                        now,
                    )?;
                    self.stats.dns_queries = self.stats.dns_queries.saturating_add(1);
                    platform::println!(
                        "network.service: DNS query sent name={} attempt={}",
                        name.as_str(),
                        retry.attempts()
                    );
                }
                DnsRetryAction::Failed(DnsErrorKind::Timeout) => {
                    self.stats.dns_timeouts = self.stats.dns_timeouts.saturating_add(1);
                    return Err(mochi_user_syscall::EAGAIN);
                }
                DnsRetryAction::Failed(DnsErrorKind::RetryLimit) => {
                    self.stats.dns_failures = self.stats.dns_failures.saturating_add(1);
                    return Err(mochi_user_syscall::EAGAIN);
                }
                DnsRetryAction::Wait => {}
            }
            self.tick(now);
            while self.poll_receive(now)? {}
            while let Some(packet) = self.udp.receive(source_port) {
                if packet.source_address != dns_server
                    || packet.source_port != DNS_PORT
                    || packet.destination_port != source_port
                {
                    continue;
                }
                match decode_dns_response(&packet.payload, transaction_id, name) {
                    Ok(answer) => {
                        platform::println!(
                            "network.service: DNS response received name={}",
                            name.as_str()
                        );
                        self.dns_cache
                            .insert(name, answer.address, answer.ttl_seconds, now)
                            .map_err(dns_errno)?;
                        platform::println!(
                            "network.service: DNS resolved name={} address={}.{}.{}.{}",
                            name.as_str(),
                            answer.address[0],
                            answer.address[1],
                            answer.address[2],
                            answer.address[3]
                        );
                        return Ok(answer.address);
                    }
                    Err(DnsError::TransactionMismatch)
                    | Err(DnsError::Response(DnsResponseCode::ServerFailure)) => continue,
                    Err(error) => {
                        self.stats.dns_failures = self.stats.dns_failures.saturating_add(1);
                        return Err(dns_errno(error));
                    }
                }
            }
            platform::thread::yield_now();
        }
    }

    fn send_udp(
        &mut self,
        source_port: u16,
        destination_port: u16,
        destination: [u8; 4],
        payload: &[u8],
        now: u64,
    ) -> Result<(), u64> {
        let source = self
            .config
            .map(|config| config.address)
            .ok_or(mochi_user_syscall::ENXIO)?;
        let mut udp = [0u8; 1_500];
        let length = UdpDatagram {
            source_port,
            destination_port,
            payload,
        }
        .encode(source, destination, &mut udp)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        self.send_routed_ipv4(destination, 17, &udp[..length], now)
    }

    pub(crate) fn tcp_connect(
        &mut self,
        owner: u64,
        remote_address: [u8; 4],
        remote_port: u16,
        started: u64,
        timeout: u64,
        random: u64,
    ) -> Result<u64, u64> {
        if remote_port == 0 {
            return Err(mochi_user_syscall::EINVAL);
        }
        let local_address = self
            .config
            .map(|config| config.address)
            .ok_or(mochi_user_syscall::ENXIO)?;
        let local_port = self.tcp.allocate_port(random as u16).map_err(tcp_errno)?;
        let handle = self
            .tcp
            .allocate_handle(random.rotate_left(17))
            .map_err(tcp_errno)?;
        let local_mss = self.info.mtu.saturating_sub(40).max(1);
        let connection = TcpConnection::connect(
            handle,
            owner,
            TcpTuple {
                local_address,
                local_port,
                remote_address,
                remote_port,
            },
            (random >> 32) as u32,
            local_mss,
            TCP_SEND_BUFFER_LIMIT,
            TCP_RECEIVE_BUFFER_LIMIT,
            TCP_RETRANSMIT_TIMEOUT,
            TCP_RETRY_LIMIT,
        );
        self.tcp.insert(connection).map_err(tcp_errno)?;
        self.stats.tcp_connections_attempted =
            self.stats.tcp_connections_attempted.saturating_add(1);
        let deadline = started.saturating_add(timeout);
        loop {
            let now = platform::time::ticks().map_err(|error| error.raw().unsigned_abs())?;
            if let Err(errno) = self.drive_tcp(handle, owner, now) {
                self.remove_tcp_connection(handle, owner);
                self.stats.tcp_connections_failed =
                    self.stats.tcp_connections_failed.saturating_add(1);
                return Err(errno);
            }
            while self.poll_receive(now)? {}
            let state = self.tcp.get_mut(handle, owner).map_err(tcp_errno)?.state;
            if state == TcpState::Established {
                self.stats.tcp_connections_established =
                    self.stats.tcp_connections_established.saturating_add(1);
                platform::println!(
                    "network.service: TCP Established remote={}.{}.{}.{}:{}",
                    remote_address[0],
                    remote_address[1],
                    remote_address[2],
                    remote_address[3],
                    remote_port
                );
                return Ok(handle);
            }
            if state == TcpState::Reset {
                self.remove_tcp_connection(handle, owner);
                self.stats.tcp_connections_failed =
                    self.stats.tcp_connections_failed.saturating_add(1);
                return Err(mochi_user_syscall::EPIPE);
            }
            if now >= deadline {
                self.tcp.get_mut(handle, owner).map_err(tcp_errno)?.abort();
                self.remove_tcp_connection(handle, owner);
                self.stats.tcp_connections_failed =
                    self.stats.tcp_connections_failed.saturating_add(1);
                self.stats.tcp_timeouts = self.stats.tcp_timeouts.saturating_add(1);
                return Err(mochi_user_syscall::EAGAIN);
            }
            platform::thread::yield_now();
        }
    }

    pub(crate) fn tcp_send(
        &mut self,
        owner: u64,
        handle: u64,
        data: &[u8],
        started: u64,
        timeout: u64,
    ) -> Result<usize, u64> {
        if let Err(error) = self
            .tcp
            .get_mut(handle, owner)
            .map_err(tcp_errno)?
            .queue_send(data)
        {
            self.stats.tcp_send_drops = self.stats.tcp_send_drops.saturating_add(1);
            return Err(tcp_errno(error));
        }
        let deadline = started.saturating_add(timeout);
        loop {
            let now = platform::time::ticks().map_err(|error| error.raw().unsigned_abs())?;
            if let Err(errno) = self.drive_tcp(handle, owner, now) {
                self.remove_tcp_connection(handle, owner);
                return Err(errno);
            }
            while self.poll_receive(now)? {}
            let connection = self.tcp.get_mut(handle, owner).map_err(tcp_errno)?;
            if connection.queued_send_len() == 0 && !connection.has_unacknowledged() {
                platform::println!(
                    "network.service: TCP payload acknowledged bytes={}",
                    data.len()
                );
                return Ok(data.len());
            }
            if matches!(connection.state, TcpState::Reset | TcpState::Closed) {
                self.remove_tcp_connection(handle, owner);
                return Err(mochi_user_syscall::EPIPE);
            }
            if now >= deadline {
                connection.abort();
                self.remove_tcp_connection(handle, owner);
                self.stats.tcp_timeouts = self.stats.tcp_timeouts.saturating_add(1);
                return Err(mochi_user_syscall::EAGAIN);
            }
            platform::thread::yield_now();
        }
    }

    pub(crate) fn tcp_receive(
        &mut self,
        owner: u64,
        handle: u64,
        out: &mut [u8],
        started: u64,
        timeout: u64,
    ) -> Result<(usize, bool), u64> {
        let deadline = started.saturating_add(timeout);
        loop {
            let now = platform::time::ticks().map_err(|error| error.raw().unsigned_abs())?;
            if let Err(errno) = self.drive_tcp(handle, owner, now) {
                self.remove_tcp_connection(handle, owner);
                return Err(errno);
            }
            while self.poll_receive(now)? {}
            let (length, closed, acknowledgment) = {
                let connection = self.tcp.get_mut(handle, owner).map_err(tcp_errno)?;
                if connection.state == TcpState::Reset {
                    self.remove_tcp_connection(handle, owner);
                    return Err(mochi_user_syscall::EPIPE);
                }
                let previous_window = connection.local_window();
                let length = connection.receive(out);
                let closed = matches!(
                    connection.state,
                    TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait | TcpState::Closed
                );
                let acknowledgment = (length != 0 && connection.local_window() > previous_window)
                    .then(|| (connection.tuple, connection.acknowledgment()));
                (length, closed, acknowledgment)
            };
            if let Some((tuple, acknowledgment)) = acknowledgment {
                self.send_tcp(tuple, acknowledgment, now)?;
            }
            if length != 0 || closed {
                if length != 0 {
                    platform::println!("network.service: TCP payload received bytes={}", length);
                }
                return Ok((length, closed));
            }
            if now >= deadline {
                return Err(mochi_user_syscall::EAGAIN);
            }
            platform::thread::yield_now();
        }
    }

    pub(crate) fn tcp_close(
        &mut self,
        owner: u64,
        handle: u64,
        started: u64,
        timeout: u64,
    ) -> Result<(), u64> {
        self.tcp
            .get_mut(handle, owner)
            .map_err(tcp_errno)?
            .request_close()
            .map_err(tcp_errno)?;
        let deadline = started.saturating_add(timeout);
        loop {
            let now = platform::time::ticks().map_err(|error| error.raw().unsigned_abs())?;
            if let Err(errno) = self.drive_tcp(handle, owner, now) {
                self.remove_tcp_connection(handle, owner);
                return Err(errno);
            }
            while self.poll_receive(now)? {}
            let connection = self.tcp.get_mut(handle, owner).map_err(tcp_errno)?;
            if matches!(connection.state, TcpState::TimeWait | TcpState::Closed) {
                platform::println!("network.service: TCP FIN close complete");
                return Ok(());
            }
            if connection.state == TcpState::Reset {
                self.remove_tcp_connection(handle, owner);
                return Err(mochi_user_syscall::EPIPE);
            }
            if now >= deadline {
                connection.abort();
                self.remove_tcp_connection(handle, owner);
                self.stats.tcp_timeouts = self.stats.tcp_timeouts.saturating_add(1);
                return Err(mochi_user_syscall::EAGAIN);
            }
            platform::thread::yield_now();
        }
    }

    fn drive_tcp(&mut self, handle: u64, owner: u64, now: u64) -> Result<(), u64> {
        let transmit = {
            let connection = self.tcp.get_mut(handle, owner).map_err(tcp_errno)?;
            connection.tick(now);
            connection.poll_transmit(now).map_err(tcp_errno)?
        };
        if let Some(transmit) = transmit {
            let tuple = self.tcp.get_mut(handle, owner).map_err(tcp_errno)?.tuple;
            if transmit.retransmission {
                self.stats.tcp_retransmissions = self.stats.tcp_retransmissions.saturating_add(1);
            }
            self.send_tcp(tuple, transmit, now)?;
        }
        Ok(())
    }

    fn remove_tcp_connection(&mut self, handle: u64, owner: u64) {
        let tuple = self
            .tcp
            .get_mut(handle, owner)
            .ok()
            .map(|connection| connection.tuple);
        if let Some(tuple) = tuple {
            let before = self.pending_ipv4.len();
            let local_port = tuple.local_port.to_be_bytes();
            let remote_port = tuple.remote_port.to_be_bytes();
            self.pending_ipv4.retain(|packet| {
                packet.protocol != TCP_PROTOCOL
                    || packet.destination != tuple.remote_address
                    || packet.payload.get(..2) != Some(local_port.as_slice())
                    || packet.payload.get(2..4) != Some(remote_port.as_slice())
            });
            self.stats.tx_dropped = self
                .stats
                .tx_dropped
                .saturating_add(before.saturating_sub(self.pending_ipv4.len()) as u64);
        }
        self.tcp.remove(handle, owner);
    }

    fn send_tcp(&mut self, tuple: TcpTuple, transmit: TcpTransmit, now: u64) -> Result<(), u64> {
        let mut segment = [0u8; 1_500];
        let length = TcpSegment {
            source_port: tuple.local_port,
            destination_port: tuple.remote_port,
            sequence: transmit.sequence,
            acknowledgment: transmit.acknowledgment,
            flags: transmit.flags,
            window: transmit.window,
            urgent_pointer: 0,
            options: transmit.options,
            payload: &transmit.payload,
        }
        .encode(tuple.local_address, tuple.remote_address, &mut segment)
        .map_err(|_| mochi_user_syscall::EINVAL)?;
        self.send_routed_ipv4(tuple.remote_address, TCP_PROTOCOL, &segment[..length], now)?;
        self.stats.tcp_segments_sent = self.stats.tcp_segments_sent.saturating_add(1);
        if transmit.flags & mochios_network_stack::TCP_FLAG_SYN != 0 && !transmit.retransmission {
            platform::println!("network.service: TCP SYN sent");
        }
        Ok(())
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

fn dns_errno(error: DnsError) -> u64 {
    match error {
        DnsError::Response(DnsResponseCode::NameError) => mochi_user_syscall::ENOENT,
        DnsError::Response(DnsResponseCode::ServerFailure)
        | DnsError::Timeout
        | DnsError::RetryLimit => mochi_user_syscall::EAGAIN,
        DnsError::CacheCapacity => mochi_user_syscall::ENOMEM,
        DnsError::UnsupportedRecord => mochi_user_syscall::ENOTSUP,
        _ => mochi_user_syscall::EINVAL,
    }
}

fn tcp_errno(error: TcpConnectionError) -> u64 {
    match error {
        TcpConnectionError::Ownership => mochi_user_syscall::EACCES,
        TcpConnectionError::NotFound => mochi_user_syscall::ENOENT,
        TcpConnectionError::SendBufferFull
        | TcpConnectionError::ReceiveBufferFull
        | TcpConnectionError::Capacity
        | TcpConnectionError::PortUnavailable => mochi_user_syscall::EAGAIN,
        TcpConnectionError::ConnectionReset => mochi_user_syscall::EPIPE,
        TcpConnectionError::Timeout | TcpConnectionError::RetryLimit => mochi_user_syscall::EAGAIN,
        TcpConnectionError::InvalidState | TcpConnectionError::InvalidAcknowledgment => {
            mochi_user_syscall::EINVAL
        }
    }
}
