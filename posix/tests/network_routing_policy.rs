//! Production network-service routing with real packet/configuration types.
//! Only device I/O is replaced; failed configuration must not reach hardware.
#![allow(dead_code)]
extern crate alloc;
extern crate self as mochi_user_platform;
thread_local! { static MODE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
thread_local! {
    static TRANSMITTED: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
    static ENTROPY_DRAWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub mod service_ready {
    pub fn generate_token() -> mochi_user_syscall::SysResult<u64> {
        crate::ENTROPY_DRAWS.with(|draws| draws.set(draws.get() + 1));
        if crate::MODE.with(|mode| mode.get()) == 4 {
            Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EIO as i64,
            ))
        } else {
            Ok(500u64 << 32 | 17)
        }
    }
}
#[macro_export]
macro_rules! logln { ($($arg:tt)*) => {{ let _ = format_args!($($arg)*); }}; }
pub mod time {
    pub fn ticks() -> Result<u64, mochi_user_syscall::SysError> {
        if crate::MODE.with(|mode| mode.get()) == 2 {
            Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::NativeError::PeerClosed.into_raw() as i64,
            ))
        } else {
            Ok(0)
        }
    }
}
pub mod thread {
    pub fn yield_now() {
        panic!("unexpected blocking network loop")
    }
}

#[path = "../../network/src/stream.rs"]
mod stream;
#[path = "../../network/src/datagram.rs"]
mod datagram;
#[path = "../../network/src/status.rs"]
mod status;
pub mod syscall {
    pub use mochi_user_syscall::*;
}
mod driver {
    use mochios_net_device_protocol::{DRIVER_NAME_LEN, DeviceStatistics, InterfaceInfo};
    pub(crate) struct DriverClient;
    impl DriverClient {
        pub(crate) fn info(&mut self) -> Result<InterfaceInfo, u64> {
            Ok(InterfaceInfo {
                interface_id: 1,
                mac: [2, 0, 0, 0, 0, 1],
                link_up: true,
                mtu: if crate::MODE.with(|mode|mode.get())==5 {600}else{1500},
                driver_id: 0,
                device_id: 0,
                driver_name: [0; DRIVER_NAME_LEN],
            })
        }
        pub(crate) fn transmit(&mut self, frame: &[u8]) -> Result<(), u64> {
            if crate::MODE.with(|mode| mode.get()) == 1 {
                return Err(mochi_user_syscall::EIO);
            }
            if crate::MODE.with(|mode| mode.get()) == 6 { return Err(mochi_user_syscall::EAGAIN); }
            if crate::MODE.with(|mode| mode.get()) >= 3 {
                crate::TRANSMITTED.with(|frames| frames.borrow_mut().push(frame.to_vec()));
                return Ok(());
            }
            panic!("configuration failure must not transmit")
        }
        pub(crate) fn receive(&mut self) -> Result<Option<Vec<u8>>, u64> {
            if crate::MODE.with(|mode| mode.get()) == 7 {
                return Ok(None);
            }
            panic!("configuration failure must not poll devices")
        }
        pub(crate) fn statistics(&mut self) -> Result<DeviceStatistics, u64> {
            panic!("unexpected driver statistics")
        }
    }
}

mod production {
    include!("../../network/src/stack.rs");

    fn tcp_fixture() -> (NetworkStack, TcpTuple) {
        crate::MODE.with(|mode| mode.set(3));
        crate::ENTROPY_DRAWS.with(|draws| draws.set(0));
        crate::TRANSMITTED.with(|frames| frames.borrow_mut().clear());
        let mut stack = NetworkStack::new(DriverClient, 7).unwrap();
        let tuple = TcpTuple {
            local_address: [10, 0, 2, 2],
            local_port: 50000,
            remote_address: [10, 0, 2, 15],
            remote_port: 8000,
        };
        stack.config = Some(Ipv4Config {
            address: tuple.remote_address,
            subnet_mask: [255, 255, 255, 0],
            gateway: tuple.local_address,
            dns: [0; 4],
        });
        stack.arp.insert(ArpEntry {
            ip: tuple.local_address,
            mac: [2, 0, 0, 0, 0, 2],
            expires_at: 10000,
        });
        (stack, tuple)
    }

    fn tcp_packet(tuple: TcpTuple, tx: &TcpTransmit) -> Vec<u8> {
        let mut tcp = [0; 1500];
        let n = TcpSegment {
            source_port: tuple.local_port,
            destination_port: tuple.remote_port,
            sequence: tx.sequence,
            acknowledgment: tx.acknowledgment,
            flags: tx.flags,
            window: tx.window,
            urgent_pointer: 0,
            options: tx.options,
            payload: &tx.payload,
        }
        .encode(tuple.local_address, tuple.remote_address, &mut tcp)
        .unwrap();
        let mut packet = vec![0; n + 20];
        Ipv4Header {
            source: tuple.local_address,
            destination: tuple.remote_address,
            protocol: TCP_PROTOCOL,
            ttl: 64,
            identification: 1,
        }
        .encode(&tcp[..n], &mut packet)
        .unwrap();
        packet
    }

    fn tcp_reply() -> Vec<u8> {
        crate::TRANSMITTED.with(|frames| frames.borrow_mut().pop().unwrap())
    }

    fn decode_tcp_reply(frame: &[u8]) -> TcpSegment<'_> {
        let (ethernet, ip) = EthernetHeader::decode(frame).unwrap();
        assert_eq!(ethernet.destination, [2, 0, 0, 0, 0, 2]);
        let (header, tcp) = Ipv4Header::decode(ip).unwrap();
        assert_eq!(header.protocol, TCP_PROTOCOL);
        TcpSegment::decode(header.source, header.destination, tcp).unwrap()
    }

    #[test]
    fn real_tcp_input_admits_listener_tracks_accept_and_delivers_data() {
        let (mut stack, tuple) = tcp_fixture();
        stack
            .tcp.table
            .listen(
                1,
                7,
                [0; 4],
                8000,
                mochios_network_stack::TcpListenConfig {
                    backlog: 2,
                    local_mss: 1200,
                    send_capacity: 64,
                    receive_capacity: 64,
                    retransmit_timeout: 10,
                    retry_limit: 2,
                },
            )
            .unwrap();
        let mut client = TcpConnection::connect(90, 9, tuple, 100, 1200, 64, 64, 10, 2);
        let syn = client.poll_transmit(0).unwrap().unwrap();
        let input = tcp_packet(tuple, &syn);
        stack.handle_ipv4(&input, 0).unwrap();
        let frame = tcp_reply();
        let syn_ack = decode_tcp_reply(&frame);
        assert_eq!(syn_ack.sequence, 500);
        assert_eq!(stack.tcp.table.accept(1, 7), Ok(None));
        stack.handle_ipv4(&input, 1).unwrap();
        let retry = tcp_reply();
        assert_eq!(decode_tcp_reply(&retry), syn_ack);
        assert_eq!(stack.stats.tcp_retransmissions, 1);
        assert_eq!(crate::ENTROPY_DRAWS.with(|draws| draws.get()), 1);
        assert_eq!(
            client.on_segment(&syn_ack, 1),
            Ok(TcpReceiveResult::Acknowledge)
        );
        stack
            .handle_ipv4(&tcp_packet(tuple, &client.acknowledgment()), 2)
            .unwrap();
        let (accepted, _) = stack.tcp.table.accept(1, 7).unwrap().unwrap();
        assert_eq!(stack.tcp.table.accept(1, 7), Ok(None));
        client.queue_send(b"hello").unwrap();
        let data = client.poll_transmit(3).unwrap().unwrap();
        stack.handle_ipv4(&tcp_packet(tuple, &data), 3).unwrap();
        let frame = tcp_reply();
        client.on_segment(&decode_tcp_reply(&frame), 3).unwrap();
        assert!(!client.has_unacknowledged());
        let mut bytes = [0; 5];
        assert_eq!(
            stack.tcp.table.get_mut(accepted, 7).unwrap().receive(&mut bytes),
            5
        );
        assert_eq!(&bytes, b"hello");
        assert_eq!(stack.stats.tcp_segments_received, 4);
        assert_eq!(stack.stats.tcp_segments_sent, 3);
        crate::MODE.with(|mode| mode.set(0));
    }

    #[test]
    fn tcp_input_rejects_checksum_entropy_and_non_unicast_sources_before_output() {
        let (mut stack, tuple) = tcp_fixture();
        stack
            .tcp.table
            .listen(
                1,
                7,
                [0; 4],
                8000,
                mochios_network_stack::TcpListenConfig {
                    backlog: 2,
                    local_mss: 1200,
                    send_capacity: 64,
                    receive_capacity: 64,
                    retransmit_timeout: 10,
                    retry_limit: 2,
                },
            )
            .unwrap();
        let mut client = TcpConnection::connect(90, 9, tuple, 100, 1200, 64, 64, 10, 2);
        let syn = client.poll_transmit(0).unwrap().unwrap();
        let mut damaged = tcp_packet(tuple, &syn);
        *damaged.last_mut().unwrap() ^= 1;
        assert_eq!(stack.handle_ipv4(&damaged, 0), Err(PacketError::Mismatch));
        assert_eq!(stack.stats.tcp_checksum_errors, 1);
        for source in [
            [127, 0, 0, 1],
            [10, 0, 2, 255],
            [0; 4],
            [224, 0, 0, 1],
            [255; 4],
        ] {
            let t = TcpTuple {
                local_address: source,
                ..tuple
            };
            assert_eq!(
                stack.handle_ipv4(&tcp_packet(t, &syn), 0),
                Err(PacketError::Mismatch)
            );
        }
        assert_eq!(crate::ENTROPY_DRAWS.with(|draws| draws.get()), 0);
        crate::MODE.with(|mode| mode.set(4));
        assert_eq!(
            stack.handle_ipv4(&tcp_packet(tuple, &syn), 0),
            Err(PacketError::Mismatch)
        );
        assert_eq!(crate::ENTROPY_DRAWS.with(|draws| draws.get()), 1);
        assert!(stack.tcp.table.is_empty());
        assert!(crate::TRANSMITTED.with(|frames| frames.borrow().is_empty()));
        crate::MODE.with(|mode| mode.set(0));
    }

    #[test]
    fn thirty_one_bit_subnet_peer_is_not_mistaken_for_directed_broadcast() {
        let (mut stack, tuple) = tcp_fixture();
        let tuple = TcpTuple {
            local_address: [10, 0, 2, 255],
            remote_address: [10, 0, 2, 254],
            ..tuple
        };
        stack.config = Some(Ipv4Config {
            address: tuple.remote_address,
            subnet_mask: [255, 255, 255, 254],
            gateway: [0; 4],
            dns: [0; 4],
        });
        stack.arp.insert(ArpEntry {
            ip: tuple.local_address,
            mac: [2, 0, 0, 0, 0, 2],
            expires_at: 10000,
        });
        let mut client = TcpConnection::connect(90, 9, tuple, 100, 1200, 64, 64, 10, 2);
        let syn = client.poll_transmit(0).unwrap().unwrap();
        stack.handle_ipv4(&tcp_packet(tuple, &syn), 0).unwrap();
        let frame = tcp_reply();
        let tx = decode_tcp_reply(&frame);
        assert_eq!(
            tx.flags,
            mochios_network_stack::TCP_FLAG_RST | mochios_network_stack::TCP_FLAG_ACK
        );
        assert_eq!(client.on_segment(&tx, 1), Ok(TcpReceiveResult::Reset));
        assert_eq!(crate::ENTROPY_DRAWS.with(|draws| draws.get()), 0);
        crate::MODE.with(|mode| mode.set(0));
    }

    #[test]
    fn reset_maps_to_the_network_wire_status_without_posix_kernel_errno() {
        let raw = tcp_errno(TcpConnectionError::ConnectionReset);
        assert_eq!(raw as i64, -32);
        assert_eq!(
            raw,
            mochios_net_device_protocol::STATUS_PEER_CLOSED as i64 as u64
        );
    }

    #[test]
    fn missing_configuration_rejects_routed_udp_dns_and_tcp_before_io() {
        let mut stack = NetworkStack::new(DriverClient, 7).unwrap();
        let failure = mochios_net_device_protocol::STATUS_NETWORK_UNAVAILABLE as i64 as u64;
        assert_eq!(failure as i64, -6);
        assert_eq!(
            stack.send_routed_ipv4([192, 0, 2, 1], 17, b"packet", 0),
            Err(failure)
        );
        assert_eq!(
            stack.send_udp(1000, 1001, [192, 0, 2, 1], b"packet", 0),
            Err(failure)
        );
        assert_eq!(stack.resolve_ipv4("example.com", 0, 1, 9), Err(failure));
        assert_eq!(
            stack.tcp_connect(7, [192, 0, 2, 1], 443, 0, 1, 9),
            Err(failure)
        );
        // Literal resolution requires neither DNS nor an installed route.
        assert_eq!(
            stack.resolve_ipv4("192.0.2.1", 0, 1, 9),
            Ok(([192, 0, 2, 1], false))
        );
        assert!(stack.pending_ipv4.is_empty());
    }

    #[test]
    fn missing_gateway_dns_and_invalid_subnet_keep_the_same_service_status() {
        let mut stack = NetworkStack::new(DriverClient, 7).unwrap();
        let failure = mochios_net_device_protocol::STATUS_NETWORK_UNAVAILABLE as i64 as u64;
        let config = Ipv4Config {
            address: [10, 0, 0, 1],
            subnet_mask: [255, 255, 255, 0],
            gateway: [0; 4],
            dns: [0; 4],
        };
        stack.config = Some(config);
        assert_eq!(
            stack.send_routed_ipv4([192, 0, 2, 1], 17, b"packet", 0),
            Err(failure)
        );
        assert_eq!(stack.resolve_ipv4("example.com", 0, 1, 9), Err(failure));
        stack.config = Some(Ipv4Config {
            subnet_mask: [0; 4],
            ..config
        });
        assert_eq!(
            stack.send_routed_ipv4([10, 0, 0, 2], 17, b"packet", 0),
            Err(failure)
        );
        assert!(stack.pending_ipv4.is_empty());
        assert_eq!(stack.stats.tx_packets, 0);
    }
    #[test]
    fn dns_clock_and_transmit_failures_release_exactly_the_query_binding() {
        for mode in [1, 2] {
            crate::MODE.with(|value| value.set(mode));
            let mut stack = NetworkStack::new(DriverClient, 7).unwrap();
            stack.config = Some(Ipv4Config {
                address: [192, 0, 2, 1],
                subnet_mask: [255, 255, 255, 0],
                gateway: [0; 4],
                dns: [192, 0, 2, 53],
            });
            stack.arp.insert(ArpEntry {
                ip: [192, 0, 2, 53],
                mac: [2, 0, 0, 0, 0, 53],
                expires_at: 10000,
            });
            for _ in 0..32 {
                assert!(stack.resolve_ipv4("example.com", 0, 100, 19).is_err());
                assert_eq!(
                    stack.udp.local_endpoint(stack.dhcp_socket).unwrap().port,
                    DHCP_CLIENT_PORT
                );
                let mut probes = Vec::new();
                for _ in 1..UDP_SOCKET_LIMIT {
                    probes.push(stack.udp.bind_endpoint([192, 0, 2, 1], 0).unwrap());
                }
                assert_eq!(
                    stack.udp.bind_endpoint([192, 0, 2, 1], 0),
                    Err(PacketError::Capacity)
                );
                for id in probes {
                    assert!(stack.udp.unbind_endpoint(id));
                }
            }
            crate::MODE.with(|value| value.set(0));
        }
    }

    #[test]
    fn real_ipv4_udp_packets_route_to_the_exact_local_binding() {
        let mut stack = NetworkStack::new(DriverClient, 7).unwrap();
        let a = stack.udp.bind_endpoint([192, 0, 2, 1], 9000).unwrap();
        let b = stack.udp.bind_endpoint([192, 0, 2, 2], 9000).unwrap();
        for (address, byte) in [
            ([192, 0, 2, 1], 1),
            ([192, 0, 2, 2], 2),
            ([192, 0, 2, 3], 3),
        ] {
            let mut udp = [0; 32];
            let n = UdpDatagram {
                source_port: 1234,
                destination_port: 9000,
                payload: &[byte],
            }
            .encode([198, 51, 100, 1], address, &mut udp)
            .unwrap();
            let mut packet = [0; 64];
            let n = Ipv4Header {
                source: [198, 51, 100, 1],
                destination: address,
                protocol: 17,
                ttl: 64,
                identification: 1,
            }
            .encode(&udp[..n], &mut packet)
            .unwrap();
            assert_eq!(
                stack.handle_ipv4(&packet[..n], 0),
                if byte == 3 {
                    Err(PacketError::Mismatch)
                } else {
                    Ok(())
                }
            );
        }
        assert_eq!(stack.udp.receive_for(a).unwrap().unwrap().payload, [1]);
        assert_eq!(stack.udp.receive_for(b).unwrap().unwrap().payload, [2]);
        assert_eq!(stack.udp.queued_for(stack.dhcp_socket), Ok(0));
    }
    #[test]
    fn dns_installs_the_server_filter_before_receive_and_rejects_foreign_packets() {
        let mut stack = NetworkStack::new(DriverClient, 7).unwrap();
        let local = [192, 0, 2, 1];
        let server = [192, 0, 2, 53];
        let socket = stack.udp.bind_endpoint(local, 8300).unwrap();
        crate::MODE.with(|value| value.set(2));
        assert!(
            stack
                .resolve_dns_query(
                    &DnsName::parse("example.com").unwrap(),
                    server,
                    socket,
                    9,
                    0,
                    100
                )
                .is_err()
        );
        crate::MODE.with(|value| value.set(0));
        assert_eq!(
            stack.udp.peer(socket),
            Ok(Some(UdpEndpoint {
                address: server,
                port: DNS_PORT
            }))
        );
        for (source, port, allowed) in [
            ([192, 0, 2, 54], DNS_PORT, false),
            (server, 1234, false),
            (server, DNS_PORT, true),
        ] {
            let mut udp = [0; 32];
            let n = UdpDatagram {
                source_port: port,
                destination_port: 8300,
                payload: b"x",
            }
            .encode(source, local, &mut udp)
            .unwrap();
            let mut packet = [0; 64];
            let n = Ipv4Header {
                source,
                destination: local,
                protocol: 17,
                ttl: 64,
                identification: 1,
            }
            .encode(&udp[..n], &mut packet)
            .unwrap();
            assert_eq!(
                stack.handle_ipv4(&packet[..n], 0),
                if allowed {
                    Ok(())
                } else {
                    Err(PacketError::Mismatch)
                }
            );
            assert_eq!(stack.udp.queued_for(socket), Ok(usize::from(allowed)));
        }
        assert_eq!(
            stack.udp.receive_for(socket).unwrap().unwrap().payload,
            b"x"
        );
        assert!(stack.udp.unbind_endpoint(socket));
    }
    include!("support/routed_tcp_cases.rs");
    include!("support/dns_routing_cases.rs");

}
