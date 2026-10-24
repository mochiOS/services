//! Production network-service routing with real packet/configuration types.
//! Only device I/O is replaced; failed configuration must not reach hardware.
#![allow(dead_code)]
extern crate alloc;
extern crate self as mochi_user_platform;
thread_local! { static MODE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
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
                mtu: 1500,
                driver_id: 0,
                device_id: 0,
                driver_name: [0; DRIVER_NAME_LEN],
            })
        }
        pub(crate) fn transmit(&mut self, _: &[u8]) -> Result<(), u64> {
            if crate::MODE.with(|mode| mode.get()) == 1 {
                return Err(mochi_user_syscall::EIO);
            }
            panic!("configuration failure must not transmit")
        }
        pub(crate) fn receive(&mut self) -> Result<Option<Vec<u8>>, u64> {
            panic!("configuration failure must not poll devices")
        }
        pub(crate) fn statistics(&mut self) -> Result<DeviceStatistics, u64> {
            panic!("unexpected driver statistics")
        }
    }
}

mod production {
    include!("../../network/src/stack.rs");

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
}
