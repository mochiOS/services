//! Production network-service routing with real packet/configuration types.
//! Only device I/O is replaced; failed configuration must not reach hardware.
#![allow(dead_code)]
extern crate alloc;

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
}
