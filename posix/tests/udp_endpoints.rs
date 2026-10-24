//! Actual no_std UDP table: address demultiplexing and stable private identities.
extern crate alloc;
use mochios_network_stack::{
    EPHEMERAL_PORT_END, EPHEMERAL_PORT_START, PacketError, UdpDatagram, UdpSocketTable,
};
const A: [u8; 4] = [192, 0, 2, 1];
const B: [u8; 4] = [192, 0, 2, 2];
fn deliver(t: &mut UdpSocketTable, to: [u8; 4], port: u16, data: &[u8]) -> Result<(), PacketError> {
    t.enqueue(
        [198, 51, 100, 7],
        to,
        UdpDatagram {
            source_port: 1234,
            destination_port: port,
            payload: data,
        },
    )
}
#[test]
fn different_local_addresses_share_a_port_without_cross_delivery() {
    let mut t = UdpSocketTable::new(4, 3, 16);
    let a = t.bind_endpoint(A, 8000).unwrap();
    let b = t.bind_endpoint(B, 8000).unwrap();
    deliver(&mut t, A, 8000, b"a").unwrap();
    deliver(&mut t, B, 8000, b"b").unwrap();
    assert_eq!(t.queued_for(a), Ok(1));
    assert_eq!(t.queued_for(b), Ok(1));
    let packet = t.receive_for(a).unwrap().unwrap();
    assert_eq!(packet.payload, b"a");
    assert_eq!(packet.destination_address, A);
    assert_eq!(packet.source_port, 1234);
    assert_eq!(t.receive_for(b).unwrap().unwrap().payload, b"b");
    assert_eq!(t.receive_for(a), Ok(None));
    assert_eq!(
        deliver(&mut t, [192, 0, 2, 3], 8000, b"x"),
        Err(PacketError::Mismatch)
    );
}
#[test]
fn wildcard_and_specific_bindings_conflict_in_both_orders_without_reserving_a_slot() {
    for wildcard_first in [false, true] {
        let mut t = UdpSocketTable::new(2, 1, 8);
        let first = t
            .bind_endpoint(if wildcard_first { [0; 4] } else { A }, 9000)
            .unwrap();
        assert_eq!(
            t.bind_endpoint(if wildcard_first { A } else { [0; 4] }, 9000),
            Err(PacketError::Mismatch)
        );
        assert_eq!(
            t.bind_endpoint(if wildcard_first { [0; 4] } else { A }, 9000),
            Err(PacketError::Mismatch)
        );
        let second = t.bind_endpoint(B, 9001).unwrap();
        assert_ne!(first, second);
        assert_eq!(t.bind_endpoint(B, 9002), Err(PacketError::Capacity));
        assert!(t.unbind_endpoint(first));
        assert!(t.unbind_endpoint(second));
        assert!(t.bind_endpoint([0; 4], 9000).is_ok());
    }
}
#[test]
fn released_identity_cannot_receive_inspect_or_remove_a_rebound_port() {
    let mut t = UdpSocketTable::new(1, 1, 8);
    let old = t.bind_endpoint(A, 10000).unwrap();
    deliver(&mut t, A, 10000, b"old").unwrap();
    assert!(t.unbind_endpoint(old));
    let new = t.bind_endpoint(A, 10000).unwrap();
    assert_ne!(new, old);
    deliver(&mut t, A, 10000, b"new").unwrap();
    assert_eq!(t.receive_for(old), Err(PacketError::Mismatch));
    assert_eq!(t.peek_for(old), Err(PacketError::Mismatch));
    assert_eq!(t.queued_for(old), Err(PacketError::Mismatch));
    assert_eq!(t.local_endpoint(old), Err(PacketError::Mismatch));
    assert!(!t.unbind_endpoint(old));
    assert_eq!(t.receive_for(new).unwrap().unwrap().payload, b"new");
}
#[test]
fn legacy_port_queries_are_confined_to_the_private_wildcard_bindings() {
    let mut t = UdpSocketTable::new(3, 2, 8);
    let application = t.bind_endpoint(A, 68).unwrap();
    deliver(&mut t, A, 68, b"app").unwrap();
    assert_eq!(t.queued(68), 0);
    assert_eq!(t.receive(68), None);
    assert!(!t.unbind(68));
    assert_eq!(t.queued_for(application), Ok(1));
    assert_eq!(t.bind(68), Err(PacketError::Mismatch));
    assert!(t.unbind_endpoint(application));
    assert_eq!(t.bind(68), Ok(68));
    deliver(&mut t, [255; 4], 68, b"dhcp").unwrap();
    assert_eq!(t.receive(68).unwrap().payload, b"dhcp");
    assert!(t.unbind(68));
}
#[test]
fn peek_empty_records_and_failed_enqueue_preserve_order_and_accounting() {
    let mut t = UdpSocketTable::new(1, 2, 3);
    let id = t.bind_endpoint(A, 12000).unwrap();
    deliver(&mut t, A, 12000, b"").unwrap();
    deliver(&mut t, A, 12000, b"abc").unwrap();
    assert_eq!(t.queued_for(id), Ok(2));
    for _ in 0..3 {
        assert!(t.peek_for(id).unwrap().unwrap().payload.is_empty());
    }
    assert_eq!(t.queued_for(id), Ok(2));
    assert_eq!(deliver(&mut t, A, 12000, b"d"), Err(PacketError::Capacity));
    assert!(t.receive_for(id).unwrap().unwrap().payload.is_empty());
    assert_eq!(
        deliver(&mut t, A, 12000, b"long"),
        Err(PacketError::Capacity)
    );
    assert_eq!(t.receive_for(id).unwrap().unwrap().payload, b"abc");
    assert_eq!(t.peek_for(id), Ok(None));
    assert_eq!(t.queued_for(id), Ok(0));
}
#[test]
fn ephemeral_scan_wraps_skips_overlaps_and_never_reuses_description_ids() {
    let mut t = UdpSocketTable::new(3, 0, 0);
    let reserved = t.bind_endpoint([0; 4], EPHEMERAL_PORT_START).unwrap();
    let end = t.bind_endpoint([0; 4], EPHEMERAL_PORT_END).unwrap();
    let mut last = None;
    for _ in 0..=u32::from(EPHEMERAL_PORT_END) - u32::from(EPHEMERAL_PORT_START) {
        let id = t.bind_endpoint(A, 0).unwrap();
        let local = t.local_endpoint(id).unwrap();
        assert_eq!(local.address, A);
        assert!(local.port > EPHEMERAL_PORT_START && local.port < EPHEMERAL_PORT_END);
        assert_ne!(last, Some(id));
        assert_eq!(
            deliver(&mut t, A, local.port, b""),
            Err(PacketError::Capacity)
        );
        assert!(t.unbind_endpoint(id));
        last = Some(id);
    }
    assert!(t.unbind_endpoint(reserved));
    assert!(t.unbind_endpoint(end));
}
#[test]
fn impossible_queue_reservations_do_not_publish_a_binding_or_panic() {
    let mut t = UdpSocketTable::new(2, usize::MAX, 8);
    assert_eq!(t.bind_endpoint(A, 4000), Err(PacketError::Capacity));
    assert_eq!(t.bind_endpoint(A, 4000), Err(PacketError::Capacity));
    assert_eq!(deliver(&mut t, A, 4000, b"x"), Err(PacketError::Mismatch));
    let mut disabled = UdpSocketTable::new(0, 1, 8);
    assert_eq!(disabled.bind_endpoint(A, 0), Err(PacketError::Capacity));
}

// Run the existing packet codec/legacy-stack tests through this required test
// directory as well, using the production file rather than copied algorithms.
#[allow(dead_code)]
#[path = "../../../user/crates/network-stack/src/udp.rs"]
mod packet_regressions;

#[test]
fn selected_peer_filters_both_source_fields_before_queue_capacity_is_charged() {
    use mochios_network_stack::UdpEndpoint;
    let mut t = UdpSocketTable::new(1, 1, 8);
    let id = t.bind_endpoint(A, 8000).unwrap();
    let peer = UdpEndpoint {
        address: B,
        port: 53,
    };
    assert_eq!(t.peer(id), Ok(None));
    t.set_peer(id, Some(peer)).unwrap();
    for (address, port) in [(A, 53), (B, 54), (A, 54)] {
        assert_eq!(
            t.enqueue(
                address,
                A,
                UdpDatagram {
                    source_port: port,
                    destination_port: 8000,
                    payload: b"bad"
                }
            ),
            Err(PacketError::Mismatch)
        );
        assert_eq!(t.queued_for(id), Ok(0));
    }
    t.enqueue(
        B,
        A,
        UdpDatagram {
            source_port: 53,
            destination_port: 8000,
            payload: b"ok",
        },
    )
    .unwrap();
    assert_eq!(t.receive_for(id).unwrap().unwrap().payload, b"ok");
    assert_eq!(t.peer(id), Ok(Some(peer)));
}

#[test]
fn changing_or_removing_peer_preserves_the_local_endpoint_and_prior_records() {
    use mochios_network_stack::UdpEndpoint;
    let mut t = UdpSocketTable::new(1, 3, 8);
    let id = t.bind_endpoint(A, 8000).unwrap();
    deliver(&mut t, A, 8000, b"before").unwrap();
    let local = t.local_endpoint(id).unwrap();
    let peer = UdpEndpoint {
        address: B,
        port: 53,
    };
    t.set_peer(id, Some(peer)).unwrap();
    assert_eq!(t.queued_for(id), Ok(1));
    assert_eq!(t.receive_for(id).unwrap().unwrap().payload, b"before");
    t.enqueue(
        B,
        A,
        UdpDatagram {
            source_port: 53,
            destination_port: 8000,
            payload: b"peer",
        },
    )
    .unwrap();
    t.set_peer(id, None).unwrap();
    assert_eq!(t.local_endpoint(id), Ok(local));
    assert_eq!(t.peer(id), Ok(None));
    deliver(&mut t, A, 8000, b"after").unwrap();
    assert_eq!(t.receive_for(id).unwrap().unwrap().payload, b"peer");
    assert_eq!(t.receive_for(id).unwrap().unwrap().payload, b"after");
}

#[test]
fn stale_peer_updates_cannot_change_a_replacement_binding() {
    use mochios_network_stack::UdpEndpoint;
    let mut t = UdpSocketTable::new(1, 1, 8);
    let old = t.bind_endpoint(A, 8000).unwrap();
    t.unbind_endpoint(old);
    let new = t.bind_endpoint(A, 8000).unwrap();
    assert_eq!(
        t.set_peer(
            old,
            Some(UdpEndpoint {
                address: B,
                port: 53
            })
        ),
        Err(PacketError::Mismatch)
    );
    assert_eq!(t.peer(old), Err(PacketError::Mismatch));
    assert_eq!(t.peer(new), Ok(None));
    deliver(&mut t, A, 8000, b"new").unwrap();
    assert_eq!(t.queued_for(new), Ok(1));
}
