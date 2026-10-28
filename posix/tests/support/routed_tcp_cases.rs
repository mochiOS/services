// Included inside the production NetworkStack test module so these cases use
// its real frame decoder, ARP queue, routing, TCP table and resource transport.
use mochios_net_device_protocol::datagram::Endpoint as NativeEndpoint;
use mochios_network_stack::{TcpConnectionTable as PeerTable, TcpListenConfig as PeerListenConfig};
fn peer_entropy() -> Option<u64> {
    Some(0x1248_5678_9abc_def0)
}
fn routed_fixture(remote: [u8; 4], small_mtu: bool) -> (NetworkStack, PeerTable) {
    crate::MODE.with(|m| m.set(if small_mtu { 5 } else { 3 }));
    crate::TRANSMITTED.with_borrow_mut(Vec::clear);
    let mut stack = NetworkStack::new(DriverClient, 7).unwrap();
    stack.config = Some(Ipv4Config {
        address: [10, 0, 2, 15],
        subnet_mask: [255, 255, 255, 0],
        gateway: [10, 0, 2, 2],
        dns: [0; 4],
    });
    stack.tcp.configure(stack.config).unwrap();
    stack.arp.insert(ArpEntry {
        ip: [10, 0, 2, 2],
        mac: [2, 0, 0, 0, 0, 2],
        expires_at: 100000,
    });
    let mut peer = PeerTable::new(16);
    peer.listen(
        91,
        7,
        remote,
        8000,
        PeerListenConfig {
            backlog: 4,
            local_mss: 1460,
            send_capacity: 16384,
            receive_capacity: 16384,
            retransmit_timeout: 500,
            retry_limit: 5,
        },
    )
    .unwrap();
    (stack, peer)
}
fn ingress(stack: &mut NetworkStack, tuple: TcpTuple, tx: &TcpTransmit, now: u64) {
    let packet = tcp_packet(tuple, tx);
    let mut frame = vec![0; packet.len() + 14];
    EthernetHeader {
        destination: stack.info.mac,
        source: [2, 0, 0, 0, 0, 2],
        ethertype: ETHERTYPE_IPV4,
    }
    .encode(&packet, &mut frame)
    .unwrap();
    stack.handle_frame(&frame, now).unwrap();
}
fn exchange(stack: &mut NetworkStack, peer: &mut PeerTable, now: u64) -> usize {
    let mut count = 0;
    for _ in 0..64 {
        stack.tcp.advance(now, peer_entropy);
        stack.tick(now);
        let frames = crate::TRANSMITTED.with_borrow_mut(core::mem::take);
        let mut progress = !frames.is_empty();
        for frame in frames {
            count += 1;
            assert!(frame.len() <= usize::from(stack.info.mtu) + 14);
            let (ethernet, packet) = EthernetHeader::decode(&frame).unwrap();
            assert_eq!(ethernet.destination, [2, 0, 0, 0, 0, 2]);
            assert_eq!(ethernet.ethertype, ETHERTYPE_IPV4);
            let (ip, payload) = Ipv4Header::decode(packet).unwrap();
            assert_eq!(ip.source, [10, 0, 2, 15]);
            assert_eq!(ip.protocol, TCP_PROTOCOL);
            let segment = TcpSegment::decode(ip.source, ip.destination, payload).unwrap();
            let tuple = TcpTuple {
                local_address: ip.destination,
                local_port: segment.destination_port,
                remote_address: ip.source,
                remote_port: segment.source_port,
            };
            let result = peer
                .receive_packet(tuple, &segment, now, peer_entropy)
                .unwrap();
            if let Some(reply) = result.reply {
                ingress(stack, tuple, &reply, now);
            }
        }
        for connection in peer.connections_mut() {
            connection.tick(now);
            if let Some(tx) = connection.poll_transmit(now).unwrap() {
                progress = true;
                ingress(stack, connection.tuple, &tx, now);
            }
        }
        if !progress {
            break;
        }
    }
    count
}
fn native_client(stack: &mut NetworkStack, remote: [u8; 4]) -> crate::stream::Socket {
    let client = stack.tcp.open().unwrap();
    stack
        .tcp
        .connect(
            client,
            NativeEndpoint {
                address: remote,
                port: 8000,
            },
            peer_entropy,
        )
        .unwrap();
    client
}
#[test]
fn native_tcp_routes_off_subnet_and_keeps_terminal_observations_owned() {
    let (mut stack, mut peer) = routed_fixture([192, 0, 2, 44], false);
    let client = native_client(&mut stack, [192, 0, 2, 44]);
    assert!(stack.tcp.status(client).unwrap().connecting);
    assert!(exchange(&mut stack, &mut peer, 0) > 0);
    let (accepted, _) = peer.accept(91, 7).unwrap().unwrap();
    assert!(stack.tcp.status(client).unwrap().writable);
    assert_eq!(stack.tcp.local(client).unwrap().address, [10, 0, 2, 15]);
    stack.tcp.send(client, b"native TCP").unwrap();
    exchange(&mut stack, &mut peer, 0);
    let mut bytes = [0; 64];
    assert_eq!(peer.get_mut(accepted, 7).unwrap().receive(&mut bytes), 10);
    assert_eq!(&bytes[..10], b"native TCP");
    peer.get_mut(accepted, 7)
        .unwrap()
        .queue_send(b"physical reply")
        .unwrap();
    exchange(&mut stack, &mut peer, 0);
    assert_eq!(stack.tcp.receive(client, true, &mut bytes), Ok(14));
    assert_eq!(&bytes[..14], b"physical reply");
    assert_eq!(stack.tcp.receive(client, false, &mut bytes), Ok(14));
    assert_eq!(stack.tcp.receive(client, false, &mut bytes), Err(-11));
    peer.get_mut(accepted, 7).unwrap().request_close().unwrap();
    exchange(&mut stack, &mut peer, 0);
    assert!(stack.tcp.status(client).unwrap().peer_closed);
    assert_eq!(stack.tcp.receive(client, false, &mut bytes), Ok(0));
    stack.tcp.send(client, b"reverse after FIN").unwrap();
    exchange(&mut stack, &mut peer, 0);
    assert_eq!(peer.get_mut(accepted, 7).unwrap().receive(&mut bytes), 17);
    stack.tcp.shutdown(client, false, true).unwrap();
    exchange(&mut stack, &mut peer, 0);
    // An unrelated legacy tick must not reap the live resource's terminal TCB.
    stack.tick(100);
    assert!(stack.tcp.status(client).is_ok());
    assert!(stack.tcp.peer(client).is_ok());
    stack.tcp.release(client, 100);
    assert_eq!(stack.tcp.status(client), Err(-9));
}
#[test]
fn native_tcp_passive_open_accepts_frames_and_outlives_listener() {
    let (mut stack, _) = routed_fixture([10, 0, 2, 2], false);
    let listener = stack.tcp.open().unwrap();
    stack
        .tcp
        .bind(
            listener,
            NativeEndpoint {
                address: [0; 4],
                port: 8000,
            },
        )
        .unwrap();
    stack.tcp.listen(listener, 2).unwrap();
    let mut peer = PeerTable::new(8);
    let tuple = TcpTuple {
        local_address: [10, 0, 2, 2],
        local_port: 50000,
        remote_address: [10, 0, 2, 15],
        remote_port: 8000,
    };
    peer.insert(TcpConnection::try_connect(9, 7, tuple, 100, 1460, 16384, 16384, 500, 5).unwrap())
        .unwrap();
    exchange(&mut stack, &mut peer, 0);
    assert!(stack.tcp.status(listener).unwrap().readable);
    let accepted = stack.tcp.accept(listener).unwrap();
    assert_eq!(stack.tcp.local(accepted).unwrap().address, [10, 0, 2, 15]);
    stack.tcp.release(listener, 0);
    peer.get_mut(9, 7)
        .unwrap()
        .queue_send(b"after accept")
        .unwrap();
    exchange(&mut stack, &mut peer, 0);
    let mut bytes = [0; 12];
    assert_eq!(stack.tcp.receive(accepted, false, &mut bytes), Ok(12));
    assert_eq!(&bytes, b"after accept");
    stack.tcp.send(accepted, b"reply").unwrap();
    exchange(&mut stack, &mut peer, 0);
    assert_eq!(peer.get_mut(9, 7).unwrap().receive(&mut bytes), 5);
}
#[test]
fn native_and_legacy_connections_share_ports_without_sharing_authority() {
    let (mut stack, mut peer) = routed_fixture([192, 0, 2, 44], false);
    let reserved = stack.tcp.open().unwrap();
    stack
        .tcp
        .bind(
            reserved,
            NativeEndpoint {
                address: [0; 4],
                port: 50000,
            },
        )
        .unwrap();
    assert_ne!(
        stack
            .tcp
            .allocate_legacy_port(50000 - mochios_network_stack::TCP_EPHEMERAL_START)
            .unwrap(),
        50000
    );
    let legacy = TcpTuple {
        local_address: [10, 0, 2, 15],
        local_port: 50002,
        remote_address: [192, 0, 2, 99],
        remote_port: 8000,
    };
    stack
        .tcp
        .table
        .insert(TcpConnection::try_connect(50, 7, legacy, 100, 1460, 64, 64, 500, 5).unwrap())
        .unwrap();
    let blocked = stack.tcp.open().unwrap();
    assert_eq!(
        stack.tcp.bind(
            blocked,
            NativeEndpoint {
                address: legacy.local_address,
                port: 50002
            }
        ),
        Err(-98)
    );
    stack.tcp.table.remove(50, 7);
    let client = native_client(&mut stack, [192, 0, 2, 44]);
    exchange(&mut stack, &mut peer, 0);
    let (handle, owner) = stack
        .tcp
        .table
        .connections_mut()
        .find(|c| c.owner & crate::stream::RESOURCE_OWNER_TAG != 0)
        .map(|c| (c.handle, c.owner))
        .unwrap();
    assert_eq!(
        stack.tcp_send(7, handle, b"forged", 0, 1),
        Err(mochi_user_syscall::EACCES)
    );
    assert_eq!(
        stack.tcp_send(owner, handle, b"forged", 0, 1),
        Err(mochi_user_syscall::EACCES)
    );
    stack.tcp_discard(owner, handle);
    assert!(stack.tcp.status(client).unwrap().writable);
    assert_eq!(
        stack.tcp_receive(owner, handle, &mut [0; 1], 0, 1),
        Err(mochi_user_syscall::EACCES)
    );
    assert_eq!(
        stack.tcp_close(owner, handle, 0, 1),
        Err(mochi_user_syscall::EACCES)
    );
}
#[test]
fn interface_loss_preserves_native_references_and_loopback_remains_available() {
    let (mut stack, mut peer) = routed_fixture([192, 0, 2, 44], false);
    let external = native_client(&mut stack, [192, 0, 2, 44]);
    exchange(&mut stack, &mut peer, 0);
    let listener = stack.tcp.open().unwrap();
    stack
        .tcp
        .bind(
            listener,
            NativeEndpoint {
                address: [127, 0, 0, 1],
                port: 8001,
            },
        )
        .unwrap();
    stack.tcp.listen(listener, 2).unwrap();
    let local = stack.tcp.open().unwrap();
    stack
        .tcp
        .connect(
            local,
            NativeEndpoint {
                address: [127, 0, 0, 1],
                port: 8001,
            },
            peer_entropy,
        )
        .unwrap();
    stack.tcp.advance(0, peer_entropy);
    let accepted = stack.tcp.accept(listener).unwrap();
    stack.interface_failed();
    assert!(stack.config.is_none());
    assert_eq!(stack.tcp.status(external).unwrap().error, -100);
    assert_eq!(stack.tcp.take_error(external), Ok(-100));
    assert_eq!(stack.tcp.take_error(external), Ok(0));
    assert!(stack.tcp.status(external).unwrap().peer_closed);
    assert!(stack.tcp.peer(external).is_ok());
    stack.tcp.send(local, b"loopback").unwrap();
    stack.tcp.advance(0, peer_entropy);
    let mut bytes = [0; 8];
    assert_eq!(stack.tcp.receive(accepted, false, &mut bytes), Ok(8));
    assert_eq!(&bytes, b"loopback");
    let failed = stack.tcp.open().unwrap();
    assert_eq!(
        stack.tcp.connect(
            failed,
            NativeEndpoint {
                address: [192, 0, 2, 44],
                port: 8000
            },
            peer_entropy
        ),
        Err(-101)
    );
}
#[test]
fn device_backpressure_retains_the_unpublished_native_segment() {
    let (mut stack, mut peer) = routed_fixture([192, 0, 2, 44], false);
    let client = native_client(&mut stack, [192, 0, 2, 44]);
    crate::MODE.with(|m| m.set(6));
    stack.tcp.advance(0, peer_entropy);
    stack.tick(0);
    assert!(crate::TRANSMITTED.with_borrow(Vec::is_empty));
    assert_eq!(stack.tcp.status(client).unwrap().error, 0);
    crate::MODE.with(|m| m.set(3));
    exchange(&mut stack, &mut peer, 0);
    assert!(stack.tcp.status(client).unwrap().writable);
    assert!(peer.accept(91, 7).unwrap().is_some());
}
#[test]
fn native_segments_respect_the_interface_mtu_in_both_directions() {
    let (mut stack, mut peer) = routed_fixture([192, 0, 2, 44], true);
    let client = native_client(&mut stack, [192, 0, 2, 44]);
    exchange(&mut stack, &mut peer, 0);
    let (accepted, _) = peer.accept(91, 7).unwrap().unwrap();
    assert_eq!(peer.get_mut(accepted, 7).unwrap().peer_mss, 560);
    let payload = vec![0xa5; 2000];
    stack.tcp.send(client, &payload).unwrap();
    assert!(exchange(&mut stack, &mut peer, 0) >= 4);
    let mut received = vec![0; 2000];
    assert_eq!(
        peer.get_mut(accepted, 7).unwrap().receive(&mut received),
        2000
    );
    assert_eq!(received, payload);
    peer.get_mut(accepted, 7)
        .unwrap()
        .queue_send(&payload)
        .unwrap();
    exchange(&mut stack, &mut peer, 0);
    assert_eq!(stack.tcp.receive(client, false, &mut received), Ok(2000));
    assert_eq!(received, payload);
}
#[test]
fn native_connect_waits_for_real_arp_resolution_before_publishing_ip() {
    let (mut stack, mut peer) = routed_fixture([192, 0, 2, 44], false);
    stack.arp = ArpCache::new(8);
    let client = native_client(&mut stack, [192, 0, 2, 44]);
    stack.tcp.advance(0, peer_entropy);
    stack.tick(0);
    let frames = crate::TRANSMITTED.with_borrow_mut(core::mem::take);
    assert!(!frames.is_empty());
    for frame in frames {
        let (eth, bytes) = EthernetHeader::decode(&frame).unwrap();
        assert_eq!(eth.ethertype, ETHERTYPE_ARP);
        assert_eq!(ArpPacket::decode(bytes).unwrap().target_ip, [10, 0, 2, 2]);
    }
    assert!(stack.tcp.status(client).unwrap().connecting);
    let reply = ArpPacket {
        operation: ARP_REPLY,
        sender_mac: [2, 0, 0, 0, 0, 2],
        sender_ip: [10, 0, 2, 2],
        target_mac: stack.info.mac,
        target_ip: [10, 0, 2, 15],
    };
    let mut arp = [0; ARP_LEN];
    reply.encode(&mut arp).unwrap();
    let mut frame = vec![0; 14 + ARP_LEN];
    EthernetHeader {
        destination: stack.info.mac,
        source: reply.sender_mac,
        ethertype: ETHERTYPE_ARP,
    }
    .encode(&arp, &mut frame)
    .unwrap();
    stack.handle_frame(&frame, 1).unwrap();
    exchange(&mut stack, &mut peer, 1);
    assert!(stack.tcp.status(client).unwrap().writable);
}
#[test]
fn invalid_routes_and_configuration_fail_without_losing_the_previous_binding() {
    let (mut stack, _) = routed_fixture([192, 0, 2, 44], false);
    let config = stack.config.unwrap();
    assert_eq!(
        stack.tcp.configure(Some(Ipv4Config {
            subnet_mask: [255, 0, 255, 0],
            ..config
        })),
        Err(-22)
    );
    assert!(stack.tcp.has_interface());
    for address in [[0; 4], [224, 0, 0, 1], [255; 4], [10, 0, 2, 255]] {
        let socket = stack.tcp.open().unwrap();
        assert!(
            stack
                .tcp
                .connect(
                    socket,
                    NativeEndpoint {
                        address,
                        port: 8000
                    },
                    peer_entropy
                )
                .is_err()
        );
        stack.tcp.release(socket, 0);
    }
    let socket = stack.tcp.open().unwrap();
    assert_eq!(
        stack.tcp.bind(
            socket,
            NativeEndpoint {
                address: config.address,
                port: 9000
            }
        ),
        Ok(())
    );
}

#[test]
fn native_timeout_is_not_reaped_by_legacy_ticks_and_invalid_failures_stay_negative() {
    let (mut stack, _) = routed_fixture([192, 0, 2, 44], false);
    let client = native_client(&mut stack, [192, 0, 2, 44]);
    for now in [0, 500, 1500, 3500, 7500, 15500, 31500, 63500] {
        stack.tcp.advance(now, peer_entropy);
        stack.tick(now);
        crate::TRANSMITTED.with_borrow_mut(Vec::clear);
    }
    assert_eq!(stack.tcp.status(client).unwrap().error, -110);
    assert_eq!(stack.tcp.take_error(client), Ok(-110));
    assert_eq!(stack.tcp.take_error(client), Ok(0));
    assert!(stack.tcp.peer(client).is_ok());
    stack.tcp.release(client, 63500);
    assert_eq!(stack.tcp.status(client), Err(-9));
    assert_eq!(
        crate::status::failure_status(1u64 << 63),
        -(mochi_user_syscall::EIO as i32)
    );
}

fn arp_ingress(stack: &mut NetworkStack, address: [u8; 4], mac: [u8; 6], operation: u16) {
    let reply = ArpPacket {
        operation,
        sender_mac: mac,
        sender_ip: address,
        target_mac: stack.info.mac,
        target_ip: stack.config.unwrap().address,
    };
    let mut arp = [0; ARP_LEN];
    reply.encode(&mut arp).unwrap();
    let mut frame = vec![0; 14 + ARP_LEN];
    EthernetHeader {
        destination: stack.info.mac,
        source: mac,
        ethertype: ETHERTYPE_ARP,
    }
    .encode(&arp, &mut frame)
    .unwrap();
    stack.handle_frame(&frame, 1).unwrap();
}
#[test]
fn concurrent_native_opens_share_an_arp_request_and_valid_requests_flush_queued_ip() {
    let (mut stack, _) = routed_fixture([192, 0, 2, 44], false);
    stack.arp = ArpCache::new(8);
    native_client(&mut stack, [192, 0, 2, 44]);
    native_client(&mut stack, [192, 0, 2, 45]);
    stack.tcp.advance(0, peer_entropy);
    stack.tick(0);
    let frames = crate::TRANSMITTED.with_borrow_mut(core::mem::take);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        EthernetHeader::decode(&frames[0]).unwrap().0.ethertype,
        ETHERTYPE_ARP
    );
    assert_eq!(stack.pending_ipv4.len(), 2);
    // Learning a valid ARP request is enough; don't strand these packets while
    // waiting for an unnecessary second response from the same next hop.
    arp_ingress(&mut stack, [10, 0, 2, 2], [2, 0, 0, 0, 0, 2], ARP_REQUEST);
    assert!(stack.pending_ipv4.is_empty());
    let frames = crate::TRANSMITTED.with_borrow_mut(core::mem::take);
    assert_eq!(
        frames
            .iter()
            .filter(|f| EthernetHeader::decode(f).unwrap().0.ethertype == ETHERTYPE_IPV4)
            .count(),
        2
    );
}
#[test]
fn an_arp_reply_flushes_its_next_hop_even_when_another_peer_is_also_pending() {
    let (mut stack, _) = routed_fixture([10, 0, 2, 2], false);
    stack.arp = ArpCache::new(8);
    native_client(&mut stack, [10, 0, 2, 2]);
    native_client(&mut stack, [10, 0, 2, 3]);
    stack.tcp.advance(0, peer_entropy);
    stack.tick(0);
    assert_eq!(stack.pending_ipv4.len(), 2);
    crate::TRANSMITTED.with_borrow_mut(Vec::clear);
    arp_ingress(&mut stack, [10, 0, 2, 2], [2, 0, 0, 0, 0, 2], ARP_REPLY);
    assert_eq!(stack.pending_ipv4.len(), 1);
    let frames = crate::TRANSMITTED.with_borrow_mut(core::mem::take);
    assert_eq!(frames.len(), 1);
    let (eth, bytes) = EthernetHeader::decode(&frames[0]).unwrap();
    assert_eq!(eth.destination, [2, 0, 0, 0, 0, 2]);
    assert_eq!(
        Ipv4Header::decode(bytes).unwrap().0.destination,
        [10, 0, 2, 2]
    );
    arp_ingress(&mut stack, [10, 0, 2, 3], [2, 0, 0, 0, 0, 3], ARP_REPLY);
    assert!(stack.pending_ipv4.is_empty());
    let frames = crate::TRANSMITTED.with_borrow_mut(core::mem::take);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        EthernetHeader::decode(&frames[0]).unwrap().0.destination,
        [2, 0, 0, 0, 0, 3]
    );
}
