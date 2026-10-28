// Included inside the actual NetworkStack module. Packets traverse its UDP
// bindings and response filter; only the empty device/time source is replaced.
fn dns_routing_fixture() -> NetworkStack {
    crate::MODE.with(|mode| mode.set(7));
    crate::TRANSMITTED.with(|frames| frames.borrow_mut().clear());
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
    stack.tcp.configure(stack.config).unwrap();
    stack
}

fn dns_routing_reply(name: &str, id: u16) -> Vec<u8> {
    let mut bytes = vec![0; DNS_MAX_MESSAGE_LEN];
    let n = encode_dns_query(id, &DnsName::parse(name).unwrap(), &mut bytes).unwrap();
    bytes.truncate(n);
    bytes[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&3u16.to_be_bytes());
    // Out-of-order terminal records plus a shorter-lived alias.
    bytes.extend_from_slice(b"\x04host\x04test\0\x00\x01\x00\x01\0\0\0\x3c\0\x04\xc0\0\x02\x01");
    bytes.extend_from_slice(b"\xc0\x0c\x00\x05\x00\x01\0\0\0\x05\0\x0b\x04host\x04test\0");
    bytes.extend_from_slice(b"\x04host\x04test\0\x00\x01\x00\x01\0\0\0\x3c\0\x04\xc0\0\x02\x02");
    bytes
}

fn queue_dns_reply(stack: &mut NetworkStack, port: u16, payload: &[u8]) {
    let mut udp = vec![0; payload.len() + 8];
    let n = UdpDatagram {
        source_port: DNS_PORT,
        destination_port: port,
        payload,
    }
    .encode([192, 0, 2, 53], [192, 0, 2, 1], &mut udp)
    .unwrap();
    let mut ipv4 = vec![0; n + 20];
    let n = Ipv4Header {
        source: [192, 0, 2, 53],
        destination: [192, 0, 2, 1],
        protocol: 17,
        ttl: 64,
        identification: 1,
    }
    .encode(&udp[..n], &mut ipv4)
    .unwrap();
    stack.handle_ipv4(&ipv4[..n], 0).unwrap();
}

fn begin_dns(stack: &mut NetworkStack, name: &str, now: u64) -> (crate::resolver::Query, u16, u16) {
    let id = stack
        .start_dns(
            DnsRecordName::from(&DnsName::parse(name).unwrap()),
            DnsRecordType::A,
            now,
            10000,
        )
        .unwrap();
    stack.pump_dns(now);
    let frames = crate::TRANSMITTED.with_borrow_mut(core::mem::take);
    let (_, packet) = EthernetHeader::decode(frames.last().unwrap()).unwrap();
    let (ip, payload) = Ipv4Header::decode(packet).unwrap();
    let udp = UdpDatagram::decode(ip.source, ip.destination, payload).unwrap();
    assert_eq!(udp.destination_port, DNS_PORT);
    assert!(udp.source_port >= 1024);
    (
        id,
        udp.source_port,
        u16::from_be_bytes(udp.payload[..2].try_into().unwrap()),
    )
}

#[test]
fn dns_service_follows_cname_and_caches_every_terminal_record_with_alias_ttl() {
    let mut stack = dns_routing_fixture();
    let (id, port, tid) = begin_dns(&mut stack, "alias.test", 0);
    queue_dns_reply(&mut stack, port, &dns_routing_reply("alias.test", tid));
    stack.pump_dns(0);
    let answer = stack.take_dns(id).unwrap().unwrap().unwrap();
    assert!(!answer.from_cache);
    assert_eq!(
        answer.records.values(),
        [
            DnsRecordValue::Ipv4([192, 0, 2, 1]),
            DnsRecordValue::Ipv4([192, 0, 2, 2])
        ]
    );
    assert_eq!(
        answer.records.canonical_name().hostname().unwrap().as_str(),
        "host.test"
    );
    assert_eq!(stack.stats.dns_queries, 1);
    let cached = stack
        .start_dns(
            crate::resolver::hostname("ALIAS.TEST.").unwrap(),
            DnsRecordType::A,
            1000,
            100,
        )
        .unwrap();
    let cached = stack.take_dns(cached).unwrap().unwrap().unwrap();
    assert!(cached.from_cache);
    assert_eq!(cached.records.values().len(), 2);
    assert_eq!(cached.records.ttl_seconds(), 4);
    crate::MODE.with(|mode| mode.set(0));
    assert_eq!(
        stack.resolve_ipv4("ALIAS.TEST.", 4999, 100),
        Ok(([192, 0, 2, 1], true))
    );
    let expired = stack
        .start_dns(
            crate::resolver::hostname("alias.test").unwrap(),
            DnsRecordType::A,
            5000,
            100,
        )
        .unwrap();
    assert!(stack.take_dns(expired).unwrap().is_none());
    stack.cancel_dns(expired, 5000).unwrap();
}

#[test]
fn dns_service_ignores_wrong_transaction_and_question_before_the_matching_reply() {
    let mut stack = dns_routing_fixture();
    let (id, port, tid) = begin_dns(&mut stack, "alias.test", 0);
    queue_dns_reply(&mut stack, port, &dns_routing_reply("alias.test", tid ^ 1));
    queue_dns_reply(&mut stack, port, &dns_routing_reply("foreign.test", tid));
    queue_dns_reply(&mut stack, port, &dns_routing_reply("alias.test", tid));
    stack.pump_dns(0);
    assert_eq!(
        stack
            .take_dns(id)
            .unwrap()
            .unwrap()
            .unwrap()
            .records
            .values()
            .len(),
        2
    );
    assert_eq!(stack.stats.dns_failures, 0);
}

#[test]
fn dns_service_does_not_cache_truncated_rrsets_or_hide_malformed_trailing_data() {
    for truncated in [true, false] {
        let mut stack = dns_routing_fixture();
        let (id, port, tid) = begin_dns(&mut stack, "alias.test", 0);
        let mut response = dns_routing_reply("alias.test", tid);
        if truncated {
            response[2] |= 2;
        } else {
            response.push(0);
        }
        queue_dns_reply(&mut stack, port, &response);
        stack.pump_dns(0);
        if truncated {
            assert!(stack.take_dns(id).unwrap().is_none());
            assert_eq!(stack.tcp.table.connections_mut().count(), 1);
            stack.cancel_dns(id, 1).unwrap();
            assert_eq!(stack.tcp.table.connections_mut().count(), 0);
        } else {
            assert_eq!(
                stack.take_dns(id).unwrap().unwrap().unwrap_err().status(),
                -22
            );
        }
        let again = stack
            .start_dns(
                crate::resolver::hostname("alias.test").unwrap(),
                DnsRecordType::A,
                2,
                100,
            )
            .unwrap();
        assert!(stack.take_dns(again).unwrap().is_none());
        stack.cancel_dns(again, 2).unwrap();
    }
}

#[test]
fn dns_tcp_fallback_crosses_real_ethernet_tcp_framing_and_fragmented_responses() {
    let server = [10, 0, 2, 2];
    let (mut stack, mut peer) = routed_fixture(server, true);
    stack.config.as_mut().unwrap().dns = server;
    peer.listen(
        92,
        7,
        server,
        DNS_PORT,
        PeerListenConfig {
            backlog: 4,
            local_mss: 113,
            send_capacity: 16384,
            receive_capacity: 16384,
            retransmit_timeout: 500,
            retry_limit: 5,
        },
    )
    .unwrap();
    let (query, port, tid) = begin_dns(&mut stack, "alias.test", 0);
    let mut response = dns_routing_reply("alias.test", tid);
    response[2] |= 2;
    let mut udp = vec![0; response.len() + 8];
    let n = UdpDatagram {
        source_port: DNS_PORT,
        destination_port: port,
        payload: &response,
    }
    .encode(server, [10, 0, 2, 15], &mut udp)
    .unwrap();
    let mut packet = vec![0; n + 20];
    let n = Ipv4Header {
        source: server,
        destination: [10, 0, 2, 15],
        protocol: 17,
        ttl: 64,
        identification: 1,
    }
    .encode(&udp[..n], &mut packet)
    .unwrap();
    stack.handle_ipv4(&packet[..n], 0).unwrap();
    stack.pump_dns(0);
    assert!(stack.take_dns(query).unwrap().is_none());
    exchange(&mut stack, &mut peer, 0);
    let (accepted, _) = peer.accept(92, 7).unwrap().unwrap();
    exchange(&mut stack, &mut peer, 0);
    let mut bytes = [0; 1024];
    let n = peer.get_mut(accepted, 7).unwrap().receive(&mut bytes);
    assert!(n > 2);
    assert_eq!(
        usize::from(u16::from_be_bytes(bytes[..2].try_into().unwrap())),
        n - 2
    );
    assert_eq!(u16::from_be_bytes(bytes[2..4].try_into().unwrap()), tid);
    let mut response = dns_routing_reply("alias.test", tid);
    response[6..8].copy_from_slice(&83u16.to_be_bytes());
    for byte in 3..83u8 {
        response.extend_from_slice(b"\x04host\x04test\0\x00\x01\x00\x01\0\0\0\x3c\0\x04");
        response.extend_from_slice(&[192, 0, 2, byte]);
    }
    assert!(response.len() > 1500);
    let mut framed = (response.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&response);
    peer.get_mut(accepted, 7)
        .unwrap()
        .queue_send(&framed[..1])
        .unwrap();
    exchange(&mut stack, &mut peer, 1);
    assert!(stack.take_dns(query).unwrap().is_none());
    peer.get_mut(accepted, 7)
        .unwrap()
        .queue_send(&framed[1..])
        .unwrap();
    peer.get_mut(accepted, 7).unwrap().request_close().unwrap();
    exchange(&mut stack, &mut peer, 2);
    stack.pump_dns(2);
    let answer = stack.take_dns(query).unwrap().unwrap().unwrap();
    assert_eq!(answer.records.values().len(), 82);
    assert_eq!(answer.records.ttl_seconds(), 5);
    assert_eq!(
        answer.records.canonical_name().hostname().unwrap().as_str(),
        "host.test"
    );
    assert_eq!(stack.stats.dns_queries, 2);
    exchange(&mut stack, &mut peer, 3);
    assert_eq!(stack.tcp.table.connections_mut().count(), 0);
    let mut free = Vec::new();
    for _ in 1..UDP_SOCKET_LIMIT {
        free.push(stack.udp.bind_endpoint([10, 0, 2, 15], 0).unwrap());
    }
    for id in free {
        assert!(stack.udp.unbind_endpoint(id));
    }
}
