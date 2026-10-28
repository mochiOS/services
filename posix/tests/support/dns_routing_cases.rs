// Included inside the actual NetworkStack module. Packets traverse its UDP
// bindings and response filter; only the empty device/time source is replaced.
fn dns_routing_fixture() -> (NetworkStack, UdpSocketId) {
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
    let socket = stack.udp.bind_endpoint([192, 0, 2, 1], 8300).unwrap();
    (stack, socket)
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

fn queue_dns_reply(stack: &mut NetworkStack, payload: &[u8]) {
    let mut udp = vec![0; payload.len() + 8];
    let n = UdpDatagram {
        source_port: DNS_PORT,
        destination_port: 8300,
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

#[test]
fn dns_service_follows_cname_and_caches_every_terminal_record_with_alias_ttl() {
    let (mut stack, socket) = dns_routing_fixture();
    queue_dns_reply(&mut stack, &dns_routing_reply("alias.test", 9));
    let name = DnsName::parse("alias.test").unwrap();
    assert_eq!(
        stack.resolve_dns_query(&name, [192, 0, 2, 53], socket, 9, 0, 100),
        Ok([192, 0, 2, 1])
    );
    assert!(stack.udp.unbind_endpoint(socket));
    assert_eq!(stack.stats.dns_queries, 1);
    let cached = stack
        .dns_cache
        .lookup_records(&DnsRecordName::from(&name), DnsRecordType::A, 1000)
        .unwrap();
    assert_eq!(
        cached.values(),
        [
            DnsRecordValue::Ipv4([192, 0, 2, 1]),
            DnsRecordValue::Ipv4([192, 0, 2, 2])
        ]
    );
    assert_eq!(
        cached.canonical_name().hostname().unwrap().as_str(),
        "host.test"
    );
    assert_eq!(cached.ttl_seconds(), 4);
    // Cache lookup uses the original alias, accepts absolute/case variants,
    // and does not attempt I/O (mode zero panics on any device transmission).
    crate::MODE.with(|mode| mode.set(0));
    assert_eq!(
        stack.resolve_ipv4("ALIAS.TEST.", 4999, 100, 9),
        Ok(([192, 0, 2, 1], true))
    );
    assert_eq!(stack.stats.dns_cache_hits, 1);
    assert!(
        stack
            .dns_cache
            .lookup_records(&DnsRecordName::from(&name), DnsRecordType::A, 5000)
            .is_none()
    );
}

#[test]
fn dns_service_ignores_wrong_transaction_and_question_before_the_matching_reply() {
    let (mut stack, socket) = dns_routing_fixture();
    queue_dns_reply(&mut stack, &dns_routing_reply("alias.test", 10));
    queue_dns_reply(&mut stack, &dns_routing_reply("foreign.test", 9));
    queue_dns_reply(&mut stack, &dns_routing_reply("alias.test", 9));
    assert_eq!(
        stack.resolve_dns_query(
            &DnsName::parse("alias.test").unwrap(),
            [192, 0, 2, 53],
            socket,
            9,
            0,
            100
        ),
        Ok([192, 0, 2, 1])
    );
    assert_eq!(stack.stats.dns_failures, 0);
    assert_eq!(stack.dns_cache.len(), 1);
}

#[test]
fn dns_service_does_not_cache_truncated_rrsets_or_hide_malformed_trailing_data() {
    for truncated in [true, false] {
        let (mut stack, socket) = dns_routing_fixture();
        let mut response = dns_routing_reply("alias.test", 9);
        let expected = if truncated {
            response[2] |= 2;
            mochi_user_syscall::EAGAIN
        } else {
            response.push(0);
            mochi_user_syscall::EINVAL
        };
        queue_dns_reply(&mut stack, &response);
        assert_eq!(
            stack.resolve_dns_query(
                &DnsName::parse("alias.test").unwrap(),
                [192, 0, 2, 53],
                socket,
                9,
                0,
                100
            ),
            Err(expected)
        );
        assert_eq!(stack.stats.dns_failures, 1);
        assert!(stack.dns_cache.is_empty());
    }
}
