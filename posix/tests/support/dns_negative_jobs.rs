//! Real resolver jobs and cache; the parent supplies controlled nonblocking
//! transport only. Packets below are generated independently of the decoder.
use super::*;
use mochios_network_stack::DnsResponseCode;
fn negative(
    query: &[u8],
    rcode: u16,
    owner: &str,
    ttl: u32,
    minimum: u32,
    answers: &[(&str, u16, u32, Vec<u8>)],
) -> Vec<u8> {
    let mut p = reply(query, answers);
    p[2..4].copy_from_slice(&(0x8180 | rcode).to_be_bytes());
    p[8..10].copy_from_slice(&1u16.to_be_bytes());
    p.extend(wire(owner));
    p.extend(6u16.to_be_bytes());
    p.extend(1u16.to_be_bytes());
    p.extend(ttl.to_be_bytes());
    let mut data = wire("ns.example");
    data.extend(wire("hostmaster.example"));
    for x in [1u32, 3600, 600, 86400, minimum] {
        data.extend(x.to_be_bytes());
    }
    p.extend((data.len() as u16).to_be_bytes());
    p.extend(data);
    p
}
fn expected(code: u16) -> Failure {
    Failure::Wire(if code == 3 {
        DnsError::Response(DnsResponseCode::NameError)
    } else {
        DnsError::NoData
    })
}
fn seed(
    r: &mut Resolver<usize, usize>,
    io: &mut Io,
    code: u16,
    ttl: u32,
    minimum: u32,
) -> resolver::Query {
    let q = start(r, io, "absent.example");
    let id = udp(io);
    let p = negative(&io.udp[&id].sent[0], code, "example", ttl, minimum, &[]);
    push(io, id, p);
    r.pump(io, 1);
    assert!(io.udp[&id].closed);
    q
}
#[test]
fn negative_cache_returns_the_same_absence_without_entropy_sockets_or_packet_io() {
    for code in [0, 3] {
        let mut r = Resolver::new();
        let mut io = Io::default();
        let q = seed(&mut r, &mut io, code, 90, 30);
        assert_eq!(r.take(q).unwrap(), Some(Err(expected(code))));
        io.entropy_error = true;
        let operations = io.operations;
        let sockets = io.next;
        let q = r
            .start(&mut io, name("ABSENT.EXAMPLE"), DnsRecordType::A, 1001, 0)
            .unwrap();
        assert_eq!(r.take(q).unwrap(), Some(Err(expected(code))));
        assert_eq!(io.operations, operations);
        assert_eq!(io.next, sockets);
        assert_eq!(r.statistics.cache_hits, 1);
        assert_eq!(r.statistics.failures, 2);
        let q = r
            .start(
                &mut io,
                name("absent.example"),
                DnsRecordType::Aaaa,
                1001,
                100,
            )
            .unwrap();
        if code == 3 {
            assert_eq!(r.take(q).unwrap(), Some(Err(expected(code))));
        } else {
            assert!(r.take(q).unwrap().is_none());
            r.cancel(&mut io, q, 1001).unwrap();
        }
    }
}
#[test]
fn expiry_zero_ttl_and_missing_soa_require_fresh_queries() {
    for (ttl, minimum, now) in [(90, 30, 30001), (0, 30, 2), (90, 0, 2)] {
        let mut r = Resolver::new();
        let mut io = Io::default();
        let q = seed(&mut r, &mut io, 3, ttl, minimum);
        assert_eq!(r.take(q).unwrap(), Some(Err(expected(3))));
        io.entropy_error = true;
        let q = r
            .start(&mut io, name("absent.example"), DnsRecordType::A, now, 100)
            .unwrap();
        assert!(r.take(q).unwrap().is_none());
        r.pump(&mut io, now);
        assert_eq!(r.take(q).unwrap(), Some(Err(Failure::Transport(-5))));
    }
    let mut r = Resolver::new();
    let mut io = Io::default();
    let q = start(&mut r, &mut io, "absent.example");
    let id = udp(&io);
    let mut p = reply(&io.udp[&id].sent[0], &[]);
    p[3] = 0x83;
    push(&mut io, id, p);
    r.pump(&mut io, 1);
    assert_eq!(r.take(q).unwrap(), Some(Err(expected(3))));
    let q = r
        .start(&mut io, name("absent.example"), DnsRecordType::A, 2, 100)
        .unwrap();
    assert!(r.take(q).unwrap().is_none());
    r.cancel(&mut io, q, 2).unwrap();
}
#[test]
fn cname_and_authority_nodata_is_terminal_in_one_message() {
    let mut r = Resolver::new();
    let mut io = Io::default();
    let q = start(&mut r, &mut io, "alias.test");
    let id = udp(&io);
    let p = negative(
        &io.udp[&id].sent[0],
        0,
        "example",
        90,
        7,
        &[("alias.test", 5, 3, wire("absent.example"))],
    );
    push(&mut io, id, p);
    r.pump(&mut io, 1);
    assert_eq!(r.take(q).unwrap(), Some(Err(expected(0))));
    assert_eq!(io.udp.len(), 1);
    assert!(io.udp[&id].closed);
    let q = r
        .start(&mut io, name("absent.example"), DnsRecordType::A, 1001, 0)
        .unwrap();
    assert_eq!(r.take(q).unwrap(), Some(Err(expected(0))));
    let q = r
        .start(
            &mut io,
            name("absent.example"),
            DnsRecordType::Aaaa,
            1001,
            100,
        )
        .unwrap();
    assert!(r.take(q).unwrap().is_none());
    r.cancel(&mut io, q, 1001).unwrap();
}
#[test]
fn cross_message_cname_can_use_cached_terminal_denial_without_extending_its_ttl() {
    let mut r = Resolver::new();
    let mut io = Io::default();
    let q = seed(&mut r, &mut io, 3, 90, 7);
    assert_eq!(r.take(q).unwrap(), Some(Err(expected(3))));
    let q = r
        .start(&mut io, name("alias.test"), DnsRecordType::A, 1001, 10000)
        .unwrap();
    r.pump(&mut io, 1001);
    let id = udp(&io);
    let p = reply(
        &io.udp[&id].sent[0],
        &[("alias.test", 5, 2, wire("absent.example"))],
    );
    push(&mut io, id, p);
    r.pump(&mut io, 1001);
    assert!(io.udp[&id].closed);
    io.entropy_error = true;
    let sockets = io.next;
    r.pump(&mut io, 2001);
    assert_eq!(r.take(q).unwrap(), Some(Err(expected(3))));
    assert_eq!(io.next, sockets);
    let q = r
        .start(&mut io, name("alias.test"), DnsRecordType::A, 3001, 100)
        .unwrap();
    assert!(r.take(q).unwrap().is_none());
    r.cancel(&mut io, q, 3001).unwrap();
    let q = r
        .start(
            &mut io,
            name("absent.example"),
            DnsRecordType::Aaaa,
            6001,
            0,
        )
        .unwrap();
    assert_eq!(r.take(q).unwrap(), Some(Err(expected(3))));
    let q = r
        .start(&mut io, name("absent.example"), DnsRecordType::A, 7001, 100)
        .unwrap();
    assert!(r.take(q).unwrap().is_none());
    r.cancel(&mut io, q, 7001).unwrap();
}
#[test]
fn tcp_negative_response_is_framed_fully_before_it_enters_the_cache() {
    let mut r = Resolver::new();
    let mut io = Io::default();
    let q = start(&mut r, &mut io, "absent.example");
    let id = udp(&io);
    let p = negative(&io.udp[&id].sent[0], 3, "example", 90, 30, &[]);
    let mut truncated = p.clone();
    truncated[2] |= 2;
    push(&mut io, id, truncated);
    r.pump(&mut io, 1);
    let t = *io.tcp.keys().next_back().unwrap();
    let socket = io.tcp.get_mut(&t).unwrap();
    socket.connected = true;
    socket.received.extend(framed(&p));
    io.write_limit = 3;
    io.read_limit = 7;
    drive(&mut r, &mut io, 2);
    assert_eq!(r.take(q).unwrap(), Some(Err(expected(3))));
    assert!(io.tcp[&t].closed);
    io.entropy_error = true;
    let q = r
        .start(&mut io, name("absent.example"), DnsRecordType::Aaaa, 3, 0)
        .unwrap();
    assert_eq!(r.take(q).unwrap(), Some(Err(expected(3))));
}
#[test]
fn wrong_transaction_or_question_does_not_poison_the_negative_cache() {
    for question in [false, true] {
        let mut r = Resolver::new();
        let mut io = Io::default();
        let q = start(&mut r, &mut io, "absent.example");
        let id = udp(&io);
        let mut p = negative(&io.udp[&id].sent[0], 3, "example", 90, 30, &[]);
        p[if question { 13 } else { 0 }] ^= 1;
        push(&mut io, id, p);
        r.pump(&mut io, 1);
        assert!(r.take(q).unwrap().is_none());
        let p = negative(&io.udp[&id].sent[0], 0, "example", 90, 7, &[]);
        push(&mut io, id, p);
        r.pump(&mut io, 2);
        assert_eq!(r.take(q).unwrap(), Some(Err(expected(0))));
        let q = r
            .start(&mut io, name("absent.example"), DnsRecordType::Aaaa, 3, 100)
            .unwrap();
        assert!(r.take(q).unwrap().is_none());
        r.cancel(&mut io, q, 3).unwrap();
    }
}
#[test]
fn network_context_loss_and_new_dns_configuration_invalidate_negative_entries() {
    for loss in [false, true] {
        let mut r = Resolver::new();
        let mut io = Io::default();
        let q = seed(&mut r, &mut io, 3, 90, 30);
        assert_eq!(r.take(q).unwrap(), Some(Err(expected(3))));
        if loss {
            io.config = Err(-6);
            assert_eq!(
                r.start(&mut io, name("absent.example"), DnsRecordType::A, 2, 100),
                Err(-6)
            );
        } else {
            io.config.as_mut().unwrap().dns = [192, 0, 2, 54];
            let q = r
                .start(&mut io, name("absent.example"), DnsRecordType::A, 2, 100)
                .unwrap();
            assert!(r.take(q).unwrap().is_none());
            r.cancel(&mut io, q, 2).unwrap();
        }
    }
}
#[test]
fn server_failures_and_denied_queries_never_turn_into_cached_absence() {
    for code in [2, 5] {
        let mut r = Resolver::new();
        let mut io = Io::default();
        let q = start(&mut r, &mut io, "absent.example");
        let id = udp(&io);
        let p = negative(&io.udp[&id].sent[0], code, "example", 90, 30, &[]);
        push(&mut io, id, p);
        r.pump(&mut io, 1);
        if code == 2 {
            assert!(r.take(q).unwrap().is_none());
            r.cancel(&mut io, q, 1).unwrap();
        } else {
            assert!(r.take(q).unwrap().unwrap().is_err());
        }
        let q = r
            .start(&mut io, name("absent.example"), DnsRecordType::A, 2, 100)
            .unwrap();
        assert!(r.take(q).unwrap().is_none());
        r.cancel(&mut io, q, 2).unwrap();
    }
}
