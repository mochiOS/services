use mochios_net_device_protocol::resolver as w;
use mochios_posix_client::resolver_packet as p;
const NAME: &[u8] = b"\x07example\x03com\0";
fn snapshot(kind: w::Kind, value: &[u8], aliases: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0; 4096];
    let n = w::encode_result(
        kind,
        0,
        w::Name::decode(aliases.first().copied().unwrap_or(NAME)).unwrap(),
        Some(w::Name::decode(NAME).unwrap()),
        false,
        aliases.iter().copied(),
        [value].into_iter(),
        &mut out,
    )
    .unwrap();
    out.truncate(n);
    out
}
#[test]
fn native_records_become_parseable_dns_replies_without_unearned_ttl_or_dnssec_claims() {
    for (kind, value) in [
        (w::Kind::A, vec![192, 0, 2, 1]),
        (w::Kind::Ns, NAME.to_vec()),
        (w::Kind::Mx, [b"\0\x0a".as_slice(), NAME].concat()),
        (
            w::Kind::Srv,
            [b"\0\x01\0\x02\x01\xbb".as_slice(), NAME].concat(),
        ),
        (w::Kind::Txt, b"\x03a\0b".to_vec()),
        (w::Kind::Soa, [NAME, NAME, &[0; 20]].concat()),
    ] {
        let bytes = snapshot(kind, &value, &[]);
        let parsed = w::decode_result(&bytes).unwrap();
        let mut full = [0; 4096];
        let needed = p::reply(&parsed, &mut full).unwrap();
        assert_eq!(&full[2..4], &[0x81, 0x00]);
        assert_eq!(&full[6..8], &[0, 1]);
        let name = mochios_network_stack::DnsRecordName::from_wire(NAME).unwrap();
        let native_kind = match kind {
            w::Kind::A => mochios_network_stack::DnsRecordType::A,
            w::Kind::Ns => mochios_network_stack::DnsRecordType::Ns,
            w::Kind::Mx => mochios_network_stack::DnsRecordType::Mx,
            w::Kind::Srv => mochios_network_stack::DnsRecordType::Srv,
            w::Kind::Txt => mochios_network_stack::DnsRecordType::Txt,
            w::Kind::Soa => mochios_network_stack::DnsRecordType::Soa,
            _ => unreachable!(),
        };
        let native =
            mochios_network_stack::decode_dns_records(&full[..needed], 0, &name, native_kind)
                .unwrap();
        assert_eq!(native.values().len(), 1);
        assert_eq!(native.ttl_seconds(), 0);
        for capacity in 0..needed {
            let mut short = vec![0; capacity];
            assert_eq!(p::reply(&parsed, &mut short), Ok(needed));
            if capacity >= 4 {
                assert_eq!(short[2] & 2, 2);
            }
        }
    }
}
#[test]
fn reconstructed_cname_paths_preserve_question_and_terminal_owner() {
    let source = b"\x05alias\x03com\0";
    let bytes = snapshot(w::Kind::A, &[192, 0, 2, 1], &[source]);
    let result = w::decode_result(&bytes).unwrap();
    let mut output = [0; 4096];
    let length = p::reply(&result, &mut output).unwrap();
    let question = mochios_network_stack::DnsRecordName::from_wire(source).unwrap();
    let decoded = mochios_network_stack::decode_dns_records(
        &output[..length],
        0,
        &question,
        mochios_network_stack::DnsRecordType::A,
    )
    .unwrap();
    assert_eq!(decoded.aliases().len(), 1);
    assert_eq!(decoded.canonical_name().wire(), NAME);
}
#[test]
fn expansion_preserves_case_escapes_binary_labels_and_counts_original_bytes() {
    let mut packet = vec![0; 12];
    packet.extend(b"\x03A.b\x02\0\xff\0");
    let offset = packet.len();
    packet.extend([0xc0, 12]);
    let mut text = [0; 1025];
    let (consumed, length) = p::expand(&packet, offset, &mut text).unwrap();
    assert_eq!(consumed, 2);
    assert_eq!(&text[..length], b"A\\.b.\\000\\255");
    assert_eq!(p::expand(&packet, 12, &mut text).unwrap().0, 8);
    assert_eq!(p::expand(&[0], 0, &mut text), Ok((1, 0)));
    assert!(p::expand(&packet, offset, &mut [0; 2]).is_err());
}
#[test]
fn expansion_rejects_cycles_forward_pointers_reserved_labels_and_overlong_names() {
    for data in [
        vec![0xc0, 12],
        vec![0xc0, 14, 0],
        vec![0x40, 0],
        vec![0xc0],
        vec![1],
        vec![0xc0, 0],
    ] {
        let mut packet = vec![0; 12];
        packet.extend(data);
        assert!(p::expand(&packet, 12, &mut [0; 1025]).is_err());
    }
    let mut packet = vec![0; 12];
    packet.extend([1, b'x'].repeat(128));
    packet.push(0);
    assert!(p::expand(&packet, 12, &mut [0; 1025]).is_err());
    assert!(p::expand(&[0; 65536], 0, &mut [0; 1025]).is_err());
    for (class, kind) in [(0, 1), (1, 255), (1, 252), (1, -1), (1, 65537)] {
        assert!(p::query_kind(class, kind).is_err());
    }
}
