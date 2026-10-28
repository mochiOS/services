use mochios_net_device_protocol::resolver as wire;
use mochios_posix_client::{
    internet::Address,
    netdb::{self as n, Error, ScopedAddress, database, dns},
    resolver::{Kind, Name},
};

#[test]
fn hosts_records_preserve_all_addresses_aliases_case_and_comments() {
    let input=b"# comment\n127.0.0.1 localhost loopback # local\n\t192.0.2.1\tPrimary.Example alias other\r\n2001:db8::1 primary.example alias\n192.0.2.2 primary.example alias\ninvalid ignored\n127.1 short\n192.0.2.256 bad\n192.0.2.7\n192.0.2.8 bad\0alias\n";
    let records = database::hosts(input).collect::<Vec<_>>();
    assert_eq!(records.len(), 4);
    assert_eq!(records[1].canonical, b"Primary.Example");
    assert_eq!(records.iter().filter(|r| r.matches(b"ALIAS")).count(), 3);
    assert!(records[0].matches(b"LOOPBACK"));
    assert!(!records[0].matches(b"local"));
    assert!(matches!(records[2].address, Address::V6(_)));
    assert_eq!(records[3].address, Address::V4([192, 0, 2, 2]));
}
#[test]
fn service_records_distinguish_protocol_case_aliases_and_all_port_boundaries() {
    let input=b"http 80/tcp www WWW # web\ndomain\t53/udp dns\ndomain 53/tcp dns\nzero 0/tcp\nmaximum 65535/udp\nbad 65536/tcp\nbad -1/tcp\nbad 80/sctp\nbad /tcp\nbad 5/tcp/udp\nbad 1\nbad 80/tcp alias\0\n";
    let records = database::services(input).collect::<Vec<_>>();
    assert_eq!(records.len(), 5);
    assert!(records[0].matches(b"www"));
    assert!(records[0].matches(b"WWW"));
    assert!(!records[0].matches(b"Http"));
    assert_eq!(records[1].transport, n::Transport::Udp);
    assert_eq!(records[2].transport, n::Transport::Tcp);
    assert_eq!(records[3].port, 0);
    assert_eq!(records[4].port, u16::MAX);
}
fn roundtrip(text: &[u8]) {
    let mut first = [0; 255];
    let name = dns::question(text, &mut first).unwrap();
    let mut display = [0; 1025];
    let n = dns::presentation(name, &mut display).unwrap();
    let mut second = [0; 255];
    assert_eq!(
        dns::question(&display[..n], &mut second).unwrap().bytes(),
        name.bytes()
    );
}
#[test]
fn dns_labels_roundtrip_root_escaped_dots_binary_bytes_and_maximum_names() {
    for name in [
        b".".as_slice(),
        b"example",
        b"EXAMPLE.com.",
        b"a\\.b.example",
        b"a\\\\b.example",
        b"\\000\\255\\046.example",
        b"space\\032name.example",
    ] {
        roundtrip(name);
    }
    // Four labels use the complete 255-byte expanded-name limit.
    let name = [
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 61],
    ]
    .join(b".".as_slice());
    roundtrip(&name);
    let mut wire = Vec::new();
    for chunk in (0u8..=255).collect::<Vec<_>>().chunks(60).take(4) {
        wire.push(chunk.len() as u8);
        wire.extend_from_slice(chunk);
    }
    wire.push(0);
    let name = Name::decode(&wire).unwrap();
    let mut out = [0; 1025];
    let n = dns::presentation(name, &mut out).unwrap();
    let mut back = [0; 255];
    assert_eq!(dns::question(&out[..n], &mut back).unwrap().bytes(), wire);
}
#[test]
fn dns_invalid_names_and_output_boundaries_do_not_cross_the_given_buffer() {
    let mut buffer = [0; 255];
    for invalid in [
        b"".as_slice(),
        b"..",
        b"a..b",
        b"a\\",
        b"a\\12",
        b"a\\256",
        b"a\\1zz",
        b"a\0b",
    ] {
        assert_eq!(
            dns::question(invalid, &mut buffer),
            Err(Error::NoName),
            "{invalid:?}"
        );
    }
    assert_eq!(
        dns::question(&vec![b'x'; 64], &mut buffer),
        Err(Error::NoName)
    );
    let oversized = [
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 62],
    ]
    .join(b".".as_slice());
    assert_eq!(dns::question(&oversized, &mut buffer), Err(Error::NoName));
    let name = Name::decode(b"\x03a.b\0").unwrap();
    for capacity in 0..4 {
        let mut out = [0xa5; 8];
        assert_eq!(
            dns::presentation(name, &mut out[..capacity]),
            Err(Error::Overflow)
        );
        assert_eq!(out[capacity..], [0xa5; 8][capacity..]);
    }
    let mut out = [0; 4];
    assert_eq!(dns::presentation(name, &mut out), Ok(4));
    assert_eq!(&out, b"a\\.b");
}
#[test]
fn reverse_questions_use_reversed_octets_or_every_ipv6_nibble() {
    let mut wire = [0; 255];
    let mut text = [0; 1025];
    let name = dns::reverse(Address::V4([192, 0, 2, 1]).into(), &mut wire).unwrap();
    let n = dns::presentation(name, &mut text).unwrap();
    assert_eq!(&text[..n], b"1.2.0.192.in-addr.arpa");
    let mut v6 = [0; 16];
    v6[0] = 0x20;
    v6[1] = 1;
    v6[2] = 0x0d;
    v6[3] = 0xb8;
    v6[15] = 0x12;
    let name = dns::reverse(
        ScopedAddress {
            address: Address::V6(v6),
            scope: 7,
        },
        &mut wire,
    )
    .unwrap();
    let n = dns::presentation(name, &mut text).unwrap();
    let expected = v6
        .iter()
        .rev()
        .flat_map(|b| [format!("{:x}.", b & 15), format!("{:x}.", b >> 4)])
        .collect::<String>()
        + "ip6.arpa";
    assert_eq!(&text[..n], expected.as_bytes());
    assert!(text[..n].starts_with(b"2.1.0.0."));
    assert!(text[..n].ends_with(b"8.b.d.0.1.0.0.2.ip6.arpa"));
}
fn packet(kind: Kind, status: i32, values: &[Vec<u8>]) -> Vec<u8> {
    let q = Name::decode(b"\x07example\0").unwrap();
    let mut out = vec![0; 100_000];
    let n = if status != 0 {
        wire::encode_failure(kind, status, q, &mut out).unwrap()
    } else {
        wire::encode_result(
            kind,
            0,
            q,
            Some(q),
            false,
            std::iter::empty(),
            values.iter().map(Vec::as_slice),
            &mut out,
        )
        .unwrap()
    };
    out.truncate(n);
    out
}
#[test]
fn dns_snapshot_adapter_preserves_large_rrsets_types_and_canonical_names() {
    for kind in [Kind::A, Kind::Aaaa] {
        let values = (0..1024u32)
            .map(|n| {
                if kind == Kind::A {
                    n.to_be_bytes().to_vec()
                } else {
                    let mut a = vec![0; 16];
                    a[12..].copy_from_slice(&n.to_be_bytes());
                    a
                }
            })
            .collect::<Vec<_>>();
        let bytes = packet(kind, 0, &values);
        let result = wire::decode_result(&bytes).unwrap();
        let mut addresses = Vec::new();
        assert_eq!(
            dns::forward(&result, &mut |h| {
                assert_eq!(h.canonical, Some(b"example".as_slice()));
                addresses.push(h.address.address.octets().to_vec());
                Ok(())
            }),
            Ok(1024)
        );
        assert_eq!(addresses, values);
        assert_eq!(
            dns::forward(&result, &mut |_| Err(Error::Memory)),
            Err(Error::Memory)
        );
        assert_eq!(dns::ptr(&result, &mut [0; 1025]), Err(Error::Fail));
    }
    let bytes = packet(Kind::A, 0, &[]);
    let result = wire::decode_result(&bytes).unwrap();
    assert_eq!(dns::forward(&result, &mut |_| panic!()), Ok(0));
}
#[test]
fn ptr_snapshot_selection_and_explicit_errors_never_fabricate_a_name() {
    let bytes = packet(
        Kind::Ptr,
        0,
        &[b"\x04host\x07example\0".to_vec(), b"\x05other\0".to_vec()],
    );
    let result = wire::decode_result(&bytes).unwrap();
    let mut out = [0; 1025];
    let n = dns::ptr(&result, &mut out).unwrap().unwrap();
    assert_eq!(&out[..n], b"host.example");
    assert_eq!(dns::forward(&result, &mut |_| panic!()), Err(Error::Fail));
    assert_eq!(dns::ptr(&result, &mut [0; 1]), Err(Error::Overflow));
    let bytes = packet(Kind::Ptr, 0, &[]);
    let result = wire::decode_result(&bytes).unwrap();
    assert_eq!(dns::ptr(&result, &mut out), Ok(None));
    for (status, error) in [
        (-2, Error::NoName),
        (-11, Error::Again),
        (-110, Error::Again),
        (-12, Error::Memory),
        (-22, Error::Fail),
        (-95, Error::Fail),
        (-13, Error::System(-13)),
        (-6, Error::System(-6)),
    ] {
        let bytes = packet(Kind::Ptr, status, &[]);
        let result = wire::decode_result(&bytes).unwrap();
        assert_eq!(dns::ptr(&result, &mut out), Err(error));
    }
    for invalid in [1, i32::MAX, i32::MIN] {
        assert_eq!(dns::status(invalid), Err(Error::Fail));
    }
}
