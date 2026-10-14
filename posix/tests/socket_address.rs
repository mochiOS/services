use mochios_posix_client::socket::{MAX_SOCKADDR_LEN, decode_sockaddr, encode_sockaddr};
use mochios_posix_protocol::socket::Address;

#[test]
fn unspecified_family_is_a_connect_selector_not_a_bind_or_send_address() {
    use mochios_posix_client::socket::{decode_connect_sockaddr, ConnectAddress};
    for bytes in [&[0, 0][..], &[0; 16][..], &[0; MAX_SOCKADDR_LEN][..]] {
        assert_eq!(
            decode_connect_sockaddr(bytes),
            Ok(ConnectAddress::Disconnect)
        );
        assert_eq!(decode_sockaddr(bytes), Err(-97));
    }
    for bytes in [&[][..], &[0][..], &[0; MAX_SOCKADDR_LEN + 1][..]] {
        assert_eq!(decode_connect_sockaddr(bytes), Err(-22));
    }
    assert_eq!(
        decode_connect_sockaddr(b"\x01\x00/socket\x00"),
        Ok(ConnectAddress::Peer(Address::UnixPath(b"/socket")))
    );
    assert_eq!(decode_connect_sockaddr(&[2, 0]), Err(-22));
    assert_eq!(decode_connect_sockaddr(&[255, 255]), Err(-97));
}

#[test]
fn unix_names_preserve_terminators_abstract_binary_names_and_unnamed_length() {
    let mut bytes = [0xff; MAX_SOCKADDR_LEN];
    assert_eq!(encode_sockaddr(Address::UnixUnnamed, &mut bytes), Ok(2));
    assert_eq!(&bytes[..3], &[1, 0, 0xff]);
    assert_eq!(
        encode_sockaddr(Address::UnixPath(b"sock"), &mut bytes),
        Ok(7)
    );
    assert_eq!(&bytes[..7], b"\x01\x00sock\x00");
    assert_eq!(
        encode_sockaddr(Address::UnixAbstract(b"a\x00b"), &mut bytes),
        Ok(6)
    );
    assert_eq!(&bytes[..6], b"\x01\x00\x00a\x00b");
    assert_eq!(
        encode_sockaddr(Address::UnixAbstract(b""), &mut bytes),
        Ok(3)
    );
    let name = [b'x'; 107];
    assert_eq!(
        encode_sockaddr(Address::UnixPath(&name), &mut bytes),
        Ok(110)
    );
    assert_eq!(bytes[109], 0);
}

#[test]
fn ip_addresses_translate_domain_tags_ports_flow_and_scope_without_wire_padding() {
    let mut bytes = [0xff; MAX_SOCKADDR_LEN];
    assert_eq!(
        encode_sockaddr(
            Address::Ipv4 {
                address: [127, 0, 0, 1],
                port: 0x1234
            },
            &mut bytes
        ),
        Ok(16)
    );
    assert_eq!(&bytes[..8], &[2, 0, 0x12, 0x34, 127, 0, 0, 1]);
    assert_eq!(&bytes[8..16], &[0; 8]);
    assert_eq!(
        encode_sockaddr(
            Address::Ipv6 {
                address: [0xab; 16],
                port: 0x1234,
                flow_info: 0x01020304,
                scope_id: 0x50607080
            },
            &mut bytes
        ),
        Ok(28)
    );
    assert_eq!(&bytes[..8], &[10, 0, 0x12, 0x34, 1, 2, 3, 4]);
    assert_eq!(&bytes[8..24], &[0xab; 16]);
    assert_eq!(&bytes[24..28], &[0x80, 0x70, 0x60, 0x50]);
}

#[test]
fn malformed_or_undersized_address_encoding_never_modifies_output() {
    for address in [
        Address::UnixPath(b""),
        Address::UnixPath(b"a\x00b"),
        Address::UnixPath(&[b'x'; 108]),
        Address::UnixAbstract(&[0; 108]),
    ] {
        let mut bytes = [0xff; MAX_SOCKADDR_LEN];
        assert_eq!(encode_sockaddr(address, &mut bytes), Err(-22));
        assert_eq!(bytes, [0xff; MAX_SOCKADDR_LEN]);
    }
    for length in [0, 1] {
        let mut bytes = [0xff; 2];
        assert_eq!(
            encode_sockaddr(Address::UnixUnnamed, &mut bytes[..length]),
            Err(-22)
        );
        assert_eq!(bytes, [0xff; 2]);
    }
}

#[test]
fn c_addresses_round_trip_all_supported_wire_forms_without_identity_or_pointers() {
    let maximum = [b'x'; 107];
    for address in [
        Address::UnixUnnamed,
        Address::UnixPath(b"relative.sock"),
        Address::UnixPath(&maximum),
        Address::UnixPath(&[0xff, 0x80]),
        Address::UnixAbstract(b"a\x00b"),
        Address::UnixAbstract(b""),
        Address::UnixAbstract(&maximum),
        Address::Ipv4 {
            address: [127, 0, 0, 1],
            port: 0x1234,
        },
        Address::Ipv6 {
            address: [0xab; 16],
            port: 0xffff,
            flow_info: 0x10203040,
            scope_id: 0x50607080,
        },
    ] {
        let mut native = [0xff; MAX_SOCKADDR_LEN];
        let length = encode_sockaddr(address, &mut native).unwrap();
        let decoded = decode_sockaddr(&native[..length]).unwrap();
        assert_eq!(decoded, address);
        let mut wire = [0; mochios_posix_protocol::socket::MAX_ADDRESS_LEN];
        let length = decoded.encode(&mut wire).unwrap();
        assert_eq!(Address::decode(&wire[..length]), Ok(address));
    }
}

#[test]
fn parser_ignores_only_abi_padding_and_preserves_length_delimited_abstract_names() {
    assert_eq!(
        decode_sockaddr(b"\x01\x00path\x00ignored"),
        Ok(Address::UnixPath(b"path"))
    );
    assert_eq!(
        decode_sockaddr(b"\x01\x00path"),
        Ok(Address::UnixPath(b"path"))
    );
    assert_eq!(
        decode_sockaddr(b"\x01\x00\x00a\x00b\x00"),
        Ok(Address::UnixAbstract(b"a\x00b\x00"))
    );
    let mut bytes = [0xfe; 128];
    let address = Address::Ipv4 {
        address: [1, 2, 3, 4],
        port: 0x1234,
    };
    encode_sockaddr(address, &mut bytes).unwrap();
    bytes[8..].fill(0xcc);
    assert_eq!(decode_sockaddr(&bytes), Ok(address));
    let address = Address::Ipv6 {
        address: [0xff; 16],
        port: 42,
        flow_info: 7,
        scope_id: 123,
    };
    encode_sockaddr(address, &mut bytes).unwrap();
    assert_eq!(decode_sockaddr(&bytes), Ok(address));
}

#[test]
fn short_unknown_or_oversized_sockaddr_is_rejected_before_serialization() {
    assert_eq!(decode_sockaddr(&[]), Err(-22));
    assert_eq!(decode_sockaddr(&[1]), Err(-22));
    assert_eq!(decode_sockaddr(&[0, 0]), Err(-97));
    let mut bytes = [b'x'; 111];
    bytes[..2].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(decode_sockaddr(&bytes), Err(-22));
    assert_eq!(decode_sockaddr(&bytes[..110]), Err(-36));
    bytes[109] = 0;
    assert_eq!(
        decode_sockaddr(&bytes[..110]),
        Ok(Address::UnixPath(&bytes[2..109]))
    );
    bytes[..2].copy_from_slice(&2u16.to_le_bytes());
    for length in 2..16 {
        assert_eq!(decode_sockaddr(&bytes[..length]), Err(-22));
    }
    bytes[..2].copy_from_slice(&10u16.to_le_bytes());
    for length in 2..28 {
        assert_eq!(decode_sockaddr(&bytes[..length]), Err(-22));
    }
}
