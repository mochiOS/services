use mochios_posix_client::socket::{MAX_SOCKADDR_LEN, encode_sockaddr};
use mochios_posix_protocol::socket::Address;

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
