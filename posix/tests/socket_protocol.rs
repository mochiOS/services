use mochios_posix_protocol::{
    ProtocolError,
    socket::{self, Address, Create, Domain, Kind},
};

#[test]
fn creation_encodes_only_socket_semantics_not_local_descriptor_flags_or_identity() {
    for domain in [Domain::Unix, Domain::Ipv4, Domain::Ipv6] {
        for kind in [Kind::Stream, Kind::Datagram, Kind::SequencedPacket] {
            for options in [0, socket::NONBLOCKING] {
                let request = Create {
                    domain,
                    kind,
                    protocol: 6,
                    options,
                };
                let mut bytes = [0xff; socket::CREATE_LEN];
                assert_eq!(request.encode(&mut bytes), Ok(socket::CREATE_LEN));
                assert_eq!(Create::decode(&bytes), Ok(request));
                assert_eq!(&bytes[12..], &[0; 4]);
                for length in 0..socket::CREATE_LEN {
                    assert!(Create::decode(&bytes[..length]).is_err());
                }
                for offset in [0, 2, 8, 12] {
                    let mut invalid = bytes;
                    invalid[offset] = 0xff;
                    assert!(Create::decode(&invalid).is_err());
                }
            }
        }
    }
    let invalid = Create {
        domain: Domain::Unix,
        kind: Kind::Stream,
        protocol: 0,
        options: 2,
    };
    let mut bytes = [0xff; socket::CREATE_LEN];
    assert_eq!(
        invalid.encode(&mut bytes),
        Err(ProtocolError::InvalidLength)
    );
    assert_eq!(bytes, [0xff; socket::CREATE_LEN]);
}

#[test]
fn all_address_forms_round_trip_without_native_sockaddr_padding_or_endian_assumptions() {
    let maximum = [b'x'; socket::MAX_UNIX_NAME_BYTES];
    for address in [
        Address::UnixPath(b"relative.sock"),
        Address::UnixPath(&maximum),
        Address::UnixAbstract(b"a\0b"),
        Address::UnixAbstract(b""),
        Address::UnixUnnamed,
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
        let mut bytes = [0xff; socket::MAX_ADDRESS_LEN + 1];
        let count = address.encode(&mut bytes).unwrap();
        assert_eq!(Address::decode(&bytes[..count]), Ok(address));
        assert_eq!(bytes[3], 0);
        for length in 0..count {
            assert!(Address::decode(&bytes[..length]).is_err());
        }
        for offset in [0, 2, 3, 4] {
            let mut invalid = bytes;
            invalid[offset] = 0xff;
            assert!(Address::decode(&invalid[..count]).is_err());
        }
        bytes[count] = 0;
        assert!(Address::decode(&bytes[..count + 1]).is_err());
    }
    let mut bytes = [0; socket::MAX_ADDRESS_LEN];
    let count = Address::Ipv4 {
        address: [1, 2, 3, 4],
        port: 0x1234,
    }
    .encode(&mut bytes)
    .unwrap();
    assert_eq!(&bytes[8..count], &[0x34, 0x12, 1, 2, 3, 4]);
}

#[test]
fn malformed_names_and_insufficient_buffers_fail_before_modifying_output() {
    let too_long = [b'x'; socket::MAX_UNIX_NAME_BYTES + 1];
    for address in [
        Address::UnixPath(b""),
        Address::UnixPath(b"a\0b"),
        Address::UnixPath(&too_long),
        Address::UnixAbstract(&too_long),
    ] {
        let mut bytes = [0xff; socket::MAX_ADDRESS_LEN];
        assert_eq!(
            address.encode(&mut bytes),
            Err(ProtocolError::InvalidLength)
        );
        assert_eq!(bytes, [0xff; socket::MAX_ADDRESS_LEN]);
    }
    let mut bytes = [0xff; 7];
    assert_eq!(
        Address::UnixUnnamed.encode(&mut bytes),
        Err(ProtocolError::BufferTooSmall)
    );
    assert_eq!(bytes, [0xff; 7]);
    let mut malformed = [0; socket::ADDRESS_HEADER_LEN];
    malformed[..2].copy_from_slice(&1u16.to_le_bytes());
    malformed[2] = 2;
    malformed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        Address::decode(&malformed),
        Err(ProtocolError::InvalidLength)
    );
}

#[test]
fn pure_policy_dispatcher_does_not_fabricate_native_socket_handles() {
    use mochios_posix_protocol as protocol;
    use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};
    let mut service = PosixService::<u32>::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 1,
                process_id: 1,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    let peer = PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut bytes = [0; socket::CREATE_LEN];
    Create {
        domain: Domain::Unix,
        kind: Kind::Stream,
        protocol: 0,
        options: 0,
    }
    .encode(&mut bytes)
    .unwrap();
    for opcode in [protocol::OP_SOCKET_CREATE, protocol::OP_SOCKET_PAIR] {
        let response = service.handle(
            peer,
            protocol::Header {
                opcode,
                request_id: 19,
                payload_len: bytes.len() as u32,
                ..Default::default()
            },
            &bytes,
        );
        assert_eq!(response.header.status, protocol::STATUS_ENOSYS);
        assert!(response.payload.is_empty());
    }
}
