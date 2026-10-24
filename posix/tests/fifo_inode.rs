use mochios_filesystem_protocol as wire;
use posix_service::fifo_inode::{METADATA_RIGHTS, validate_reply};

fn valid() -> (wire::Header, Vec<u8>, mnu_abi::IpcObjectHandles) {
    let mut payload = vec![0; wire::NODE_STATUS_LEN];
    wire::encode_node_status(
        wire::NodeStatus {
            node_id: (2 << 32) | 17,
            device: 2,
            kind: wire::NODE_TYPE_FIFO,
            mode: 0o640,
            ..Default::default()
        },
        &mut payload,
    )
    .unwrap();
    let header = wire::Header {
        opcode: wire::OP_STATUS,
        request_id: 71,
        flags: wire::OPEN_REPLY_FIFO,
        open_id: 27,
        node_id: (2 << 32) | 17,
        length: payload.len() as u32,
        ..Default::default()
    };
    let mut objects = mnu_abi::IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = mnu_abi::IpcObjectHandle {
        handle: 91,
        rights: METADATA_RIGHTS,
        reserved: 0,
    };
    (header, payload, objects)
}

#[test]
fn retained_fifo_requires_matching_identity_framing_and_exact_metadata_authority() {
    let (header, payload, objects) = valid();
    let status = validate_reply(header, 71, &payload, &objects).unwrap();
    assert_eq!((status.device, status.node_id), (2, (2 << 32) | 17));
    for count in [0, 2, u32::MAX] {
        let mut bad = objects;
        bad.count = count;
        assert_eq!(validate_reply(header, 71, &payload, &bad), Err(-5));
    }
    for rights in [
        0,
        METADATA_RIGHTS & !mnu_abi::HANDLE_RIGHT_TRANSFER,
        METADATA_RIGHTS | mnu_abi::HANDLE_RIGHT_READ,
        METADATA_RIGHTS | mnu_abi::HANDLE_RIGHT_WRITE,
        METADATA_RIGHTS | mnu_abi::HANDLE_RIGHT_MAP,
    ] {
        let mut bad = objects;
        bad.handles[0].rights = rights;
        assert_eq!(validate_reply(header, 71, &payload, &bad), Err(-5));
    }
    for alter in 0..8 {
        let mut bad = header;
        match alter {
            0 => bad.opcode = wire::OP_OPEN_AT,
            1 => bad.flags = 0,
            2 => bad.flags |= 2,
            3 => bad.open_id = 0,
            4 => bad.open_id = u64::MAX,
            5 => bad.request_id += 1,
            6 => bad.node_id += 1,
            _ => bad.length -= 1,
        }
        assert_eq!(validate_reply(bad, 71, &payload, &objects), Err(-5));
    }
    for length in 0..payload.len() {
        assert_eq!(
            validate_reply(header, 71, &payload[..length], &objects),
            Err(-5)
        );
    }
    for corrupt in 0..6 {
        let mut status = status;
        match corrupt {
            0 => status.kind = wire::NODE_TYPE_REGULAR,
            1 => status.device = 3,
            2 => status.size = 1,
            3 => status.blocks = 1,
            4 => status.special_device = 1,
            _ => status.mode |= 0o100000,
        }
        let mut bad = payload.clone();
        wire::encode_node_status(status, &mut bad).unwrap();
        assert_eq!(validate_reply(header, 71, &bad, &objects), Err(-5));
    }
}

#[test]
fn remote_failure_is_preserved_only_without_attached_authority_or_payload() {
    let (mut header, payload, objects) = valid();
    header.status = -13;
    header.flags = 0;
    header.length = 0;
    assert_eq!(
        validate_reply(header, 71, &[], &mnu_abi::IpcObjectHandles::default()),
        Err(-13)
    );
    assert_eq!(validate_reply(header, 71, &[], &objects), Err(-5));
    assert_eq!(
        validate_reply(header, 71, &payload, &mnu_abi::IpcObjectHandles::default()),
        Err(-5)
    );
}
