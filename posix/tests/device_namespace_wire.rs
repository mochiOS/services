use mochios_filesystem_protocol::{self as wire, device_namespace as config};

#[test]
fn owner_configuration_codec_has_checked_lengths_version_and_operation_fields() {
    for (opcode, kind, mode, uid, gid) in [
        (
            wire::OP_DEVICE_NODE_CREATE,
            config::KIND_DIRECTORY,
            0o755,
            501,
            20,
        ),
        (
            wire::OP_DEVICE_NODE_CREATE,
            config::KIND_NULL,
            0o600,
            u32::MAX,
            u32::MAX,
        ),
        (wire::OP_DEVICE_NODE_SET_ATTRIBUTES, 0, 0o660, 1000, 1000),
        (wire::OP_DEVICE_NODE_REMOVE, 0, 0, 0, 0),
    ] {
        for name in [b"session".as_slice(), b"0", &[0xff; 255]] {
            let request = config::Request {
                kind,
                mode,
                uid,
                gid,
                name,
            };
            let mut output = [0xcc; config::HEADER_LEN + config::MAX_NAME_LEN + 1];
            let length = config::encode(opcode, request, &mut output).unwrap();
            assert_eq!(config::decode(opcode, &output[..length]), Ok(request));
            assert!(output[18..24].iter().all(|&byte| byte == 0));
            assert!(output[length..].iter().all(|&byte| byte == 0xcc));
            for short in 0..length {
                assert!(config::decode(opcode, &output[..short]).is_err());
            }
            for at in [0usize, 1, 16, 17, 18, 23] {
                let mut bad = output;
                bad[at] ^= 0x80;
                assert!(config::decode(opcode, &bad[..length]).is_err());
            }
            assert!(config::decode(opcode, &output[..length + 1]).is_err());
            let mut short = vec![0xcc; length - 1];
            assert!(config::encode(opcode, request, &mut short).is_err());
            assert!(short.iter().all(|&byte| byte == 0xcc));
        }
    }
}

#[test]
fn malformed_or_cross_operation_configuration_cannot_encode_or_decode() {
    let create = config::Request {
        kind: config::KIND_DIRECTORY,
        mode: 0o755,
        uid: 501,
        gid: 20,
        name: b"session",
    };
    let mut valid = [0; config::HEADER_LEN + 7];
    config::encode(wire::OP_DEVICE_NODE_CREATE, create, &mut valid).unwrap();
    for opcode in [
        wire::OP_DEVICE_NODE_REMOVE,
        wire::OP_DEVICE_NODE_SET_ATTRIBUTES,
        wire::OP_OPEN_AT,
        u16::MAX,
    ] {
        assert!(config::decode(opcode, &valid).is_err());
        let mut output = [0xcc; 279];
        assert!(config::encode(opcode, create, &mut output).is_err());
        assert_eq!(output, [0xcc; 279]);
    }
    for name in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b", &[b'a'; 256]] {
        let mut output = [0xcc; 280];
        assert!(
            config::encode(
                wire::OP_DEVICE_NODE_CREATE,
                config::Request { name, ..create },
                &mut output
            )
            .is_err()
        );
        assert_eq!(output, [0xcc; 280]);
    }
    for mode in [0o100600u32, 0x10000, u32::MAX] {
        let mut bad = valid;
        bad[4..8].copy_from_slice(&mode.to_le_bytes());
        assert!(config::decode(wire::OP_DEVICE_NODE_CREATE, &bad).is_err());
    }
    for kind in [0u16, 3, u16::MAX] {
        let mut bad = valid;
        bad[2..4].copy_from_slice(&kind.to_le_bytes());
        assert!(config::decode(wire::OP_DEVICE_NODE_CREATE, &bad).is_err());
    }
}
