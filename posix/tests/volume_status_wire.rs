use mochios_filesystem_protocol::volume_status::{GET, READ_ONLY, RESPONSE_LEN, Status};
fn value() -> Status {
    Status {
        block_bytes: 4096,
        flags: READ_ONLY,
        blocks: 1 << 40,
        free_blocks: 1 << 39,
        inodes: 1 << 32,
        free_inodes: 1 << 31,
        filesystem_id: 0x0102030405060708,
        name_bytes_max: 255,
    }
}
#[test]
fn counters_use_explicit_64_bit_little_endian_layout() {
    let status = value();
    let bytes = status.encode();
    assert_eq!(bytes.len(), RESPONSE_LEN);
    assert_eq!(&bytes[8..16], &(1u64 << 40).to_le_bytes());
    assert_eq!(&bytes[40..48], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(Status::decode(&bytes), Some(status));
    assert_eq!(GET.to_le_bytes(), *b"MFS1VSTA");
}
#[test]
fn rejects_truncated_extended_reserved_or_inconsistent_accounting() {
    let bytes = value().encode();
    for length in 0..RESPONSE_LEN {
        assert_eq!(Status::decode(&bytes[..length]), None);
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert_eq!(Status::decode(&extended), None);
    for offset in 52..56 {
        let mut bad = bytes;
        bad[offset] = 1;
        assert_eq!(Status::decode(&bad), None);
    }
    for bad in [
        Status {
            block_bytes: 0,
            ..value()
        },
        Status {
            flags: 2,
            ..value()
        },
        Status {
            free_blocks: u64::MAX,
            ..value()
        },
        Status {
            free_inodes: u64::MAX,
            ..value()
        },
        Status {
            name_bytes_max: 0,
            ..value()
        },
    ] {
        assert_eq!(Status::decode(&bad.encode()), None);
    }
}

#[test]
fn assigned_filesystem_and_posix_opcodes_have_no_numeric_aliases() {
    // Independent constants do not get enum-style collision checks from rustc.
    for source in [
        include_str!("../../../user/crates/filesystem-protocol/src/lib.rs"),
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
    ] {
        let mut assigned = std::collections::BTreeMap::new();
        for declaration in source
            .lines()
            .filter(|line| line.starts_with("pub const OP_"))
        {
            let (name, value) = declaration.split_once('=').unwrap();
            let value = value.split(';').next().unwrap().trim().replace('_', "");
            let number = if let Some(value) = value.strip_prefix("0x") {
                u16::from_str_radix(value, 16).unwrap()
            } else {
                value.parse::<u16>().unwrap()
            };
            assert_eq!(
                assigned.insert(number, name),
                None,
                "duplicate opcode {number}: {name}"
            );
        }
        assert!(assigned.len() > 50);
    }
}
