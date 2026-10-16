//! Run the production no_std wire codec without rebuilding the SDK or OS.
#![allow(dead_code)]
use mochios_filesystem_protocol as wire;
#[path = "../../../user/crates/posix-client/src/directory.rs"]
mod directory;

#[test]
fn legacy_encoding_stays_byte_identical_and_has_no_cursor() {
    let mut output = [0xa5; 64];
    let length =
        wire::encode_dir_entry(0x1234, wire::NODE_TYPE_REGULAR, b"file", &mut output).unwrap();
    assert_eq!(length, 20);
    assert_eq!(
        &output[..length],
        &[
            0x34, 0x12, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, b'f', b'i', b'l', b'e'
        ]
    );
    let (header, name, consumed) = wire::decode_dir_entry(&output).unwrap();
    assert_eq!(header.next_position, None);
    assert_eq!(name, b"file");
    assert_eq!(consumed, length);
    assert!(output[length..].iter().all(|byte| *byte == 0xa5));
}

#[test]
fn opaque_positions_round_trip_without_truncation_or_count_arithmetic() {
    for position in [0, 1, 65536, i64::MAX as u64, u64::MAX] {
        let mut output = [0xa5; 64];
        let length = wire::encode_cursor_dir_entry(
            42,
            wire::NODE_TYPE_DIRECTORY,
            b"dir",
            position,
            &mut output,
        )
        .unwrap();
        assert_eq!(length, wire::CURSOR_DIRENT_HEADER_LEN + 3);
        assert_eq!(&output[14..16], &[1, 0]);
        assert_eq!(&output[16..24], &position.to_le_bytes());
        let (header, name, consumed) = wire::decode_dir_entry(&output).unwrap();
        assert_eq!(
            (header.node_id, header.kind, header.name_len),
            (42, wire::NODE_TYPE_DIRECTORY, 3)
        );
        assert_eq!(header.next_position, Some(position));
        assert_eq!(name, b"dir");
        assert_eq!(consumed, length);
        assert!(output[length..].iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn mixed_records_keep_exact_boundaries_and_nonconsecutive_positions() {
    let mut bytes = [0; 256];
    let mut length = 0;
    for (name, position) in [
        (b"one".as_slice(), Some(2)),
        (b"legacy", None),
        (b"three", Some(9000)),
    ] {
        length += match position {
            Some(position) => {
                wire::encode_cursor_dir_entry(1, 1, name, position, &mut bytes[length..])
            }
            None => wire::encode_dir_entry(1, 1, name, &mut bytes[length..]),
        }
        .unwrap();
    }
    let mut remaining = &bytes[..length];
    for (name, position) in [
        (b"one".as_slice(), Some(2)),
        (b"legacy", None),
        (b"three", Some(9000)),
    ] {
        let (header, decoded, consumed) = wire::decode_dir_entry(remaining).unwrap();
        assert_eq!(decoded, name);
        assert_eq!(header.next_position, position);
        remaining = &remaining[consumed..];
    }
    assert!(remaining.is_empty());
    let entries = directory::DirectoryEntries::new(&bytes[..length])
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        entries.iter().map(|entry| entry.name).collect::<Vec<_>>(),
        ["one", "legacy", "three"]
    );
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.next_position)
            .collect::<Vec<_>>(),
        [Some(2), None, Some(9000)]
    );
}

#[test]
fn ordinary_directory_iterator_stops_at_an_unsupported_extension() {
    let mut bytes = [0; 64];
    let length = wire::encode_cursor_dir_entry(1, 1, b"file", 2, &mut bytes).unwrap();
    bytes[14..16].copy_from_slice(&2u16.to_le_bytes());
    let mut entries = directory::DirectoryEntries::new(&bytes[..length]);
    assert!(matches!(
        entries.next(),
        Some(Err(directory::DirectoryDecodeError::Protocol(
            wire::ProtocolError::UnsupportedVersion
        )))
    ));
    assert_eq!(entries.next(), None);
}

#[test]
fn every_truncated_cursor_record_is_rejected_without_reading_past_input() {
    let mut bytes = [0; 64];
    let length = wire::encode_cursor_dir_entry(1, 1, b"filename", 300, &mut bytes).unwrap();
    for end in 0..length {
        assert_eq!(
            wire::decode_dir_entry(&bytes[..end]),
            Err(wire::ProtocolError::BufferTooSmall)
        );
    }
    assert!(wire::decode_dir_entry(&bytes[..length]).is_ok());
}

#[test]
fn unsupported_record_extensions_are_not_silently_treated_as_names() {
    let mut bytes = [0; 64];
    wire::encode_cursor_dir_entry(1, 1, b"file", 2, &mut bytes).unwrap();
    for flags in [2u16, 3, 0x8000, u16::MAX] {
        bytes[14..16].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(
            wire::decode_dir_entry(&bytes),
            Err(wire::ProtocolError::UnsupportedVersion)
        );
    }
}

#[test]
fn short_output_does_not_publish_a_partial_cursor_record() {
    for capacity in 0..wire::CURSOR_DIRENT_HEADER_LEN + 4 {
        let mut output = [0xa5; 64];
        assert_eq!(
            wire::encode_cursor_dir_entry(1, 1, b"file", 2, &mut output[..capacity]),
            Err(wire::ProtocolError::BufferTooSmall)
        );
        assert!(output.iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn both_formats_enforce_the_same_name_rules_without_changing_output_on_failure() {
    let overlong = [b'x'; wire::MAX_NAME_LEN + 1];
    for name in [
        b"".as_slice(),
        b"bad/name",
        b"bad\0name",
        overlong.as_slice(),
    ] {
        for cursor in [false, true] {
            let mut output = [0xa5; 512];
            let result = if cursor {
                wire::encode_cursor_dir_entry(1, 1, name, 2, &mut output)
            } else {
                wire::encode_dir_entry(1, 1, name, &mut output)
            };
            assert_eq!(result, Err(wire::ProtocolError::InvalidLength));
            assert!(output.iter().all(|byte| *byte == 0xa5));
        }
    }
}

#[test]
fn maximum_length_non_utf8_names_and_corrupt_names_use_the_wire_byte_contract() {
    let name = [0xff; wire::MAX_NAME_LEN];
    let mut output = [0; 512];
    let length = wire::encode_cursor_dir_entry(1, 1, &name, 7, &mut output).unwrap();
    let (_, decoded, consumed) = wire::decode_dir_entry(&output[..length]).unwrap();
    assert_eq!(decoded, name);
    assert_eq!(consumed, length);
    for bad in [0, b'/'] {
        output[wire::CURSOR_DIRENT_HEADER_LEN] = bad;
        assert_eq!(
            wire::decode_dir_entry(&output[..length]),
            Err(wire::ProtocolError::InvalidLength)
        );
    }
}
