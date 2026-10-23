use mochios_filesystem_protocol::object_limits::{GET, Limits, RESPONSE_LEN};

#[test]
fn explicit_little_endian_limits_round_trip_without_native_layout() {
    let limits = Limits {
        name_bytes_max: 0x01020304,
        path_bytes_max: 0x11121314,
        link_count_max: 0x21222324,
        filesystem_block_bytes: 0x31323334,
    };
    let bytes = limits.encode();
    assert_eq!(
        bytes,
        [4, 3, 2, 1, 20, 19, 18, 17, 36, 35, 34, 33, 52, 51, 50, 49]
    );
    assert_eq!(Limits::decode(&bytes), Some(limits));
    assert_eq!(GET.to_le_bytes(), *b"MFS1LIMT");
}

#[test]
fn every_incomplete_or_extended_response_is_rejected() {
    for length in 0..RESPONSE_LEN {
        assert_eq!(Limits::decode(&vec![0; length]), None);
    }
    assert_eq!(Limits::decode(&[0; RESPONSE_LEN + 1]), None);
    let maximum = Limits {
        name_bytes_max: u32::MAX,
        path_bytes_max: u32::MAX,
        link_count_max: u32::MAX,
        filesystem_block_bytes: u32::MAX,
    };
    assert_eq!(Limits::decode(&maximum.encode()), Some(maximum));
}
