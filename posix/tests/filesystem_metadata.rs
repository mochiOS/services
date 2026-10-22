use mochios_filesystem_protocol as fs;
use posix_service::filesystem_metadata;

#[test]
fn scoped_node_identity_is_split_without_losing_volume_or_inode() {
    for volume in [0, 1, 65535, 65536, u32::MAX] {
        for inode in [2, 65535, 65536, u32::MAX] {
            let status = fs::NodeStatus {
                device: u64::from(volume),
                node_id: (u64::from(volume) << 32) | u64::from(inode),
                kind: fs::NODE_TYPE_REGULAR,
                ..Default::default()
            };
            let result = filesystem_metadata::translate(status).unwrap();
            assert_eq!((result.device, result.inode), (volume.into(), inode.into()));
            assert_eq!((result.device << 32) | result.inode, status.node_id);
        }
    }
}

#[test]
fn null_device_metadata_retains_character_type_and_device_number() {
    let status = fs::NodeStatus {
        device: 3,
        node_id: (3 << 32) | 2,
        kind: fs::NODE_TYPE_SPECIAL,
        mode: 0o020666,
        special_device: 259,
        link_count: 1,
        ..Default::default()
    };
    let converted = filesystem_metadata::translate(status).unwrap();
    assert_eq!((converted.device, converted.inode), (3, 2));
    assert_eq!((converted.mode, converted.special_device), (0o020666, 259));
}

#[test]
fn inconsistent_provider_identity_is_rejected_not_truncated() {
    let mut status = fs::NodeStatus {
        kind: fs::NODE_TYPE_REGULAR,
        device: 1,
        node_id: 2,
        ..Default::default()
    };
    assert_eq!(filesystem_metadata::translate(status), Err(-5));
    status.device = 0;
    status.node_id = (1 << 32) | 2;
    assert_eq!(filesystem_metadata::translate(status), Err(-5));
}
