use super::*;
use mochios_filesystem_protocol::volume_status as wire;
fn path_status(service: &FilesystemService, path: &[u8]) -> Result<wire::Status, i32> {
    let response = service.volume_status_at(
        protocol::Header {
            opcode: protocol::OP_VOLUME_STATUS_AT,
            ..Default::default()
        },
        path,
        PathAnchors::default(),
        root_credentials(),
    )?;
    wire::Status::decode(&response.payload).ok_or(5)
}
#[test]
fn statistics_follow_retained_mount_and_live_inode_and_block_accounting() {
    let fixture = Fixture::new();
    let data = fixture.volume_with_block_size("volume-accounting", Some(1024));
    let expected_blocks = 8192;
    let summary = Command::new("dumpe2fs")
        .args(["-h"])
        .arg(fixture.0.join("volume-accounting.ext4"))
        .output()
        .unwrap();
    assert!(summary.status.success());
    let summary = String::from_utf8(summary.stdout).unwrap();
    let expected_inodes: u64 = summary
        .lines()
        .find_map(|line| {
            line.strip_prefix("Inode count:")
                .map(|count| count.trim().parse().unwrap())
        })
        .unwrap();
    let mut service = FilesystemService::new(data);
    service
        .configure_memory_updates(Box::new(unmapped_updates::UnmappedUpdates))
        .unwrap();
    service
        .mount_named_volume(
            b"/",
            b"system",
            fixture.volume_with_block_size("volume-mounted", Some(4096)),
            b"/",
        )
        .unwrap();
    let root = open(
        &mut service,
        b"/",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    );
    let mounted = open(
        &mut service,
        b"/system/file",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    let before = path_status(&service, b"/").unwrap();
    let other = path_status(&service, b"/system/file").unwrap();
    assert_eq!(before.blocks, expected_blocks);
    assert_eq!(before.inodes, expected_inodes);
    assert_eq!(before.block_bytes, 1024);
    assert_eq!(other.block_bytes, 4096);
    assert_ne!(before.filesystem_id, other.filesystem_id);
    assert_eq!(service.provider_volume_status(mounted.open_id), Ok(other));
    assert_eq!(before.flags, 0);
    let fresh = open(
        &mut service,
        b"/created",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE | protocol::OPEN_AT_CREATE,
        PathAnchors::default(),
    );
    let allocated = path_status(&service, b"/").unwrap();
    assert_eq!(allocated.free_inodes + 1, before.free_inodes);
    assert_eq!(service.provider_write(fresh.open_id, &[3; 4096]), Ok(4096));
    let written = service.provider_volume_status(root.open_id).unwrap();
    assert!(written.free_blocks < allocated.free_blocks);
    service
        .unlink_at(
            protocol::Header {
                opcode: protocol::OP_UNLINK_AT,
                ..Default::default()
            },
            b"/created",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    assert_eq!(
        service.provider_volume_status(fresh.open_id).unwrap(),
        written
    );
    service.provider_close(fresh.open_id).unwrap();
    let after = path_status(&service, b"/").unwrap();
    assert_eq!(after.free_inodes, before.free_inodes);
    assert_eq!(after.free_blocks, before.free_blocks);
    assert_eq!(service.provider_volume_status(fresh.open_id), Err(9));
}
#[test]
fn path_query_checks_search_and_shape_without_opening_target_data() {
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("volume-policy"));
    assert!(path_status(&service, b"/file").is_ok());
    assert!(path_status(&service, b"/absolute").is_ok());
    assert_eq!(path_status(&service, b""), Err(2));
    assert_eq!(path_status(&service, b"/missing"), Err(2));
    let mut unprivileged = root_credentials();
    unprivileged.effective_uid = 501;
    unprivileged.effective_gid = 20;
    let header = protocol::Header {
        opcode: protocol::OP_VOLUME_STATUS_AT,
        ..Default::default()
    };
    let file = open(
        &mut service,
        b"/file",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    service
        .chmod_handle(
            protocol::Header {
                mode: 0,
                ..Default::default()
            },
            file.open_id,
            root_credentials(),
        )
        .unwrap();
    assert!(
        service
            .volume_status_at(header, b"/file", PathAnchors::default(), unprivileged)
            .is_ok()
    );
    assert!(matches!(
        service.volume_status_at(
            header,
            b"/blocked/private",
            PathAnchors::default(),
            unprivileged
        ),
        Err(13)
    ));
    for header in [
        protocol::Header {
            flags: protocol::STAT_AT_NOFOLLOW,
            ..header
        },
        protocol::Header {
            open_id: 1,
            ..header
        },
        protocol::Header {
            offset: 1,
            ..header
        },
    ] {
        assert!(matches!(
            service.volume_status_at(header, b"/file", PathAnchors::default(), root_credentials()),
            Err(22)
        ));
    }
}
#[test]
fn provider_reply_validates_shape_and_reports_read_only_backend() {
    let fixture = Fixture::new();
    drop(fixture.volume("volume-readonly"));
    let image = Image(Arc::new(Mutex::new(
        fs::read(fixture.0.join("volume-readonly.ext4")).unwrap(),
    )));
    let mut service = FilesystemService::new(Ext4::load(Box::new(image)).unwrap());
    let opened = open(
        &mut service,
        b"/file",
        protocol::OPEN_AT_READ,
        PathAnchors::default(),
    );
    let header = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_QUERY,
        object_id: opened.open_id,
        argument: 0,
        basis: wire::GET,
        length: wire::RESPONSE_LEN as u32,
        data_length: 0,
    };
    let (length, bytes) =
        filesystem_service::volume_status::handle(&service, header, &[], 0).unwrap();
    assert_eq!(length, wire::RESPONSE_LEN as u64);
    assert_eq!(
        filesystem_service::volume_status::handle(
            &service,
            mnu_abi::provider::RequestHeader {
                opcode: mnu_abi::provider::OP_CONTROL,
                ..header
            },
            &[],
            0,
        )
        .unwrap()
        .1,
        bytes
    );
    assert_eq!(wire::Status::decode(&bytes).unwrap().flags, wire::READ_ONLY);
    for header in [
        mnu_abi::provider::RequestHeader {
            length: 0,
            ..header
        },
        mnu_abi::provider::RequestHeader {
            argument: 1,
            ..header
        },
        mnu_abi::provider::RequestHeader {
            data_length: 1,
            ..header
        },
    ] {
        assert_eq!(
            filesystem_service::volume_status::handle(&service, header, &[], 0),
            Err(22)
        );
    }
    assert_eq!(
        filesystem_service::volume_status::handle(&service, header, &[], 1),
        Err(22)
    );
    assert_eq!(
        filesystem_service::volume_status::handle(
            &service,
            mnu_abi::provider::RequestHeader {
                opcode: mnu_abi::provider::OP_WRITE,
                ..header
            },
            &[],
            0
        ),
        Err(95)
    );
    assert_eq!(service.provider_volume_status(u64::MAX), Err(9));
}

#[test]
fn device_volume_paths_and_retained_descriptions_use_the_same_namespace_accounting() {
    use filesystem_service::devfs::DeviceFilesystem;
    let fixture = Fixture::new();
    let mut service = FilesystemService::new(fixture.volume("device-volume-status"));
    service
        .mount_devices(b"/devices", DeviceFilesystem::default())
        .unwrap();
    service
        .mount_devices(b"/other-devices", DeviceFilesystem::default())
        .unwrap();
    let disk = path_status(&service, b"/").unwrap();
    let devices = path_status(&service, b"/devices").unwrap();
    let other = path_status(&service, b"/other-devices/null").unwrap();
    assert_ne!(devices.filesystem_id, disk.filesystem_id);
    assert_ne!(devices.filesystem_id, other.filesystem_id);
    assert_eq!(devices.blocks, 0);
    assert_eq!(devices.free_inodes, u64::from(u32::MAX) - 2);
    for flags in [protocol::OPEN_AT_READ, protocol::OPEN_AT_WRITE] {
        let opened = open(
            &mut service,
            b"/devices/null",
            flags,
            PathAnchors::default(),
        );
        assert_eq!(
            service.provider_volume_status(opened.open_id).unwrap(),
            devices
        );
        service.provider_close(opened.open_id).unwrap();
        assert_eq!(service.provider_volume_status(opened.open_id), Err(9));
    }
    let directory = open(
        &mut service,
        b"/devices",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    );
    let response = service
        .volume_status_at(
            protocol::Header {
                opcode: protocol::OP_VOLUME_STATUS_AT,
                flags: protocol::STAT_AT_ROOT_ATTACHED | protocol::STAT_AT_BASE_ATTACHED,
                ..Default::default()
            },
            b"/../null",
            PathAnchors {
                root_open_id: Some(directory.open_id),
                base_open_id: Some(directory.open_id),
            },
            root_credentials(),
        )
        .unwrap();
    assert_eq!(wire::Status::decode(&response.payload), Some(devices));
    assert_eq!(
        service.provider_volume_status(directory.open_id),
        Ok(devices)
    );
    assert_eq!(service.provider_volume_status(u64::MAX), Err(9));
}
