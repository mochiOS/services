use filesystem_service::partition::{
    DiscoveryError, PartitionRange, find_by_type, find_by_type_ordinal,
};
use filesystem_service::storage::SectorDevice;

struct Disk(Vec<u8>);
impl SectorDevice for Disk {
    type Error = ();
    fn read_sectors(&mut self, lba: u64, output: &mut [u8]) -> Result<(), ()> {
        let start = usize::try_from(lba)
            .ok()
            .and_then(|lba| lba.checked_mul(512))
            .ok_or(())?;
        let end = start.checked_add(output.len()).ok_or(())?;
        output.copy_from_slice(self.0.get(start..end).ok_or(())?);
        Ok(())
    }
    fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), ()> {
        panic!("discovery must not write")
    }
    fn flush(&mut self) -> Result<(), ()> {
        panic!("discovery must not flush")
    }
}

// Independent reference implementation for GPT fixture checksums.
fn checksum(bytes: &[u8]) -> u32 {
    let mut result = !0u32;
    for byte in bytes {
        let mut value = (result ^ u32::from(*byte)) & 255;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0xedb88320
            } else {
                value >> 1
            };
        }
        result = (result >> 8) ^ value;
    }
    !result
}
fn seal(disk: &mut Disk) {
    let crc = checksum(&disk.0[1024..1536]);
    disk.0[600..604].copy_from_slice(&crc.to_le_bytes());
    disk.0[528..532].fill(0);
    let crc = checksum(&disk.0[512..604]);
    disk.0[528..532].copy_from_slice(&crc.to_le_bytes());
}
fn fixture() -> Disk {
    let mut disk = Disk(vec![0; 1536]);
    let h = &mut disk.0[512..1024];
    h[..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
    h[12..16].copy_from_slice(&92u32.to_le_bytes());
    for (offset, value) in [(24, 1u64), (32, 999), (40, 34), (48, 998), (72, 2)] {
        h[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    h[80..84].copy_from_slice(&4u32.to_le_bytes());
    h[84..88].copy_from_slice(&128u32.to_le_bytes());
    entry(&mut disk, 2, [7; 16], 100, 199);
    seal(&mut disk);
    disk
}
fn entry(disk: &mut Disk, index: usize, kind: [u8; 16], first: u64, last: u64) {
    let e = &mut disk.0[1024 + index * 128..1024 + (index + 1) * 128];
    e[..16].copy_from_slice(&kind);
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
}

#[test]
fn empty_slots_do_not_hide_a_later_partition_and_type_is_caller_selected() {
    let mut disk = fixture();
    assert_eq!(
        find_by_type(&mut disk, [7; 16]),
        Ok(Some(PartitionRange {
            first_lba: 100,
            sector_count: 100
        }))
    );
    assert_eq!(find_by_type(&mut disk, [8; 16]), Ok(None));
    assert_eq!(
        find_by_type(&mut disk, [0; 16]),
        Err(DiscoveryError::InvalidTable)
    );
}

#[test]
fn paired_partition_selection_uses_lba_order_not_gpt_entry_order() {
    let mut disk = fixture();
    entry(&mut disk, 0, [7; 16], 300, 399);
    seal(&mut disk);
    assert_eq!(
        find_by_type_ordinal(&mut disk, [7; 16], 2, 0),
        Ok(Some(PartitionRange {
            first_lba: 100,
            sector_count: 100
        }))
    );
    assert_eq!(
        find_by_type_ordinal(&mut disk, [7; 16], 2, 1),
        Ok(Some(PartitionRange {
            first_lba: 300,
            sector_count: 100
        }))
    );
    assert_eq!(
        find_by_type(&mut disk, [7; 16]),
        Err(DiscoveryError::AmbiguousType)
    );
}

#[test]
fn incomplete_extra_overlapping_or_invalid_partition_selections_fail_closed() {
    let mut disk = fixture();
    assert_eq!(
        find_by_type_ordinal(&mut disk, [7; 16], 2, 0),
        Err(DiscoveryError::AmbiguousType)
    );
    for (count, ordinal) in [(0, 0), (129, 0), (2, 2)] {
        assert_eq!(
            find_by_type_ordinal(&mut disk, [7; 16], count, ordinal),
            Err(DiscoveryError::InvalidTable)
        );
    }
    entry(&mut disk, 0, [7; 16], 150, 249);
    seal(&mut disk);
    assert_eq!(
        find_by_type_ordinal(&mut disk, [7; 16], 2, 1),
        Err(DiscoveryError::InvalidTable)
    );
    entry(&mut disk, 0, [7; 16], 300, 399);
    entry(&mut disk, 1, [7; 16], 500, 599);
    seal(&mut disk);
    assert_eq!(
        find_by_type_ordinal(&mut disk, [7; 16], 2, 0),
        Err(DiscoveryError::AmbiguousType)
    );
    assert_eq!(find_by_type_ordinal(&mut disk, [8; 16], 2, 1), Ok(None));
}
#[test]
fn corrupted_header_and_array_fail_closed() {
    let mut disk = fixture();
    disk.0[600] ^= 1;
    assert_eq!(
        find_by_type(&mut disk, [7; 16]),
        Err(DiscoveryError::InvalidTable)
    );
    let mut disk = fixture();
    disk.0[1024] ^= 1;
    assert_eq!(
        find_by_type(&mut disk, [7; 16]),
        Err(DiscoveryError::InvalidTable)
    );
}
#[test]
fn duplicate_types_are_not_silently_selected() {
    let mut disk = fixture();
    entry(&mut disk, 3, [7; 16], 300, 399);
    seal(&mut disk);
    assert_eq!(
        find_by_type(&mut disk, [7; 16]),
        Err(DiscoveryError::AmbiguousType)
    );
}
#[test]
fn malformed_ranges_and_device_failures_are_distinct() {
    for (first, last) in [(0, 199), (200, 199), (100, 999), (100, u64::MAX)] {
        let mut disk = fixture();
        entry(&mut disk, 2, [7; 16], first, last);
        seal(&mut disk);
        assert_eq!(
            find_by_type(&mut disk, [7; 16]),
            Err(DiscoveryError::InvalidTable)
        );
    }
    assert_eq!(
        find_by_type(&mut Disk(vec![]), [7; 16]),
        Err(DiscoveryError::Device(()))
    );
}

#[test]
fn unbounded_entry_layouts_and_overflowing_locations_are_rejected() {
    for (offset, value) in [(80, 0u32), (80, 129), (84, 129), (84, 1024)] {
        let mut disk = fixture();
        disk.0[512 + offset..516 + offset].copy_from_slice(&value.to_le_bytes());
        seal(&mut disk);
        assert_eq!(
            find_by_type(&mut disk, [7; 16]),
            Err(DiscoveryError::InvalidTable)
        );
    }
    for lba in [0u64, 1, 34, u64::MAX] {
        let mut disk = fixture();
        disk.0[584..592].copy_from_slice(&lba.to_le_bytes());
        seal(&mut disk);
        assert_eq!(
            find_by_type(&mut disk, [7; 16]),
            Err(DiscoveryError::InvalidTable)
        );
    }
}

struct FileDisk(std::fs::File);
impl SectorDevice for FileDisk {
    type Error = std::io::Error;
    fn read_sectors(&mut self, lba: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        use std::io::{Read, Seek, SeekFrom};
        let start = lba
            .checked_mul(512)
            .ok_or_else(|| std::io::Error::other("offset overflow"))?;
        self.0.seek(SeekFrom::Start(start))?;
        self.0.read_exact(output)
    }
    fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "read-only image",
        ))
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
#[ignore = "requires an already built out/artifacts/disk.img; never builds or boots the OS"]
fn system_image_is_readable_through_the_user_space_filesystem_backend() {
    use filesystem_service::{
        ext4::Ext4Storage,
        service::{FilesystemService, PathAnchors},
        storage::PartitionIo,
    };
    use mochios_filesystem_protocol as protocol;
    use std::sync::Arc;

    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../out/artifacts/disk.img");
    let mut disk = FileDisk(std::fs::File::open(path).unwrap());
    let system_type = [
        0x68, 0x63, 0x6f, 0x6d, 0x4f, 0x69, 0x00, 0x53, 0x80, 0x00, 0x6d, 0x50, 0x61, 0x72, 0x74,
        0x01,
    ];
    let range = find_by_type(&mut disk, system_type).unwrap().unwrap();
    let partition = Arc::new(PartitionIo::new(disk, range.first_lba, range.sector_count));
    let filesystem = ext4plus::Ext4::load(Box::new(Ext4Storage::new(partition))).unwrap();
    let mut service = FilesystemService::new(filesystem);
    let mut credentials = [0u8; protocol::CREDENTIALS_MAX_LEN];
    let size = protocol::encode_credentials_payload(0, 0, &[], &[], &mut credentials).unwrap();
    let credentials = protocol::decode_credentials_payload(&credentials[..size])
        .unwrap()
        .0;
    let opened = service
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ,
                ..protocol::Header::default()
            },
            b"/system/packages/binder/manifest.toml",
            PathAnchors::default(),
            credentials,
        )
        .unwrap();
    let bytes = service.provider_read(opened.header.open_id, 4096).unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("org.mochios.binder")
    );
}

#[test]
#[ignore = "requires an already built out/artifacts/disk.img; never builds or boots the OS"]
fn system_source_is_projected_into_the_data_namespace_without_a_duplicate_system_directory() {
    use filesystem_service::{
        ext4::Ext4Storage,
        service::{FilesystemService, PathAnchors},
        storage::PartitionIo,
    };
    use mochios_filesystem_protocol as protocol;
    use std::sync::Arc;

    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../out/artifacts/disk.img");
    let load = |partition_type| {
        let mut disk = FileDisk(std::fs::File::open(&path).unwrap());
        let range = find_by_type(&mut disk, partition_type).unwrap().unwrap();
        let partition = Arc::new(PartitionIo::new(disk, range.first_lba, range.sector_count));
        ext4plus::Ext4::load(Box::new(Ext4Storage::new(partition))).unwrap()
    };
    let mut partition_type = [
        0x68, 0x63, 0x6f, 0x6d, 0x4f, 0x69, 0x00, 0x53, 0x80, 0x00, 0x6d, 0x50, 0x61, 0x72, 0x74,
        0x02,
    ];
    let data = load(partition_type);
    assert!(data.symlink_metadata("/system").is_err());
    partition_type[15] = 0x01;
    let system = load(partition_type);
    let mut service = FilesystemService::new(data.clone());
    service
        .mount_named_volume(b"/", b"system", system, b"/system")
        .unwrap();
    let mut bytes = [0u8; protocol::CREDENTIALS_MAX_LEN];
    let length = protocol::encode_credentials_payload(0, 0, &[], &[], &mut bytes).unwrap();
    let credentials = protocol::decode_credentials_payload(&bytes[..length])
        .unwrap()
        .0;
    let request = protocol::Header {
        opcode: protocol::OP_OPEN_AT,
        flags: protocol::OPEN_AT_READ,
        ..Default::default()
    };
    let opened = service
        .open_at(
            request,
            b"/system/packages/binder/manifest.toml",
            PathAnchors::default(),
            credentials,
        )
        .unwrap();
    let manifest = service.provider_read(opened.header.open_id, 4096).unwrap();
    assert!(
        std::str::from_utf8(&manifest)
            .unwrap()
            .contains("org.mochios.binder")
    );
    assert!(matches!(
        service.open_at(
            request,
            b"/system/system/packages/binder/manifest.toml",
            PathAnchors::default(),
            credentials
        ),
        Err(2)
    ));
    let flags = protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY;
    let root = service
        .open_at(
            protocol::Header { flags, ..request },
            b"/",
            PathAnchors::default(),
            credentials,
        )
        .unwrap();
    let mounted = service
        .open_at(
            protocol::Header { flags, ..request },
            b"/system",
            PathAnchors::default(),
            credentials,
        )
        .unwrap();
    assert_eq!(
        service
            .path_handle(
                protocol::Header::default(),
                root.header.open_id,
                mounted.header.open_id
            )
            .unwrap()
            .payload,
        b"/system"
    );
    for path in [
        b"/bin".as_slice(),
        b"/applications",
        b"/home",
        b"/var",
        b"/tmp",
    ] {
        service
            .open_at(
                protocol::Header { flags, ..request },
                path,
                PathAnchors::default(),
                credentials,
            )
            .unwrap();
    }
    assert!(data.symlink_metadata("/system").is_err());
}

#[test]
#[ignore = "requires an already built out/artifacts/disk.img; never builds or boots the OS"]
fn immutable_system_dictionary_reads_do_not_reread_indirect_blocks_for_every_chunk() {
    use filesystem_service::{ext4::ImmutableExt4Storage, storage::PartitionIo};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountedDisk(FileDisk, Arc<AtomicUsize>);
    impl SectorDevice for CountedDisk {
        type Error = std::io::Error;
        fn read_sectors(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
            self.1.fetch_add(1, Ordering::Relaxed);
            self.0.read_sectors(lba, bytes)
        }
        fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
            panic!("read-only test")
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            panic!("read-only test")
        }
    }
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../out/artifacts/disk.img");
    let calls = Arc::new(AtomicUsize::new(0));
    let mut disk = CountedDisk(FileDisk(std::fs::File::open(path).unwrap()), calls.clone());
    let kind = [
        0x68, 0x63, 0x6f, 0x6d, 0x4f, 0x69, 0x00, 0x53, 0x80, 0x00, 0x6d, 0x50, 0x61, 0x72, 0x74,
        0x01,
    ];
    let range = find_by_type(&mut disk, kind).unwrap().unwrap();
    let partition = Arc::new(PartitionIo::new(disk, range.first_lba, range.sector_count));
    let filesystem = ext4plus::Ext4::load(Box::new(ImmutableExt4Storage::new(partition))).unwrap();
    let inode = filesystem
        .path_to_inode(
            "/system/libraries/ime/ja.mime".try_into().unwrap(),
            ext4plus::FollowSymlinks::All,
        )
        .unwrap();
    let mut file = ext4plus::file::File::open_inode(&filesystem, inode).unwrap();
    let mut buffer = [0; 4088];
    let mut position = 0;
    let mut chunks = 0;
    let started = std::time::Instant::now();
    loop {
        let count = file.read_bytes_at(&mut buffer, position).unwrap();
        if count == 0 {
            break;
        }
        position += count as u64;
        chunks += 1;
    }
    let reads = calls.load(Ordering::Relaxed);
    eprintln!(
        "System dictionary: {position} bytes, {chunks} chunks, {reads} device reads, {:?}",
        started.elapsed()
    );
    assert!(position > 0);
    assert!(
        reads < chunks / 4,
        "indirect block reads were not amortized"
    );
}

#[test]
fn inventory_table_validates_all_extents_and_preserves_guid_and_label() {
    use filesystem_service::partition::inspect;
    let mut disk = fixture();
    disk.0[568..584].fill(5);
    disk.0[1024 + 2 * 128 + 16..1024 + 2 * 128 + 32].fill(6);
    disk.0[1024 + 2 * 128 + 56..1024 + 2 * 128 + 58].copy_from_slice(&(b'D' as u16).to_le_bytes());
    seal(&mut disk);
    let table = inspect(&mut disk).unwrap();
    assert_eq!(table.sectors, 1000); assert_eq!(table.guid, [5;16]);
    assert_eq!(table.partitions[0].name, "D"); assert_eq!(table.partitions[0].guid, [6;16]);
    entry(&mut disk, 0, [9;16], 150, 250);
    disk.0[1040..1056].fill(10); seal(&mut disk);
    assert!(matches!(inspect(&mut disk), Err(DiscoveryError::InvalidTable)));
    disk.0[1024] ^= 1;
    assert!(matches!(inspect(&mut disk), Err(DiscoveryError::InvalidTable)));
}
