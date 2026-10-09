use filesystem_service::partition::{DiscoveryError, PartitionRange, find_by_type};
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
