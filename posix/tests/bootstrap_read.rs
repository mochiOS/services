use filesystem_service::bootstrap_read::BootstrapReader;
use filesystem_service::partition::find_by_type;
use filesystem_service::storage::{PartitionIo, SectorDevice};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

struct Disk(std::fs::File);

#[test]
fn core_boot_policy_reads_use_user_space_storage_not_kernel_path_open() {
    let core = include_str!("../../core/src/main.rs");
    let bootstrap = include_str!("../../core/src/boot_files.rs");
    let reader = include_str!("../../filesystem/src/bootstrap_read.rs");
    assert!(!core.contains("platform::file::"));
    assert!(bootstrap.contains("find_system_partition(0)"));
    assert!(bootstrap.contains("MAX_BOOT_POLICY_BYTES"));
    assert!(!bootstrap.contains("FileOpen"));
    assert!(!reader.contains("load_with_writer"));
    assert!(!reader.contains("mochi_user_platform"));
}
impl SectorDevice for Disk {
    type Error = std::io::Error;
    fn read_sectors(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0
            .seek(SeekFrom::Start(lba.checked_mul(512).unwrap()))?;
        self.0.read_exact(bytes)
    }
    fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
        panic!("bootstrap reader must not write")
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        panic!("bootstrap reader must not flush")
    }
}

#[test]
#[ignore = "requires an existing out/artifacts/disk.img; never builds or boots the OS"]
fn early_boot_reads_are_bounded_and_need_no_posix_endpoint() {
    let image =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../out/artifacts/disk.img");
    let mut disk = Disk(std::fs::File::open(image).unwrap());
    let kind = [
        0x68, 0x63, 0x6f, 0x6d, 0x4f, 0x69, 0x00, 0x53, 0x80, 0x00, 0x6d, 0x50, 0x61, 0x72, 0x74,
        0x01,
    ];
    let range = find_by_type(&mut disk, kind).unwrap().unwrap();
    let reader = BootstrapReader::load(Arc::new(PartitionIo::new(
        disk,
        range.first_lba,
        range.sector_count,
    )))
    .unwrap();
    let path = "/system/packages/logger/manifest.toml";
    let bytes = reader.read(path, 256 * 1024).unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("org.mochios.logger")
    );
    assert_eq!(reader.read(path, bytes.len()).unwrap(), bytes);
    assert!(reader.read(path, bytes.len() - 1).is_err());
    assert!(reader.read(path, 0).is_err());
    assert!(
        reader
            .read("system/packages/logger/manifest.toml", usize::MAX)
            .is_err()
    );
    assert!(reader.read("/system/packages/logger", usize::MAX).is_err());
    assert!(
        reader
            .read("/system/no-such-bootstrap-file", usize::MAX)
            .is_err()
    );
    assert_eq!(reader.read(path, bytes.len()).unwrap(), bytes);
}
