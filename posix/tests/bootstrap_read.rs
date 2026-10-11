use filesystem_service::bootstrap_read::BootstrapReader;
use filesystem_service::partition::find_by_type;
use filesystem_service::storage::{PartitionIo, SectorDevice};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("mochios-bootstrap-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn reader(&self) -> BootstrapReader {
        let source = self.0.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(source.join("directory")).unwrap();
        std::fs::write(source.join("file"), b"0123456789abcdef").unwrap();
        std::fs::write(source.join("empty"), b"").unwrap();
        for name in ["alpha", "beta", "gamma", "delta"] {
            std::fs::write(source.join("directory").join(name), name.as_bytes()).unwrap();
        }
        std::os::unix::fs::symlink("/file", source.join("absolute")).unwrap();
        std::os::unix::fs::symlink("../file", source.join("directory/relative")).unwrap();
        let image = self.0.join("image.ext4");
        let result = std::process::Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-F", "-d"])
            .arg(&source)
            .arg(&image)
            .arg("8192")
            .output()
            .expect("mke2fs required for bootstrap reader tests");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let file = std::fs::File::open(image).unwrap();
        let sectors = file.metadata().unwrap().len() / 512;
        BootstrapReader::load(Arc::new(PartitionIo::new(Disk(file), 0, sectors))).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn bootstrap_range_reads_are_bounded_cursor_free_and_partition_local() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let mut output = [0xaa; 6];
    assert_eq!(reader.read_at("/file", 3, &mut output).unwrap(), 6);
    assert_eq!(&output, b"345678");
    assert_eq!(reader.read_at("/absolute", 14, &mut output).unwrap(), 2);
    assert_eq!(&output[..2], b"ef");
    assert_eq!(&output[2..], b"5678");
    assert_eq!(
        reader
            .read_at("/directory/relative", 0, &mut output)
            .unwrap(),
        6
    );
    assert_eq!(&output, b"012345");
    for offset in [16, 17, u64::MAX - 6] {
        assert_eq!(reader.read_at("/file", offset, &mut output).unwrap(), 0);
        assert_eq!(&output, b"012345");
    }
    assert_eq!(reader.read_at("/file", 0, &mut []).unwrap(), 0);
    assert_eq!(reader.read_at("/empty", 0, &mut output).unwrap(), 0);
    assert!(reader.read_at("/file", u64::MAX, &mut output).is_err());
    for path in ["relative", "/file\0suffix", "/directory", "/missing"] {
        assert!(reader.read_at(path, 0, &mut output).is_err());
    }
    assert_eq!(reader.read("/file", 16).unwrap(), b"0123456789abcdef");
}

#[test]
fn bootstrap_directory_pages_advance_without_duplicates_or_dot_entries() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let full = reader.read_directory("/directory", 0, 20, 1024).unwrap();
    assert!(full.eof);
    let mut cursor = 0;
    let mut names = Vec::new();
    loop {
        let page = reader.read_directory("/directory", cursor, 2, 8).unwrap();
        assert!(page.names.len() <= 2);
        assert!(page.names.iter().map(String::len).sum::<usize>() <= 8);
        assert!(page.names.iter().all(|name| name != "." && name != ".."));
        if !page.eof {
            assert!(page.next_entry > cursor);
        }
        cursor = page.next_entry;
        names.extend(page.names);
        if page.eof {
            break;
        }
    }
    assert_eq!(names, full.names);
    assert_eq!(names.len(), 5);
    assert_eq!(cursor, full.next_entry);
    let final_page = reader.read_directory("/directory", cursor, 2, 8).unwrap();
    assert!(final_page.eof && final_page.names.is_empty());
    assert_eq!(final_page.next_entry, cursor);
    let beyond = reader.read_directory("/directory", 1000, 2, 8).unwrap();
    assert!(beyond.eof && beyond.names.is_empty());
}

#[test]
fn bootstrap_directory_limits_and_non_directory_errors_are_explicit() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    assert_eq!(
        reader
            .read_directory("/file", 0, 2, 100)
            .err()
            .unwrap()
            .raw_os_error(),
        Some(20)
    );
    for (entries, bytes) in [(0, 100), (1, 0), (2, 1)] {
        assert!(
            reader
                .read_directory("/directory", 0, entries, bytes)
                .is_err()
        );
    }
    for path in ["relative", "/directory\0suffix", "/missing"] {
        assert!(reader.read_directory(path, 0, 2, 100).is_err());
    }
    assert!(
        reader
            .read_directory("/directory", 0, 20, 1024)
            .unwrap()
            .eof
    );
}

#[test]
fn bootstrap_errors_preserve_path_and_object_failures() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let mut output = [0; 4];
    assert_eq!(
        reader.read("/missing", 1024).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        reader
            .read_at("/missing", 0, &mut output)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        reader
            .read_directory("/missing", 0, 2, 100)
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        reader.read("/directory", 1024).unwrap_err().raw_os_error(),
        Some(21)
    );
    assert_eq!(
        reader
            .read_at("/directory", 0, &mut output)
            .unwrap_err()
            .raw_os_error(),
        Some(21)
    );
    for path in ["relative", "/file\0suffix"] {
        assert_eq!(
            reader.read(path, 1024).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(reader.read("/file", 16).unwrap(), b"0123456789abcdef");
}

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
