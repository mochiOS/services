//! Exercise the actual ext4 writer before exposing timestamp mutation over IPC.
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use ext4plus::inode::{Inode, InodeTimestamp as Time, TimestampError};
use ext4plus::{Ext4, Ext4Read, Ext4Write};

#[path = "../../filesystem/src/inode_time.rs"]
mod inode_time;

#[derive(Clone)]
struct Image(Arc<Mutex<Vec<u8>>>);

impl Ext4Read for Image {
    fn read(&self, offset: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let offset = usize::try_from(offset)?;
        let end = offset.checked_add(output.len()).ok_or("read overflow")?;
        output.copy_from_slice(
            self.0
                .lock()
                .unwrap()
                .get(offset..end)
                .ok_or("read bounds")?,
        );
        Ok(())
    }
}

impl Ext4Write for Image {
    fn flush(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let offset = usize::try_from(offset)?;
        let end = offset.checked_add(bytes.len()).ok_or("write overflow")?;
        self.0
            .lock()
            .unwrap()
            .get_mut(offset..end)
            .ok_or("write bounds")?
            .copy_from_slice(bytes);
        Ok(())
    }
}

struct Fixture {
    directory: PathBuf,
    image: Image,
    inode_size: usize,
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl Fixture {
    fn new(inode_size: usize, extra_size: Option<u16>) -> Self {
        Self::create(inode_size, extra_size, false)
    }

    fn create(inode_size: usize, extra_size: Option<u16>, tree: bool) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("inode-time-updates-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("filesystem.img");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(8 * 1024 * 1024)
            .unwrap();
        let mut format = Command::new("mke2fs");
        format
            .args([
                "-q",
                "-F",
                "-b",
                "1024",
                "-t",
                if inode_size == 128 { "ext2" } else { "ext4" },
                "-I",
            ])
            .arg(inode_size.to_string());
        if extra_size.is_some() {
            // debugfs treats checksum_hi differently when extra_isize is
            // shortened below it. Keep the partial-layout fixtures checksum
            // free; the normal 256-byte fixtures verify metadata checksums.
            format.args(["-O", "^metadata_csum"]);
        }
        if tree {
            let source = directory.join("source");
            for child in ["work", "hidden", "dev", "system"] {
                std::fs::create_dir_all(source.join(child)).unwrap();
            }
            std::fs::write(source.join("work/target"), b"data").unwrap();
            std::fs::write(source.join("hidden/target"), b"private").unwrap();
            std::os::unix::fs::symlink("target", source.join("work/link")).unwrap();
            format.arg("-d").arg(&source);
        }
        run(format.arg(&path));
        if let Some(extra_size) = extra_size {
            run(Command::new("debugfs")
                .args(["-w", "-R"])
                .arg(format!("set_inode_field / extra_isize {extra_size}"))
                .arg(&path));
        }
        let image = Image(Arc::new(Mutex::new(std::fs::read(path).unwrap())));
        Self {
            directory,
            image,
            inode_size,
        }
    }

    fn load(&self) -> Ext4 {
        Ext4::load_with_writer(
            Box::new(self.image.clone()),
            Some(Box::new(self.image.clone())),
        )
        .unwrap()
    }

    fn root_record(&self) -> Vec<u8> {
        let image = self.image.0.lock().unwrap();
        // The fixture explicitly uses 1KiB blocks. First group descriptor is
        // block 2; its inode table low block is at offset 8. Root is inode 2.
        let table = u32::from_le_bytes(image[2056..2060].try_into().unwrap()) as usize;
        let start = table * 1024 + self.inode_size;
        image[start..start + self.inode_size].to_vec()
    }

    fn save(&self) -> PathBuf {
        let path = self.directory.join("updated.img");
        std::fs::write(&path, &*self.image.0.lock().unwrap()).unwrap();
        path
    }
}

#[path = "support/filesystem_time_policy.rs"]
mod policy;

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn time(seconds: i64, nanoseconds: u32) -> Time {
    Time {
        seconds,
        nanoseconds,
    }
}

fn times(inode: &Inode) -> [(i64, u32); 3] {
    [inode.atime(), inode.mtime(), inode.ctime()].map(|value| inode_time::decode(value).unwrap())
}

#[test]
fn signed_epoch_boundaries_and_nanoseconds_persist_with_valid_checksums() {
    let fixture = Fixture::new(256, None);
    let disk = fixture.load();
    let mut inode = disk.read_root_inode().unwrap();
    let original = fixture.root_record();
    for seconds in [
        -2_147_483_648,
        -1,
        0,
        2_147_483_647,
        2_147_483_648,
        4_294_967_295,
        4_294_967_296,
        6_442_450_943,
        6_442_450_944,
        8_589_934_591,
        8_589_934_592,
        10_737_418_239,
        10_737_418_240,
        12_884_901_887,
        12_884_901_888,
        15_032_385_535,
    ] {
        inode
            .set_signed_timestamps(
                Some(time(seconds, 1)),
                Some(time(seconds, 999_999_999)),
                Some(time(seconds, 123_456_789)),
            )
            .unwrap();
        inode.write(&disk).unwrap();
        let reloaded = fixture.load().read_root_inode().unwrap();
        assert_eq!(
            times(&reloaded),
            [(seconds, 1), (seconds, 999_999_999), (seconds, 123_456_789)]
        );
        let record = fixture.root_record();
        for offset in 0..record.len() {
            // Only the three timestamp fields and the two checksum words
            // may change. In particular, do not grow i_extra_isize or touch
            // inline xattrs, ownership, mode, size, or block mappings.
            if !(8..20).contains(&offset)
                && !(0x7c..0x7e).contains(&offset)
                && !(0x82..0x90).contains(&offset)
            {
                assert_eq!(record[offset], original[offset], "inode byte {offset:#x}");
            }
        }
        let low = seconds as u32;
        let epoch = ((seconds - i64::from(low as i32)) >> 32) as u32;
        for (offset, extra_offset, nanos) in [
            (8, 0x8c, 1),
            (16, 0x88, 999_999_999),
            (12, 0x84, 123_456_789),
        ] {
            assert_eq!(&record[offset..offset + 4], &low.to_le_bytes());
            assert_eq!(
                &record[extra_offset..extra_offset + 4],
                &((nanos << 2) | epoch).to_le_bytes()
            );
        }
    }
    // Independently read the persisted image using e2fsprogs, not our decoder.
    let output = Command::new("debugfs")
        .args(["-R", "stat /"])
        .arg(fixture.save())
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("0x7fffffff:1d6f3457"), "{output}"); // ctime: epoch 3, 123456789ns
    assert!(output.contains("0x7fffffff:ee6b27ff"), "{output}"); // mtime: epoch 3, 999999999ns
    assert!(output.contains("0x7fffffff:00000007"), "{output}"); // atime: epoch 3, 1ns
}

#[test]
fn every_field_is_validated_before_any_field_is_modified() {
    let fixture = Fixture::new(256, None);
    let disk = fixture.load();
    let mut inode = disk.read_root_inode().unwrap();
    inode
        .set_signed_timestamps(
            Some(time(-1, 7)),
            Some(time(2_147_483_648, 9)),
            Some(time(1, 11)),
        )
        .unwrap();
    inode.write(&disk).unwrap();
    let original = fixture.root_record();
    let baseline = times(&inode);
    for invalid in [
        time(i64::MIN, 0),
        time(-2_147_483_649, 0),
        time(15_032_385_536, 0),
        time(i64::MAX, 0),
        time(0, 1_000_000_000),
        time(0, u32::MAX),
    ] {
        let expected = if invalid.nanoseconds >= 1_000_000_000 {
            TimestampError::InvalidNanoseconds
        } else {
            TimestampError::OutOfRange
        };
        for slot in 0..3 {
            let mut fields = [Some(time(123, 456)); 3];
            fields[slot] = Some(invalid);
            assert_eq!(
                inode.set_signed_timestamps(fields[0], fields[1], fields[2]),
                Err(expected)
            );
            assert_eq!(times(&inode), baseline);
            inode.write(&disk).unwrap();
            assert_eq!(fixture.root_record(), original);
        }
    }
    inode.set_signed_timestamps(None, None, None).unwrap();
    assert_eq!(times(&inode), baseline);
    inode
        .set_signed_timestamps(None, Some(time(0, 0)), None)
        .unwrap();
    inode.write(&disk).unwrap();
    let reloaded = fixture.load().read_root_inode().unwrap();
    assert_eq!(times(&reloaded), [baseline[0], (0, 0), baseline[2]]);
    // Replacing a fractional post-2038 value with epoch zero clears old extras.
    assert_eq!(&fixture.root_record()[0x88..0x8c], &[0; 4]);
}

#[test]
fn old_128_byte_inodes_floor_fractional_seconds_without_wrapping_dates() {
    let fixture = Fixture::new(128, None);
    let disk = fixture.load();
    let mut inode = disk.read_root_inode().unwrap();
    for seconds in [-2_147_483_648, -1, 0, 2_147_483_647] {
        let value = Some(time(seconds, 999_999_999));
        inode.set_signed_timestamps(value, value, value).unwrap();
        inode.write(&disk).unwrap();
        assert_eq!(
            times(&fixture.load().read_root_inode().unwrap()),
            [(seconds, 0); 3]
        );
    }
    let before = fixture.root_record();
    assert_eq!(
        inode.set_signed_timestamps(Some(time(0, 0)), Some(time(2_147_483_648, 0)), None),
        Err(TimestampError::OutOfRange)
    );
    inode.write(&disk).unwrap();
    assert_eq!(fixture.root_record(), before);
}

#[test]
fn each_extra_word_is_gated_by_declared_inode_size_not_allocated_record_size() {
    for extra_size in [0, 4, 8, 12, 16] {
        let fixture = Fixture::new(256, Some(extra_size));
        let disk = fixture.load();
        let mut inode = disk.read_root_inode().unwrap();
        let before = fixture.root_record();
        let value = Some(time(-1, 999_999_999));
        inode.set_signed_timestamps(value, value, value).unwrap();
        inode.write(&disk).unwrap();
        let after = fixture.root_record();
        for (field, offset, minimum) in [(0, 0x8c, 16), (1, 0x88, 12), (2, 0x84, 8)] {
            let has_extra = extra_size >= minimum;
            assert_eq!(
                times(&inode)[field],
                (-1, if has_extra { 999_999_999 } else { 0 })
            );
            if !has_extra {
                assert_eq!(&after[offset..offset + 4], &before[offset..offset + 4]);
            }
            let future = Some(time(2_147_483_648, 0));
            let mut fields = [None; 3];
            fields[field] = future;
            let result = inode.set_signed_timestamps(fields[0], fields[1], fields[2]);
            assert_eq!(
                result,
                if has_extra {
                    Ok(())
                } else {
                    Err(TimestampError::OutOfRange)
                }
            );
        }
    }
}

#[test]
fn oversized_declared_inode_layout_is_an_error_not_an_overflow_or_partial_update() {
    let fixture = Fixture::new(256, Some(u16::MAX));
    let disk = fixture.load();
    let mut inode = disk.read_root_inode().unwrap();
    let before = fixture.root_record();
    assert_eq!(
        inode.set_signed_timestamps(Some(time(0, 0)), Some(time(0, 0)), Some(time(0, 0))),
        Err(TimestampError::InvalidInodeLayout)
    );
    inode.write(&disk).unwrap();
    assert_eq!(fixture.root_record(), before);
}
