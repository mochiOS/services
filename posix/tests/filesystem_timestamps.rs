use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use ext4plus::{Ext4, Ext4Read};
use filesystem_service::service::{FilesystemService, PathAnchors};
use mochios_filesystem_protocol as wire;

use posix_service::filesystem_metadata;
#[path = "../../filesystem/src/inode_time.rs"]
mod inode_time;

// Boundary values from ext4's signed-low-seconds plus unsigned epoch encoding.
const CASES: [(u32, u32, i64); 8] = [
    (0x8000_0000, 0, -2_147_483_648),
    (0xffff_ffff, 0, -1),
    (0x7fff_ffff, 0, 2_147_483_647),
    (0x8000_0000, 1, 2_147_483_648),
    (0x7fff_ffff, 1, 6_442_450_943),
    (0x8000_0000, 2, 6_442_450_944),
    (0x8000_0000, 3, 10_737_418_240),
    (0x7fff_ffff, 3, 15_032_385_535),
];

#[test]
fn ext4_epoch_bits_are_added_to_signed_not_unsigned_low_seconds() {
    for (low, epoch, expected) in CASES {
        let packed = (u64::from(epoch) << 32) | u64::from(low);
        assert_eq!(
            inode_time::decode(Duration::new(packed, 123_456_789)),
            Some((expected, 123_456_789))
        );
    }
    for invalid in [1_u64 << 34, u64::MAX] {
        assert_eq!(inode_time::decode(Duration::from_secs(invalid)), None);
    }
}

#[test]
fn signed_filesystem_timestamps_round_trip_without_changing_wire_width() {
    for seconds in [
        i64::MIN,
        -2_147_483_648,
        -1,
        0,
        2_147_483_648,
        15_032_385_535,
        i64::MAX,
    ] {
        let status = wire::NodeStatus {
            access_time_seconds: seconds,
            access_time_nanoseconds: 123_456_789,
            modification_time_seconds: seconds,
            modification_time_nanoseconds: 987_654_321,
            change_time_seconds: seconds,
            change_time_nanoseconds: 1,
            kind: wire::NODE_TYPE_REGULAR,
            ..Default::default()
        };
        let mut encoded = [0; wire::NODE_STATUS_LEN];
        assert_eq!(wire::encode_node_status(status, &mut encoded).unwrap(), 112);
        for offset in [64, 80, 96] {
            assert_eq!(&encoded[offset..offset + 8], &seconds.to_le_bytes());
        }
        let decoded = wire::decode_node_status(&encoded).unwrap();
        assert_eq!(decoded, status);
        let posix = filesystem_metadata::translate(decoded).unwrap();
        assert_eq!(
            (
                posix.access_time_seconds,
                posix.modification_time_seconds,
                posix.change_time_seconds
            ),
            (seconds, seconds, seconds)
        );
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "filesystem-timestamps-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Image(Vec<u8>);
impl Ext4Read for Image {
    fn read(
        &self,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(output.len())
            .ok_or_else(|| std::io::Error::other("read overflow"))?;
        let bytes = self
            .0
            .get(start..end)
            .ok_or_else(|| std::io::Error::other("read outside test image"))?;
        output.copy_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn actual_ext4_inode_times_survive_path_handle_and_posix_stat_replies() {
    let fixture = Fixture::new();
    let source = fixture.0.join("source");
    std::fs::create_dir(&source).unwrap();
    for index in 0..CASES.len() {
        std::fs::write(source.join(format!("case{index}")), b"data").unwrap();
    }
    let image = fixture.0.join("filesystem.img");
    std::fs::File::create(&image)
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();
    run(Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-I", "256", "-F", "-d"])
        .arg(&source)
        .arg(&image));
    let commands = fixture.0.join("timestamps.commands");
    let mut operations = String::new();
    for (index, (low, epoch, _)) in CASES.into_iter().enumerate() {
        for (field, nanos) in [
            ("atime", 123_456_789u32),
            ("mtime", 987_654_321),
            ("ctime", 1),
        ] {
            operations.push_str(&format!("set_inode_field /case{index} {field} 0x{low:x}\n"));
            operations.push_str(&format!(
                "set_inode_field /case{index} {field}_extra 0x{:x}\n",
                (nanos << 2) | epoch
            ));
        }
    }
    std::fs::write(&commands, operations).unwrap();
    run(Command::new("debugfs")
        .args(["-w", "-f"])
        .arg(&commands)
        .arg(&image));
    let filesystem = Ext4::load(Box::new(Image(std::fs::read(&image).unwrap()))).unwrap();
    let mut service = FilesystemService::new(filesystem);
    let mut credential_bytes = [0; wire::CREDENTIALS_MAX_LEN];
    let count = wire::encode_credentials_payload(0, 0, &[], &[], &mut credential_bytes).unwrap();
    let credentials = wire::decode_credentials_payload(&credential_bytes[..count])
        .unwrap()
        .0;
    for (index, (_, _, expected)) in CASES.into_iter().enumerate() {
        let path = format!("/case{index}");
        let path_reply = service
            .stat_at(
                wire::Header {
                    opcode: wire::OP_STAT_AT,
                    ..Default::default()
                },
                path.as_bytes(),
                PathAnchors::default(),
                credentials,
            )
            .unwrap();
        let opened = service
            .open_at(
                wire::Header {
                    opcode: wire::OP_OPEN_AT,
                    flags: wire::OPEN_AT_READ,
                    ..Default::default()
                },
                path.as_bytes(),
                PathAnchors::default(),
                credentials,
            )
            .unwrap();
        let handle_reply = service
            .stat_handle(
                wire::Header {
                    opcode: wire::OP_STAT_HANDLE,
                    ..Default::default()
                },
                opened.header.open_id,
            )
            .unwrap();
        for reply in [path_reply, handle_reply] {
            assert_eq!(reply.header.status, 0);
            let file =
                filesystem_metadata::translate(wire::decode_node_status(&reply.payload).unwrap())
                    .unwrap();
            assert_eq!(
                (
                    file.access_time_seconds,
                    file.modification_time_seconds,
                    file.change_time_seconds
                ),
                (expected, expected, expected),
                "case {index}"
            );
            assert_eq!(
                (
                    file.access_time_nanoseconds,
                    file.modification_time_nanoseconds,
                    file.change_time_nanoseconds
                ),
                (123_456_789, 987_654_321, 1)
            );
            let mut output = [0; mochios_posix_protocol::FILE_STATUS_LEN];
            mochios_posix_protocol::encode_file_status(file, &mut output).unwrap();
            assert_eq!(
                mochios_posix_protocol::decode_file_status(&output).unwrap(),
                file
            );
        }
    }
}
