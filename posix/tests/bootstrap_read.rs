use filesystem_service::bootstrap_read::BootstrapReader;
use filesystem_service::partition::find_by_type;
use filesystem_service::storage::{PartitionIo, SectorDevice};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;

#[allow(dead_code)]
#[path = "../../capability/src/bootstrap_file.rs"]
mod bootstrap_file;

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
        let large: Vec<u8> = (0..130_000).map(|index| (index % 251) as u8).collect();
        std::fs::write(source.join("large"), large).unwrap();
        std::fs::create_dir(source.join("long-names")).unwrap();
        for index in 0..140 {
            let name = format!("{index:03}{}", "x".repeat(252));
            std::fs::write(source.join("long-names").join(name), []).unwrap();
        }
        std::os::unix::fs::symlink("loop", source.join("loop")).unwrap();
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

fn bootstrap_request(opcode: u16, path: &[u8], offset: u64, budget: u32) -> Vec<u8> {
    use mochios_filesystem_protocol as wire;
    let mut message = vec![0; wire::HEADER_LEN + path.len()];
    wire::encode(
        wire::Header {
            opcode,
            request_id: 123,
            offset,
            flags: budget,
            length: path.len() as u32,
            ..wire::Header::default()
        },
        path,
        &mut message,
    )
    .unwrap();
    message
}

fn bootstrap_response(
    reader: &BootstrapReader,
    request: &[u8],
    budget: usize,
) -> (mochios_filesystem_protocol::Header, Vec<u8>) {
    use mochios_filesystem_protocol as wire;
    let mut reply = vec![0xaa; wire::HEADER_LEN + budget];
    let length = filesystem_service::bootstrap_ipc::respond(reader, request, &mut reply).unwrap();
    assert!(length <= reply.len());
    assert!(reply[length..].iter().all(|byte| *byte == 0xaa));
    let (header, payload) = wire::decode(&reply[..length]).unwrap();
    assert_eq!(header.opcode, wire::OP_STATUS);
    assert_eq!(length, wire::HEADER_LEN + payload.len());
    (header, payload.to_vec())
}

#[test]
fn bootstrap_wire_reads_are_bounded_and_report_eof_and_typed_errors() {
    use filesystem_service::bootstrap_ipc::{EOF, MAX_TRANSFER};
    use mochios_filesystem_protocol as wire;
    let fixture = Fixture::new();
    let reader = fixture.reader();
    for (offset, expected, next, eof) in [
        (3, b"3456".as_slice(), 7, 0),
        (14, b"ef", 16, EOF),
        (16, b"", 16, EOF),
    ] {
        let (header, bytes) = bootstrap_response(
            &reader,
            &bootstrap_request(wire::OP_READ, b"/file", offset, 4),
            4,
        );
        assert_eq!(header.request_id, 123);
        assert_eq!(header.status, 0);
        assert_eq!(header.offset, next);
        assert_eq!(header.flags, eof);
        assert_eq!(bytes, expected);
    }
    for (path, offset, budget, status) in [
        (b"/missing".as_slice(), 0, 4, -2),
        (b"/directory", 0, 4, -21),
        (b"/file", u64::MAX, 4, -22),
        (b"/file", 0, 0, -22),
        (b"/file", 0, MAX_TRANSFER as u32 + 1, -22),
        (b"relative", 0, 4, -22),
        (b"/file\0suffix", 0, 4, -22),
        (b"/\xff", 0, 4, -22),
    ] {
        let (header, bytes) = bootstrap_response(
            &reader,
            &bootstrap_request(wire::OP_READ, path, offset, budget),
            4,
        );
        assert_eq!(header.status, status);
        assert_eq!(header.request_id, 123);
        assert!(bytes.is_empty());
        assert_eq!(header.flags, 0);
    }
    let request = bootstrap_request(wire::OP_READ, b"/file", 0, MAX_TRANSFER as u32);
    let (header, bytes) = bootstrap_response(&reader, &request, MAX_TRANSFER);
    assert_eq!(header.status, 0);
    assert_eq!(bytes, b"0123456789abcdef");
    assert_eq!(header.flags, EOF);
}

#[test]
fn bootstrap_wire_directory_pages_preserve_cookies_and_stay_within_budget() {
    use filesystem_service::bootstrap_ipc::EOF;
    use mochios_filesystem_protocol as wire;
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let expected = reader
        .read_directory("/directory", 0, 20, 1024)
        .unwrap()
        .names;
    let mut names = Vec::new();
    let mut cursor = 0;
    for _ in 0..20 {
        let (header, bytes) = bootstrap_response(
            &reader,
            &bootstrap_request(wire::OP_READDIR, b"/directory", cursor, 32),
            32,
        );
        assert_eq!(header.status, 0);
        assert_eq!(header.request_id, 123);
        assert!(bytes.len() <= 32);
        let mut remaining = bytes.as_slice();
        while !remaining.is_empty() {
            let (entry, name, consumed) = wire::decode_dir_entry(remaining).unwrap();
            assert_eq!(entry.node_id, 0);
            assert_eq!(entry.kind, 0);
            assert!(![b".".as_slice(), b".."].contains(&name));
            names.push(std::str::from_utf8(name).unwrap().to_owned());
            remaining = &remaining[consumed..];
        }
        if header.flags == EOF {
            break;
        }
        assert!(header.offset > cursor);
        cursor = header.offset;
    }
    assert_eq!(names, expected);
    for (path, budget, expected) in [
        (b"/file".as_slice(), 32, -20),
        (b"/missing", 32, -2),
        (b"/directory", 16, -22),
        (b"/directory", 17, -22),
    ] {
        let (header, bytes) = bootstrap_response(
            &reader,
            &bootstrap_request(wire::OP_READDIR, path, 0, budget),
            32,
        );
        assert_eq!(header.status, expected);
        assert!(bytes.is_empty());
    }
}

#[test]
fn bootstrap_wire_rejects_mutation_object_ids_and_malformed_frames() {
    use mochios_filesystem_protocol as wire;
    let fixture = Fixture::new();
    let reader = fixture.reader();
    for opcode in [
        wire::OP_WRITE,
        wire::OP_UNLINK,
        wire::OP_RENAME,
        wire::OP_OPEN,
        wire::OP_MOUNT,
        wire::OP_STATUS,
        u16::MAX,
    ] {
        let (header, bytes) =
            bootstrap_response(&reader, &bootstrap_request(opcode, b"/file", 0, 4), 4);
        assert_eq!(header.status, -38);
        assert!(bytes.is_empty());
    }
    let valid = bootstrap_request(wire::OP_READ, b"/file", 0, 4);
    for index in [16, 24, 32, 56, 60] {
        let mut request = valid.clone();
        request[index] = 1;
        assert_eq!(bootstrap_response(&reader, &request, 4).0.status, -22);
    }
    for length in 0..valid.len() {
        assert_eq!(
            bootstrap_response(&reader, &valid[..length], 4).0.status,
            -22
        );
    }
    let mut extra = valid.clone();
    extra.push(0);
    assert_eq!(bootstrap_response(&reader, &extra, 4).0.status, -22);
    for index in [0, 4, 48] {
        let mut request = valid.clone();
        request[index] ^= 0xff;
        assert_eq!(bootstrap_response(&reader, &request, 4).0.status, -22);
    }
    // An undersized payload buffer is a wire error, not a partial success.
    assert_eq!(bootstrap_response(&reader, &valid, 3).0.status, -22);
    let mut short = [0; wire::HEADER_LEN - 1];
    assert!(filesystem_service::bootstrap_ipc::respond(&reader, &valid, &mut short).is_err());
    assert_eq!(reader.read("/file", 16).unwrap(), b"0123456789abcdef");
}

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
fn bootstrap_wire_large_files_and_maximum_names_paginate_without_loss() {
    use filesystem_service::bootstrap_ipc::{EOF, MAX_TRANSFER};
    use mochios_filesystem_protocol as wire;
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let expected = reader.read("/large", 130_000).unwrap();
    let mut all = Vec::new();
    let mut offset = 0;
    loop {
        let (header, bytes) = bootstrap_response(
            &reader,
            &bootstrap_request(wire::OP_READ, b"/large", offset, MAX_TRANSFER as u32),
            MAX_TRANSFER,
        );
        assert_eq!(header.status, 0);
        assert_eq!(header.offset, offset + bytes.len() as u64);
        all.extend(bytes);
        if header.flags == EOF {
            break;
        }
        assert!(header.offset > offset);
        offset = header.offset;
    }
    assert_eq!(all, expected);
    for budget in [wire::DIRENT_HEADER_LEN + wire::MAX_NAME_LEN, MAX_TRANSFER] {
        let mut cursor = 0;
        let mut names = Vec::new();
        loop {
            let (header, bytes) = bootstrap_response(
                &reader,
                &bootstrap_request(wire::OP_READDIR, b"/long-names", cursor, budget as u32),
                budget,
            );
            assert_eq!(header.status, 0);
            let mut payload = bytes.as_slice();
            let mut count = 0;
            while !payload.is_empty() {
                let (_, name, used) = wire::decode_dir_entry(payload).unwrap();
                assert_eq!(name.len(), wire::MAX_NAME_LEN);
                names.push(name.to_vec());
                payload = &payload[used..];
                count += 1;
            }
            assert!(count <= 128);
            if header.flags == EOF {
                break;
            }
            assert!(header.offset > cursor);
            cursor = header.offset;
        }
        assert_eq!(names.len(), 140);
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 140);
    }
    for (path, expected) in [(b"/file/child".as_slice(), -20), (b"/loop", -40)] {
        let (header, bytes) =
            bootstrap_response(&reader, &bootstrap_request(wire::OP_READ, path, 0, 4), 4);
        assert_eq!(header.status, expected);
        assert!(bytes.is_empty());
    }
}

#[test]
fn bootstrap_client_round_trips_real_immutable_filesystem_and_propagates_errors() {
    use mochi_user_platform::syscall::{self, SysError};
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let mut previous_id = 0;
    let mut client =
        bootstrap_file::Client::new(4, |endpoint, request: &[u8], reply: &mut [u8]| {
            assert_eq!(endpoint, 4);
            let (header, _) = mochios_filesystem_protocol::decode(request).unwrap();
            assert_eq!(header.request_id, previous_id + 1);
            previous_id = header.request_id;
            filesystem_service::bootstrap_ipc::respond(&reader, request, reply)
                .map_err(|_| SysError::from_raw(syscall::EIO as i64))
        });
    for (path, limit) in [
        ("/large", 130_000),
        ("/file", 16),
        ("/empty", 0),
        ("/absolute", 16),
    ] {
        assert_eq!(
            client.read_file(path, limit).unwrap(),
            reader.read(path, limit).unwrap()
        );
    }
    assert_eq!(client.read_file("/file", 15).unwrap_err().raw(), -27);
    assert_eq!(client.read_file("/missing", 100).unwrap_err().raw(), -2);
    assert_eq!(client.read_file("/directory", 100).unwrap_err().raw(), -21);
    assert_eq!(client.read_dir_names("/file", 1024).unwrap_err().raw(), -20);
    let expected = reader
        .read_directory("/long-names", 0, 1000, 100_000)
        .unwrap()
        .names;
    assert_eq!(
        client.read_dir_names("/long-names", 100_000).unwrap(),
        expected
    );
    assert_eq!(
        client.read_dir_names("/long-names", 100).unwrap_err().raw(),
        -75
    );
    assert_eq!(client.read_file("/file", 16).unwrap(), b"0123456789abcdef");
}

#[test]
fn bootstrap_client_rejects_corrupt_replies_and_propagates_transport_failure() {
    use mochi_user_platform::syscall::{self, SysError};
    use mochios_filesystem_protocol as wire;
    let fixture = Fixture::new();
    let reader = fixture.reader();
    for index in [0, 4, 6, 8, 16, 24, 32, 40, 48, 52, 56, 60] {
        let mut client = bootstrap_file::Client::new(4, |_, request: &[u8], reply: &mut [u8]| {
            let length =
                filesystem_service::bootstrap_ipc::respond(&reader, request, reply).unwrap();
            reply[index] ^= 0x80;
            Ok(length)
        });
        assert_eq!(
            client.read_file("/file", 16).unwrap_err().raw(),
            -5,
            "field {index}"
        );
    }
    for extra in [1, wire::HEADER_LEN + 100_000] {
        let mut client = bootstrap_file::Client::new(4, |_, request: &[u8], reply: &mut [u8]| {
            let length =
                filesystem_service::bootstrap_ipc::respond(&reader, request, reply).unwrap();
            Ok(length + extra)
        });
        assert_eq!(client.read_file("/file", 16).unwrap_err().raw(), -5);
    }
    let mut client = bootstrap_file::Client::new(4, |_, _: &[u8], _: &mut [u8]| {
        Err(SysError::from_raw(
            syscall::NativeError::PeerClosed.into_raw() as i64,
        ))
    });
    assert_eq!(
        client.read_file("/file", 16).unwrap_err().native_error(),
        Some(syscall::NativeError::PeerClosed)
    );
    let mut client = bootstrap_file::Client::new(4, |_, request: &[u8], reply: &mut [u8]| {
        let (header, _) = wire::decode(request).unwrap();
        Ok(wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id,
                ..wire::Header::default()
            },
            &[],
            reply,
        )
        .unwrap())
    });
    assert_eq!(client.read_file("/file", 16).unwrap_err().raw(), -5);
    assert_eq!(
        client.read_dir_names("/directory", 1024).unwrap_err().raw(),
        -5
    );
}

#[test]
fn bootstrap_client_short_reads_require_explicit_eof_and_errors_do_not_return_partial_data() {
    use mochi_user_platform::syscall::SysError;
    use mochios_filesystem_protocol as wire;
    let mut pieces = [
        b"ab".as_slice(),
        b"c".as_slice(),
        b"def".as_slice(),
        b"".as_slice(),
    ]
    .into_iter();
    let mut cursor = 0;
    let mut client = bootstrap_file::Client::new(4, |_, request: &[u8], reply: &mut [u8]| {
        let (request, _) = wire::decode(request).unwrap();
        assert_eq!(request.offset, cursor);
        let bytes = pieces.next().expect("stop after explicit EOF");
        cursor += bytes.len() as u64;
        Ok(wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: request.request_id,
                offset: cursor,
                length: bytes.len() as u32,
                flags: if bytes.is_empty() {
                    wire::BOOTSTRAP_EOF
                } else {
                    0
                },
                ..wire::Header::default()
            },
            bytes,
            reply,
        )
        .unwrap())
    });
    assert_eq!(client.read_file("/file", 10).unwrap(), b"abcdef");
    assert!(pieces.next().is_none());
    let mut calls = 0;
    let mut client = bootstrap_file::Client::new(4, |_, request: &[u8], reply: &mut [u8]| {
        calls += 1;
        if calls > 1 {
            return Err(SysError::from_raw(-13));
        }
        let (request, _) = wire::decode(request).unwrap();
        Ok(wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: request.request_id,
                offset: 2,
                length: 2,
                ..wire::Header::default()
            },
            b"ab",
            reply,
        )
        .unwrap())
    });
    assert_eq!(client.read_file("/file", 10).unwrap_err().raw(), -13);
    assert_eq!(calls, 2);
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
