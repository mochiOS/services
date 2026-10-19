//! Compile the production wire adapter against a reader that injects typed
//! filesystem failures, without depending on a host's errno numbering.
use std::io;

mod bootstrap_read {
    use std::io;
    pub struct BootstrapReader(pub fn() -> io::Error);
    pub struct BootstrapDirectoryPage {
        pub names: Vec<String>,
        pub next_entry: u64,
        pub eof: bool,
    }
    impl BootstrapReader {
        pub fn read_at(&self, _: &str, _: u64, _: &mut [u8]) -> io::Result<usize> {
            Err((self.0)())
        }
        pub fn read_directory(
            &self,
            _: &str,
            _: u64,
            _: usize,
            _: usize,
        ) -> io::Result<BootstrapDirectoryPage> {
            Err((self.0)())
        }
    }
}

#[path = "../../filesystem/src/bootstrap_ipc.rs"]
mod bootstrap_ipc;
use mochios_filesystem_protocol as wire;

fn reply_status(factory: fn() -> io::Error, opcode: u16) -> i32 {
    let mut request = [0; wire::HEADER_LEN + 5];
    let length = wire::encode(
        wire::Header {
            opcode,
            request_id: 77,
            flags: 512,
            length: 5,
            ..Default::default()
        },
        b"/file",
        &mut request,
    )
    .unwrap();
    let mut response = [0xa5; wire::HEADER_LEN + 512];
    let length = bootstrap_ipc::respond(
        &bootstrap_read::BootstrapReader(factory),
        &request[..length],
        &mut response,
    )
    .unwrap();
    let (header, payload) = wire::decode(&response[..length]).unwrap();
    assert_eq!(header.request_id, 77);
    assert_eq!(header.offset, 0);
    assert_eq!(header.flags, 0);
    assert!(payload.is_empty());
    assert!(response[length..].iter().all(|byte| *byte == 0xa5));
    header.status
}

#[test]
fn typed_filesystem_failures_use_stable_wire_statuses() {
    for (factory, expected) in [
        ((|| io::ErrorKind::NotFound.into()) as fn() -> io::Error, -2),
        (|| io::ErrorKind::PermissionDenied.into(), -13),
        (|| io::ErrorKind::AlreadyExists.into(), -17),
        (|| io::ErrorKind::NotADirectory.into(), -20),
        (|| io::ErrorKind::IsADirectory.into(), -21),
        (|| io::ErrorKind::InvalidInput.into(), -22),
        (|| io::ErrorKind::FileTooLarge.into(), -27),
        (|| io::ErrorKind::StorageFull.into(), -28),
        (|| io::ErrorKind::ReadOnlyFilesystem.into(), -30),
        (|| io::ErrorKind::OutOfMemory.into(), -12),
        (|| io::ErrorKind::Other.into(), -5),
    ] {
        for opcode in [wire::OP_READ, wire::OP_READDIR] {
            assert_eq!(reply_status(factory, opcode), expected);
        }
    }
}

#[test]
fn path_failures_keep_ext4_identity_instead_of_becoming_newlib_errno_numbers() {
    for (factory, expected) in [
        (
            (|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    ext4plus::error::Ext4Error::PathTooLong,
                )
            }) as fn() -> io::Error,
            -36,
        ),
        (
            || {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    ext4plus::error::Ext4Error::TooManySymlinks,
                )
            },
            -40,
        ),
    ] {
        for opcode in [wire::OP_READ, wire::OP_READDIR] {
            assert_eq!(reply_status(factory, opcode), expected);
        }
    }
}

#[test]
fn unknown_raw_error_numbers_never_escape_as_filesystem_statuses() {
    for factory in [
        (|| io::Error::from_raw_os_error(2_000_001)) as fn() -> io::Error,
        || io::Error::from_raw_os_error(i32::MAX),
        || io::Error::from_raw_os_error(i32::MIN),
    ] {
        assert_eq!(reply_status(factory, wire::OP_READ), -5);
        assert_eq!(reply_status(factory, wire::OP_READDIR), -5);
    }
}

#[test]
fn request_errors_are_wire_failures_not_constructed_os_errors() {
    let unused = || panic!("invalid request must not call the reader");
    assert_eq!(reply_status(unused, wire::OP_WRITE), -38);
    for source in [
        include_str!("../../filesystem/src/bootstrap_ipc.rs"),
        include_str!("../../filesystem/src/bootstrap_read.rs"),
    ] {
        assert!(!source.contains("from_raw_os_error"));
        assert!(!source.contains("raw_os_error()"));
    }
}
