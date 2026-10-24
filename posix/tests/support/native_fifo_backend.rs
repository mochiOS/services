//! Real RuntimeFilesystem continuation path; the fixture calls no test RPC.
use super::{RuntimeFilesystem, payload};
use mnu_abi::IpcObjectHandles;
use mochi_user_platform as platform;
use mochios_filesystem_protocol as fs;
use mochios_posix_protocol as posix;
use posix_service::{AttachedObject, OpenCompletion, PathObjects, PreparedOpen};

pub fn run(filesystem: &RuntimeFilesystem) {
    let path = format!(
        "/tmp/fifo-backend-193-{}",
        platform::process::current_execution_identity()
            .unwrap()
            .process_id
    );
    let bytes = payload(path.as_bytes(), 0);
    filesystem
        .empty_call(
            fs::Header {
                opcode: fs::OP_CREATE_FIFO_AT,
                request_id: 94,
                length: bytes.len() as u32,
                mode: 0o600,
                ..Default::default()
            },
            &bytes,
            IpcObjectHandles::default(),
        )
        .unwrap();
    let root_bytes = payload(b"/", 0);
    let root = filesystem
        .open_call(
            fs::Header {
                opcode: fs::OP_OPEN_AT,
                request_id: 95,
                length: root_bytes.len() as u32,
                flags: fs::OPEN_AT_SEARCH | fs::OPEN_AT_DIRECTORY,
                ..Default::default()
            },
            &root_bytes,
            IpcObjectHandles::default(),
        )
        .unwrap();
    let prepared = |options| PreparedOpen {
        base: posix::OpenBase::ProcessRoot,
        options,
        mode: 0,
        path: path.as_bytes().to_vec(),
        effective_uid: 0,
        effective_gid: 0,
        supplementary_groups: Vec::new(),
    };
    let paths = || PathObjects {
        root: AttachedObject {
            handle: root.handle,
            rights: root.rights,
        },
        base: None,
    };
    let pending = filesystem
        .continuation_open(&prepared(posix::OPEN_READ), paths(), None)
        .unwrap_or_else(|_| panic!("reader backend"));
    let (reader, notification) = match pending {
        OpenCompletion::FifoPending { data, notification } => (data, notification),
        _ => panic!("pending read open"),
    };
    let writer = match filesystem
        .continuation_open(
            &prepared(posix::OPEN_WRITE | posix::OPEN_NONBLOCK),
            paths(),
            None,
        )
        .unwrap_or_else(|_| panic!("writer backend"))
    {
        OpenCompletion::Ready(writer) => writer,
        _ => panic!("nonblocking writer must be ready"),
    };
    let mut items = [platform::syscall::HandleWaitItem {
        handle: notification.handle,
        interests: mnu_abi::HANDLE_SIGNAL_READABLE,
        ..Default::default()
    }];
    platform::process::wait_many(
        &mut items,
        platform::time::monotonic_nanoseconds().unwrap() + 2_000_000_000,
    )
    .unwrap();
    platform::handle::close(notification.handle).unwrap();
    assert_eq!(
        platform::handle::write(writer.handle, b"backend").unwrap(),
        7
    );
    let mut output = [0; 16];
    assert_eq!(
        platform::handle::read(reader.handle, &mut output).unwrap(),
        7
    );
    assert_eq!(&output[..7], b"backend");
    let metadata = super::super::query_provider_metadata(
        [filesystem.device_endpoint, filesystem.fifo_endpoint],
        mnu_abi::IpcObjectHandle {
            handle: reader.handle,
            reserved: 0,
            rights: reader.rights,
        },
        mnu_abi::HANDLE_RIGHT_TRANSFER,
    )
    .unwrap();
    assert_eq!(
        super::stat(filesystem, metadata.handle).kind,
        fs::NODE_TYPE_FIFO
    );
    platform::handle::close(metadata.handle).unwrap();
    platform::handle::close(writer.handle).unwrap();
    assert_eq!(
        platform::handle::read(reader.handle, &mut output).unwrap(),
        0
    );
    platform::handle::close(reader.handle).unwrap();
    platform::handle::close(root.handle).unwrap();
    filesystem
        .empty_call(
            fs::Header {
                opcode: fs::OP_UNLINK_AT,
                request_id: 96,
                length: bytes.len() as u32,
                ..Default::default()
            },
            &bytes,
            IpcObjectHandles::default(),
        )
        .unwrap();
    platform::io::stdout(b"fifo-backend: PASS RuntimeFilesystem retained open, pending continuation, data and metadata routing\n").unwrap();
}
