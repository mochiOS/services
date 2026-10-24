//! Exercise the production owner and its authenticated retained-inode handoff.
use super::super::fifo_native::Worker;
use super::{RuntimeFilesystem, payload, stat};
use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
use mochi_user_platform as platform;
use mochios_filesystem_protocol as fs;
use posix_service::{
    fifo::{Access, WaitCondition},
    fifo_wait_ipc, pty_metadata_ipc,
};

fn register(
    filesystem: &RuntimeFilesystem,
    worker: &Worker,
    path: &[u8],
    access: Access,
    nonblocking: bool,
) -> super::super::fifo_native::Registered {
    let payload = payload(path, 0);
    let mut request = vec![0; fs::HEADER_LEN + payload.len()];
    let header = fs::Header {
        opcode: fs::OP_OPEN_AT,
        request_id: 91,
        length: payload.len() as u32,
        flags: fs::OPEN_AT_RETAIN_FIFO
            | match access {
                Access::Read => fs::OPEN_AT_READ,
                Access::Write => fs::OPEN_AT_WRITE,
            },
        ..Default::default()
    };
    let length = fs::encode(header, &payload, &mut request).unwrap();
    let mut response = vec![0; fs::HEADER_LEN + fs::NODE_STATUS_LEN];
    let mut objects = IpcObjectHandles::default();
    let native = filesystem
        .call(&request[..length], &mut response, &mut objects)
        .unwrap();
    let (header, payload) =
        posix_service::filesystem_transport::reply_frame(&response, native, 91).unwrap();
    Worker::register(
        worker.endpoint(),
        header,
        payload,
        objects,
        access,
        nonblocking,
    )
    .unwrap()
}
pub fn run(filesystem: &RuntimeFilesystem, worker: &mut Worker) {
    let path = format!(
        "/tmp/fifo-worker-191-{}",
        platform::process::current_execution_identity()
            .unwrap()
            .process_id
    );
    let bytes = payload(path.as_bytes(), 0);
    let make = || {
        filesystem
            .empty_call(
                fs::Header {
                    opcode: fs::OP_CREATE_FIFO_AT,
                    request_id: 92,
                    length: bytes.len() as u32,
                    mode: 0o600,
                    ..Default::default()
                },
                &bytes,
                IpcObjectHandles::default(),
            )
            .unwrap()
    };
    let unlink = || {
        filesystem
            .empty_call(
                fs::Header {
                    opcode: fs::OP_UNLINK_AT,
                    request_id: 93,
                    length: bytes.len() as u32,
                    ..Default::default()
                },
                &bytes,
                IpcObjectHandles::default(),
            )
            .unwrap()
    };
    make();
    let reader = register(filesystem, worker, path.as_bytes(), Access::Read, false);
    assert!(!reader.ready);
    assert_eq!(worker.shutdown(), Err(-16));
    let source = IpcObjectHandle {
        handle: reader.object.handle,
        reserved: 0,
        rights: reader.object.rights,
    };
    let wait = fifo_wait_ipc::query(worker.endpoint(), source, WaitCondition::Open).unwrap();
    let writer = register(filesystem, worker, path.as_bytes(), Access::Write, true);
    assert!(writer.ready);
    let mut items = [platform::syscall::HandleWaitItem {
        handle: wait.handle,
        interests: mnu_abi::HANDLE_SIGNAL_READABLE,
        ..Default::default()
    }];
    platform::process::wait_many(
        &mut items,
        platform::time::monotonic_nanoseconds().unwrap() + 2_000_000_000,
    )
    .unwrap();
    platform::handle::close(wait.handle).unwrap();
    assert_eq!(
        platform::handle::write(writer.object.handle, b"worker").unwrap(),
        6
    );
    let mut output = [0; 16];
    assert_eq!(
        platform::handle::read(reader.object.handle, &mut output).unwrap(),
        6
    );
    assert_eq!(&output[..6], b"worker");
    platform::io::stdout(b"fifo-worker: PASS retained FS IPC handoff, blocking rendezvous registration and native data\n").unwrap();
    let before =
        pty_metadata_ipc::query(worker.endpoint(), source, mnu_abi::HANDLE_RIGHT_TRANSFER).unwrap();
    let original = stat(filesystem, before.handle);
    platform::handle::close(before.handle).unwrap();
    unlink();
    make();
    let after =
        pty_metadata_ipc::query(worker.endpoint(), source, mnu_abi::HANDLE_RIGHT_TRANSFER).unwrap();
    assert_eq!(stat(filesystem, after.handle).node_id, original.node_id);
    platform::handle::close(after.handle).unwrap();
    let replacement = register(filesystem, worker, path.as_bytes(), Access::Read, true);
    let new_metadata = pty_metadata_ipc::query(
        worker.endpoint(),
        IpcObjectHandle {
            handle: replacement.object.handle,
            reserved: 0,
            rights: replacement.object.rights,
        },
        mnu_abi::HANDLE_RIGHT_TRANSFER,
    )
    .unwrap();
    assert_ne!(
        stat(filesystem, new_metadata.handle).node_id,
        original.node_id
    );
    platform::handle::close(new_metadata.handle).unwrap();
    platform::io::stdout(
        b"fifo-worker: PASS data Handle resolves retained metadata after unlink and replacement\n",
    )
    .unwrap();
    platform::handle::close(writer.object.handle).unwrap();
    assert_eq!(
        platform::handle::read(reader.object.handle, &mut output).unwrap(),
        0
    );
    platform::handle::close(reader.object.handle).unwrap();
    platform::handle::close(replacement.object.handle).unwrap();
    worker.shutdown().unwrap();
    unlink();
    platform::io::stdout(b"fifo-worker: PASS busy shutdown preserves authority and final release permits clean shutdown\n").unwrap();
}
