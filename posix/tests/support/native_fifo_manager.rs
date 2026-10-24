//! Same-process owner thread; real filesystem replies and native data IPC.
use super::{RuntimeFilesystem, payload};
use mnu_abi::{IpcObjectHandles, SyscallNumber, provider};
use mochi_user_platform as platform;
use mochios_filesystem_protocol as wire;
use posix_service::{
    fifo::Access,
    fifo_manager::{AdmittedInode, FilesystemScope, Manager},
    filesystem_reference::Reference,
};

fn prepare(
    fs: &RuntimeFilesystem,
    scope: FilesystemScope,
    path: &[u8],
    access: Access,
) -> AdmittedInode {
    let payload = payload(path, 0);
    let mut request = vec![0; wire::HEADER_LEN + payload.len()];
    let header = wire::Header {
        opcode: wire::OP_OPEN_AT,
        request_id: 81,
        length: payload.len() as u32,
        flags: wire::OPEN_AT_RETAIN_FIFO
            | match access {
                Access::Read => wire::OPEN_AT_READ,
                Access::Write => wire::OPEN_AT_WRITE,
            },
        ..Default::default()
    };
    let length = wire::encode(header, &payload, &mut request).unwrap();
    let mut response = vec![0; wire::HEADER_LEN + wire::NODE_STATUS_LEN];
    let mut objects = IpcObjectHandles::default();
    let native = fs
        .call(&request[..length], &mut response, &mut objects)
        .unwrap();
    let (header, payload) =
        posix_service::filesystem_transport::reply_frame(&response, native, 81).unwrap();
    scope
        .admit(
            header,
            81,
            payload,
            &mut objects,
            access,
            Reference::from_received,
        )
        .unwrap()
}

fn create(endpoint: u32, id: u64, rights: u64, options: u64) -> Result<u32, i32> {
    let handle = platform::handle::create_provider_object(endpoint, id, rights).map_err(|_| -5)?;
    if platform::syscall::call2(SyscallNumber::HandleOptionsSet, u64::from(handle), options)
        .is_err()
    {
        let _ = platform::handle::close(handle);
        return Err(-5);
    }
    Ok(handle)
}

pub fn run(fs: &RuntimeFilesystem) {
    let path = format!(
        "/tmp/fifo-manager-188-{}",
        platform::process::current_execution_identity()
            .unwrap()
            .process_id
    );
    let bytes = payload(path.as_bytes(), 0);
    let make = || {
        fs.empty_call(
            wire::Header {
                opcode: wire::OP_CREATE_FIFO_AT,
                request_id: 82,
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
        fs.empty_call(
            wire::Header {
                opcode: wire::OP_UNLINK_AT,
                request_id: 83,
                length: bytes.len() as u32,
                ..Default::default()
            },
            &bytes,
            IpcObjectHandles::default(),
        )
        .unwrap()
    };
    make();
    let scope = FilesystemScope::new().unwrap();
    let mut admitted = vec![
        prepare(fs, scope, path.as_bytes(), Access::Read),
        prepare(fs, scope, path.as_bytes(), Access::Read),
        prepare(fs, scope, path.as_bytes(), Access::Write),
    ];
    // Keep old inode authority alive while replacing the name with a new FIFO.
    unlink();
    make();
    admitted.push(prepare(fs, scope, path.as_bytes(), Access::Read));
    admitted.push(prepare(fs, scope, path.as_bytes(), Access::Write));
    let (opened_tx, opened_rx) = std::sync::mpsc::channel();
    let (released_tx, released_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let endpoint = platform::ipc::create_handle().unwrap();
        let mut manager = Manager::default();
        let mut opened = Vec::new();
        let signal = |id, signals| {
            let mask = mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_WRITABLE
                | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
            match platform::handle::signal_provider_object(id, signals, mask & !signals) {
                Ok(()) => Ok(()),
                // The ID is owned by this thread and the masks are validated.
                // Final native close may precede its queued OP_RELEASE. Keep
                // the inode pin until release; there is no remaining observer.
                Err(error) if super::super::socket_native::notification_is_retired(error.raw()) => {
                    Ok(())
                }
                Err(error) => Err(mochios_posix_protocol::status::normalize_failure(
                    error.raw(),
                )),
            }
        };
        for admission in admitted {
            let object = manager
                .open(
                    admission,
                    true,
                    |id, rights, options| create(endpoint, id, rights, options),
                    |handle| {
                        let _ = platform::handle::close(handle);
                    },
                )
                .unwrap();
            manager.visit_signals(object.channel, signal).unwrap();
            opened.push((object.handle, object.object_id));
        }
        opened_tx.send(opened).unwrap();
        let mut released = 0;
        let mut request = [0; provider::REQUEST_HEADER_LEN + provider::MAX_DATA_LEN];
        let mut response = [0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
        while released < 5 {
            let mut objects = IpcObjectHandles::default();
            let native =
                platform::ipc::wait_object_handles(u64::from(endpoint), &mut request, &mut objects)
                    .unwrap();
            let length = native as u32 as usize;
            assert!(length <= request.len());
            let (header, _) = provider::RequestHeader::decode(&request[..length]).unwrap();
            let dispatch = manager
                .handle_provider_request(
                    &request[..length],
                    objects.delivery_flags,
                    objects.count,
                    &mut response,
                )
                .unwrap();
            assert_eq!(objects.count, 0);
            if let Some(key) = dispatch.changed {
                manager.visit_signals(key, signal).unwrap();
            }
            if let Some(length) = dispatch.reply_length {
                platform::ipc::reply(native >> 32, &response[..length]).unwrap();
            } else {
                assert_eq!(header.opcode, provider::OP_RELEASE);
                released += 1;
                released_tx.send(header.object_id).unwrap();
            }
        }
        platform::handle::close(endpoint).unwrap();
    });
    let opened = opened_rx.recv().unwrap();
    assert_eq!(opened.len(), 5);
    let mut output = [0; 16];
    assert_eq!(platform::handle::write(opened[2].0, b"old").unwrap(), 3);
    assert_eq!(
        platform::handle::read(opened[3].0, &mut output)
            .unwrap_err()
            .raw(),
        -11
    );
    assert_eq!(platform::handle::write(opened[4].0, b"new").unwrap(), 3);
    assert_eq!(
        platform::handle::read(opened[0].0, &mut output[..1]).unwrap(),
        1
    );
    assert_eq!(output[0], b'o');
    assert_eq!(platform::handle::read(opened[1].0, &mut output).unwrap(), 2);
    assert_eq!(&output[..2], b"ld");
    assert_eq!(platform::handle::read(opened[3].0, &mut output).unwrap(), 3);
    assert_eq!(&output[..3], b"new");
    platform::io::stdout(
        b"fifo-manager: PASS admitted filesystem references share only the same inode queue\n",
    )
    .unwrap();
    platform::handle::close(opened[2].0).unwrap();
    assert_eq!(released_rx.recv().unwrap(), opened[2].1);
    assert_eq!(platform::handle::read(opened[0].0, &mut output).unwrap(), 0);
    assert_eq!(
        platform::handle::read(opened[3].0, &mut output)
            .unwrap_err()
            .raw(),
        -11
    );
    platform::io::stdout(
        b"fifo-manager: PASS old inode EOF leaves same-name replacement channel alive\n",
    )
    .unwrap();
    for index in [0, 1, 3, 4] {
        platform::handle::close(opened[index].0).unwrap();
    }
    let mut released = Vec::new();
    for _ in 0..4 {
        released.push(released_rx.recv().unwrap());
    }
    released.sort_unstable();
    let mut expected = vec![opened[0].1, opened[1].1, opened[3].1, opened[4].1];
    expected.sort_unstable();
    assert_eq!(released, expected);
    worker.join().unwrap();
    unlink();
    platform::io::stdout(
        b"fifo-manager: PASS final native releases retire inode pins and owner worker\n",
    )
    .unwrap();
}
