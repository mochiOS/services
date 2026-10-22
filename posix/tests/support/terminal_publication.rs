use super::*;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_SEND as S,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use posix_service::{PeerIdentity, pty::PtyManager, terminal_publication};
use std::sync::mpsc;

// Native handle installation, final release and owner identification are
// simulated here. Both services' real namespace/PTY logic runs unchanged.
#[derive(Debug)]
struct Metadata(u32);
impl posix_service::pty_metadata::Backend for Metadata {
    fn duplicate(&self, _rights: u64) -> Result<u32, i32> {
        Ok(self.0 + 1000)
    }
}
#[derive(Debug)]
struct Factory {
    manager: Arc<Mutex<PtyManager>>,
    grant: u64,
}
impl filesystem_service::device_factory::Factory for Factory {
    fn open(
        &self,
        metadata: IpcObjectHandle,
        request: protocol::device_open::Request,
    ) -> Result<IpcObjectHandle, i32> {
        assert_ne!(metadata.handle, 0);
        assert_eq!(metadata.rights & (D | T), D | T);
        let reference = posix_service::pty_metadata::Reference::new(
            Box::new(Metadata(metadata.handle)),
            metadata.rights,
        )?;
        let object = self
            .manager
            .lock()
            .unwrap()
            .open_slave_with_metadata(self.grant, reference)?;
        Ok(IpcObjectHandle {
            handle: u32::try_from(object).unwrap(),
            reserved: 0,
            rights: request.rights,
        })
    }
}
impl Drop for Factory {
    fn drop(&mut self) {
        self.manager.lock().unwrap().release(self.grant).unwrap();
    }
}

#[test]
fn published_terminal_names_open_fresh_slaves_and_retire_without_holding_terminal_state() {
    let fixture = Fixture::new();
    let mut filesystem = FilesystemService::new(fixture.volume("published-terminal-names"));
    filesystem
        .mount_devices(b"/dev", Default::default())
        .unwrap();
    let dev = device_open(
        &mut filesystem,
        b"/dev",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    configure_received_device(
        &mut filesystem,
        dev,
        protocol::OP_DEVICE_NODE_CREATE,
        protocol::device_namespace::Request {
            kind: protocol::device_namespace::KIND_DIRECTORY,
            mode: 0o755,
            uid: 0,
            gid: 0,
            name: b"pts",
        },
    )
    .unwrap();
    let parent = device_open(
        &mut filesystem,
        b"/dev/pts",
        protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let manager = Arc::new(Mutex::new(PtyManager::new()));
    let pair = manager.lock().unwrap().open().unwrap();
    let grant = manager
        .lock()
        .unwrap()
        .create_slave_factory(pair.master_object_id)
        .unwrap();
    let (sender, receiver) = mpsc::channel();
    let peer = PeerIdentity {
        process_id: 71,
        effective_uid: 501,
        effective_gid: 20,
    };
    let lease = terminal_publication::register_with(
        99,
        pair.master_object_id,
        peer,
        sender.clone(),
        |payload| {
            // Registration must run outside the terminal manager lock: filesystem
            // factory opens can need this very lock on their owner thread.
            assert!(manager.try_lock().is_ok());
            let mut objects = IpcObjectHandles::default();
            objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
            objects.count = 3;
            for (slot, (handle, rights)) in
                objects
                    .handles
                    .iter_mut()
                    .zip([(29, C | T), (31, S), (33, T)])
            {
                *slot = IpcObjectHandle {
                    handle,
                    reserved: 0,
                    rights,
                };
            }
            let response = filesystem_service::device_registration_ipc::handle(
                &mut filesystem,
                protocol::Header {
                    opcode: protocol::OP_DEVICE_NODE_REGISTER_EXTERNAL,
                    length: payload.len() as u32,
                    ..Default::default()
                },
                payload,
                &mut objects,
                |_| Ok(parent),
                |_, _| {
                    Ok(Arc::new(Factory {
                        manager: manager.clone(),
                        grant,
                    }))
                },
            )
            .map_err(|error| -error)?;
            protocol::decode_node_status(&response.payload).map_err(|_| -5)
        },
    )
    .unwrap();
    manager
        .lock()
        .unwrap()
        .attach_slave_name(pair.master_object_id, lease)
        .unwrap();
    let path = format!("/dev/pts/99-{}", pair.master_object_id);
    assert!(receiver.try_recv().is_err());
    let mut opens = Vec::new();
    let mut credentials = root_credentials();
    credentials.effective_uid = 501;
    credentials.effective_gid = 20;
    let mut other = credentials;
    other.effective_uid = 999;
    assert_eq!(
        filesystem
            .open_at(
                protocol::Header {
                    flags: protocol::OPEN_AT_WRITE,
                    ..Default::default()
                },
                path.as_bytes(),
                PathAnchors::default(),
                other
            )
            .err(),
        Some(13)
    );
    for _ in 0..2 {
        let response = filesystem
            .open_at(
                protocol::Header {
                    flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_WRITE,
                    ..Default::default()
                },
                path.as_bytes(),
                PathAnchors::default(),
                credentials,
            )
            .unwrap();
        let open = response.header.open_id;
        let status = filesystem
            .stat_handle(protocol::Header::default(), open)
            .unwrap();
        let status = protocol::decode_node_status(&status.payload).unwrap();
        assert_eq!(
            (status.uid, status.gid, status.mode & 0o7777),
            (501, 20, 0o600)
        );
        let slave = filesystem
            .external_open(open)
            .unwrap()
            .unwrap()
            .publish(IpcObjectHandle {
                handle: 900 + opens.len() as u32,
                reserved: 0,
                rights: C | D | T,
            })
            .unwrap();
        opens.push((open, u64::from(slave.handle)));
    }
    assert_ne!(opens[0].1, opens[1].1);
    manager
        .lock()
        .unwrap()
        .write(pair.master_object_id, b"hello\n")
        .unwrap();
    assert_eq!(
        manager.lock().unwrap().read(opens[0].1, 32).unwrap(),
        b"hello\n"
    );
    let first_terminal = manager.lock().unwrap().slave_terminal_id(opens[0].1);
    let second_terminal = manager.lock().unwrap().slave_terminal_id(opens[1].1);
    assert_eq!(first_terminal, second_terminal);
    manager
        .lock()
        .unwrap()
        .release(pair.master_object_id)
        .unwrap();
    let retired = receiver.try_recv().unwrap();
    assert_eq!(
        retired.component,
        format!("99-{}", pair.master_object_id).as_bytes()
    );
    // Return the observed owned record to the queue for the real worker.
    sender.send(retired).unwrap();
    drop(sender);
    terminal_publication::retire(
        receiver,
        |name| {
            assert!(
                manager.try_lock().is_ok(),
                "cleanup must not hold terminal state"
            );
            let mut payload = vec![0; protocol::device_removal::HEADER_LEN + name.component.len()];
            let length = protocol::device_removal::encode(
                protocol::device_removal::Request {
                    device: name.device,
                    node_id: name.node_id,
                    name: &name.component,
                },
                &mut payload,
            )
            .unwrap();
            let mut objects = IpcObjectHandles::default();
            objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
            objects.count = 1;
            objects.handles[0] = IpcObjectHandle {
                handle: 29,
                reserved: 0,
                rights: C | T,
            };
            filesystem_service::device_namespace_ipc::handle(
                &mut filesystem,
                protocol::Header {
                    opcode: protocol::OP_DEVICE_NODE_REMOVE_IF_SAME,
                    length: length as u32,
                    ..Default::default()
                },
                &payload,
                &objects,
                |_| Ok(parent),
            )
            .map(|_| ())
            .map_err(|error| -error)
        },
        |_, error| panic!("unexpected cleanup failure: {error}"),
    );
    assert_eq!(
        device_open(
            &mut filesystem,
            path.as_bytes(),
            protocol::OPEN_AT_READ,
            PathAnchors::default()
        ),
        Err(2)
    );
    for (open, slave) in opens {
        let status = filesystem
            .stat_handle(protocol::Header::default(), open)
            .unwrap();
        assert_eq!(
            protocol::decode_node_status(&status.payload)
                .unwrap()
                .link_count,
            0
        );
        assert_eq!(manager.lock().unwrap().read(slave, 32).unwrap(), b"");
        manager.lock().unwrap().release(slave).unwrap();
        filesystem.provider_close(open).unwrap();
    }
    manager
        .lock()
        .unwrap()
        .release(pair.slave_object_id)
        .unwrap();
    filesystem.provider_close(parent).unwrap();
    filesystem.provider_close(dev).unwrap();
}
