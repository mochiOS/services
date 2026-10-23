//! Real native endpoint/grant transfer and owner-only identification.
//! This isolates the exchange; filesystem pathname integration is not tested.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("device-observation: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use filesystem_service::device_factory::{Factory, NativeFactory};
    use mnu_abi::{HANDLE_RIGHT_SEND, IpcObjectHandle, IpcObjectHandles};
    use mochi_user_platform as platform;
    use mochios_filesystem_protocol::device_observation as wire;
    use mochios_posix_protocol as posix;
    use posix_service::{pty::PtyManager, pty_factory::FACTORY_RIGHTS};
    use std::sync::{Mutex, mpsc};

    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let endpoint = platform::ipc::create_handle().unwrap();
        let mut manager = PtyManager::new();
        let pair = manager.open().unwrap();
        manager
            .write(pair.master_object_id, b"preserved\n")
            .unwrap();
        let factory_id = manager.create_slave_factory(pair.master_object_id).unwrap();
        let grant =
            platform::handle::create_provider_object(endpoint, factory_id, FACTORY_RIGHTS).unwrap();
        let wrong = platform::handle::create_provider_object(
            endpoint,
            pair.master_object_id,
            FACTORY_RIGHTS,
        )
        .unwrap();
        let send = platform::handle::duplicate(endpoint, HANDLE_RIGHT_SEND).unwrap();
        let other_send = platform::handle::duplicate(endpoint, HANDLE_RIGHT_SEND).unwrap();
        let attributes = manager.attributes(pair.master_object_id).unwrap();
        let readiness = manager.signals(pair.master_object_id).unwrap();
        let manager = Mutex::new(manager);
        sender.send((send, other_send, grant, wrong)).unwrap();
        for _ in 0..4 {
            let mut request = [0; wire::REQUEST_LEN];
            let mut objects = IpcObjectHandles::default();
            let message =
                platform::ipc::wait_object_handles(u64::from(endpoint), &mut request, &mut objects)
                    .unwrap();
            assert_eq!(message as u32 as usize, request.len());
            posix_service::pty_observation::serve(&manager, message >> 32, &request, objects);
        }
        let mut manager = manager.lock().unwrap();
        assert_eq!(
            manager.attributes(pair.master_object_id).unwrap(),
            attributes
        );
        assert_eq!(manager.signals(pair.master_object_id).unwrap(), readiness);
        assert!(manager.take_terminal_signal().is_none());
        assert_eq!(
            manager.read(pair.slave_object_id, 64).unwrap(),
            b"preserved\n"
        );
        assert_eq!(
            manager.reopen_slave(pair.master_object_id).unwrap(),
            factory_id + 1
        );
        platform::handle::close(endpoint).unwrap();
    });
    let (send, other_send, grant, wrong) = receiver.recv().unwrap();
    let object = |handle, rights| IpcObjectHandle {
        handle,
        reserved: 0,
        rights,
    };
    let factory = NativeFactory::from_received(
        object(send, HANDLE_RIGHT_SEND),
        object(grant, FACTORY_RIGHTS),
    )
    .unwrap();
    let request = wire::Request {
        selector: posix::PTY_QUERY_LIMITS,
        capacity: posix::terminal_limits::RESPONSE_LEN as u32,
    };
    let limits =
        posix::terminal_limits::Limits::decode(&factory.observe(request).unwrap()).unwrap();
    assert_eq!(
        limits.canonical_bytes as usize,
        posix_service::pty::CANONICAL_LINE_CAPACITY
    );
    assert_eq!(
        limits.input_bytes as usize,
        posix_service::pty::BUFFER_CAPACITY
    );
    assert_eq!(limits.disabled_character, 0);
    platform::io::stdout(
        b"device-observation: PASS native factory Handle transfer and owner query\n",
    )
    .unwrap();
    for selector in [
        posix::PTY_CONTROL_FLUSH,
        posix::PTY_CONTROL_SET_ATTRIBUTES_NOW,
    ] {
        assert_eq!(
            factory.observe(wire::Request {
                selector,
                ..request
            }),
            Err(95)
        );
    }
    platform::io::stdout(b"device-observation: PASS mutation selectors denied\n").unwrap();
    let wrong = NativeFactory::from_received(
        object(other_send, HANDLE_RIGHT_SEND),
        object(wrong, FACTORY_RIGHTS),
    )
    .unwrap();
    assert_eq!(wrong.observe(request), Err(9));
    drop(wrong);
    drop(factory);
    worker.join().unwrap();
    platform::io::stdout(
        b"device-observation: PASS wrong object denied, no data open or terminal state change\n",
    )
    .unwrap();
}
