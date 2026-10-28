//! Actual network-service DNS factory/job Handles, including no-NIC results.
#![cfg(target_os = "mochios")]
use mochi_user_platform as p;
use mochios_posix_client::{
    ClientError, ObjectHandleAttachment as Object, SyscallEndpointTransport, resolver as client,
};
fn name() -> client::Name<'static> {
    client::Name::decode(b"\x07example\x03com\0").unwrap()
}
fn wait(h: u32) {
    let mut items = [mnu_abi::HandleWaitItem {
        handle: h,
        interests: mnu_abi::HANDLE_SIGNAL_READABLE,
        ..Default::default()
    }];
    p::process::wait_many(
        &mut items,
        p::time::monotonic_nanoseconds().unwrap() + 5_000_000_000,
    )
    .unwrap();
    assert_ne!(items[0].observed & mnu_abi::HANDLE_SIGNAL_READABLE, 0);
}
fn snapshot(h: u32) {
    wait(h);
    let obs = client::observe(&client::NativeIo, h).unwrap();
    assert!(obs.ready);
    assert_eq!(obs.status, -6);
    let mut bytes = [0; 512];
    let result =
        client::snapshot(&client::NativeIo, h, client::Kind::A, name(), &mut bytes).unwrap();
    assert_eq!(result.status, -6);
    assert_eq!(result.values().len(), 0);
    assert!(result.canonical.is_none());
}
fn start(endpoint: &SyscallEndpointTransport, factory: Object<u32>) -> Object<u32> {
    let deadline = p::time::ticks().unwrap() + 5000;
    loop {
        match client::start(endpoint, factory, client::Kind::A, name(), 100) {
            Ok(h) => return h,
            Err(ClientError::Remote(-24)) => {
                assert!(
                    p::time::ticks().unwrap() < deadline,
                    "DNS final-reference release deadline"
                );
                std::thread::yield_now();
            }
            Err(e) => panic!("DNS open {e:?}"),
        }
    }
}
fn raw_release_rejected(network: u32) {
    use mnu_abi::provider;
    let mut bytes = [0; provider::REQUEST_HEADER_LEN];
    provider::RequestHeader {
        opcode: provider::OP_RELEASE,
        object_id: (5 << 60) | 3,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut bytes)
    .unwrap();
    let mut response = [0; provider::RESPONSE_HEADER_LEN];
    let mut attached = p::ipc::IpcObjectHandles::default();
    let n = p::ipc::call_object_handles(network, &bytes, &mut response, &mut attached).unwrap()
        as u32 as usize;
    assert_eq!(attached.count, 0);
    let (reply, data) = provider::ResponseHeader::decode(&response[..n]).unwrap();
    assert_eq!(reply.status, -13);
    assert!(data.is_empty());
}
fn delegate_readonly(job: u32) {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    let done = Arc::new(AtomicBool::new(false));
    let closed = done.clone();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let endpoint = p::ipc::create_handle().unwrap();
        tx.send(endpoint).unwrap();
        let mut request = [0; 4];
        let mut attached = p::ipc::IpcObjectHandles::default();
        let message =
            p::ipc::wait_object_handles(u64::from(endpoint), &mut request, &mut attached).unwrap();
        assert_eq!(&request, b"hold");
        assert_eq!(attached.count, 1);
        assert_eq!(
            attached.delivery_flags,
            mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
        );
        let h = attached.handles[0];
        assert_eq!(
            h.rights,
            mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WAIT
        );
        p::ipc::reply(message >> 32, b"ok").unwrap();
        let deadline = p::time::ticks().unwrap() + 5000;
        while !closed.load(Ordering::Acquire) {
            assert!(p::time::ticks().unwrap() < deadline);
            std::thread::yield_now();
        }
        snapshot(h.handle);
        assert!(
            matches!(client::cancel(&client::NativeIo,h.handle),Err(ClientError::Transport(e)) if e.native_error()==Some(p::syscall::NativeError::AccessDenied))
        );
        p::handle::close(h.handle).unwrap();
        p::handle::close(endpoint).unwrap();
    });
    let endpoint = rx.recv().unwrap();
    let mut reply = [0; 2];
    let mut attached = p::ipc::IpcObjectHandles::default();
    attached.count = 1;
    attached.handles[0] = p::ipc::IpcObjectHandle {
        handle: job,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WAIT,
    };
    assert_eq!(
        p::ipc::call_object_handles(endpoint, b"hold", &mut reply, &mut attached).unwrap() as u32,
        2
    );
    assert_eq!(&reply, b"ok");
    assert_eq!(attached.count, 0);
    assert_eq!(attached.delivery_flags, 0);
    p::handle::close(job).unwrap();
    done.store(true, Ordering::Release);
    reader.join().unwrap();
}
fn case(network: u32, uid: u32) {
    let endpoint = SyscallEndpointTransport::new(network);
    let all = client::Limits {
        scopes: client::ALL_SCOPES,
        maximum_timeout: 1000,
    };
    let original = client::acquire(&endpoint, all).unwrap();
    assert_eq!(
        client::limits(&client::NativeIo, original.handle).unwrap(),
        all
    );
    client::validate(&endpoint, original).unwrap();
    let reduced = client::Limits {
        scopes: client::A_SCOPE,
        maximum_timeout: 500,
    };
    let factory = client::derive(&endpoint, original, reduced).unwrap();
    assert!(matches!(
        client::derive(&endpoint, factory, all),
        Err(ClientError::Remote(-13))
    ));
    assert!(matches!(
        client::start(&endpoint, factory, client::Kind::Aaaa, name(), 100),
        Err(ClientError::Remote(-13))
    ));
    assert!(matches!(
        client::start(&endpoint, factory, client::Kind::A, name(), 501),
        Err(ClientError::Remote(-13))
    ));
    let job = start(&endpoint, factory);
    assert_eq!(job.rights, client::JOB_RIGHTS);
    snapshot(job.handle);
    assert!(!client::cancel(&client::NativeIo, job.handle).unwrap());
    snapshot(job.handle);
    raw_release_rejected(network);
    snapshot(job.handle);
    assert_eq!(
        p::handle::write(job.handle, b"forbidden")
            .unwrap_err()
            .native_error(),
        Some(p::syscall::NativeError::AccessDenied)
    );
    let rights = mnu_abi::HANDLE_RIGHT_READ
        | mnu_abi::HANDLE_RIGHT_WAIT
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER;
    let reader = p::handle::duplicate(job.handle, rights).unwrap();
    p::handle::close(job.handle).unwrap();
    snapshot(reader);
    assert!(
        matches!(client::start(&endpoint,Object{handle:reader,rights:client::JOB_RIGHTS},client::Kind::A,name(),100),Err(ClientError::Transport(e)) if e.native_error()==Some(p::syscall::NativeError::AccessDenied))
    );
    p::handle::close(reader).unwrap();
    let capability = b"net.connect";
    p::syscall::call2(
        mnu_abi::SyscallNumber::CapDrop,
        capability.as_ptr() as u64,
        capability.len() as u64,
    )
    .unwrap();
    assert!(matches!(
        client::acquire(&endpoint, all),
        Err(ClientError::Remote(-13))
    ));
    client::validate(&endpoint, factory).unwrap();
    let foreign_endpoint = p::ipc::create_handle().unwrap();
    let foreign =
        p::handle::create_provider_object(foreign_endpoint, (3 << 60) | 1, client::FACTORY_RIGHTS)
            .unwrap();
    assert!(matches!(
        client::validate(
            &endpoint,
            Object {
                handle: foreign,
                rights: client::FACTORY_RIGHTS
            }
        ),
        Err(ClientError::Remote(-13))
    ));
    p::handle::close(foreign).unwrap();
    p::handle::close(foreign_endpoint).unwrap();
    p::handle::close(original.handle).unwrap();
    p::io::stdout(b"dns-provider: starting read-only IPC delegation\n").unwrap();
    delegate_readonly(start(&endpoint, factory).handle);
    p::io::stdout(b"dns-provider: starting final-reference churn\n").unwrap();
    for _ in 0..64 {
        let h = start(&endpoint, factory);
        snapshot(h.handle);
        p::handle::close(h.handle).unwrap();
    }
    p::handle::close(factory.handle).unwrap();
    if uid == 0 {
        p::io::stdout(b"dns-provider: PASS scopes, deadlines, native origin, rights attenuation, IPC delegation, CapDrop, no-NIC result and final lifetime euid 0\n").unwrap();
    } else {
        p::io::stdout(b"dns-provider: PASS scopes, deadlines, native origin, rights attenuation, IPC delegation, CapDrop, no-NIC result and final lifetime euid 501\n").unwrap();
    }
}
pub fn run(network: u32) {
    unsafe extern "C" {
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn seteuid(uid: u32) -> i32;
        fn geteuid() -> u32;
        fn _exit(code: i32) -> !;
        fn alarm(seconds: u32) -> u32;
    }
    for uid in [0, 501] {
        unsafe {
            let pid = fork();
            assert!(pid >= 0);
            if pid == 0 {
                alarm(30);
                assert_eq!(seteuid(uid), 0);
                assert_eq!(geteuid(), uid);
                case(network, uid);
                _exit(0);
            }
            let mut status = 0;
            assert_eq!(waitpid(pid, &mut status, 0), pid);
            assert_eq!(status, 0, "DNS child uid {uid} status {status}");
        }
    }
    p::io::stdout(b"dns-provider: PASS both credential children\n").unwrap();
}
