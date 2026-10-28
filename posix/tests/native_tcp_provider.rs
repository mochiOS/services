//! Real IPC attachments, kernel rights, Provider lifetime and TCP transport.
#![cfg(target_os = "mochios")]
#[path = "../../../user/crates/net-device-protocol/src/datagram.rs"]
mod datagram;
#[path = "../../../user/crates/net-device-protocol/src/datagram_authority.rs"]
mod datagram_authority;
#[path = "../../../user/crates/net-device-protocol/src/stream.rs"]
mod wire;
use mochi_user_platform as p;
const FACTORY_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
const RESOURCE_RIGHTS: u64 = FACTORY_RIGHTS
    | mnu_abi::HANDLE_RIGHT_READ
    | mnu_abi::HANDLE_RIGHT_WRITE
    | mnu_abi::HANDLE_RIGHT_WAIT;
fn rpc(
    endpoint: u32,
    operation: u16,
    bytes: &[u8],
    source: Option<u32>,
) -> Result<Option<u32>, i64> {
    let mut handles = p::ipc::IpcObjectHandles::default();
    if let Some(source) = source {
        handles.count = 1;
        handles.handles[0] = p::ipc::IpcObjectHandle {
            handle: source,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_CONTROL,
        };
    }
    let mut reply = [0; wire::REPLY_LEN];
    let result = p::ipc::call_object_handles(endpoint, bytes, &mut reply, &mut handles);
    let checked = (|| {
        let n = result.map_err(|e| e.raw())? as u32 as usize;
        if handles.delivery_flags != 0 {
            return Err(-5);
        }
        let status = wire::status(operation, reply.get(..n).ok_or(-5)?).map_err(|_| -5)?;
        if status != 0 {
            return Err(i64::from(status));
        }
        if operation == wire::VALIDATE {
            if handles.count != 0 {
                return Err(-5);
            }
            return Ok(None);
        }
        if handles.count != 1 {
            return Err(-5);
        }
        let h = handles.handles[0];
        let rights = if matches!(operation, wire::ACQUIRE | wire::DERIVE) {
            FACTORY_RIGHTS
        } else {
            RESOURCE_RIGHTS
        };
        if h.handle == 0 || Some(h.handle) == source || h.reserved != 0 || h.rights != rights {
            return Err(-5);
        }
        Ok(Some(h.handle))
    })();
    if checked.is_err() {
        for (i, h) in handles
            .handles
            .iter()
            .take(handles.count as usize)
            .enumerate()
        {
            if h.handle != 0
                && Some(h.handle) != source
                && !handles.handles[..i]
                    .iter()
                    .any(|old| old.handle == h.handle)
            {
                let _ = p::handle::close(h.handle);
            }
        }
    }
    checked
}
fn acquire(endpoint: u32, scope: u32) -> Result<u32, i64> {
    rpc(
        endpoint,
        wire::ACQUIRE,
        &wire::scoped(wire::ACQUIRE, scope).unwrap(),
        None,
    )
    .map(|h| h.unwrap())
}
fn open(endpoint: u32, factory: u32) -> u32 {
    rpc(
        endpoint,
        wire::OPEN,
        &wire::header(wire::OPEN),
        Some(factory),
    )
    .unwrap()
    .unwrap()
}
fn address(port: u16) -> [u8; 8] {
    let mut bytes = [0; 8];
    wire::Endpoint {
        address: [127, 0, 0, 1],
        port,
    }
    .encode(&mut bytes)
    .unwrap();
    bytes
}
fn control(h: u32, tag: u64, input: &[u8]) {
    assert_eq!(p::handle::control(h, tag, input, &mut []).unwrap(), 0);
}
fn wait(h: u32, interests: u64) {
    let mut items = [mnu_abi::HandleWaitItem {
        handle: h,
        interests,
        ..Default::default()
    }];
    p::process::wait_many(
        &mut items,
        p::time::monotonic_nanoseconds().unwrap() + 5_000_000_000,
    )
    .unwrap();
    assert_ne!(items[0].observed & interests, 0);
}
fn status(h: u32) -> wire::Observation {
    let mut bytes = [0; wire::STATUS_LEN];
    assert_eq!(
        p::handle::query(h, wire::STATUS, &[], &mut bytes).unwrap(),
        bytes.len()
    );
    wire::Observation::decode(&bytes).unwrap()
}
fn case(network: u32, port: u16) {
    let factory = acquire(network, wire::ALL_SCOPES).unwrap();
    let mut limits = [0; wire::LIMITS_LEN];
    assert_eq!(
        p::handle::control(factory, wire::QUERY_LIMITS, &[], &mut limits).unwrap(),
        limits.len()
    );
    assert_eq!(
        wire::Limits::decode(&limits).unwrap().scopes,
        wire::ALL_SCOPES
    );
    let connect_factory = rpc(
        network,
        wire::DERIVE,
        &wire::scoped(wire::DERIVE, wire::CONNECT_SCOPE).unwrap(),
        Some(factory),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        rpc(
            network,
            wire::DERIVE,
            &wire::scoped(wire::DERIVE, wire::ALL_SCOPES).unwrap(),
            Some(connect_factory)
        ),
        Err(-13)
    );
    // Never invoke an arbitrary attached object to discover whether it is a
    // factory: the exact trusted network endpoint must reject this foreign one.
    let foreign_endpoint = p::ipc::create_handle().unwrap();
    let foreign = p::handle::create_provider_object(foreign_endpoint, 7, FACTORY_RIGHTS).unwrap();
    assert_eq!(
        rpc(
            network,
            wire::OPEN,
            &wire::header(wire::OPEN),
            Some(foreign)
        ),
        Err(-13)
    );
    p::handle::close(foreign).unwrap();
    p::handle::close(foreign_endpoint).unwrap();
    // A guessed private ID in ordinary IPC cannot forge a native release.
    let mut forged = [0; mnu_abi::provider::REQUEST_HEADER_LEN];
    mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_RELEASE,
        object_id: (4 << 60) | 1,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut forged)
    .unwrap();
    let mut response = [0; mnu_abi::provider::RESPONSE_HEADER_LEN];
    let n = p::ipc::call_object_handles(network, &forged, &mut response, &mut Default::default())
        .unwrap() as u32 as usize;
    assert_eq!(
        mnu_abi::provider::ResponseHeader::decode(&response[..n])
            .unwrap()
            .0
            .status,
        -13
    );
    for name in [b"net.connect".as_slice(), b"net.listen".as_slice()] {
        mochi_user_syscall::call2(
            mnu_abi::SyscallNumber::CapDrop,
            name.as_ptr() as u64,
            name.len() as u64,
        )
        .unwrap();
    }
    assert_eq!(acquire(network, wire::ALL_SCOPES), Err(-13));
    assert_eq!(
        rpc(
            network,
            wire::VALIDATE,
            &wire::header(wire::VALIDATE),
            Some(factory)
        ),
        Ok(None)
    );
    let listener = open(network, factory);
    let client = open(network, connect_factory);
    assert_eq!(
        p::handle::control(client, wire::LISTEN, &4u32.to_le_bytes(), &mut [])
            .unwrap_err()
            .raw(),
        -13
    );
    assert_eq!(
        p::handle::control(listener, wire::BIND, &address(80), &mut [])
            .unwrap_err()
            .raw(),
        -13
    );
    control(listener, wire::BIND, &address(port));
    control(listener, wire::LISTEN, &4u32.to_le_bytes());
    let alias = p::handle::duplicate(listener, RESOURCE_RIGHTS).unwrap();
    p::handle::close(listener).unwrap();
    control(client, wire::CONNECT, &address(port));
    wait(client, mnu_abi::HANDLE_SIGNAL_WRITABLE);
    wait(alias, mnu_abi::HANDLE_SIGNAL_READABLE);
    let accepted = rpc(
        network,
        wire::ACCEPT,
        &wire::header(wire::ACCEPT),
        Some(alias),
    )
    .unwrap()
    .unwrap();
    p::handle::close(alias).unwrap();
    assert_eq!(status(client).error, 0);
    assert_eq!(p::handle::write(client, b"hello").unwrap(), 5);
    wait(accepted, mnu_abi::HANDLE_SIGNAL_READABLE);
    let mut out = [0; 16];
    assert_eq!(p::handle::read_at(accepted, &mut out[..2], 0).unwrap(), 2);
    assert_eq!(&out[..2], b"he");
    assert_eq!(p::handle::read(accepted, &mut out).unwrap(), 5);
    assert_eq!(&out[..5], b"hello");
    assert_eq!(p::handle::read(accepted, &mut out).unwrap_err().raw(), -11);
    assert_eq!(p::handle::write(accepted, b"reply").unwrap(), 5);
    wait(client, mnu_abi::HANDLE_SIGNAL_READABLE);
    assert_eq!(p::handle::read(client, &mut out).unwrap(), 5);
    assert_eq!(&out[..5], b"reply");
    let read_rights = mnu_abi::HANDLE_RIGHT_READ
        | mnu_abi::HANDLE_RIGHT_WAIT
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER;
    let reader = p::handle::duplicate(accepted, read_rights).unwrap();
    p::handle::close(accepted).unwrap();
    assert_eq!(
        p::handle::duplicate(reader, RESOURCE_RIGHTS)
            .unwrap_err()
            .native_error(),
        Some(mnu_abi::status::Error::AccessDenied)
    );
    assert_eq!(
        p::handle::write(reader, b"bad").unwrap_err().native_error(),
        Some(mnu_abi::status::Error::AccessDenied)
    );
    assert_eq!(
        p::handle::control(
            reader,
            wire::SHUTDOWN,
            &wire::WRITE_SHUTDOWN.to_le_bytes(),
            &mut []
        )
        .unwrap_err()
        .native_error(),
        Some(mnu_abi::status::Error::AccessDenied)
    );
    assert!(
        rpc(
            network,
            wire::ACCEPT,
            &wire::header(wire::ACCEPT),
            Some(reader)
        )
        .is_err()
    );
    assert_eq!(p::handle::write(client, b"more").unwrap(), 4);
    wait(reader, mnu_abi::HANDLE_SIGNAL_READABLE);
    assert_eq!(p::handle::read(reader, &mut out).unwrap(), 4);
    assert_eq!(&out[..4], b"more");
    control(client, wire::SHUTDOWN, &wire::WRITE_SHUTDOWN.to_le_bytes());
    wait(reader, mnu_abi::HANDLE_SIGNAL_PEER_CLOSED);
    assert_eq!(p::handle::read(reader, &mut out).unwrap(), 0);
    p::handle::close(reader).unwrap();
    p::handle::close(client).unwrap();
    p::handle::close(factory).unwrap();
    p::handle::close(connect_factory).unwrap();
    p::io::stdout(b"tcp-provider: PASS separate scopes, attenuation, CapDrop, foreign object rejection, native origin, duplicate lifetime, rights, loopback data, readiness and half-close\n").unwrap();
}
pub fn run(network: u32) {
    unsafe extern "C" {
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn seteuid(uid: u32) -> i32;
        fn geteuid() -> u32;
        fn _exit(status: i32) -> !;
    }
    for uid in [0, 501] {
        p::io::stdout(if uid == 0 {
            b"tcp-provider: starting euid 0\n"
        } else {
            b"tcp-provider: starting euid 501\n"
        })
        .unwrap();
        let pid = unsafe { fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if uid != 0 {
                assert_eq!(unsafe { seteuid(uid) }, 0);
            }
            assert_eq!(unsafe { geteuid() }, uid);
            case(network, 58000 + uid as u16);
            unsafe { _exit(0) }
        }
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        p::io::stdout(if uid == 0 {
            b"tcp-provider: PASS euid 0 child status 0\n"
        } else {
            b"tcp-provider: PASS euid 501 child status 0\n"
        })
        .unwrap();
    }
}
