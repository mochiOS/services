//! Production TCP authority, Provider and transport; only native mechanisms
//! (IPC authentication/Handle ownership, entropy, signals) are fixture boundaries.
extern crate alloc;
extern crate self as mochi_user_platform;
use mnu_abi::provider;
use mochios_net_device_protocol::stream as wire;
use std::cell::RefCell;
#[path = "../../network/src/stream_provider.rs"]
mod server;
#[path = "../../network/src/stream.rs"]
mod stream;
#[derive(Default)]
struct State {
    allowed: u32,
    create_failed: bool,
    signal_failed: bool,
    reply_failed: bool,
    created: Vec<(u64, u32, u64)>,
    closed: Vec<u32>,
    checks: Vec<(u64, String)>,
    response: Vec<u8>,
    attached: Vec<mnu_abi::IpcObjectHandle>,
    signals: Vec<(u64, u64, u64)>,
}
thread_local! { static STATE:RefCell<State>=RefCell::new(State::default()); }
pub mod capability {
    pub fn check_thread(sender: u64, name: &str) -> mochi_user_syscall::SysResult<u64> {
        crate::STATE.with_borrow_mut(|s| {
            s.checks.push((sender, name.into()));
            let bit = match name {
                "net.connect" => 1,
                "net.listen" => 2,
                _ => panic!(),
            };
            Ok(u64::from(sender == 77 && s.allowed & bit != 0))
        })
    }
}
pub mod service_ready {
    pub fn generate_token() -> mochi_user_syscall::SysResult<u64> {
        Ok(0x1234_5678_90ab_cdef)
    }
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
    pub fn reply(_: u64, bytes: &[u8]) -> mochi_user_syscall::SysResult<()> {
        crate::STATE.with_borrow_mut(|s| {
            s.response = bytes.into();
            s.attached.clear();
        });
        Ok(())
    }
    pub fn reply_object_handles(
        sender: u64,
        bytes: &[u8],
        handles: &IpcObjectHandles,
    ) -> mochi_user_syscall::SysResult<()> {
        reply(sender, bytes)?;
        crate::STATE.with_borrow_mut(|s| {
            if s.reply_failed {
                return Err(mochi_user_syscall::SysError::from_raw(-5));
            }
            s.attached = handles.handles[..handles.count as usize].into();
            Ok(())
        })
    }
}
pub mod handle {
    pub fn identify_provider_object(handle: u32) -> mochi_user_syscall::SysResult<u64> {
        crate::STATE.with_borrow(|s| {
            s.created
                .iter()
                .find(|r| r.1 == handle)
                .map(|r| r.0)
                .ok_or(mochi_user_syscall::SysError::from_raw(-13))
        })
    }
    pub fn create_provider_object(
        endpoint: u32,
        id: u64,
        rights: u64,
    ) -> mochi_user_syscall::SysResult<u32> {
        assert_eq!(endpoint, 5);
        crate::STATE.with_borrow_mut(|s| {
            if s.create_failed {
                return Err(mochi_user_syscall::SysError::from_raw(-12));
            }
            let h = s.created.len() as u32 + 100;
            s.created.push((id, h, rights));
            Ok(h)
        })
    }
    pub fn close(h: u32) -> mochi_user_syscall::SysResult<()> {
        crate::STATE.with_borrow_mut(|s| s.closed.push(h));
        Ok(())
    }
    pub fn signal_provider_object(
        id: u64,
        set: u64,
        clear: u64,
    ) -> mochi_user_syscall::SysResult<()> {
        crate::STATE.with_borrow_mut(|s| {
            s.signals.push((id, set, clear));
            if s.signal_failed {
                Err(mochi_user_syscall::SysError::from_raw(-5))
            } else {
                Ok(())
            }
        })
    }
}
fn setup() -> server::Server {
    STATE.with_borrow_mut(|s| {
        *s = State {
            allowed: wire::ALL_SCOPES,
            ..Default::default()
        }
    });
    server::Server::new(Some(5))
}
fn attached(h: u32) -> ipc::IpcObjectHandles {
    let mut a = ipc::IpcObjectHandles::default();
    a.count = 1;
    a.handles[0] = ipc::IpcObjectHandle {
        handle: h,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_CONTROL,
    };
    a
}
fn rpc(
    s: &mut server::Server,
    op: u16,
    request: &[u8],
    handles: &ipc::IpcObjectHandles,
) -> (i32, Option<u32>) {
    assert!(s.dispatch(77, request, handles, 0));
    STATE.with_borrow(|s| {
        (
            wire::status(op, &s.response).unwrap(),
            s.attached.first().map(|h| h.handle),
        )
    })
}
fn factory(s: &mut server::Server, scopes: u32) -> u32 {
    let (status, h) = rpc(
        s,
        wire::ACQUIRE,
        &wire::scoped(wire::ACQUIRE, scopes).unwrap(),
        &Default::default(),
    );
    assert_eq!(status, 0);
    h.unwrap()
}
fn open(s: &mut server::Server, factory: u32) -> u32 {
    let (status, h) = rpc(s, wire::OPEN, &wire::header(wire::OPEN), &attached(factory));
    assert_eq!(status, 0);
    h.unwrap()
}
fn native(
    s: &mut server::Server,
    h: u32,
    op: u16,
    basis: u64,
    input: &[u8],
    length: usize,
    trusted: bool,
) -> (i64, u64, Vec<u8>) {
    let id = STATE.with_borrow(|s| s.created.iter().find(|r| r.1 == h).unwrap().0);
    let mut bytes = vec![0; provider::REQUEST_HEADER_LEN + input.len()];
    provider::RequestHeader {
        opcode: op,
        object_id: id,
        argument: 0,
        basis,
        length: if op == provider::OP_WRITE {
            input.len() as u32
        } else {
            length as u32
        },
        data_length: input.len() as u32,
    }
    .encode(input, &mut bytes)
    .unwrap();
    let handles = ipc::IpcObjectHandles {
        delivery_flags: if trusted {
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
        } else {
            0
        },
        ..Default::default()
    };
    assert!(s.dispatch(77, &bytes, &handles, 0));
    if trusted && op == provider::OP_RELEASE {
        return (0, 0, vec![]);
    }
    STATE.with_borrow(|s| {
        let (h, data) = provider::ResponseHeader::decode(&s.response).unwrap();
        (h.status, h.value, data.to_vec())
    })
}
fn control(s: &mut server::Server, h: u32, tag: u64, input: &[u8]) -> i64 {
    native(s, h, provider::OP_CONTROL, tag, input, 0, true).0
}
fn endpoint(port: u16) -> [u8; 8] {
    let mut bytes = [0; 8];
    wire::Endpoint {
        address: [127, 0, 0, 1],
        port,
    }
    .encode(&mut bytes)
    .unwrap();
    bytes
}
fn pair(s: &mut server::Server) -> (u32, u32, u32) {
    let f = factory(s, wire::ALL_SCOPES);
    let listener = open(s, f);
    let client = open(s, f);
    assert_eq!(control(s, listener, wire::BIND, &endpoint(8000)), 0);
    assert_eq!(control(s, listener, wire::LISTEN, &4u32.to_le_bytes()), 0);
    assert_eq!(control(s, client, wire::CONNECT, &endpoint(8000)), 0);
    for _ in 0..4 {
        s.pump(0);
    }
    let (status, accepted) = rpc(
        s,
        wire::ACCEPT,
        &wire::header(wire::ACCEPT),
        &attached(listener),
    );
    assert_eq!(status, 0);
    (listener, client, accepted.unwrap())
}

#[test]
fn connect_and_listen_authority_are_separate_and_check_authenticated_sender() {
    let mut s = setup();
    STATE.with_borrow_mut(|s| s.allowed = wire::CONNECT_SCOPE);
    assert_eq!(
        rpc(
            &mut s,
            wire::ACQUIRE,
            &wire::scoped(wire::ACQUIRE, wire::LISTEN_SCOPE).unwrap(),
            &Default::default()
        )
        .0,
        -13
    );
    let f = factory(&mut s, wire::CONNECT_SCOPE);
    let socket = open(&mut s, f);
    assert_eq!(
        control(&mut s, socket, wire::LISTEN, &4u32.to_le_bytes()),
        -13
    );
    assert_eq!(control(&mut s, socket, wire::BIND, &endpoint(80)), -13);
    assert_eq!(
        STATE.with_borrow(|s| s.checks.clone()),
        vec![(77, "net.listen".into()), (77, "net.connect".into())]
    );
    assert!(s.dispatch(
        78,
        &wire::scoped(wire::ACQUIRE, wire::CONNECT_SCOPE).unwrap(),
        &Default::default(),
        0
    ));
    assert_eq!(
        STATE.with_borrow(|s| wire::status(wire::ACQUIRE, &s.response).unwrap()),
        -13
    );
}

#[test]
fn held_factory_can_be_attenuated_after_capability_drop_but_never_escalated() {
    let mut s = setup();
    let parent = factory(&mut s, wire::ALL_SCOPES);
    STATE.with_borrow_mut(|s| s.allowed = 0);
    let (status, child) = rpc(
        &mut s,
        wire::DERIVE,
        &wire::scoped(wire::DERIVE, wire::CONNECT_SCOPE).unwrap(),
        &attached(parent),
    );
    assert_eq!(status, 0);
    let child = child.unwrap();
    assert_eq!(
        rpc(
            &mut s,
            wire::DERIVE,
            &wire::scoped(wire::DERIVE, wire::ALL_SCOPES).unwrap(),
            &attached(child)
        )
        .0,
        -13
    );
    native(&mut s, parent, provider::OP_RELEASE, 0, &[], 0, true);
    let socket = open(&mut s, child);
    assert_eq!(
        control(&mut s, socket, wire::LISTEN, &4u32.to_le_bytes()),
        -13
    );
    let (status, _, data) = native(
        &mut s,
        child,
        provider::OP_CONTROL,
        wire::QUERY_LIMITS,
        &[],
        wire::LIMITS_LEN,
        true,
    );
    assert_eq!(status, 0);
    assert_eq!(
        wire::Limits::decode(&data).unwrap(),
        wire::Limits {
            scopes: wire::CONNECT_SCOPE,
            minimum_port: 1024
        }
    );
}

#[test]
fn unknown_opcode_version_and_noncanonical_scope_return_explicit_errors() {
    let mut s = setup();
    assert_eq!(
        rpc(&mut s, 77, &wire::header(77), &Default::default()).0,
        -38
    );
    let mut bytes = wire::scoped(wire::ACQUIRE, wire::ALL_SCOPES).unwrap();
    bytes[4] = 2;
    assert_eq!(
        rpc(&mut s, wire::ACQUIRE, &bytes, &Default::default()).0,
        -22
    );
    bytes[4] = 1;
    bytes[8] = 0x80;
    assert_eq!(
        rpc(&mut s, wire::ACQUIRE, &bytes, &Default::default()).0,
        -22
    );
    assert!(STATE.with_borrow(|s| s.created.is_empty()));
}

#[test]
fn forged_release_attachment_identity_and_bad_rights_never_authorize_resources() {
    let mut s = setup();
    let f = factory(&mut s, wire::ALL_SCOPES);
    assert_eq!(
        native(&mut s, f, provider::OP_RELEASE, 0, &[], 0, false).0,
        -13
    );
    for mut handles in [attached(f), attached(9999)] {
        if handles.handles[0].handle == f {
            handles.handles[0].rights |= mnu_abi::HANDLE_RIGHT_READ;
        }
        assert_eq!(
            rpc(&mut s, wire::OPEN, &wire::header(wire::OPEN), &handles).0,
            -13
        );
    }
    assert_eq!(
        rpc(
            &mut s,
            wire::VALIDATE,
            &wire::header(wire::VALIDATE),
            &attached(f)
        )
        .0,
        0
    );
    let resource = open(&mut s, f);
    assert_eq!(
        rpc(
            &mut s,
            wire::OPEN,
            &wire::header(wire::OPEN),
            &attached(resource)
        )
        .0,
        -13
    );
    assert_eq!(
        rpc(
            &mut s,
            wire::ACCEPT,
            &wire::header(wire::ACCEPT),
            &attached(f)
        )
        .0,
        -13
    );
}

#[test]
fn actual_provider_transfers_data_peeks_readiness_and_half_close() {
    let mut s = setup();
    let (listener, client, accepted) = pair(&mut s);
    native(&mut s, listener, provider::OP_RELEASE, 0, &[], 0, true);
    assert_eq!(
        native(&mut s, client, provider::OP_WRITE, 0, b"hello", 0, true),
        (0, 5, vec![])
    );
    let (status, _, data) = native(
        &mut s,
        accepted,
        provider::OP_QUERY,
        wire::STATUS,
        &[],
        wire::STATUS_LEN,
        true,
    );
    assert_eq!(status, 0);
    assert_ne!(
        u32::from_le_bytes(data[..4].try_into().unwrap()) & wire::READABLE,
        0
    );
    assert_eq!(
        native(&mut s, accepted, provider::OP_READ_AT, 0, &[], 2, true),
        (0, 2, b"he".to_vec())
    );
    assert_eq!(
        native(&mut s, accepted, provider::OP_READ, 0, &[], 8, true),
        (0, 5, b"hello".to_vec())
    );
    assert_eq!(
        native(&mut s, accepted, provider::OP_READ, 0, &[], 8, true).0,
        -11
    );
    assert_eq!(
        control(
            &mut s,
            client,
            wire::SHUTDOWN,
            &wire::WRITE_SHUTDOWN.to_le_bytes()
        ),
        0
    );
    assert_eq!(
        native(&mut s, accepted, provider::OP_READ, 0, &[], 8, true),
        (0, 0, vec![])
    );
    assert_eq!(
        native(&mut s, accepted, provider::OP_WRITE, 0, b"reply", 0, true).1,
        5
    );
    assert_eq!(
        native(&mut s, client, provider::OP_READ, 0, &[], 8, true).2,
        b"reply"
    );
}

#[test]
fn read_queries_cannot_consume_status_or_perform_mutation() {
    let mut s = setup();
    let f = factory(&mut s, wire::CONNECT_SCOPE);
    let c = open(&mut s, f);
    assert_eq!(control(&mut s, c, wire::CONNECT, &endpoint(9000)), 0);
    let (_, _, before) = native(&mut s, c, provider::OP_QUERY, wire::STATUS, &[], 8, true);
    assert_eq!(i32::from_le_bytes(before[4..].try_into().unwrap()), -111);
    assert_eq!(
        native(
            &mut s,
            c,
            provider::OP_QUERY,
            wire::TAKE_ERROR,
            &[],
            4,
            true
        )
        .0,
        -95
    );
    let (_, _, after) = native(&mut s, c, provider::OP_QUERY, wire::STATUS, &[], 8, true);
    assert_eq!(before, after);
    let (_, _, taken) = native(
        &mut s,
        c,
        provider::OP_CONTROL,
        wire::TAKE_ERROR,
        &[],
        4,
        true,
    );
    assert_eq!(i32::from_le_bytes(taken.try_into().unwrap()), -111);
    assert_eq!(
        native(
            &mut s,
            c,
            provider::OP_CONTROL,
            wire::TAKE_ERROR,
            &[],
            4,
            true
        )
        .2,
        [0; 4]
    );
}

#[test]
fn native_creation_and_reply_failures_release_exact_resource_without_exhausting_capacity() {
    let mut s = setup();
    let f = factory(&mut s, wire::ALL_SCOPES);
    STATE.with_borrow_mut(|s| s.create_failed = true);
    assert_eq!(
        rpc(&mut s, wire::OPEN, &wire::header(wire::OPEN), &attached(f)).0,
        -5
    );
    STATE.with_borrow_mut(|s| {
        s.create_failed = false;
        s.reply_failed = true;
    });
    for _ in 0..80 {
        assert_eq!(
            rpc(&mut s, wire::OPEN, &wire::header(wire::OPEN), &attached(f)).0,
            0
        );
    }
    STATE.with_borrow_mut(|s| {
        s.reply_failed = false;
        s.signal_failed = true;
    });
    assert_eq!(
        rpc(&mut s, wire::OPEN, &wire::header(wire::OPEN), &attached(f)).0,
        -5
    );
    STATE.with_borrow_mut(|s| s.signal_failed = false);
    open(&mut s, f);
}

#[test]
fn native_accept_allocation_failure_keeps_ready_connection_queued() {
    let mut s = setup();
    let f = factory(&mut s, wire::ALL_SCOPES);
    let listener = open(&mut s, f);
    let client = open(&mut s, f);
    assert_eq!(control(&mut s, listener, wire::BIND, &endpoint(8000)), 0);
    assert_eq!(
        control(&mut s, listener, wire::LISTEN, &4u32.to_le_bytes()),
        0
    );
    assert_eq!(control(&mut s, client, wire::CONNECT, &endpoint(8000)), 0);
    STATE.with_borrow_mut(|s| s.create_failed = true);
    assert_eq!(
        rpc(
            &mut s,
            wire::ACCEPT,
            &wire::header(wire::ACCEPT),
            &attached(listener)
        )
        .0,
        -5
    );
    STATE.with_borrow_mut(|s| s.create_failed = false);
    assert_eq!(
        rpc(
            &mut s,
            wire::ACCEPT,
            &wire::header(wire::ACCEPT),
            &attached(listener)
        )
        .0,
        0
    );
}

#[test]
fn malformed_attachment_metadata_does_not_close_the_borrowed_reference() {
    let mut s = setup();
    let f = factory(&mut s, wire::ALL_SCOPES);
    let closed = STATE.with_borrow(|s| s.closed.len());
    for mode in 0..4 {
        let mut h = attached(f);
        match mode {
            0 => h.count = 0,
            1 => h.handles[0].reserved = 1,
            2 => h.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            _ => h.count = 2,
        };
        assert_eq!(
            rpc(&mut s, wire::OPEN, &wire::header(wire::OPEN), &h).0,
            -13
        );
    }
    assert_eq!(STATE.with_borrow(|s| s.closed.len()), closed);
    open(&mut s, f);
}

#[test]
fn wire_replies_limits_and_observations_require_canonical_records() {
    let mut reply = [0; wire::REPLY_LEN];
    wire::reply(wire::OPEN, 0, &mut reply).unwrap();
    assert!(wire::status(wire::ACQUIRE, &reply).is_err());
    reply[15] = 1;
    assert!(wire::status(wire::OPEN, &reply).is_err());
    assert!(wire::scoped(wire::ACQUIRE, 0).is_err());
    assert!(wire::scoped(wire::DERIVE, 4).is_err());
    let mut limits = [0; wire::LIMITS_LEN];
    wire::Limits {
        scopes: 3,
        minimum_port: 1024,
    }
    .encode(&mut limits)
    .unwrap();
    assert_eq!(wire::Limits::decode(&limits).unwrap().scopes, 3);
    limits[11] = 1;
    assert!(wire::Limits::decode(&limits).is_err());
    let mut status = [0; wire::STATUS_LEN];
    wire::Observation {
        flags: wire::CONNECTING,
        error: 0,
    }
    .encode(&mut status)
    .unwrap();
    assert_eq!(
        wire::Observation::decode(&status).unwrap().flags,
        wire::CONNECTING
    );
    status[0] = 0x80;
    assert!(wire::Observation::decode(&status).is_err());
    status[0] = 0;
    status[4] = 1;
    assert!(wire::Observation::decode(&status).is_err());
}
