//! Production POSIX adapter -> production network Provider -> packet transport.
//! Fixture code models only native Handle references, rights and IPC delivery.
extern crate alloc;
extern crate self as mochi_user_platform;
use mnu_abi::{IpcObjectHandles, provider};
pub use mochi_user_syscall as syscall;
use mochios_net_device_protocol::stream as wire;
use posix_service::{OpenedObject, filesystem_transport, inet_datagram, inet_stream};
use std::{cell::RefCell, collections::BTreeMap};
#[path = "../src/inet_stream_native.rs"]
mod adapter;
#[path = "../../network/src/stream_provider.rs"]
mod server;
#[path = "support/tcp_provider_fixture.rs"]
mod provider_fixture;
#[path = "../../network/src/stream.rs"]
mod stream;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Endpoint(u32),
    Provider(u32, u64),
}
#[derive(Clone, Copy)]
struct Reference {
    target: Target,
    rights: u64,
}
struct State {
    server: Option<provider_fixture::Fixture>,
    handles: BTreeMap<u32, Reference>,
    next: u32,
    releases: Vec<u64>,
    response: Option<(Vec<u8>, IpcObjectHandles)>,
    allowed: u32,
    duplicate_failed: bool,
    corrupt: u8,
    foreign_calls: usize,
}
impl Default for State {
    fn default() -> Self {
        Self {
            server: Some(provider_fixture::Fixture::new(Some(5))),
            handles: BTreeMap::from([(
                5,
                Reference {
                    target: Target::Endpoint(5),
                    rights: mochios_posix_protocol::network::endpoint_rights(),
                },
            )]),
            next: 100,
            releases: Vec::new(),
            response: None,
            allowed: wire::ALL_SCOPES,
            duplicate_failed: false,
            corrupt: 0,
            foreign_calls: 0,
        }
    }
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
fn err(n: i64) -> syscall::SysError {
    syscall::SysError::from_raw(n)
}
fn allocate(s: &mut State, target: Target, rights: u64) -> u32 {
    let h = s.next;
    s.next += 1;
    assert!(s.handles.insert(h, Reference { target, rights }).is_none());
    h
}
fn reference(h: u32, rights: u64) -> syscall::SysResult<Reference> {
    STATE.with_borrow(|s| {
        let r = *s.handles.get(&h).ok_or(err(-9))?;
        if rights & r.rights != rights {
            return Err(err(-13));
        }
        Ok(r)
    })
}
fn transfer(h: u32, rights: u64) -> syscall::SysResult<u32> {
    let r = reference(h, rights | mnu_abi::HANDLE_RIGHT_TRANSFER)?;
    Ok(STATE.with_borrow_mut(|s| allocate(s, r.target, rights)))
}
pub mod capability {
    pub fn check_thread(sender: u64, name: &str) -> crate::syscall::SysResult<u64> {
        Ok(crate::STATE.with_borrow(|s| {
            u64::from(
                sender == 77
                    && s.allowed
                        & match name {
                            "net.connect" => 1,
                            "net.listen" => 2,
                            _ => 0,
                        }
                        != 0,
            )
        }))
    }
}
pub mod service_ready {
    pub fn generate_token() -> crate::syscall::SysResult<u64> {
        Ok(0x1234_5678_90ab_cdef)
    }
}
fn dispatch(bytes: &[u8], handles: &IpcObjectHandles) {
    let mut server = STATE.with_borrow_mut(|s| {
        s.response = None;
        s.server.take().unwrap()
    });
    server.pump(0);
    assert!(server.dispatch(77, bytes, handles, 0));
    STATE.with_borrow_mut(|s| {
        assert!(s.server.replace(server).is_none());
    });
}
fn drain() {
    loop {
        let release = STATE.with_borrow_mut(|s| {
            if s.server.is_some() {
                s.releases.pop()
            } else {
                None
            }
        });
        let Some(id) = release else { break };
        let mut bytes = [0; provider::REQUEST_HEADER_LEN];
        provider::RequestHeader {
            opcode: provider::OP_RELEASE,
            object_id: id,
            argument: 0,
            basis: 0,
            length: 0,
            data_length: 0,
        }
        .encode(&[], &mut bytes)
        .unwrap();
        // Release has no reply, preserve an in-flight call's captured response.
        let response = STATE.with_borrow_mut(|s| s.response.take());
        dispatch(
            &bytes,
            &IpcObjectHandles {
                delivery_flags: mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
                ..Default::default()
            },
        );
        STATE.with_borrow_mut(|s| {
            assert!(s.response.is_none());
            s.response = response;
        });
    }
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
    pub fn reply(_: u64, bytes: &[u8]) -> crate::syscall::SysResult<()> {
        crate::STATE.with_borrow_mut(|s| {
            assert!(s.response.is_none());
            s.response = Some((bytes.into(), Default::default()));
        });
        Ok(())
    }
    pub fn reply_object_handles(
        _: u64,
        bytes: &[u8],
        handles: &IpcObjectHandles,
    ) -> crate::syscall::SysResult<()> {
        let mut received = IpcObjectHandles::default();
        for h in handles.handles.iter().take(handles.count as usize) {
            let receiver = crate::transfer(h.handle, h.rights)?;
            received.handles[received.count as usize] = IpcObjectHandle {
                handle: receiver,
                reserved: 0,
                rights: h.rights,
            };
            received.count += 1;
        }
        crate::STATE.with_borrow_mut(|s| {
            assert!(s.response.is_none());
            s.response = Some((bytes.into(), received));
        });
        Ok(())
    }
    pub fn call_object_handles(
        endpoint: u32,
        request: &[u8],
        response: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> crate::syscall::SysResult<u64> {
        let ep = crate::reference(endpoint, mnu_abi::HANDLE_RIGHT_SEND)?;
        if ep.target != crate::Target::Endpoint(5) {
            crate::STATE.with_borrow_mut(|s| s.foreign_calls += 1);
            return Err(crate::err(-13));
        }
        let mut delivered = IpcObjectHandles {
            delivery_flags: mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
            ..Default::default()
        };
        for h in handles.handles.iter().take(handles.count as usize) {
            if h.reserved != 0 {
                return Err(crate::err(-22));
            }
            let received = crate::transfer(h.handle, h.rights)?;
            delivered.handles[delivered.count as usize] = IpcObjectHandle {
                handle: received,
                reserved: 0,
                rights: h.rights,
            };
            delivered.count += 1;
        }
        crate::dispatch(request, &delivered);
        for h in delivered.handles.iter().take(delivered.count as usize) {
            crate::handle::close(h.handle)?;
        }
        crate::drain();
        let (bytes, mut received) = crate::STATE.with_borrow_mut(|s| s.response.take().unwrap());
        crate::STATE.with_borrow_mut(|s| match s.corrupt {
            0 => (),
            1 => received.handles[0].rights |= mnu_abi::HANDLE_RIGHT_MAP,
            2 => {
                received.handles[1] = received.handles[0];
                received.count = 2;
            }
            3 => received.handles[0].reserved = 1,
            4 => received.delivery_flags = 1,
            _ => panic!(),
        });
        assert!(bytes.len() <= response.len());
        response[..bytes.len()].copy_from_slice(&bytes);
        *handles = received;
        Ok(bytes.len() as u64)
    }
}
fn native(
    h: u32,
    op: u16,
    basis: u64,
    payload: &[u8],
    capacity: usize,
    rights: u64,
) -> syscall::SysResult<(u64, Vec<u8>)> {
    let r = reference(h, rights)?;
    let Target::Provider(5, id) = r.target else {
        STATE.with_borrow_mut(|s| s.foreign_calls += 1);
        return Err(err(-13));
    };
    let mut request = vec![0; provider::REQUEST_HEADER_LEN + payload.len()];
    provider::RequestHeader {
        opcode: op,
        object_id: id,
        argument: 0,
        basis,
        length: if op == provider::OP_WRITE {
            payload.len()
        } else {
            capacity
        } as u32,
        data_length: payload.len() as u32,
    }
    .encode(payload, &mut request)
    .unwrap();
    dispatch(
        &request,
        &IpcObjectHandles {
            delivery_flags: mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            ..Default::default()
        },
    );
    drain();
    let (bytes, handles) = STATE.with_borrow_mut(|s| s.response.take().unwrap());
    assert_eq!(handles.count, 0);
    let (reply, data) = provider::ResponseHeader::decode(&bytes).unwrap();
    if reply.status != 0 {
        return Err(err(reply.status));
    }
    Ok((reply.value, data.into()))
}
pub mod handle {
    pub fn create_provider_object(
        endpoint: u32,
        id: u64,
        rights: u64,
    ) -> crate::syscall::SysResult<u32> {
        assert_eq!(endpoint, 5);
        Ok(crate::STATE
            .with_borrow_mut(|s| crate::allocate(s, crate::Target::Provider(endpoint, id), rights)))
    }
    pub fn identify_provider_object(h: u32) -> crate::syscall::SysResult<u64> {
        let r = crate::reference(h, mnu_abi::HANDLE_RIGHT_CONTROL)?;
        match r.target {
            crate::Target::Provider(5, id) => Ok(id),
            _ => Err(crate::err(-13)),
        }
    }
    pub fn duplicate(h: u32, rights: u64) -> crate::syscall::SysResult<u32> {
        if crate::STATE.with_borrow(|s| s.duplicate_failed) {
            return Err(crate::err(-12));
        }
        let r = crate::reference(h, rights | mnu_abi::HANDLE_RIGHT_DUPLICATE)?;
        Ok(crate::STATE.with_borrow_mut(|s| crate::allocate(s, r.target, rights)))
    }
    pub fn close(h: u32) -> crate::syscall::SysResult<()> {
        crate::STATE.with_borrow_mut(|s| {
            let r = s.handles.remove(&h).ok_or(crate::err(-9))?;
            if !s.handles.values().any(|v| v.target == r.target) {
                if let crate::Target::Provider(5, id) = r.target {
                    s.releases.push(id);
                }
            }
            Ok::<(), crate::syscall::SysError>(())
        })?;
        crate::drain();
        Ok(())
    }
    pub fn signal_provider_object(_: u64, _: u64, _: u64) -> crate::syscall::SysResult<()> {
        Ok(())
    }
    pub fn query(
        h: u32,
        tag: u64,
        input: &[u8],
        out: &mut [u8],
    ) -> crate::syscall::SysResult<usize> {
        operate(h, tag, input, out, mnu_abi::HANDLE_RIGHT_READ)
    }
    pub fn control(
        h: u32,
        tag: u64,
        input: &[u8],
        out: &mut [u8],
    ) -> crate::syscall::SysResult<usize> {
        operate(h, tag, input, out, mnu_abi::HANDLE_RIGHT_CONTROL)
    }
    fn operate(
        h: u32,
        tag: u64,
        input: &[u8],
        out: &mut [u8],
        rights: u64,
    ) -> crate::syscall::SysResult<usize> {
        let (_, bytes) = crate::native(
            h,
            if rights == mnu_abi::HANDLE_RIGHT_READ {
                mnu_abi::provider::OP_QUERY
            } else {
                mnu_abi::provider::OP_CONTROL
            },
            tag,
            input,
            out.len(),
            rights,
        )?;
        assert!(bytes.len() <= out.len());
        out[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    pub fn write(h: u32, input: &[u8]) -> crate::syscall::SysResult<usize> {
        crate::native(
            h,
            mnu_abi::provider::OP_WRITE,
            0,
            input,
            0,
            mnu_abi::HANDLE_RIGHT_WRITE,
        )
        .map(|v| v.0 as usize)
    }
    fn receive(h: u32, out: &mut [u8], peek: bool) -> crate::syscall::SysResult<usize> {
        let (n, bytes) = crate::native(
            h,
            if peek {
                mnu_abi::provider::OP_READ_AT
            } else {
                mnu_abi::provider::OP_READ
            },
            0,
            &[],
            out.len(),
            mnu_abi::HANDLE_RIGHT_READ,
        )?;
        assert_eq!(n as usize, bytes.len());
        out[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    pub fn read(h: u32, out: &mut [u8]) -> crate::syscall::SysResult<usize> {
        receive(h, out, false)
    }
    pub fn read_at(h: u32, out: &mut [u8], offset: u64) -> crate::syscall::SysResult<usize> {
        assert_eq!(offset, 0);
        receive(h, out, true)
    }
}
fn setup() {
    STATE.with_borrow_mut(|s| *s = State::default());
}
fn backend() -> adapter::NetworkBackend {
    let mut out = [0; wire::REPLY_LEN];
    let mut handles = IpcObjectHandles::default();
    ipc::call_object_handles(
        5,
        &wire::scoped(wire::ACQUIRE, wire::ALL_SCOPES).unwrap(),
        &mut out,
        &mut handles,
    )
    .unwrap();
    assert_eq!(wire::status(wire::ACQUIRE, &out), Ok(0));
    assert_eq!(handles.count, 1);
    let h = handles.handles[0];
    adapter::NetworkBackend::new(
        5,
        OpenedObject {
            handle: h.handle,
            rights: h.rights,
        },
    )
    .unwrap()
}
fn create() -> mochios_posix_protocol::socket::Create {
    mochios_posix_protocol::socket::Create {
        domain: mochios_posix_protocol::socket::Domain::Ipv4,
        kind: mochios_posix_protocol::socket::Kind::Stream,
        protocol: 6,
        options: 0,
    }
}
fn fresh() -> inet_stream::Stream<adapter::NetworkBackend> {
    let b = backend();
    b.validate().unwrap();
    inet_stream::Stream::new(b, create()).unwrap()
}
fn address() -> mochios_posix_protocol::socket::Address<'static> {
    mochios_posix_protocol::socket::Address::Ipv4 {
        address: [127, 0, 0, 1],
        port: 8000,
    }
}
fn connected() -> (
    inet_stream::Stream<adapter::NetworkBackend>,
    inet_stream::Stream<adapter::NetworkBackend>,
) {
    let mut listener = fresh();
    listener.bind(address()).unwrap();
    listener.listen(1).unwrap();
    let mut client = fresh();
    client.connect(address()).unwrap();
    for _ in 0..16 {
        let _ = client.connect_result(client.attempt());
    }
    assert_eq!(
        client.connect_result(client.attempt()),
        Ok(inet_stream::ConnectProgress::Connected)
    );
    (listener, client)
}
#[test]
fn production_adapter_pins_endpoint_and_accepted_reference_outlives_listener() {
    setup();
    let (mut listener, mut client) = connected();
    handle::close(5).unwrap();
    STATE.with_borrow_mut(|s| {
        s.handles.insert(
            5,
            Reference {
                target: Target::Endpoint(9),
                rights: mochios_posix_protocol::network::endpoint_rights(),
            },
        );
    });
    let mut accepted = listener
        .accept(mochios_posix_protocol::socket::Accept { options: 0 })
        .unwrap();
    drop(listener);
    client.send(b"hello").unwrap();
    let mut bytes = [0; 5];
    assert_eq!(accepted.receive(true, &mut bytes), Ok(5));
    assert_eq!(&bytes, b"hello");
    assert_eq!(accepted.receive(false, &mut bytes), Ok(5));
    assert_eq!(accepted.receive(false, &mut bytes), Err(-11));
    accepted.send(b"reply").unwrap();
    assert_eq!(client.receive(false, &mut bytes), Ok(5));
    assert_eq!(&bytes, b"reply");
    client
        .shutdown(mochios_posix_protocol::socket::SHUTDOWN_WRITE)
        .unwrap();
    assert_eq!(accepted.receive(false, &mut bytes), Ok(0));
    drop(client);
    drop(accepted);
    STATE.with_borrow(|s| {
        assert_eq!(s.foreign_calls, 0);
        assert_eq!(s.handles.len(), 1);
        assert!(s.handles.contains_key(&5));
    });
}
#[test]
fn malformed_reply_closes_distinct_received_references_and_owned_factory() {
    for corrupt in 1..=4 {
        setup();
        let b = backend();
        b.validate().unwrap();
        STATE.with_borrow_mut(|s| s.corrupt = corrupt);
        assert!(inet_stream::Stream::new(b, create()).is_err());
        STATE.with_borrow(|s| assert_eq!(s.handles.len(), 1));
    }
}
#[test]
fn factory_validation_never_invokes_an_arbitrary_attached_provider() {
    setup();
    let rights = mnu_abi::HANDLE_RIGHT_CONTROL
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER;
    let fake = STATE.with_borrow_mut(|s| allocate(s, Target::Provider(9, 1), rights));
    let b = adapter::NetworkBackend::new(
        5,
        OpenedObject {
            handle: fake,
            rights,
        },
    )
    .unwrap();
    assert_eq!(b.validate(), Err(-13));
    drop(b);
    STATE.with_borrow(|s| {
        assert_eq!(s.foreign_calls, 0);
        assert_eq!(s.handles.len(), 1);
    });
}
#[test]
fn duplicate_failure_precedes_accept_and_constructor_failure_closes_factory() {
    setup();
    let (mut listener, mut client) = connected();
    STATE.with_borrow_mut(|s| s.duplicate_failed = true);
    assert!(
        listener
            .accept(mochios_posix_protocol::socket::Accept { options: 0 })
            .is_err()
    );
    STATE.with_borrow_mut(|s| s.duplicate_failed = false);
    let mut accepted = listener
        .accept(mochios_posix_protocol::socket::Accept { options: 0 })
        .unwrap();
    client.send(b"x").unwrap();
    assert_eq!(accepted.receive(false, &mut [0; 1]), Ok(1));
    drop(listener);
    drop(client);
    drop(accepted);
    STATE.with_borrow(|s| assert_eq!(s.handles.len(), 1));
    let b = backend();
    drop(b);
    STATE.with_borrow_mut(|s| s.duplicate_failed = true);
    let mut out = [0; wire::REPLY_LEN];
    let mut handles = IpcObjectHandles::default();
    ipc::call_object_handles(
        5,
        &wire::scoped(wire::ACQUIRE, wire::ALL_SCOPES).unwrap(),
        &mut out,
        &mut handles,
    )
    .unwrap();
    let h = handles.handles[0];
    assert!(
        adapter::NetworkBackend::new(
            5,
            OpenedObject {
                handle: h.handle,
                rights: h.rights
            }
        )
        .is_err()
    );
    STATE.with_borrow(|s| assert_eq!(s.handles.len(), 1));
}
