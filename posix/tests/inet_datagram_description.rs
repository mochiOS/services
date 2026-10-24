//! Run POSIX description policy through its actual native packet adapter.
//! Only the native Handle/IPC mechanism is replaced with an in-memory fixture.
extern crate alloc;
extern crate self as mochi_user_platform;
use mochios_net_device_protocol::{datagram as packet, datagram_authority as authority};
use mochios_posix_protocol::socket::{self as wire, Address, Domain, Kind};
use posix_service::OpenedObject;
use std::{cell::RefCell, collections::BTreeMap};
#[path = "../../network/src/datagram.rs"]
mod datagram;
#[path = "../src/inet_datagram.rs"]
mod inet_datagram;
#[path = "../src/inet_datagram_native.rs"]
mod inet_datagram_native;
use datagram::Backend as PacketBackend;
use inet_datagram::{Backend, Datagram, Endpoint};
use inet_datagram_native::NetworkBackend;
pub mod syscall {
    pub use mochi_user_syscall::*;
}
struct State {
    backend: datagram::Loopback,
    bindings: BTreeMap<u32, mochios_network_stack::UdpSocketId>,
    next: u32,
    closed: Vec<u32>,
    open_mode: u8,
    local_bad: bool,
    source_bad: bool,
    peer_failure: bool,
    last_attached: u64,
}
impl State {
    fn new() -> Self {
        Self {
            backend: datagram::Loopback::new(),
            bindings: BTreeMap::new(),
            next: 100,
            closed: vec![],
            open_mode: 0,
            local_bad: false,
            source_bad: false,
            peer_failure: false,
            last_attached: 0,
        }
    }
    fn id(&self, handle: u32) -> Result<mochios_network_stack::UdpSocketId, i32> {
        self.bindings.get(&handle).copied().ok_or(-9)
    }
}
thread_local! { static STATE:RefCell<State>=RefCell::new(State::new()); }
fn error(status: i32) -> syscall::SysError {
    syscall::SysError::from_raw(i64::from(status))
}
fn packet_rights() -> u64 {
    mnu_abi::HANDLE_RIGHT_READ
        | mnu_abi::HANDLE_RIGHT_WRITE
        | mnu_abi::HANDLE_RIGHT_CONTROL
        | mnu_abi::HANDLE_RIGHT_WAIT
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
    pub fn call_object_handles(
        endpoint: u32,
        request: &[u8],
        reply: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> Result<u64, crate::syscall::SysError> {
        assert_eq!(endpoint, 9);
        assert_eq!((handles.count, handles.delivery_flags), (1, 0));
        assert_eq!(
            (handles.handles[0].handle, handles.handles[0].reserved),
            (7, 0)
        );
        assert_eq!(handles.handles[0].rights, mnu_abi::HANDLE_RIGHT_CONTROL);
        crate::STATE.with_borrow_mut(|s| {
            s.last_attached = handles.handles[0].rights;
            let local = crate::packet::decode_open(request).unwrap();
            if s.open_mode == 4 {
                return Err(crate::error(-5));
            }
            *handles = IpcObjectHandles::default();
            let result = if s.open_mode == 1 {
                Err(-98)
            } else if local.port != 0 && local.port < 1024 {
                Err(-13)
            } else {
                s.backend.bind(local)
            };
            match result {
                Ok(id) => {
                    let handle = s.next;
                    s.next += 1;
                    s.bindings.insert(handle, id);
                    handles.count = 1;
                    handles.handles[0] = IpcObjectHandle {
                        handle,
                        reserved: 0,
                        rights: crate::packet_rights(),
                    };
                    if s.open_mode == 2 {
                        handles.handles[0].rights |= mnu_abi::HANDLE_RIGHT_MAP;
                    }
                    if s.open_mode == 3 {
                        handles.count = 2;
                        handles.handles[1] = handles.handles[0];
                    }
                    crate::authority::reply_for(2, 0, reply).unwrap();
                }
                Err(status) => {
                    crate::authority::reply_for(2, status, reply).unwrap();
                }
            }
            Ok(if s.open_mode == 5 {
                reply.len() as u64 + 1
            } else {
                crate::authority::REPLY_LEN as u64
            })
        })
    }
    use crate::PacketBackend;
}
pub mod handle {
    use crate::{PacketBackend, STATE, error, packet, syscall};
    pub fn close(handle: u32) -> Result<(), syscall::SysError> {
        STATE.with_borrow_mut(|s| {
            s.closed.push(handle);
            if let Some(id) = s.bindings.remove(&handle) {
                s.backend.release(id);
            }
        });
        Ok(())
    }
    pub fn control(
        handle: u32,
        tag: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, syscall::SysError> {
        STATE.with_borrow_mut(|s| {
            let id = s.id(handle).map_err(error)?;
            match tag {
                packet::LOCAL => {
                    let mut local = s.backend.local(id).map_err(error)?;
                    if s.local_bad {
                        local.port = 0;
                    }
                    Ok(local.encode(output).unwrap())
                }
                packet::SOURCE => {
                    let destination = packet::Endpoint::decode(input).unwrap();
                    let mut source = s.backend.source(id, destination).map_err(error)?;
                    if s.source_bad {
                        source.port = 0;
                    }
                    Ok(source.encode(output).unwrap())
                }
                packet::SET_PEER => {
                    if s.peer_failure {
                        return Err(error(-5));
                    }
                    let peer = packet::Endpoint::decode(input).unwrap();
                    s.backend
                        .set_peer(id, if peer.unspecified() { None } else { Some(peer) })
                        .map_err(error)?;
                    Ok(0)
                }
                _ => panic!("unexpected control"),
            }
        })
    }
    pub fn write(handle: u32, input: &[u8]) -> Result<usize, syscall::SysError> {
        STATE.with_borrow_mut(|s| {
            let id = s.id(handle).map_err(error)?;
            let (destination, payload) = packet::decode_send(input).unwrap();
            s.backend.send(id, destination, payload, 0).map_err(error)?;
            Ok(input.len())
        })
    }
    pub fn read(handle: u32, output: &mut [u8]) -> Result<usize, syscall::SysError> {
        receive(handle, output, false)
    }
    pub fn read_at(
        handle: u32,
        output: &mut [u8],
        offset: u64,
    ) -> Result<usize, syscall::SysError> {
        assert_eq!(offset, 0);
        receive(handle, output, true)
    }
    fn receive(handle: u32, output: &mut [u8], peek: bool) -> Result<usize, syscall::SysError> {
        STATE.with_borrow_mut(|s| {
            let id = s.id(handle).map_err(error)?;
            s.backend.receive(id, peek, output).map_err(error)
        })
    }
}
fn reset() {
    STATE.with_borrow_mut(|s| *s = State::new());
}
fn backend() -> NetworkBackend {
    NetworkBackend::new(
        9,
        OpenedObject {
            handle: 7,
            rights: mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER,
        },
    )
    .unwrap()
}
fn create() -> wire::Create {
    wire::Create {
        domain: Domain::Ipv4,
        kind: Kind::Datagram,
        protocol: 17,
        options: 0,
    }
}
fn socket() -> Datagram<NetworkBackend> {
    Datagram::new(backend(), create()).unwrap()
}
fn ip(port: u16) -> Address<'static> {
    Address::Ipv4 {
        address: [127, 0, 0, 1],
        port,
    }
}

#[test]
fn creation_is_unbound_and_invalid_creation_releases_factory() {
    reset();
    let mut s = socket();
    assert_eq!(s.local_address(), Ok(Endpoint::UNSPECIFIED));
    assert_eq!(s.peer_address(), Err(-107));
    STATE.with_borrow(|s| assert!(s.bindings.is_empty()));
    s.set_options(wire::NONBLOCKING).unwrap();
    assert_eq!(s.set_options(2), Err(-22));
    assert_eq!(s.options(), wire::NONBLOCKING);
    s.set_receive_timeout(12);
    s.set_send_timeout(34);
    assert_eq!((s.receive_timeout(), s.send_timeout()), (12, 34));
    drop(s);
    for (change, status) in [(0, -97), (1, -94), (2, -93), (3, -22)] {
        let mut request = create();
        match change {
            0 => request.domain = Domain::Unix,
            1 => request.kind = Kind::Stream,
            2 => request.protocol = 6,
            _ => request.options = 2,
        }
        assert!(matches!(Datagram::new(backend(),request),Err(e) if e==status));
    }
    STATE.with_borrow(|s| assert_eq!(s.closed, [7; 5]));
}
#[test]
fn invalid_destinations_do_not_autobind_and_bind_is_single_publication() {
    reset();
    let mut s = socket();
    assert_eq!(s.send_to(None, b"x"), Err(-89));
    assert_eq!(s.send_to(Some(ip(0)), b"x"), Err(-22));
    assert_eq!(s.send_to(Some(Address::UnixUnnamed), b"x"), Err(-97));
    assert_eq!(s.send_to(Some(ip(8000)), &[0; 1473]), Err(-90));
    STATE.with_borrow(|s| assert!(s.bindings.is_empty()));
    assert_eq!(s.bind(ip(53)), Err(-13));
    s.bind(ip(8000)).unwrap();
    assert_eq!(s.bind(ip(8001)), Err(-22));
    assert_eq!(s.local_address().unwrap().port, 8000);
}
#[test]
fn malformed_or_failed_open_closes_only_received_references_once_and_allows_retry() {
    for mode in 1..=5 {
        reset();
        STATE.with_borrow_mut(|s| s.open_mode = mode);
        let mut s = socket();
        assert_eq!(s.bind(ip(8000)), Err(if mode == 1 { -98 } else { -5 }));
        STATE.with_borrow(|s| {
            assert!(s.bindings.is_empty());
            assert!(!s.closed.contains(&7));
            assert_eq!(s.closed.len(), usize::from(matches!(mode, 2 | 3 | 5)));
        });
        STATE.with_borrow_mut(|s| s.open_mode = 0);
        s.bind(ip(8000)).unwrap();
    }
    reset();
    let mut s = socket();
    STATE.with_borrow_mut(|s| s.local_bad = true);
    assert_eq!(s.bind(ip(8000)), Err(-5));
    STATE.with_borrow(|s| assert!(s.bindings.is_empty()));
    STATE.with_borrow_mut(|s| s.local_bad = false);
    s.bind(ip(8000)).unwrap();
}
#[test]
fn send_receive_preserve_records_peek_truncation_and_zero_length_datagrams() {
    reset();
    let mut sender = socket();
    let mut receiver = socket();
    receiver.bind(ip(8000)).unwrap();
    assert_eq!(sender.send_to(Some(ip(8000)), b"hello"), Ok(5));
    assert_ne!(sender.local_address().unwrap().port, 0);
    let mut output = [0; 2];
    for _ in 0..2 {
        let r = receiver.receive_from(true, &mut output).unwrap();
        assert_eq!((r.copied, r.original), (2, 5));
        assert_eq!(&output, b"he");
        assert_ne!(r.source.port, 0);
    }
    assert_eq!(
        receiver.receive_from(false, &mut output).unwrap().original,
        5
    );
    assert_eq!(receiver.receive_from(false, &mut output), Err(-11));
    assert_eq!(sender.send_to(Some(ip(8000)), b""), Ok(0));
    let r = receiver.receive_from(false, &mut []).unwrap();
    assert_eq!((r.copied, r.original), (0, 0));
    sender.send_to(Some(ip(8000)), b"discard").unwrap();
    let r = receiver.receive_from(false, &mut []).unwrap();
    assert_eq!((r.copied, r.original), (0, 7));
    assert_eq!(receiver.receive_from(false, &mut output), Err(-11));
}
#[test]
fn connected_wildcard_reports_routed_source_and_failed_peer_change_keeps_old_peer() {
    reset();
    let mut s = socket();
    s.connect(ip(8000)).unwrap();
    assert_eq!(s.local_address().unwrap().address, [127, 0, 0, 1]);
    assert_eq!(s.peer_address().unwrap().port, 8000);
    STATE.with_borrow_mut(|s| s.peer_failure = true);
    assert_eq!(s.connect(ip(8001)), Err(-5));
    assert_eq!(s.peer_address().unwrap().port, 8000);
    assert_eq!(s.disconnect(), Err(-5));
    assert_eq!(s.peer_address().unwrap().port, 8000);
    STATE.with_borrow_mut(|s| s.peer_failure = false);
    s.disconnect().unwrap();
    assert_eq!(s.peer_address(), Err(-107));
    let local = s.local_address().unwrap();
    assert_eq!(local.address, [0; 4]);
    assert_ne!(local.port, 0);
    assert_eq!(s.send_to(None, b"x"), Err(-89));
}
#[test]
fn peer_filter_and_disconnect_preserve_queued_records_and_local_port() {
    reset();
    let mut receiver = socket();
    receiver.bind(ip(8000)).unwrap();
    let mut allowed = socket();
    allowed.bind(ip(8001)).unwrap();
    let mut other = socket();
    other.bind(ip(8002)).unwrap();
    other.send_to(Some(ip(8000)), b"already-queued").unwrap();
    receiver.connect(ip(8001)).unwrap();
    other.send_to(Some(ip(8000)), b"filtered").unwrap();
    allowed.send_to(Some(ip(8000)), b"allowed").unwrap();
    let mut output = [0; 64];
    let r = receiver.receive_from(false, &mut output).unwrap();
    assert_eq!(&output[..r.copied], b"already-queued");
    let r = receiver.receive_from(false, &mut output).unwrap();
    assert_eq!(&output[..r.copied], b"allowed");
    assert_eq!(receiver.receive_from(false, &mut output), Err(-11));
    receiver.disconnect().unwrap();
    other.send_to(Some(ip(8000)), b"after").unwrap();
    let r = receiver.receive_from(false, &mut output).unwrap();
    assert_eq!(&output[..r.copied], b"after");
    assert_eq!(receiver.local_address().unwrap().port, 8000);
}
#[test]
fn connected_send_can_override_destination_and_unspecified_remote_is_local() {
    reset();
    let mut s = socket();
    let mut first = socket();
    let mut second = socket();
    first.bind(ip(8000)).unwrap();
    second.bind(ip(8001)).unwrap();
    s.connect(ip(8000)).unwrap();
    s.send_to(None, b"default").unwrap();
    s.send_to(
        Some(Address::Ipv4 {
            address: [0; 4],
            port: 8001,
        }),
        b"override",
    )
    .unwrap();
    let mut output = [0; 64];
    assert_eq!(first.receive_from(false, &mut output).unwrap().original, 7);
    assert_eq!(second.receive_from(false, &mut output).unwrap().original, 8);
    assert_eq!(s.peer_address().unwrap().port, 8000);
}
#[test]
fn final_description_drop_releases_binding_and_factory_without_port_leaks() {
    reset();
    for _ in 0..64 {
        let mut s = socket();
        s.bind(ip(8000)).unwrap();
    }
    STATE.with_borrow(|s| {
        assert!(s.bindings.is_empty());
        assert_eq!(s.closed.iter().filter(|h| **h == 7).count(), 64);
    });
}
#[test]
fn unavailable_external_route_does_not_commit_a_peer_or_report_a_false_source() {
    reset();
    let mut s = socket();
    assert_eq!(
        s.connect(Address::Ipv4 {
            address: [192, 0, 2, 1],
            port: 8000
        }),
        Err(-6)
    );
    assert_eq!(s.peer_address(), Err(-107));
    assert_eq!(s.local_address().unwrap().address, [0; 4]);
    assert_eq!(
        s.send_to(
            Some(Address::Ipv4 {
                address: [192, 0, 2, 1],
                port: 8000
            }),
            b"x"
        ),
        Err(-6)
    );
}
#[test]
fn backend_constructor_consumes_invalid_owned_factory() {
    reset();
    assert!(matches!(
        NetworkBackend::new(
            9,
            OpenedObject {
                handle: 7,
                rights: mnu_abi::HANDLE_RIGHT_CONTROL
            }
        ),
        Err(-13)
    ));
    STATE.with_borrow(|s| assert_eq!(s.closed, [7]));
}

#[test]
fn malformed_source_reply_cannot_publish_a_connected_peer() {
    reset();
    let mut s = socket();
    STATE.with_borrow_mut(|s| s.source_bad = true);
    assert_eq!(s.connect(ip(8000)), Err(-5));
    assert_eq!(s.peer_address(), Err(-107));
    STATE.with_borrow_mut(|s| s.source_bad = false);
    s.connect(ip(8000)).unwrap();
    STATE.with_borrow_mut(|s| s.source_bad = true);
    assert_eq!(s.local_address(), Err(-5));
}
