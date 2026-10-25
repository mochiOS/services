//! Run POSIX description policy through its actual native packet adapter.
//! Only the native Handle/IPC mechanism is replaced with an in-memory fixture.
extern crate alloc;
extern crate self as mochi_user_platform;
use mochios_net_device_protocol::{datagram as packet, datagram_authority as authority};
use mochios_posix_protocol::socket::{self as wire, Address, Domain, Kind};
use posix_service::OpenedObject;
pub use posix_service::filesystem_transport;
use std::{cell::RefCell, collections::BTreeMap};
#[path = "../../network/src/datagram.rs"]
mod datagram;
use posix_service::inet_datagram;
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
            if request == crate::authority::VALIDATE {
                *handles = IpcObjectHandles::default();
                crate::authority::reply_for(3, if s.open_mode == 1 { -13 } else { 0 }, reply)
                    .unwrap();
                return Ok(crate::authority::REPLY_LEN as u64);
            }
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
pub mod process {
    pub fn wait_many(
        items: &mut [mnu_abi::HandleWaitItem],
        _: u64,
    ) -> Result<usize, crate::syscall::SysError> {
        crate::STATE.with_borrow(|s| {
            let id = s.id(items[0].handle).map_err(crate::error)?;
            items[0].observed = mnu_abi::HANDLE_SIGNAL_WRITABLE
                | if s.backend.readable(id).map_err(crate::error)? {
                    mnu_abi::HANDLE_SIGNAL_READABLE
                } else {
                    0
                };
            Ok(0)
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

fn provider_request(
    registry: &mut posix_service::inet_socket::Registry<NetworkBackend>,
    id: u64,
    op: u16,
    tag: u64,
    input: &[u8],
    capacity: u32,
    native: bool,
) -> (i64, u64, Vec<u8>) {
    use mnu_abi::provider as p;
    let header = p::RequestHeader {
        opcode: op,
        object_id: id,
        argument: 0,
        basis: tag,
        length: if op == p::OP_WRITE {
            input.len() as u32
        } else {
            capacity
        },
        data_length: input.len() as u32,
    };
    let mut request = [0; p::REQUEST_HEADER_LEN + p::MAX_DATA_LEN];
    let n = header.encode(input, &mut request).unwrap();
    let mut response = [0; p::RESPONSE_HEADER_LEN + p::MAX_DATA_LEN];
    let n = registry
        .dispatch(
            &request[..n],
            if native {
                mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
            } else {
                0
            },
            0,
            &mut response,
        )
        .unwrap();
    if let Some(n) = n {
        let (header, data) = p::ResponseHeader::decode(&response[..n]).unwrap();
        (header.status, header.value, data.to_vec())
    } else {
        (0, 0, vec![])
    }
}
#[test]
fn provider_registry_executes_native_controls_data_and_final_release_in_a_disjoint_namespace() {
    use mnu_abi::provider as p;
    reset();
    let mut registry = posix_service::inet_socket::Registry::new();
    let receiver = registry.insert(socket()).unwrap();
    let sender = registry.insert(socket()).unwrap();
    assert!(posix_service::inet_socket::is_inet(receiver));
    assert!(receiver <= i64::MAX as u64);
    assert!(!posix_service::inet_socket::is_inet(1 << 63));
    assert!(posix_service::socket_connect::job_id(receiver).is_err());
    assert!(posix_service::socket_transfer::job_id(receiver).is_err());
    assert!(!posix_service::socket_route::is_route(receiver));
    assert!(posix_service::socket_receive_wait::job_id(receiver).is_err());
    let mut address = [0; wire::MAX_ADDRESS_LEN];
    let n = ip(8000).encode(&mut address).unwrap();
    assert_eq!(
        provider_request(
            &mut registry,
            receiver,
            p::OP_CONTROL,
            wire::CONTROL_BIND,
            &address[..n],
            0,
            true
        )
        .0,
        0
    );
    registry.connect(sender, ip(8000)).unwrap();
    assert_eq!(
        provider_request(&mut registry, sender, p::OP_WRITE, 0, b"hello", 0, true),
        (0, 5, vec![])
    );
    let mut notifications = vec![];
    registry.pump(|id, set| {
        notifications.push((id, set));
        Ok(())
    });
    assert_ne!(
        notifications
            .iter()
            .find(|(id, _)| *id == receiver)
            .unwrap()
            .1
            & mnu_abi::HANDLE_SIGNAL_READABLE,
        0
    );
    assert_eq!(
        provider_request(&mut registry, receiver, p::OP_READ, 0, &[], 2, false).0,
        -13
    );
    for _ in 0..2 {
        assert_eq!(
            provider_request(&mut registry, receiver, p::OP_READ_AT, 0, &[], 2, true),
            (0, 2, b"he".to_vec())
        );
    }
    assert_eq!(
        provider_request(&mut registry, receiver, p::OP_READ, 0, &[], 2, true),
        (0, 2, b"he".to_vec())
    );
    assert_eq!(
        provider_request(&mut registry, receiver, p::OP_READ, 0, &[], 32, true).0,
        -11
    );
    registry.pump(|id, set| {
        notifications.push((id, set));
        Ok(())
    });
    assert_eq!(
        notifications
            .iter()
            .rev()
            .find(|(id, _)| *id == receiver)
            .unwrap()
            .1
            & mnu_abi::HANDLE_SIGNAL_READABLE,
        0
    );
    let (_, _, bytes) = provider_request(
        &mut registry,
        sender,
        p::OP_CONTROL,
        wire::CONTROL_LOCAL_ADDRESS,
        &[],
        wire::MAX_ADDRESS_LEN as u32,
        true,
    );
    assert!(
        matches!(wire::Address::decode(&bytes).unwrap(),Address::Ipv4{address:[127,0,0,1],port} if port!=0)
    );
    assert_eq!(
        provider_request(
            &mut registry,
            sender,
            p::OP_CONTROL,
            wire::CONTROL_SET_OPTIONS,
            &wire::NONBLOCKING.to_le_bytes(),
            0,
            true
        )
        .0,
        0
    );
    let (_, _, options) = provider_request(
        &mut registry,
        sender,
        p::OP_CONTROL,
        wire::CONTROL_GET_OPTIONS,
        &[],
        4,
        true,
    );
    assert_eq!(options, wire::NONBLOCKING.to_le_bytes());
    assert_eq!(
        provider_request(&mut registry, sender, p::OP_RELEASE, 0, &[], 0, false).0,
        -13
    );
    assert_eq!(
        provider_request(
            &mut registry,
            sender,
            p::OP_CONTROL,
            wire::CONTROL_KIND,
            &[],
            4,
            true
        )
        .2,
        (Kind::Datagram as u32).to_le_bytes()
    );
    provider_request(&mut registry, sender, p::OP_RELEASE, 0, &[], 0, true);
    provider_request(&mut registry, receiver, p::OP_RELEASE, 0, &[], 0, true);
    STATE.with_borrow(|s| assert!(s.bindings.is_empty()));
    let replacement = registry.insert(socket()).unwrap();
    assert_ne!(replacement, sender);
    assert_ne!(replacement, receiver);
    assert_eq!(registry.connect(sender, ip(8000)), Err(-9));
}
#[test]
fn readiness_rearms_only_unforwarded_levels_and_failed_signal_does_not_lose_a_wake() {
    reset();
    let mut registry = posix_service::inet_socket::Registry::new();
    let id = registry.insert(socket()).unwrap();
    registry.connect(id, ip(8000)).unwrap();
    registry.pump(|_, _| Err(-12));
    let mut watches = vec![];
    registry.watches(|h, bits| watches.push((h, bits)));
    assert_eq!(watches.len(), 1);
    assert_ne!(watches[0].1 & mnu_abi::HANDLE_SIGNAL_WRITABLE, 0);
    registry.pump(|_, _| Ok(()));
    watches.clear();
    registry.watches(|h, bits| watches.push((h, bits)));
    assert_eq!(watches[0].1 & mnu_abi::HANDLE_SIGNAL_WRITABLE, 0);
    assert_ne!(watches[0].1 & mnu_abi::HANDLE_SIGNAL_READABLE, 0);
    let mut called = false;
    registry.pump(|_, _| {
        called = true;
        Ok(())
    });
    assert!(!called);
}
#[test]
fn factory_validation_is_a_control_plane_request_without_creating_a_binding() {
    reset();
    let backend = backend();
    backend.validate().unwrap();
    STATE.with_borrow(|s| assert!(s.bindings.is_empty()));
    STATE.with_borrow_mut(|s| s.open_mode = 1);
    assert_eq!(backend.validate(), Err(-13));
}

#[test]
fn shared_ram_records_preserve_empty_datagrams_sources_and_failed_output_copies() {
    use mochios_posix_protocol::socket_record::{self as wire, Operation, Reply, Request};
    use posix_service::socket_record_io::RecordBuffer;
    struct Ram {
        bytes: Vec<u8>,
        failed: bool,
    }
    impl RecordBuffer for Ram {
        fn extent(&self) -> Result<u64, i32> {
            Ok(self.bytes.len() as u64)
        }
        fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), i32> {
            out.copy_from_slice(&self.bytes[offset as usize..offset as usize + out.len()]);
            Ok(())
        }
        fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32> {
            if self.failed {
                return Err(-14);
            }
            self.bytes[offset as usize..offset as usize + input.len()].copy_from_slice(input);
            Ok(())
        }
    }
    reset();
    let mut registry = posix_service::inet_socket::Registry::new();
    let receiver = registry.insert(socket()).unwrap();
    let sender = registry.insert(socket()).unwrap();
    let mut address = [0; mochios_posix_protocol::socket::MAX_ADDRESS_LEN];
    let n = ip(8000).encode(&mut address).unwrap();
    assert_eq!(
        provider_request(
            &mut registry,
            receiver,
            mnu_abi::provider::OP_CONTROL,
            mochios_posix_protocol::socket::CONTROL_BIND,
            &address[..n],
            0,
            true
        )
        .0,
        0
    );
    let mut ram = Ram {
        bytes: vec![0; 128],
        failed: false,
    };
    let mut response = [0; wire::MAX_REPLY_LEN];
    let send = Request {
        operation: Operation::SendTo,
        offset: 17,
        length: 0,
        peek: false,
    };
    registry
        .transfer_record(sender, send, Some(ip(8000)), &mut ram, &mut response)
        .unwrap();
    let receive = Request {
        operation: Operation::Receive,
        ..send
    };
    let n = registry
        .transfer_record(receiver, receive, None, &mut ram, &mut response)
        .unwrap();
    let r = Reply::decode(receive, &response[..n]).unwrap();
    assert_eq!((r.copied, r.length), (0, 0));
    assert!(matches!(r.source,Some(Address::Ipv4{address:[127,0,0,1],port}) if port!=0));
    ram.bytes[17..22].copy_from_slice(b"hello");
    let send = Request { length: 5, ..send };
    registry
        .transfer_record(sender, send, Some(ip(8000)), &mut ram, &mut response)
        .unwrap();
    let receive = Request {
        length: 2,
        ..receive
    };
    ram.failed = true;
    assert_eq!(
        registry.transfer_record(receiver, receive, None, &mut ram, &mut response),
        Err(-14)
    );
    ram.failed = false;
    let peek = Request {
        peek: true,
        ..receive
    };
    for _ in 0..2 {
        let n = registry
            .transfer_record(receiver, peek, None, &mut ram, &mut response)
            .unwrap();
        let r = Reply::decode(peek, &response[..n]).unwrap();
        assert_eq!((r.copied, r.length), (2, 5));
        assert_eq!(&ram.bytes[17..19], b"he");
    }
    let bad = Request {
        offset: 128,
        length: 1,
        ..receive
    };
    assert_eq!(
        registry.transfer_record(receiver, bad, None, &mut ram, &mut response),
        Err(-22)
    );
    assert_eq!(
        registry.transfer_record(receiver, receive, None, &mut ram, &mut response[..1]),
        Err(-22)
    );
    let n = registry
        .transfer_record(receiver, receive, None, &mut ram, &mut response)
        .unwrap();
    assert_eq!(Reply::decode(receive, &response[..n]).unwrap().length, 5);
    assert_eq!(
        registry.transfer_record(receiver, receive, None, &mut ram, &mut response),
        Err(-11)
    );
    registry
        .transfer_record(sender, send, Some(ip(8000)), &mut ram, &mut response)
        .unwrap();
    let receive = Request {
        length: 0,
        ..receive
    };
    let n = registry
        .transfer_record(receiver, receive, None, &mut ram, &mut response)
        .unwrap();
    let r = Reply::decode(receive, &response[..n]).unwrap();
    assert_eq!((r.copied, r.length), (0, 5));
    assert_eq!(
        registry.transfer_record(receiver, receive, None, &mut ram, &mut response),
        Err(-11)
    );
}
