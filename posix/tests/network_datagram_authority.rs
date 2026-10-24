//! Execute the actual authority server. Native delivery flags and Handle APIs
//! are the fixture boundary; the server's lifecycle/authorization is not mocked.
extern crate alloc;
extern crate self as mochi_user_platform;
use mnu_abi::provider;
use mochios_net_device_protocol::datagram_authority as wire;
use std::cell::RefCell;
#[path = "../../network/src/datagram.rs"]
mod datagram;
#[path = "../../network/src/datagram_authority.rs"]
mod server;
#[derive(Default)]
struct State {
    allowed: bool,
    endpoint_failed: bool,
    create_failed: bool,
    reply_failed: bool,
    signal_failed: bool,
    signals: Vec<(u64, u64, u64)>,
    created: Vec<(u64, u32, u64)>,
    closed: Vec<u32>,
    response: Vec<u8>,
    attached: Vec<mnu_abi::IpcObjectHandle>,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
pub mod capability {
    pub fn check_thread(sender: u64, name: &str) -> Result<u64, mochi_user_syscall::SysError> {
        assert_eq!((sender, name), (77, "net.connect"));
        Ok(crate::STATE.with_borrow(|s| u64::from(s.allowed)))
    }
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
    pub fn create_handle() -> Result<u32, mochi_user_syscall::SysError> {
        crate::STATE.with_borrow(|s| {
            if s.endpoint_failed {
                Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::NativeError::ResourceUnavailable.into_raw() as i64,
                ))
            } else {
                Ok(5)
            }
        })
    }
    pub fn reply(sender: u64, bytes: &[u8]) -> Result<(), mochi_user_syscall::SysError> {
        assert_eq!(sender, 77);
        crate::STATE.with_borrow_mut(|s| {
            s.response = bytes.to_vec();
            s.attached.clear();
        });
        Ok(())
    }
    pub fn reply_object_handles(
        sender: u64,
        bytes: &[u8],
        handles: &IpcObjectHandles,
    ) -> Result<(), mochi_user_syscall::SysError> {
        reply(sender, bytes)?;
        crate::STATE.with_borrow_mut(|s| {
            if s.reply_failed {
                return Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::NativeError::PeerClosed.into_raw() as i64,
                ));
            }
            s.attached = handles.handles[..handles.count as usize].to_vec();
            Ok(())
        })
    }
}
pub mod handle {
    pub fn identify_provider_object(handle: u32) -> Result<u64, mochi_user_syscall::SysError> {
        crate::STATE.with_borrow(|s| {
            s.created
                .iter()
                .find(|r| r.1 == handle)
                .map(|r| r.0)
                .ok_or_else(|| {
                    mochi_user_syscall::SysError::from_raw(
                        mochi_user_syscall::NativeError::AccessDenied.into_raw() as i64,
                    )
                })
        })
    }
    pub fn signal_provider_object(
        id: u64,
        set: u64,
        clear: u64,
    ) -> Result<(), mochi_user_syscall::SysError> {
        crate::STATE.with_borrow_mut(|s| {
            s.signals.push((id, set, clear));
            if s.signal_failed {
                Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::NativeError::ResourceUnavailable.into_raw() as i64,
                ))
            } else {
                Ok(())
            }
        })
    }
    pub fn create_provider_object(
        endpoint: u32,
        id: u64,
        rights: u64,
    ) -> Result<u32, mochi_user_syscall::SysError> {
        assert_eq!(endpoint, 5);
        crate::STATE.with_borrow_mut(|s| {
            if s.create_failed {
                return Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::NativeError::ResourceUnavailable.into_raw() as i64,
                ));
            }
            let h = s.created.len() as u32 + 100;
            s.created.push((id, h, rights));
            Ok(h)
        })
    }
    pub fn close(handle: u32) -> Result<(), mochi_user_syscall::SysError> {
        crate::STATE.with_borrow_mut(|s| s.closed.push(handle));
        Ok(())
    }
}
fn reset() {
    STATE.with_borrow_mut(|s| {
        *s = State {
            allowed: true,
            ..Default::default()
        }
    });
}
fn acquire(s: &mut server::Server) -> i32 {
    assert!(s.dispatch(77, &wire::ACQUIRE, &ipc::IpcObjectHandles::default()));
    STATE.with_borrow(|s| wire::status(&s.response).unwrap())
}
fn request(s: &mut server::Server, id: u64, opcode: u16, native: bool) -> i64 {
    let header = provider::RequestHeader {
        opcode,
        object_id: id,
        argument: 0,
        basis: if opcode == provider::OP_CONTROL {
            wire::QUERY_LIMITS
        } else {
            0
        },
        length: if opcode == provider::OP_CONTROL {
            wire::LIMITS_LEN as u32
        } else {
            0
        },
        data_length: 0,
    };
    let mut bytes = [0; 128];
    let n = header.encode(&[], &mut bytes).unwrap();
    let handles = ipc::IpcObjectHandles {
        delivery_flags: if native {
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
        } else {
            0
        },
        ..Default::default()
    };
    assert!(s.dispatch(77, &bytes[..n], &handles));
    if native && opcode == provider::OP_RELEASE {
        return 0;
    }
    STATE.with_borrow(|s| {
        provider::ResponseHeader::decode(&s.response)
            .unwrap()
            .0
            .status
    })
}
#[test]
fn only_authenticated_acquisition_issues_a_narrow_resource_and_queries_do_not_recheck_ambient_caps()
{
    reset();
    let mut s = server::Server::new();
    STATE.with_borrow_mut(|s| s.allowed = false);
    assert_eq!(acquire(&mut s), -13);
    STATE.with_borrow(|s| assert!(s.created.is_empty()));
    STATE.with_borrow_mut(|s| s.allowed = true);
    assert_eq!(acquire(&mut s), 0);
    let id = STATE.with_borrow(|s| {
        assert_eq!(s.attached.len(), 1);
        assert_eq!(s.attached[0].rights, server::RIGHTS);
        assert_eq!(s.closed, [100]);
        assert_eq!(
            server::RIGHTS & (mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE),
            0
        );
        s.created[0].0
    });
    STATE.with_borrow_mut(|s| s.allowed = false);
    assert_eq!(request(&mut s, id, provider::OP_CONTROL, true), 0);
    STATE.with_borrow(|s| {
        let (_, data) = provider::ResponseHeader::decode(&s.response).unwrap();
        assert_eq!(wire::Limits::decode(data).unwrap().minimum_port, 1024);
    });
    assert_eq!(acquire(&mut s), -13);
}
#[test]
fn forged_queries_and_releases_never_authorize_or_retire_an_object() {
    reset();
    let mut s = server::Server::new();
    assert_eq!(acquire(&mut s), 0);
    let id = STATE.with_borrow(|s| s.created[0].0);
    assert_eq!(request(&mut s, id, provider::OP_CONTROL, false), -13);
    assert_eq!(request(&mut s, id, provider::OP_RELEASE, false), -13);
    assert_eq!(request(&mut s, id, provider::OP_CONTROL, true), 0);
    request(&mut s, id, provider::OP_RELEASE, true);
    assert_eq!(request(&mut s, id, provider::OP_CONTROL, true), -9);
    assert_eq!(acquire(&mut s), 0);
    let new = STATE.with_borrow(|s| s.created[1].0);
    assert_ne!(new, id);
    request(&mut s, id, provider::OP_RELEASE, true);
    assert_eq!(request(&mut s, new, provider::OP_CONTROL, true), 0);
}
#[test]
fn failures_and_global_quota_never_publish_orphan_authorities() {
    reset();
    STATE.with_borrow_mut(|s| s.endpoint_failed = true);
    let mut s = server::Server::new();
    assert_eq!(acquire(&mut s), -5);
    reset();
    let mut s = server::Server::new();
    STATE.with_borrow_mut(|s| s.create_failed = true);
    assert_eq!(acquire(&mut s), -5);
    STATE.with_borrow_mut(|s| {
        s.create_failed = false;
        s.reply_failed = true;
    });
    for _ in 0..100 {
        assert!(s.dispatch(77, &wire::ACQUIRE, &Default::default()));
        STATE.with_borrow(|s| assert!(s.attached.is_empty()));
    }
    STATE.with_borrow_mut(|s| s.reply_failed = false);
    for _ in 0..64 {
        assert_eq!(acquire(&mut s), 0);
    }
    assert_eq!(acquire(&mut s), -24);
    let id = STATE.with_borrow(|s| s.created.last().unwrap().0);
    request(&mut s, id, provider::OP_RELEASE, true);
    assert_eq!(acquire(&mut s), 0);
    STATE.with_borrow(|s| assert_eq!(s.created.len(), s.closed.len()));
}
#[test]
fn malformed_requests_do_not_mint_handles_or_own_borrowed_attachments() {
    reset();
    let mut s = server::Server::new();
    for request in [
        &wire::ACQUIRE[..4],
        &[b'N', b'U', b'D', b'P', 2, 0, 1, 0][..],
    ] {
        assert!(s.dispatch(77, request, &Default::default()));
        STATE.with_borrow(|s| assert_eq!(wire::status(&s.response), Ok(-22)));
    }
    let mut unknown = wire::ACQUIRE;
    unknown[6] = 127;
    assert!(s.dispatch(77, &unknown, &Default::default()));
    STATE.with_borrow(|s| assert_eq!(wire::status(&s.response), Ok(-38)));
    let mut handles = ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0].handle = 999;
    assert!(s.dispatch(77, &wire::ACQUIRE, &handles));
    STATE.with_borrow(|s| {
        assert!(s.created.is_empty());
        assert!(s.closed.is_empty());
    });
}

#[test]
fn explicit_endpoint_delivery_and_strict_wire_metadata_are_supported() {
    reset();
    let mut server = server::Server::new();
    let handles = ipc::IpcObjectHandles {
        delivery_flags: mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
        ..Default::default()
    };
    assert!(server.dispatch(77, &wire::ACQUIRE, &handles));
    STATE.with_borrow(|s| assert_eq!(wire::status(&s.response), Ok(0)));
    let mut bytes = [0; wire::REPLY_LEN];
    wire::reply(-13, &mut bytes).unwrap();
    for index in [0, 4, 6, 12, 15] {
        let mut bad = bytes;
        bad[index] ^= 2;
        assert!(wire::status(&bad).is_err());
    }
    let mut limits = [0; wire::LIMITS_LEN];
    wire::Limits {
        minimum_port: 1024,
        maximum_payload: 1472,
    }
    .encode(&mut limits)
    .unwrap();
    assert_eq!(wire::Limits::decode(&limits).unwrap().maximum_payload, 1472);
    for index in [0, 2, 8, 11] {
        let mut bad = limits;
        bad[index] ^= 2;
        assert!(wire::Limits::decode(&bad).is_err());
    }
    assert!(wire::Limits::decode(&limits[..11]).is_err());
}

fn open_packet(
    s: &mut server::Server,
    b: &mut impl datagram::Backend,
    grant: u32,
    local: mochios_net_device_protocol::datagram::Endpoint,
) -> Result<(u64, u32), i32> {
    use mochios_net_device_protocol::datagram as packet;
    let mut bytes = [0; 16];
    let n = packet::open(local, &mut bytes).unwrap();
    let mut attached = ipc::IpcObjectHandles::default();
    attached.count = 1;
    attached.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    attached.handles[0] = ipc::IpcObjectHandle {
        handle: grant,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_CONTROL,
    };
    assert!(s.dispatch_datagram(77, &bytes[..n], &attached, b, 0));
    STATE.with_borrow(|s| {
        let status = wire::status_for(packet::OPEN_OPCODE, &s.response).unwrap();
        if status != 0 {
            assert!(s.attached.is_empty());
            return Err(status);
        }
        if s.reply_failed {
            assert!(s.attached.is_empty());
            return Err(-5);
        }
        let h = s.attached[0];
        assert_eq!(
            h.rights & (mnu_abi::HANDLE_RIGHT_SEEK | mnu_abi::HANDLE_RIGHT_MAP),
            0
        );
        Ok((s.created.last().unwrap().0, h.handle))
    })
}
fn packet_request(
    s: &mut server::Server,
    b: &mut impl datagram::Backend,
    id: u64,
    opcode: u16,
    code: u64,
    input: &[u8],
    capacity: u32,
    native: bool,
) -> (i64, u64, Vec<u8>) {
    s.pump_datagrams(b, 0);
    let header = provider::RequestHeader {
        opcode,
        object_id: id,
        argument: 0,
        basis: code,
        length: if opcode == provider::OP_WRITE {
            input.len() as u32
        } else {
            capacity
        },
        data_length: input.len() as u32,
    };
    let mut bytes = [0; provider::REQUEST_HEADER_LEN + provider::MAX_DATA_LEN];
    let n = header.encode(input, &mut bytes).unwrap();
    let handles = ipc::IpcObjectHandles {
        delivery_flags: if native {
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
        } else {
            0
        },
        ..Default::default()
    };
    assert!(s.dispatch_datagram(77, &bytes[..n], &handles, b, 0));
    if native && opcode == provider::OP_RELEASE {
        return (0, 0, vec![]);
    }
    STATE.with_borrow(|s| {
        let (header, data) = provider::ResponseHeader::decode(&s.response).unwrap();
        (header.status, header.value, data.to_vec())
    })
}
fn packet_local(
    s: &mut server::Server,
    b: &mut impl datagram::Backend,
    id: u64,
) -> mochios_net_device_protocol::datagram::Endpoint {
    use mochios_net_device_protocol::datagram as packet;
    let (status, _, bytes) =
        packet_request(s, b, id, provider::OP_CONTROL, packet::LOCAL, &[], 8, true);
    assert_eq!(status, 0);
    packet::Endpoint::decode(&bytes).unwrap()
}
#[test]
fn attached_authority_creates_real_loopback_records_with_peek_truncation_and_readiness() {
    use mochios_net_device_protocol::datagram as packet;
    reset();
    let mut s = server::Server::new();
    assert_eq!(acquire(&mut s), 0);
    let grant = STATE.with_borrow(|s| s.attached[0].handle);
    let mut b = datagram::Loopback::new();
    let local = packet::Endpoint {
        address: [127, 0, 0, 1],
        port: 0,
    };
    let (a, _) = open_packet(&mut s, &mut b, grant, local).unwrap();
    let (receiver, _) = open_packet(&mut s, &mut b, grant, local).unwrap();
    let target = packet_local(&mut s, &mut b, receiver);
    let mut send = [0; 64];
    let n = packet::send(Some(target), b"message", &mut send).unwrap();
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            a,
            provider::OP_WRITE,
            0,
            &send[..n],
            0,
            true
        )
        .0,
        0
    );
    s.pump_datagrams(&mut b, 0);
    STATE.with_borrow(|s| {
        assert!(
            s.signals
                .iter()
                .any(|(id, set, _)| *id == receiver && set & mnu_abi::HANDLE_SIGNAL_READABLE != 0)
        )
    });
    for _ in 0..2 {
        let (status, _, bytes) = packet_request(
            &mut s,
            &mut b,
            receiver,
            provider::OP_READ_AT,
            0,
            &[],
            14,
            true,
        );
        assert_eq!(status, 0);
        let record = packet::decode_received(&bytes).unwrap();
        assert_eq!(record.payload, b"me");
        assert_eq!(record.original_length, 7);
        assert!(record.truncated());
    }
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            receiver,
            provider::OP_READ,
            0,
            &[],
            11,
            true
        )
        .0,
        -22
    );
    let (status, _, bytes) = packet_request(
        &mut s,
        &mut b,
        receiver,
        provider::OP_READ,
        0,
        &[],
        14,
        true,
    );
    assert_eq!(status, 0);
    assert_eq!(packet::decode_received(&bytes).unwrap().payload, b"me");
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            receiver,
            provider::OP_READ,
            0,
            &[],
            64,
            true
        )
        .0,
        -11
    );
    s.pump_datagrams(&mut b, 0);
    STATE.with_borrow(|s| {
        assert!(
            s.signals
                .iter()
                .rev()
                .find(|(id, _, _)| *id == receiver)
                .unwrap()
                .2
                & mnu_abi::HANDLE_SIGNAL_READABLE
                != 0
        )
    });
    let n = packet::send(Some(target), b"", &mut send).unwrap();
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            a,
            provider::OP_WRITE,
            0,
            &send[..n],
            0,
            true
        )
        .0,
        0
    );
    let (status, n, bytes) = packet_request(
        &mut s,
        &mut b,
        receiver,
        provider::OP_READ,
        0,
        &[],
        64,
        true,
    );
    assert_eq!((status, n), (0, 12));
    assert!(packet::decode_received(&bytes).unwrap().payload.is_empty());
}
#[test]
fn derived_packet_handles_outlive_factory_and_forged_requests_cannot_consume_or_close() {
    use mochios_net_device_protocol::datagram as packet;
    reset();
    let mut s = server::Server::new();
    assert_eq!(acquire(&mut s), 0);
    let factory = STATE.with_borrow(|s| s.created[0]);
    let mut b = datagram::Loopback::new();
    let local = packet::Endpoint {
        address: [127, 0, 0, 1],
        port: 0,
    };
    let (a, _) = open_packet(&mut s, &mut b, factory.1, local).unwrap();
    let (receiver, _) = open_packet(&mut s, &mut b, factory.1, local).unwrap();
    let target = packet_local(&mut s, &mut b, receiver);
    request(&mut s, factory.0, provider::OP_RELEASE, true);
    assert_eq!(open_packet(&mut s, &mut b, factory.1, local), Err(-13));
    STATE.with_borrow_mut(|s| s.allowed = false);
    let mut frame = [0; 32];
    let n = target.encode(&mut frame).unwrap();
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            a,
            provider::OP_CONTROL,
            packet::SET_PEER,
            &frame[..n],
            0,
            true
        )
        .0,
        0
    );
    let n = packet::send(None, b"owned", &mut frame).unwrap();
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            a,
            provider::OP_WRITE,
            0,
            &frame[..n],
            0,
            true
        )
        .0,
        0
    );
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            receiver,
            provider::OP_READ,
            0,
            &[],
            64,
            false
        )
        .0,
        -13
    );
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            receiver,
            provider::OP_RELEASE,
            0,
            &[],
            0,
            false
        )
        .0,
        -13
    );
    let (status, _, data) = packet_request(
        &mut s,
        &mut b,
        receiver,
        provider::OP_READ,
        0,
        &[],
        64,
        true,
    );
    assert_eq!(status, 0);
    assert_eq!(packet::decode_received(&data).unwrap().payload, b"owned");
    packet_request(
        &mut s,
        &mut b,
        receiver,
        provider::OP_RELEASE,
        0,
        &[],
        0,
        true,
    );
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            receiver,
            provider::OP_CONTROL,
            packet::LOCAL,
            &[],
            8,
            true
        )
        .0,
        -9
    );
}
#[test]
fn packet_creation_checks_scope_and_rolls_back_bindings_on_every_publication_failure() {
    use datagram::Backend;
    use mochios_net_device_protocol::datagram as packet;
    for mode in 0..3 {
        reset();
        let mut s = server::Server::new();
        assert_eq!(acquire(&mut s), 0);
        let grant = STATE.with_borrow(|s| s.attached[0].handle);
        let mut b = datagram::Loopback::new();
        let local = packet::Endpoint {
            address: [127, 0, 0, 1],
            port: 0,
        };
        assert_eq!(open_packet(&mut s, &mut b, 999, local), Err(-13));
        assert_eq!(
            open_packet(
                &mut s,
                &mut b,
                grant,
                packet::Endpoint { port: 53, ..local }
            ),
            Err(-13)
        );
        assert_eq!(
            open_packet(
                &mut s,
                &mut b,
                grant,
                packet::Endpoint {
                    address: [192, 0, 2, 1],
                    ..local
                }
            ),
            Err(-99)
        );
        STATE.with_borrow_mut(|s| {
            s.create_failed = mode == 0;
            s.signal_failed = mode == 1;
            s.reply_failed = mode == 2;
        });
        for _ in 0..32 {
            let result = open_packet(&mut s, &mut b, grant, local);
            if mode != 2 {
                assert_eq!(result, Err(-5));
            }
        }
        STATE.with_borrow_mut(|s| {
            s.create_failed = false;
            s.signal_failed = false;
            s.reply_failed = false;
        });
        let mut live = vec![];
        for _ in 0..8 {
            live.push(b.bind(local).unwrap());
        }
        assert_eq!(b.bind(local), Err(-24));
        for id in live {
            b.release(id);
        }
        assert!(open_packet(&mut s, &mut b, grant, local).is_ok());
    }
}

#[test]
fn transmit_backpressure_bounds_records_and_reports_completion_errors_once() {
    use datagram::Backend;
    use mochios_net_device_protocol::datagram as packet;
    struct Congested {
        sockets: mochios_network_stack::UdpSocketTable,
        failure: i32,
        sent: Vec<Vec<u8>>,
    }
    impl Backend for Congested {
        fn sockets(&self) -> &mochios_network_stack::UdpSocketTable {
            &self.sockets
        }
        fn sockets_mut(&mut self) -> &mut mochios_network_stack::UdpSocketTable {
            &mut self.sockets
        }
        fn interface_address(&self) -> Option<[u8; 4]> {
            Some([192, 0, 2, 1])
        }
        fn transmit(
            &mut self,
            _: u16,
            _: packet::Endpoint,
            data: &[u8],
            _: u64,
        ) -> Result<(), i32> {
            if self.failure != 0 {
                return Err(self.failure);
            }
            self.sent.push(data.to_vec());
            Ok(())
        }
    }
    reset();
    let mut s = server::Server::new();
    assert_eq!(acquire(&mut s), 0);
    let grant = STATE.with_borrow(|s| s.attached[0].handle);
    let mut b = Congested {
        sockets: mochios_network_stack::UdpSocketTable::new(8, 8, 1472),
        failure: -11,
        sent: vec![],
    };
    let (id, _) = open_packet(
        &mut s,
        &mut b,
        grant,
        packet::Endpoint {
            address: [0; 4],
            port: 0,
        },
    )
    .unwrap();
    let mut frame = [0; 9];
    for byte in 0..8 {
        packet::send(
            Some(packet::Endpoint {
                address: [192, 0, 2, 2],
                port: 8000,
            }),
            &[byte],
            &mut frame,
        )
        .unwrap();
        assert_eq!(
            packet_request(&mut s, &mut b, id, provider::OP_WRITE, 0, &frame, 0, true).0,
            0
        );
    }
    assert_eq!(
        packet_request(&mut s, &mut b, id, provider::OP_WRITE, 0, &frame, 0, true).0,
        -11
    );
    s.pump_datagrams(&mut b, 0);
    STATE.with_borrow(|s| assert_eq!(s.signals.iter().rev().find(|r| r.0 == id).unwrap().1, 0));
    b.failure = 0;
    s.pump_datagrams(&mut b, 0);
    assert_eq!(b.sent, (0..8).map(|byte| vec![byte]).collect::<Vec<_>>());
    STATE.with_borrow(|s| {
        assert_eq!(
            s.signals.iter().rev().find(|r| r.0 == id).unwrap().1,
            mnu_abi::HANDLE_SIGNAL_WRITABLE
        )
    });
    b.failure = -5;
    assert_eq!(
        packet_request(&mut s, &mut b, id, provider::OP_WRITE, 0, &frame, 0, true).0,
        0
    );
    s.pump_datagrams(&mut b, 0);
    STATE.with_borrow(|s| {
        assert_ne!(
            s.signals.last().unwrap().1 & mnu_abi::HANDLE_SIGNAL_READABLE,
            0
        )
    });
    assert_eq!(
        packet_request(&mut s, &mut b, id, provider::OP_READ, 0, &[], 64, true).0,
        -5
    );
    assert_eq!(
        packet_request(&mut s, &mut b, id, provider::OP_READ, 0, &[], 64, true).0,
        -11
    );
    assert_eq!(
        packet_request(&mut s, &mut b, id, provider::OP_WRITE, 0, &frame, 0, true).0,
        0
    );
    let (status, _, bytes) = packet_request(
        &mut s,
        &mut b,
        id,
        provider::OP_CONTROL,
        packet::TAKE_STATUS,
        &[],
        4,
        true,
    );
    assert_eq!(status, 0);
    assert_eq!(i32::from_le_bytes(bytes.try_into().unwrap()), -5);
    let (_, _, bytes) = packet_request(
        &mut s,
        &mut b,
        id,
        provider::OP_CONTROL,
        packet::TAKE_STATUS,
        &[],
        4,
        true,
    );
    assert_eq!(bytes, [0; 4]);
}

#[test]
fn packet_wire_rejects_malformed_lengths_reserved_fields_and_truncation_flags() {
    use mochios_net_device_protocol::datagram as p;
    let endpoint = p::Endpoint {
        address: [127, 0, 0, 1],
        port: 8000,
    };
    let mut frame = [0; 32];
    assert_eq!(p::open(endpoint, &mut frame).unwrap(), 16);
    assert!(p::decode_open(&frame[..15]).is_err());
    frame[14] = 1;
    assert!(p::decode_open(&frame[..16]).is_err());
    let n = p::received(endpoint, b"abc", &mut frame[..13]).unwrap();
    let received = p::decode_received(&frame[..n]).unwrap();
    assert!(received.truncated());
    assert_eq!((received.original_length, received.payload), (3, &b"a"[..]));
    frame[8] = 0;
    assert!(p::decode_received(&frame[..n]).is_err());
    frame[8] = 2;
    assert!(p::decode_received(&frame[..n]).is_err());
    assert!(p::decode_send(&[0; 7]).is_err());
    assert!(p::send(Some(endpoint), &[0; 1473], &mut [0; 1481]).is_err());
}

#[test]
fn source_query_uses_bound_port_and_route_without_changing_binding_or_peer() {
    use mochios_net_device_protocol::datagram as packet;
    reset();
    let mut s = server::Server::new();
    assert_eq!(acquire(&mut s), 0);
    let grant = STATE.with_borrow(|s| s.attached[0].handle);
    let mut b = datagram::Loopback::new();
    let (id, _) = open_packet(
        &mut s,
        &mut b,
        grant,
        packet::Endpoint {
            address: [0; 4],
            port: 0,
        },
    )
    .unwrap();
    let before = packet_local(&mut s, &mut b, id);
    let mut destination = [0; 8];
    packet::Endpoint {
        address: [127, 0, 0, 2],
        port: 8000,
    }
    .encode(&mut destination)
    .unwrap();
    let (status, _, bytes) = packet_request(
        &mut s,
        &mut b,
        id,
        provider::OP_CONTROL,
        packet::SOURCE,
        &destination,
        8,
        true,
    );
    assert_eq!(status, 0);
    assert_eq!(
        packet::Endpoint::decode(&bytes).unwrap(),
        packet::Endpoint {
            address: [127, 0, 0, 1],
            port: before.port
        }
    );
    assert_eq!(packet_local(&mut s, &mut b, id), before);
    let (status, _, peer) = packet_request(
        &mut s,
        &mut b,
        id,
        provider::OP_CONTROL,
        packet::PEER,
        &[],
        8,
        true,
    );
    assert_eq!(status, 0);
    assert!(packet::Endpoint::decode(&peer).unwrap().unspecified());
    packet::Endpoint {
        address: [192, 0, 2, 1],
        port: 8000,
    }
    .encode(&mut destination)
    .unwrap();
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            id,
            provider::OP_CONTROL,
            packet::SOURCE,
            &destination,
            8,
            true
        )
        .0,
        -6
    );
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            id,
            provider::OP_CONTROL,
            packet::SOURCE,
            &destination,
            8,
            false
        )
        .0,
        -13
    );
    destination[6] = 1;
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            id,
            provider::OP_CONTROL,
            packet::SOURCE,
            &destination,
            8,
            true
        )
        .0,
        -22
    );
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            id,
            provider::OP_CONTROL,
            packet::SOURCE,
            &[],
            8,
            true
        )
        .0,
        -95
    );
}

#[test]
fn validation_accepts_only_attached_live_factory_authority_and_never_rechecks_ambient_caps() {
    reset();
    let mut s = server::Server::new();
    assert_eq!(acquire(&mut s), 0);
    let factory = STATE.with_borrow(|s| s.attached[0].handle);
    let id = STATE.with_borrow(|s| s.created.last().unwrap().0);
    let created = STATE.with_borrow(|s| s.created.len());
    STATE.with_borrow_mut(|s| s.allowed = false);
    for handle in [factory, 999] {
        let mut attached = ipc::IpcObjectHandles::default();
        attached.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
        attached.count = 1;
        attached.handles[0] = ipc::IpcObjectHandle {
            handle,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_CONTROL,
        };
        assert!(s.dispatch(77, &wire::VALIDATE, &attached));
        STATE.with_borrow(|s| {
            assert_eq!(
                wire::status_for(3, &s.response),
                Ok(if handle == factory { 0 } else { -13 })
            )
        });
    }
    assert_eq!(STATE.with_borrow(|s| s.created.len()), created);
    request(&mut s, id, provider::OP_RELEASE, true);
    let mut attached = ipc::IpcObjectHandles::default();
    attached.count = 1;
    attached.handles[0] = ipc::IpcObjectHandle {
        handle: factory,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_CONTROL,
    };
    assert!(s.dispatch(77, &wire::VALIDATE, &attached));
    STATE.with_borrow(|s| assert_eq!(wire::status_for(3, &s.response), Ok(-13)));
}

#[test]
fn draining_a_record_clears_readiness_before_the_native_read_is_acknowledged() {
    use mochios_net_device_protocol::datagram as packet;
    reset();
    let mut s = server::Server::new();
    assert_eq!(acquire(&mut s), 0);
    let grant = STATE.with_borrow(|s| s.attached[0].handle);
    let mut b = datagram::Loopback::new();
    let local = packet::Endpoint {
        address: [127, 0, 0, 1],
        port: 0,
    };
    let (receiver, _) = open_packet(&mut s, &mut b, grant, local).unwrap();
    let destination = packet_local(&mut s, &mut b, receiver);
    let (sender, _) = open_packet(&mut s, &mut b, grant, local).unwrap();
    let mut frame = [0; 32];
    let n = packet::send(Some(destination), b"record", &mut frame).unwrap();
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            sender,
            provider::OP_WRITE,
            0,
            &frame[..n],
            0,
            true
        )
        .0,
        0
    );
    STATE.with_borrow(|s| {
        assert_ne!(
            s.signals
                .iter()
                .rev()
                .find(|(id, _, _)| *id == receiver)
                .unwrap()
                .1
                & mnu_abi::HANDLE_SIGNAL_READABLE,
            0
        )
    });
    assert_eq!(
        packet_request(
            &mut s,
            &mut b,
            receiver,
            provider::OP_READ,
            0,
            &[],
            64,
            true
        )
        .0,
        0
    );
    STATE.with_borrow(|s| {
        assert_eq!(
            s.signals
                .iter()
                .rev()
                .find(|(id, _, _)| *id == receiver)
                .unwrap()
                .1
                & mnu_abi::HANDLE_SIGNAL_READABLE,
            0
        )
    });
}
