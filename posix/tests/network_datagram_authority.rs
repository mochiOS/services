//! Execute the actual authority server. Native delivery flags and Handle APIs
//! are the fixture boundary; the server's lifecycle/authorization is not mocked.
extern crate alloc;
extern crate self as mochi_user_platform;
use mnu_abi::provider;
use mochios_net_device_protocol::datagram_authority as wire;
use std::cell::RefCell;
#[path = "../../network/src/datagram_authority.rs"]
mod server;
#[derive(Default)]
struct State {
    allowed: bool,
    endpoint_failed: bool,
    create_failed: bool,
    reply_failed: bool,
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
