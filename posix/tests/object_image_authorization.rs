//! Execute the broker's actual admission/authorization logic. No I/O on a
//! supplied Provider is allowed in this serialized service.
extern crate alloc;
extern crate self as mochi_user_platform;
extern crate self as mochi_user_syscall;
use std::cell::RefCell;
pub const EACCES: u64 = (-13i64) as u64;
pub const EINVAL: u64 = (-22i64) as u64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SysError(i64);
impl SysError {
    pub fn from_raw(raw: i64) -> Self {
        Self(raw)
    }
}
#[derive(Default)]
struct State {
    allowed: bool,
    issued: Vec<(u64, String, Vec<u8>)>,
    issue_error: Option<SysError>,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
pub mod capability {
    pub use mochios_capability_protocol::{
        decode_authorize_captured_image_request, decode_authorize_exec_object_request,
    };
    pub fn check_thread(sender: u64, name: &str) -> Result<u64, crate::SysError> {
        assert_eq!((sender, name), (77, "process.spawn"));
        Ok(crate::STATE.with_borrow(|s| u64::from(s.allowed)))
    }
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
}
pub mod handle {
    pub const HANDLE_RIGHT_READ: u64 = mnu_abi::HANDLE_RIGHT_READ;
    pub fn read_at(_: u32, _: &mut [u8], _: u64) -> Result<usize, crate::SysError> {
        panic!("broker read an untrusted Provider")
    }
}
mod state {
    pub struct CapabilityServiceState;
}
pub mod memory {
    pub fn object_length(handle: u64) -> Result<u64, crate::SysError> {
        assert_eq!(handle, 19);
        Ok(b"retained RAM".len() as u64)
    }
}
mod signed_image {
    pub fn capture(handle: u32, length: u64) -> Result<Vec<u8>, crate::SysError> {
        assert_eq!((handle, length), (19, b"retained RAM".len() as u64));
        Ok(b"retained RAM".to_vec())
    }
    pub fn authorize_snapshot(
        _: &crate::state::CapabilityServiceState,
        sender: u64,
        key: &str,
        public_key: Option<&[u8; 32]>,
        snapshot: &[u8],
    ) -> Result<(), crate::SysError> {
        assert!(public_key.is_none());
        assert_eq!(snapshot, b"retained RAM");
        crate::service::authorize_exec_for_requester(sender, key, b"common-source-gate", &[])
            .map(|_| ())
    }
}
pub mod service {
    pub fn authorize_exec_for_requester(
        sender: u64,
        key: &str,
        fields: &[u8],
        caps: &[u8],
    ) -> Result<u64, crate::SysError> {
        assert!(caps.is_empty());
        crate::STATE.with_borrow_mut(|s| {
            if let Some(e) = s.issue_error {
                return Err(e);
            }
            s.issued.push((sender, key.into(), fields.to_vec()));
            Ok(0)
        })
    }
}
#[path = "../../capability/src/object_image.rs"]
mod object_image;
fn request(digest: [u8; 32]) -> Vec<u8> {
    let mut b = vec![0; 300];
    let n = mochios_capability_protocol::encode_authorize_exec_object_request(
        "opaque:retained",
        &digest,
        &mut b,
    )
    .unwrap();
    b.truncate(n);
    b
}
fn attachment() -> ipc::IpcObjectHandles {
    let mut a = ipc::IpcObjectHandles::default();
    a.count = 1;
    a.handles[0] = ipc::IpcObjectHandle {
        handle: 19,
        reserved: 0,
        rights: handle::HANDLE_RIGHT_READ,
    };
    a
}
fn reset() {
    STATE.with_borrow_mut(|s| {
        *s = State {
            allowed: true,
            ..Default::default()
        }
    });
}
#[test]
fn retained_transport_dispatches_only_the_captured_bytes_to_the_common_source_gate() {
    use sha2::{Digest, Sha256};
    let expected: [u8; 32] = Sha256::digest(b"retained RAM").into();
    for digest in [[0; 32], expected, [0xff; 32]] {
        reset();
        let result = object_image::authorize(
            &state::CapabilityServiceState,
            77,
            &request(digest),
            &attachment(),
        );
        if digest == expected {
            result.unwrap();
            STATE.with_borrow(|s| {
                assert_eq!(
                    s.issued,
                    [(77, "opaque:retained".into(), b"common-source-gate".to_vec())]
                )
            });
        } else {
            assert!(result.is_err());
            STATE.with_borrow(|s| assert!(s.issued.is_empty()));
        }
    }
    let source = include_str!("../../capability/src/object_image.rs");
    for forbidden in ["handle::read", "read_file(", "open_at(", "find_by_name("] {
        assert!(
            !source.contains(forbidden),
            "broker performs external I/O: {forbidden}"
        );
    }
}
#[test]
fn malformed_delivery_and_missing_authority_never_publish() {
    for case in 0..9 {
        reset();
        let mut a = attachment();
        let mut b = request([1; 32]);
        match case {
            0 => a.count = 0,
            1 => a.count = 2,
            2 => a.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            3 => a.handles[0].handle = 0,
            4 => a.handles[0].reserved = 1,
            5 => a.handles[0].rights = 0,
            6 => a.handles[0].rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            7 => STATE.with_borrow_mut(|s| s.allowed = false),
            _ => b[4] ^= 1,
        }
        assert!(object_image::authorize(&state::CapabilityServiceState, 77, &b, &a).is_err());
        STATE.with_borrow(|s| assert!(s.issued.is_empty()));
    }
}
#[test]
fn native_errors_and_received_reference_cleanup_are_preserved() {
    reset();
    STATE.with_borrow_mut(|s| s.issue_error = Some(SysError(-321)));
    use sha2::{Digest, Sha256};
    assert_eq!(
        object_image::authorize(
            &state::CapabilityServiceState,
            77,
            &request(Sha256::digest(b"retained RAM").into()),
            &attachment(),
        ),
        Err(SysError(-321))
    );
    STATE.with_borrow(|s| assert!(s.issued.is_empty()));
    let server = include_str!("../../capability/src/server.rs");
    let b = server
        .split("if opcode == platform::capability::AUTHORIZE_EXEC_OBJECT_OPCODE {")
        .nth(1)
        .unwrap()
        .split("continue;")
        .next()
        .unwrap();
    assert!(
        b.find("crate::object_image::authorize").unwrap()
            < b.find("close_received_handles(&attached)").unwrap()
    );
    assert!(
        b.find("close_received_handles(&attached)").unwrap() < b.find("capability_reply").unwrap()
    );
}

#[test]
fn captured_image_authorization_never_accepts_overrides_or_looks_up_a_path() {
    reset();
    let mut request = [0u8; 64];
    let n = mochios_capability_protocol::encode_authorize_captured_image_request(
        "unregistered:key",
        &mut request,
    )
    .unwrap();
    object_image::authorize_captured(77, &request[..n]).unwrap();
    STATE.with_borrow(|s| {
        assert_eq!(s.issued.len(), 1);
        assert_eq!(s.issued[0].1, "unregistered:key");
        use mnu_abi::exec::*;
        assert_eq!(s.issued[0].2, format!("{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_SPAWN_INHERIT}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0\0").as_bytes());
    });
    STATE.with_borrow_mut(|s| s.allowed = false);
    assert_eq!(
        object_image::authorize_captured(77, &request[..n]),
        Err(SysError::from_raw(EACCES as i64))
    );
    request[4] = 99;
    assert_eq!(
        object_image::authorize_captured(77, &request[..n]),
        Err(SysError::from_raw(EINVAL as i64))
    );
}
