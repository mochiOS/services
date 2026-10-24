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
    pub use mochios_capability_protocol::decode_authorize_exec_object_request;
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
fn caller_digest_can_only_select_bytes_within_its_current_security_domain() {
    for digest in [[0; 32], [0x5a; 32], [0xff; 32]] {
        reset();
        object_image::authorize(77, &request(digest), &attachment()).unwrap();
        STATE.with_borrow(|s|{
   assert_eq!(s.issued.len(),1);let(sender,key,fields)=&s.issued[0];assert_eq!((*sender,key.as_str()),(77,"opaque:retained"));
   let hex=digest.iter().map(|b|format!("{b:02x}")).collect::<String>();use mnu_abi::exec::*;
   let expected=format!("{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE_INHERIT}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0{EXECUTABLE_DIGEST_PREFIX}{hex}\0\0");
   assert_eq!(fields,expected.as_bytes());
  });
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
        assert!(object_image::authorize(77, &b, &a).is_err());
        STATE.with_borrow(|s| assert!(s.issued.is_empty()));
    }
}
#[test]
fn native_errors_and_received_reference_cleanup_are_preserved() {
    reset();
    STATE.with_borrow_mut(|s| s.issue_error = Some(SysError(-321)));
    assert_eq!(
        object_image::authorize(77, &request([2; 32]), &attachment()),
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
