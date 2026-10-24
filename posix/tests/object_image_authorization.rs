//! Execute the broker's actual admission/hash/authorization logic with controlled
//! native boundaries. Real IPC and image replacement are separate native tests.
extern crate alloc;
extern crate self as mochi_user_platform;
extern crate self as mochi_user_syscall;
use sha2::{Digest, Sha256};
use std::cell::RefCell;

pub const EACCES: u64 = (-13i64) as u64;
pub const EFBIG: u64 = (-27i64) as u64;
pub const EINVAL: u64 = (-22i64) as u64;
pub const EIO: u64 = (-5i64) as u64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SysError(i64);
impl SysError {
    pub fn from_raw(raw: i64) -> Self {
        Self(raw)
    }
}
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    chunk: usize,
    allowed: bool,
    read_calls: usize,
    fail_read: bool,
    oversize_read: bool,
    generated_size: Option<u64>,
    issued: Vec<(u64, String, Vec<u8>)>,
    issue_error: Option<SysError>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
pub mod capability {
    pub use mochios_capability_protocol::decode_authorize_exec_object_request;
    pub fn check_thread(sender: u64, cap: &str) -> Result<u64, crate::SysError> {
        assert_eq!((sender, cap), (77, "process.spawn"));
        Ok(crate::STATE.with_borrow(|s| u64::from(s.allowed)))
    }
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
}
pub mod handle {
    pub const HANDLE_RIGHT_READ: u64 = mnu_abi::HANDLE_RIGHT_READ;
    pub fn read_at(handle: u32, output: &mut [u8], offset: u64) -> Result<usize, crate::SysError> {
        assert_eq!(handle, 19);
        crate::STATE.with_borrow_mut(|s| {
            s.read_calls += 1;
            if s.fail_read {
                return Err(crate::SysError(-123));
            }
            if s.oversize_read {
                return Ok(output.len() + 1);
            }
            let size = s.generated_size.unwrap_or(s.bytes.len() as u64);
            let count = size
                .saturating_sub(offset)
                .min(output.len() as u64)
                .min(s.chunk as u64) as usize;
            if s.generated_size.is_some() {
                output[..count].fill(0x5a);
            } else {
                output[..count].copy_from_slice(
                    &s.bytes[offset.min(size) as usize..offset.min(size) as usize + count],
                );
            }
            Ok(count)
        })
    }
}
pub mod service {
    pub fn authorize_exec_for_requester(
        sender: u64,
        identity: &str,
        fields: &[u8],
        caps: &[u8],
    ) -> Result<u64, crate::SysError> {
        assert!(caps.is_empty());
        crate::STATE.with_borrow_mut(|s| {
            if let Some(error) = s.issue_error {
                return Err(error);
            }
            s.issued.push((sender, identity.into(), fields.to_vec()));
            Ok(0)
        })
    }
}
#[path = "../../capability/src/object_image.rs"]
mod object_image;

fn request() -> Vec<u8> {
    let mut output = vec![0; 300];
    let len = mochios_capability_protocol::encode_authorize_exec_object_request(
        "opaque:retained",
        &mut output,
    )
    .unwrap();
    output.truncate(len);
    output
}
fn attachment() -> ipc::IpcObjectHandles {
    let mut objects = ipc::IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = ipc::IpcObjectHandle {
        handle: 19,
        reserved: 0,
        rights: handle::HANDLE_RIGHT_READ,
    };
    objects
}
fn reset() {
    STATE.with_borrow_mut(|s| {
        *s = State {
            bytes: (0..17001).map(|n| (n % 251) as u8).collect(),
            chunk: 17,
            allowed: true,
            ..Default::default()
        }
    });
}

#[test]
fn short_positional_reads_bind_exact_digest_without_identity_or_grant_overrides() {
    for size in [0, 1, 4095, 4096, 4097, 17001] {
        reset();
        STATE.with_borrow_mut(|s| s.bytes.truncate(size));
        object_image::authorize(77, &request(), &attachment()).unwrap();
        STATE.with_borrow(|s| {
            assert_eq!(s.issued.len(),1);
            let (sender,key,fields)=&s.issued[0];assert_eq!((*sender,key.as_str()),(77,"opaque:retained"));
            let digest: [u8;32]=Sha256::digest(&s.bytes).into();
            let hex=digest.iter().map(|b|format!("{b:02x}")).collect::<String>();
            use mnu_abi::exec::*;
            let expected=format!("{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE_INHERIT}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0{EXECUTABLE_DIGEST_PREFIX}{hex}\0\0");
            assert_eq!(fields,expected.as_bytes());
        });
    }
}

#[test]
fn malformed_delivery_and_missing_authority_never_read_or_publish() {
    for case in 0..9 {
        reset();
        let mut objects = attachment();
        let mut request = request();
        match case {
            0 => objects.count = 0,
            1 => objects.count = 2,
            2 => objects.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            3 => objects.handles[0].handle = 0,
            4 => objects.handles[0].reserved = 1,
            5 => objects.handles[0].rights = 0,
            6 => objects.handles[0].rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            7 => STATE.with_borrow_mut(|s| s.allowed = false),
            _ => request[4] ^= 1,
        }
        assert!(object_image::authorize(77, &request, &objects).is_err());
        STATE.with_borrow(|s| {
            assert_eq!(s.read_calls, 0);
            assert!(s.issued.is_empty());
        });
    }
}

#[test]
fn read_failures_excess_bytes_and_native_authorization_errors_are_preserved() {
    for case in 0..4 {
        reset();
        STATE.with_borrow_mut(|s| match case {
            0 => s.fail_read = true,
            1 => s.oversize_read = true,
            2 => {
                s.generated_size = Some(64 * 1024 * 1024 + 1);
                s.chunk = 4096;
            }
            _ => s.issue_error = Some(SysError(-321)),
        });
        let expected = match case {
            0 => SysError(-123),
            1 => SysError(EIO as i64),
            2 => SysError(EFBIG as i64),
            _ => SysError(-321),
        };
        assert_eq!(
            object_image::authorize(77, &request(), &attachment()),
            Err(expected)
        );
        STATE.with_borrow(|s| assert!(s.issued.is_empty()));
    }
    let server = include_str!("../../capability/src/server.rs");
    let branch = server
        .split("if opcode == platform::capability::AUTHORIZE_EXEC_OBJECT_OPCODE {")
        .nth(1)
        .unwrap()
        .split("continue;")
        .next()
        .unwrap();
    assert!(
        branch.find("crate::object_image::authorize").unwrap()
            < branch.find("close_received_handles(&attached)").unwrap()
    );
    assert!(
        branch.find("close_received_handles(&attached)").unwrap()
            < branch.find("capability_reply").unwrap()
    );
}
