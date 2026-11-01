//! Actual broker admission and shared signature verifier, with native RAM and
//! authorization mechanisms replaced by observable, fault-injectable adapters.
extern crate alloc;
extern crate self as mochi_user_platform;
use mochi_user_syscall::{EACCES, NativeError, SysError};
use mochios_capability_protocol::{ProtocolError, signed_image as wire};
use mochios_elf_signature::{sign_adhoc, sign_ed25519};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

#[path = "support/signed_elf.rs"]
mod fixture;
#[path = "../../capability/src/object_image.rs"]
mod object_image;
#[path = "../../capability/src/signed_image.rs"]
mod signed_image;

#[derive(Default)]
struct State {
    allowed: bool,
    bytes: Vec<u8>,
    extent: u64,
    length_error: Option<SysError>,
    read_error: Option<SysError>,
    issue_error: Option<SysError>,
    part_limit: usize,
    bad_count: bool,
    grow: bool,
    length_calls: usize,
    reads: usize,
    issued: Vec<(u64, String, Vec<u8>)>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

pub mod capability {
    pub use mochios_capability_protocol::{
        decode_authorize_captured_image_request, decode_authorize_exec_object_request, signed_image,
    };
    pub fn check_thread(sender: u64, name: &str) -> Result<u64, crate::SysError> {
        assert_eq!((sender, name), (77, "process.spawn"));
        Ok(crate::STATE.with_borrow(|s| u64::from(s.allowed)))
    }
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
}
pub mod memory_object {
    pub const READONLY_BUFFER_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP;
}
pub mod memory {
    pub fn object_length(handle: u64) -> Result<u64, crate::SysError> {
        assert_eq!(handle, 19);
        crate::STATE.with_borrow_mut(|s| {
            s.length_calls += 1;
            if let Some(error) = s.length_error {
                return Err(error);
            }
            Ok(s.extent)
        })
    }
}
pub mod handle {
    pub const HANDLE_RIGHT_READ: u64 = mnu_abi::HANDLE_RIGHT_READ;
    pub fn read_at(handle: u32, out: &mut [u8], offset: u64) -> Result<usize, crate::SysError> {
        assert_eq!(handle, 19);
        assert!(out.len() <= 256 * 1024);
        crate::STATE.with_borrow_mut(|s| {
            s.reads += 1;
            if let Some(error) = s.read_error {
                return Err(error);
            }
            if s.bad_count {
                return Ok(out.len() + 1);
            }
            if s.grow && offset == s.extent {
                out[0] = 1;
                return Ok(1);
            }
            let tail = s.bytes.get(offset as usize..).unwrap_or(&[]);
            let n = tail.len().min(out.len()).min(s.part_limit);
            out[..n].copy_from_slice(&tail[..n]);
            Ok(n)
        })
    }
}
pub mod service {
    pub fn authorize_exec_for_requester(
        sender: u64,
        key: &str,
        fields: &[u8],
        caps: &[u8],
    ) -> Result<u64, crate::SysError> {
        assert!(
            caps.is_empty(),
            "signature verification must not mint grants"
        );
        crate::STATE.with_borrow_mut(|s| {
            if let Some(error) = s.issue_error {
                return Err(error);
            }
            s.issued.push((sender, key.into(), fields.to_vec()));
            Ok(0)
        })
    }
}

fn setup(bytes: Vec<u8>) -> (Vec<u8>, ipc::IpcObjectHandles) {
    let length = bytes.len() as u64;
    STATE.with_borrow_mut(|s| {
        *s = State {
            allowed: true,
            bytes,
            extent: length,
            part_limit: usize::MAX,
            ..State::default()
        }
    });
    let request = encode(length, None);
    let mut attached = ipc::IpcObjectHandles::default();
    attached.count = 1;
    attached.handles[0] = ipc::IpcObjectHandle {
        handle: 19,
        reserved: 0,
        rights: memory_object::READONLY_BUFFER_RIGHTS,
    };
    (request, attached)
}
fn encode(length: u64, key: Option<&[u8; 32]>) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    let n = wire::encode(
        &wire::Request {
            source_length: length,
            public_key: key,
            identity: "opaque:signed",
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(n);
    bytes
}
fn no_issue() {
    STATE.with_borrow(|s| assert!(s.issued.is_empty()));
}

#[test]
fn wire_is_bounded_versioned_and_accepts_no_ambient_authority() {
    for public_key in [None, Some(&[7; 32])] {
        let bytes = encode(17, public_key);
        assert_eq!(
            wire::decode(&bytes).unwrap(),
            wire::Request {
                source_length: 17,
                public_key,
                identity: "opaque:signed"
            }
        );
        for n in 0..wire::PREFIX_LEN + usize::from(public_key.is_some()) * 32 {
            assert!(wire::decode(&bytes[..n]).is_err());
        }
        for (offset, value, error) in [
            (0, 0, ProtocolError::UnknownOpcode),
            (4, 2, ProtocolError::UnsupportedVersion),
            (16, 2, ProtocolError::InvalidField),
            (20, 1, ProtocolError::InvalidField),
        ] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert_eq!(wire::decode(&bad), Err(error));
        }
        let mut zero = bytes.clone();
        zero[8..16].fill(0);
        assert_eq!(wire::decode(&zero), Err(ProtocolError::InvalidField));
        let mut nul = bytes.clone();
        nul.push(0);
        assert_eq!(wire::decode(&nul), Err(ProtocolError::InvalidField));
        let mut utf8 = bytes.clone();
        *utf8.last_mut().unwrap() = 0xff;
        assert_eq!(wire::decode(&utf8), Err(ProtocolError::InvalidUtf8));
        let mut long = bytes.clone();
        long.resize(400, b'a');
        assert_eq!(wire::decode(&long), Err(ProtocolError::InvalidField));
        let req = wire::decode(&bytes).unwrap();
        assert!(wire::encode(&req, &mut vec![0; bytes.len() - 1]).is_err());
    }
}

#[test]
fn signed_ram_uses_the_broker_measured_full_digest_with_no_new_grants() {
    let signed = sign_adhoc(&fixture::unsigned()).unwrap();
    let raw: [u8; 32] = Sha256::digest(&signed).into();
    let (request, attached) = setup(signed);
    STATE.with_borrow_mut(|s| s.part_limit = 17);
    signed_image::authorize(77, &request, &attached).unwrap();
    STATE.with_borrow(|s| {
        assert!(s.reads > 2);
        assert_eq!(s.length_calls, 2);
        assert_eq!(s.issued.len(), 1);
        let (sender, identity, fields) = &s.issued[0];
        assert_eq!((*sender, identity.as_str()), (77, "opaque:signed"));
        let hex = raw.iter().map(|v| format!("{v:02x}")).collect::<String>();
        use mnu_abi::exec::*;
        assert_eq!(fields, format!("{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE_INHERIT}\0{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged\0{EXECUTABLE_DIGEST_PREFIX}{hex}\0\0").as_bytes());
    });
}

#[test]
fn unsigned_tampered_and_key_mismatched_images_never_receive_a_permit() {
    let unsigned = fixture::unsigned();
    let signed = sign_adhoc(&unsigned).unwrap();
    let mut tampered = signed.clone();
    tampered[0xf0] ^= 1;
    for bytes in [unsigned, tampered] {
        let (request, attached) = setup(bytes);
        assert_eq!(
            signed_image::authorize(77, &request, &attached),
            Err(SysError::from_raw(EACCES as i64))
        );
        no_issue();
    }
    let (request, attached) = setup(signed);
    let with_key = encode(
        wire::decode(&request).unwrap().source_length,
        Some(&[7; 32]),
    );
    assert!(signed_image::authorize(77, &with_key, &attached).is_err());
    no_issue();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let signed = sign_ed25519(&fixture::unsigned(), &key).unwrap();
    let length = signed.len() as u64;
    let (_, attached) = setup(signed);
    assert!(signed_image::authorize(77, &encode(length, None), &attached).is_err());
    no_issue();
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[8; 32])
        .verifying_key()
        .to_bytes();
    assert!(signed_image::authorize(77, &encode(length, Some(&wrong)), &attached).is_err());
    no_issue();
    let public = key.verifying_key().to_bytes();
    signed_image::authorize(77, &encode(length, Some(&public)), &attached).unwrap();
    STATE.with_borrow(|s| assert_eq!(s.issued.len(), 1));
}

#[test]
fn malformed_delivery_and_missing_authority_fail_before_any_ram_access() {
    for case in 0..11 {
        let (mut request, mut attached) = setup(sign_adhoc(&fixture::unsigned()).unwrap());
        match case {
            0 => attached.count = 0,
            1 => attached.count = 2,
            2 => attached.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            3 => attached.handles[0].handle = 0,
            4 => attached.handles[0].reserved = 1,
            5 => attached.handles[0].rights = mnu_abi::HANDLE_RIGHT_READ,
            6 => attached.handles[0].rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            7 => STATE.with_borrow_mut(|s| s.allowed = false),
            8 => request[4] = 99,
            9 => request[8..16].copy_from_slice(&u64::MAX.to_le_bytes()),
            _ => request[8..16].fill(0),
        }
        assert!(signed_image::authorize(77, &request, &attached).is_err());
        STATE.with_borrow(|s| {
            assert_eq!(s.length_calls, 0);
            assert_eq!(s.reads, 0);
        });
        no_issue();
    }
}

#[test]
fn providers_and_inconsistent_extents_are_rejected_without_provider_io() {
    for case in 0..2 {
        let (request, attached) = setup(sign_adhoc(&fixture::unsigned()).unwrap());
        STATE.with_borrow_mut(|s| match case {
            0 => s.length_error = Some(SysError::from(NativeError::InvalidArgument.into_raw())),
            _ => s.extent += 1,
        });
        assert!(signed_image::authorize(77, &request, &attached).is_err());
        STATE.with_borrow(|s| assert_eq!(s.reads, 0));
        no_issue();
    }
    // These are the production native type checks, not Provider metadata.
    let query = include_str!("../../../core/src/syscall/handle.rs")
        .split("pub fn memory_object_length(")
        .nth(1)
        .unwrap()
        .split("pub fn memory_object_resize(")
        .next()
        .unwrap();
    assert!(query.contains("object_native(raw, HandleRights::MAP)"));
    assert!(query.contains("KernelObject::VmObject(object)"));
    assert!(query.contains(".memory_length()"));
    let ram = include_str!("../../../core/src/mem/vm_object.rs")
        .split("pub fn memory_length(")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn resize_memory(")
        .next()
        .unwrap();
    assert!(ram.contains("VmObjectSource::Memory(memory) => Some(memory.length())"));
    assert!(ram.contains("_ => None"));
}

#[test]
fn snapshot_failures_and_native_authorization_errors_are_not_retried() {
    for case in 0..5 {
        let (request, attached) = setup(sign_adhoc(&fixture::unsigned()).unwrap());
        STATE.with_borrow_mut(|s| match case {
            0 => {
                s.bytes.truncate(17);
            }
            1 => s.bad_count = true,
            2 => s.grow = true,
            3 => s.read_error = Some(SysError::from(NativeError::BackingFailure.into_raw())),
            _ => s.issue_error = Some(SysError::from(NativeError::AccessDenied.into_raw())),
        });
        let error = signed_image::authorize(77, &request, &attached).unwrap_err();
        if case == 3 {
            assert_eq!(
                error,
                SysError::from(NativeError::BackingFailure.into_raw())
            );
        }
        if case == 4 {
            assert_eq!(error, SysError::from(NativeError::AccessDenied.into_raw()));
        }
        no_issue();
    }
}

#[test]
fn service_dispatch_releases_received_references_before_replying() {
    let source = include_str!("../../capability/src/server.rs");
    let branch = source
        .split("if opcode == platform::capability::signed_image::AUTHORIZE_OPCODE {")
        .nth(1)
        .unwrap()
        .split("continue;")
        .next()
        .unwrap();
    assert!(
        branch.find("crate::signed_image::authorize").unwrap()
            < branch.find("close_received_handles(&attached)").unwrap()
    );
    assert!(
        branch.find("close_received_handles(&attached)").unwrap()
            < branch.find("capability_reply").unwrap()
    );
}
