extern crate self as mochi_user_platform;
use std::{cell::RefCell, collections::BTreeMap};

pub mod syscall {
    pub use mochi_user_syscall::{EACCES, EINVAL, EIO, ENOENT};
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SysError(pub i64);
    impl SysError {
        pub fn from_raw(value: i64) -> Self {
            Self(value)
        }
    }
}
#[derive(Default)]
struct State {
    denied: Option<&'static str>,
    events: Vec<&'static str>,
    image: Vec<u8>,
    closed: Vec<u32>,
    fail_authorize: bool,
    fail_read: bool,
    fail_write: bool,
    reply: Reply,
}
struct Reply {
    count: u32,
    flags: u32,
    reserved: u32,
    rights: u64,
    actual_rights: u64,
    status: u64,
    length: u32,
    fail_call: bool,
    duplicate: bool,
}
impl Default for Reply {
    fn default() -> Self {
        Self {
            count: 1,
            flags: 0,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_READ,
            actual_rights: mnu_abi::HANDLE_RIGHT_READ,
            status: 0,
            length: 8,
            fail_call: false,
            duplicate: false,
        }
    }
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn event(value: &'static str) {
    STATE.with_borrow_mut(|s| s.events.push(value));
}
fn error(value: u64) -> syscall::SysError {
    syscall::SysError::from_raw(value as i64)
}

pub mod service {
    pub use mnu_abi::exec::ExecutionClass;
}
pub mod capability {
    pub use mochios_capability_protocol::{
        decode_prepare_execution_image_reply, encode_prepare_execution_image_request,
    };
    pub fn check_thread(sender: u64, capability: &str) -> Result<u64, crate::syscall::SysError> {
        assert_eq!(sender, 17);
        Ok(crate::STATE.with_borrow(|s| u64::from(s.denied != Some(capability))))
    }
}
pub mod memory_object {
    pub struct MemoryObject;
    impl MemoryObject {
        pub fn create_resizable(length: u64) -> Result<Self, crate::syscall::SysError> {
            assert_eq!(length, 5);
            crate::event("allocate");
            Ok(Self)
        }
        pub fn handle(&self) -> u32 {
            32
        }
    }
    impl Drop for MemoryObject {
        fn drop(&mut self) {
            crate::event("source close");
        }
    }
}
pub mod handle {
    pub use mnu_abi::HANDLE_RIGHT_READ;
    pub fn write_at(
        handle: u32,
        bytes: &[u8],
        offset: u64,
    ) -> Result<usize, crate::syscall::SysError> {
        assert_eq!(handle, 32);
        crate::STATE.with_borrow_mut(|s| {
            if s.fail_write {
                return Err(crate::error(mochi_user_syscall::EIO));
            }
            assert_eq!(s.image.len(), offset as usize);
            let count = bytes.len().min(2);
            s.image.extend_from_slice(&bytes[..count]);
            s.events.push("write");
            Ok(count)
        })
    }
    pub fn close(handle: u32) -> Result<(), crate::syscall::SysError> {
        crate::STATE.with_borrow_mut(|s| {
            assert!(!s.closed.contains(&handle));
            s.closed.push(handle);
        });
        Ok(())
    }
    pub fn rights(_: u32) -> Result<u64, crate::syscall::SysError> {
        Ok(crate::STATE.with_borrow(|s| s.reply.actual_rights))
    }
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
        assert_eq!(handles.count, 0);
        let (class, path) =
            mochios_capability_protocol::decode_prepare_execution_image_request(request).unwrap();
        assert_eq!((class, path), (2, "/image"));
        crate::STATE.with_borrow(|s| {
            if s.reply.fail_call {
                return Err(crate::error(mochi_user_syscall::EIO));
            }
            reply.copy_from_slice(&s.reply.status.to_le_bytes());
            handles.count = s.reply.count;
            handles.delivery_flags = s.reply.flags;
            for (index, slot) in handles
                .handles
                .iter_mut()
                .take(s.reply.count as usize)
                .enumerate()
            {
                *slot = IpcObjectHandle {
                    handle: if s.reply.duplicate {
                        32
                    } else {
                        32 + index as u32
                    },
                    rights: s.reply.rights,
                    reserved: s.reply.reserved,
                };
            }
            Ok(u64::from(s.reply.length))
        })
    }
}
mod state {
    pub struct Record {
        pub manifest: (),
        pub manifest_path: String,
    }
    pub struct Index {
        pub by_binary: std::collections::BTreeMap<String, Record>,
    }
    pub struct CapabilityServiceState {
        pub package_index: Index,
    }
}
mod resolver {
    use crate::syscall::SysError;
    pub type FileReader = fn(&str) -> Result<Vec<u8>, SysError>;
    pub fn binary_caps<'a>(
        _: &'a (),
        _: &str,
        _: &str,
        _: FileReader,
    ) -> Result<&'a [String], SysError> {
        crate::event("verify caps");
        Ok(&[])
    }
    pub fn application_identity(_: &(), _: &str, _: FileReader) -> Result<(), SysError> {
        crate::event("verify identity");
        Ok(())
    }
    pub fn authorize_spawn_image(
        sender: u64,
        path: &str,
        _: &(),
        _: &[String],
        _: crate::service::ExecutionClass,
        bytes: &[u8],
    ) -> Result<(), SysError> {
        assert_eq!((sender, path), (17, "/image"));
        crate::STATE.with_borrow_mut(|s| {
            assert_eq!(bytes, &s.image);
            s.events.push("authorize");
            if s.fail_authorize {
                Err(crate::error(mochi_user_syscall::EACCES))
            } else {
                Ok(())
            }
        })
    }
}
fn read(_: &str) -> Result<Vec<u8>, syscall::SysError> {
    event("read");
    if STATE.with_borrow(|s| s.fail_read) {
        Err(error(mochi_user_syscall::EIO))
    } else {
        Ok(b"image".to_vec())
    }
}
fn fixture() -> state::CapabilityServiceState {
    state::CapabilityServiceState {
        package_index: state::Index {
            by_binary: BTreeMap::from([(
                "/image".into(),
                state::Record {
                    manifest: (),
                    manifest_path: "/manifest".into(),
                },
            )]),
        },
    }
}

#[path = "../../../user/crates/platform/src/capability/prepared_image.rs"]
mod client;
#[path = "../../capability/src/prepared_image.rs"]
mod server;

#[test]
fn oversized_image_uses_userspace_file_size_status_before_allocating_or_authorizing() {
    fn oversized_read(_: &str) -> Result<Vec<u8>, syscall::SysError> {
        event("read oversized");
        Ok(vec![0; 64 * 1024 * 1024 + 1])
    }
    STATE.set(State::default());
    assert_eq!(
        server::prepare(&fixture(), 17, 2, "/image", oversized_read).err(),
        Some(syscall::SysError(mochios_posix_protocol::STATUS_EFBIG as i64))
    );
    STATE.with_borrow(|state| {
        assert!(state.events.contains(&"read oversized"));
        assert!(!state.events.contains(&"allocate"));
        assert!(!state.events.contains(&"authorize"));
    });
}

#[test]
fn image_preparation_requires_all_authenticated_authority_before_reading() {
    for denied in ["capabilities.manage", "fs.read.all", "process.spawn"] {
        STATE.set(State {
            denied: Some(denied),
            ..Default::default()
        });
        assert_eq!(
            server::prepare(&fixture(), 17, 2, "/image", read).err(),
            Some(error(mochi_user_syscall::EACCES))
        );
        STATE.with_borrow(|s| assert!(s.events.is_empty()));
    }
}

#[test]
fn copied_snapshot_is_authorized_and_every_preparation_failure_releases_ownership() {
    STATE.set(State::default());
    let image = server::prepare(&fixture(), 17, 2, "/image", read).unwrap();
    STATE.with_borrow(|s| {
        assert_eq!(s.image, b"image");
        assert_eq!(s.events.last(), Some(&"authorize"));
    });
    drop(image);
    STATE.with_borrow(|s| assert_eq!(s.events.last(), Some(&"source close")));
    for step in 0..3 {
        STATE.set(State {
            fail_read: step == 0,
            fail_write: step == 1,
            fail_authorize: step == 2,
            ..Default::default()
        });
        assert!(server::prepare(&fixture(), 17, 2, "/image", read).is_err());
        STATE.with_borrow(|s| {
            if step == 0 {
                assert!(!s.events.contains(&"allocate"));
            } else {
                assert_eq!(s.events.last(), Some(&"source close"));
            }
        });
    }
}

#[test]
fn receiver_owns_exactly_one_read_only_reference_until_drop() {
    STATE.set(State::default());
    let image = client::prepare_execution_image(9, "/image", service::ExecutionClass::Privileged).unwrap();
    assert_eq!(image.handle(), 32);
    STATE.with_borrow(|s| assert!(s.closed.is_empty()));
    drop(image);
    STATE.with_borrow(|s| assert_eq!(s.closed, [32]));
}

#[test]
fn malformed_or_overprivileged_replies_close_all_received_references_once() {
    STATE.set(State {
        reply: Reply {
            status: 13,
            count: 0,
            ..Default::default()
        },
        ..Default::default()
    });
    assert_eq!(
        client::prepare_execution_image(9, "/image", service::ExecutionClass::Privileged).err(),
        Some(error(mochi_user_syscall::EACCES))
    );
    STATE.with_borrow(|s| assert!(s.closed.is_empty()));
    for invalid in 0..8 {
        let mut reply = Reply::default();
        match invalid {
            0 => reply.length = 7,
            1 => reply.flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            2 => reply.count = 2,
            3 => {
                reply.count = 2;
                reply.duplicate = true;
            }
            4 => reply.rights |= mnu_abi::HANDLE_RIGHT_TRANSFER,
            5 => reply.actual_rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            6 => reply.reserved = 1,
            _ => reply.status = u64::MAX,
        }
        STATE.set(State {
            reply,
            ..Default::default()
        });
        assert!(client::prepare_execution_image(9, "/image", service::ExecutionClass::Privileged).is_err());
        STATE.with_borrow(|s| {
            assert_eq!(s.closed, if invalid == 2 { vec![32, 33] } else { vec![32] })
        });
    }
    STATE.set(State {
        reply: Reply {
            fail_call: true,
            ..Default::default()
        },
        ..Default::default()
    });
    assert!(client::prepare_execution_image(9, "/image", service::ExecutionClass::Privileged).is_err());
    STATE.with_borrow(|s| assert!(s.closed.is_empty()));
}

#[test]
fn image_protocol_has_a_version_no_pid_and_strict_bounds() {
    use mochios_capability_protocol::*;
    let bytes = encode_prepare_execution_image_request(2, "/image").unwrap();
    assert_eq!(bytes.len(), 16 + "/image".len());
    assert_eq!(
        decode_prepare_execution_image_request(&bytes),
        Ok((2, "/image"))
    );
    let mut invalid = bytes.clone();
    invalid[4..8].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(
        decode_prepare_execution_image_request(&invalid),
        Err(ProtocolError::UnsupportedVersion)
    );
    assert!(encode_prepare_execution_image_request(1, "/image").is_err());
    assert!(encode_prepare_execution_image_request(2, &"x".repeat(300)).is_err());
    assert!(decode_prepare_execution_image_reply(&[0; 7]).is_err());
    assert_eq!(
        decode_prepare_execution_image_reply(&13u64.to_le_bytes()),
        Ok(13)
    );
}

#[test]
fn namespace_launch_uses_the_prepared_handle_without_a_path_launch_fallback() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let spawn = launcher
        .split("fn spawn(")
        .nth(1)
        .unwrap()
        .split("fn reap_namespace_launch")
        .next()
        .unwrap();
    assert!(spawn.contains("prepare_execution_image(spec.path, spec.execution_class)?"));
    assert!(spawn.contains("NativeProcess::create_with_rollback("));
    assert!(spawn.contains("image.handle()"));
    for obsolete in ["spawn_manifest", "encode_spawn_args", "security_identity"] {
        assert!(
            !launcher.contains(obsolete),
            "legacy launch dependency: {obsolete}"
        );
    }

    let server = include_str!("../../capability/src/server.rs");
    let request_gate = server.find("!attached.is_user_delivery()").unwrap();
    let dispatch = server
        .find("if opcode == platform::capability::PREPARE_EXECUTION_IMAGE_OPCODE")
        .unwrap();
    assert!(request_gate < dispatch);
    let dispatch = server[dispatch..].split("continue;").next().unwrap();
    assert!(dispatch.contains("crate::prepared_image::prepare("));
    assert!(dispatch.contains("sender,"));
    assert!(dispatch.contains("rights: platform::handle::HANDLE_RIGHT_READ,"));
    assert!(dispatch.contains("platform::ipc::reply_object_handles("));
}
