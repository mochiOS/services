extern crate self as mochi_user_platform;

use std::cell::RefCell;
pub mod syscall {
    pub use mnu_abi::{EINVAL, EIO};
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SysError(i64);
    impl SysError {
        pub fn from_raw(value: i64) -> Self {
            Self(value)
        }
    }
}

#[derive(Default)]
struct State {
    events: Vec<&'static str>,
    image: Vec<u8>,
    fail_read: bool,
    fail_create: bool,
    fail_identify: bool,
    fail_resume: bool,
    fail_terminate_once: bool,
    status_calls: usize,
    exited: bool,
    partial: bool,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn event(name: &'static str) {
    STATE.with_borrow_mut(|s| s.events.push(name));
}
fn error() -> syscall::SysError {
    syscall::SysError::from_raw(-5)
}

mod bootstrap_file {
    pub fn read_image(_: &str) -> Result<Vec<u8>, crate::syscall::SysError> {
        crate::event("read");
        if crate::STATE.with_borrow(|s| s.fail_read) {
            Err(crate::error())
        } else {
            Ok(b"exact image".to_vec())
        }
    }
}
pub mod random {
    pub fn fill(bytes: &mut [u8]) -> Result<(), crate::syscall::SysError> {
        crate::event("random");
        bytes.fill(7);
        Ok(())
    }
}
pub mod memory_object {
    pub struct MemoryObject;
    impl MemoryObject {
        pub fn create_resizable(length: u64) -> Result<Self, crate::syscall::SysError> {
            assert_eq!(length, b"exact image".len() as u64);
            crate::event("allocate");
            Ok(Self)
        }
        pub fn handle(&self) -> u32 {
            32
        }
    }
    impl Drop for MemoryObject {
        fn drop(&mut self) {
            crate::event("image close");
        }
    }
}
pub mod handle {
    pub fn write_at(
        handle: u32,
        bytes: &[u8],
        offset: u64,
    ) -> Result<usize, crate::syscall::SysError> {
        assert_eq!(handle, 32);
        crate::STATE.with_borrow_mut(|s| {
            assert_eq!(offset as usize, s.image.len());
            s.events.push("write");
            let count = bytes.len().min(if s.partial { 2 } else { bytes.len() });
            s.image.extend_from_slice(&bytes[..count]);
            Ok(count)
        })
    }
    pub fn close(handle: u32) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 9);
        crate::STATE.with_borrow_mut(|s| {
            if s.fail_identify || s.fail_resume {
                assert!(s.exited);
            }
            assert!(!s.events.contains(&"process close"));
            s.events.push("process close");
        });
        Ok(())
    }
}
pub mod process {
    pub struct Status {
        pub process_id: u64,
        pub state: u32,
    }
    pub fn create_stopped(image: u32, metadata: &[u8]) -> Result<u32, crate::syscall::SysError> {
        assert_eq!(image, 32);
        let request = mnu_abi::process_create::decode(metadata).unwrap();
        assert_eq!(request.identity, "/system/services/signature.service");
        assert_eq!(request.label, "signature.service");
        assert_eq!(request.handles().count(), 0);
        crate::event("create");
        if crate::STATE.with_borrow(|s| s.fail_create) {
            Err(crate::error())
        } else {
            Ok(9)
        }
    }
    pub fn handle_status(handle: u32) -> Result<Status, crate::syscall::SysError> {
        assert_eq!(handle, 9);
        crate::STATE.with_borrow_mut(|s| {
            s.events.push("status");
            s.status_calls += 1;
            if s.fail_identify && s.status_calls == 1 {
                return Err(crate::error());
            }
            Ok(Status {
                process_id: 99,
                state: if s.exited {
                    mnu_abi::PROCESS_STATE_EXITED
                } else {
                    mnu_abi::PROCESS_STATE_RUNNING
                },
            })
        })
    }
    pub fn resume_handle(handle: u32) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 9);
        crate::event("resume");
        if crate::STATE.with_borrow(|s| s.fail_resume) {
            Err(crate::error())
        } else {
            Ok(())
        }
    }
    pub fn terminate_handle(handle: u32, _: u64) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 9);
        crate::STATE.with_borrow_mut(|s| {
            s.events.push("terminate");
            if std::mem::take(&mut s.fail_terminate_once) {
                return Err(crate::error());
            }
            s.exited = true;
            Ok(())
        })
    }
}
pub mod thread {
    pub fn sleep_milliseconds(_: u64) -> Result<(), crate::syscall::SysError> {
        crate::event("sleep");
        Ok(())
    }
}
pub mod io {
    pub const STDERR: u64 = 2;
}
pub fn write_fmt(_: u64, _: std::fmt::Arguments<'_>) -> Result<(), syscall::SysError> {
    event("diagnostic");
    Ok(())
}

#[path = "../../capability/src/native_bootstrap.rs"]
mod production;

fn launch(denied: bool) -> Result<u64, syscall::SysError> {
    production::spawn(
        "/system/services/signature.service",
        &["42".into()],
        |bytes| {
            event("authorize");
            STATE.with_borrow(|s| assert_eq!(bytes, &s.image));
            if denied { Err(error()) } else { Ok(()) }
        },
    )
}

#[test]
fn exact_owned_image_is_authorized_before_create_and_resume() {
    STATE.set(State {
        partial: true,
        ..Default::default()
    });
    assert_eq!(launch(false), Ok(99));
    STATE.with_borrow(|s| {
        assert_eq!(s.image, b"exact image");
        let authorized = s.events.iter().position(|e| *e == "authorize").unwrap();
        assert_eq!(
            &s.events[authorized..],
            [
                "authorize",
                "create",
                "status",
                "resume",
                "process close",
                "image close"
            ]
        );
        assert!(s.events.iter().filter(|e| **e == "write").count() > 1);
    });
}

#[test]
fn read_or_authorization_failure_never_creates_a_process_or_uses_a_path_fallback() {
    STATE.set(State {
        fail_read: true,
        ..Default::default()
    });
    assert_eq!(launch(false), Err(error()));
    STATE.with_borrow(|s| assert_eq!(s.events, ["read"]));
    STATE.set(State::default());
    assert_eq!(launch(true), Err(error()));
    STATE.with_borrow(|s| {
        assert!(!s.events.contains(&"create"));
        assert_eq!(s.events.last(), Some(&"image close"));
    });
}

#[test]
fn failed_creation_closes_only_the_image_and_post_creation_failure_waits_for_exit() {
    STATE.set(State {
        fail_create: true,
        ..Default::default()
    });
    assert_eq!(launch(false), Err(error()));
    STATE.with_borrow(|s| assert!(!s.events.contains(&"process close")));
    for fail_identify in [false, true] {
        STATE.set(State {
            fail_identify,
            fail_resume: !fail_identify,
            fail_terminate_once: true,
            ..Default::default()
        });
        assert_eq!(launch(false), Err(error()));
        STATE.with_borrow(|s| {
            assert!(s.exited);
            assert_eq!(
                &s.events[s.events.len() - 2..],
                ["process close", "image close"]
            );
            assert!(s.events.iter().filter(|e| **e == "terminate").count() >= 2);
        });
    }
}

#[test]
fn bootstrap_service_policy_no_longer_calls_legacy_path_creation() {
    let source = include_str!("../../capability/src/service_bootstrap.rs");
    assert!(!source.contains("spawn_manifest("));
    assert!(!source.contains("encode_identity_args("));
    assert!(source.contains("authorize_spawn_image("));
    assert!(source.contains("native_bootstrap::spawn("));
}
