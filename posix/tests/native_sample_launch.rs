extern crate self as mochi_user_platform;
use std::cell::RefCell;

pub mod syscall {
    pub use mnu_abi::{EINVAL, EIO, ENOENT, EOVERFLOW};
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SysError(pub i64);
    impl SysError {
        pub fn from_raw(raw: i64) -> Self {
            Self(raw)
        }
    }
}
#[derive(Default)]
struct State {
    fail: Option<&'static str>,
    events: Vec<&'static str>,
    exited: bool,
    terminate_attempts: usize,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn step(name: &'static str) -> Result<(), syscall::SysError> {
    STATE.with_borrow_mut(|state| {
        state.events.push(name);
        if state.fail == Some(name) {
            state.fail = None;
            Err(syscall::SysError(mnu_abi::EIO as i64))
        } else {
            Ok(())
        }
    })
}
pub mod service {
    pub use mnu_abi::exec::ExecutionClass;
}
pub mod random {
    pub fn fill(bytes: &mut [u8]) -> Result<(), crate::syscall::SysError> {
        crate::step("random")?;
        bytes.fill(1);
        Ok(())
    }
}
pub mod capability {
    pub struct Image;
    impl Image {
        pub fn handle(&self) -> u32 {
            32
        }
    }
    impl Drop for Image {
        fn drop(&mut self) {
            crate::step("close image").unwrap();
        }
    }
    pub fn prepare_execution_image(
        endpoint: u32,
        path: &str,
        class: crate::service::ExecutionClass,
    ) -> Result<Image, crate::syscall::SysError> {
        assert_eq!(endpoint, 9);
        assert_eq!(path, "/image");
        assert_eq!(class, crate::service::ExecutionClass::Unprivileged);
        crate::step("prepare")?;
        Ok(Image)
    }
}
pub mod process {
    use crate::{STATE, step, syscall::SysError};
    pub fn find_by_name(name: &str) -> Result<u64, SysError> {
        assert_eq!(name, "capability.service");
        step("discover")?;
        Ok(9)
    }
    pub fn create_stopped(image: u32, metadata: &[u8]) -> Result<u32, SysError> {
        assert_eq!(image, 32);
        assert!(!metadata.is_empty());
        step("create")?;
        Ok(41)
    }
    pub fn handle_status(handle: u32) -> Result<mnu_abi::ProcessStatus, SysError> {
        assert_eq!(handle, 41);
        step("status")?;
        Ok(mnu_abi::ProcessStatus {
            process_id: 200,
            state: STATE.with_borrow(|state| {
                if state.exited {
                    mnu_abi::PROCESS_STATE_EXITED
                } else {
                    mnu_abi::PROCESS_STATE_RUNNING
                }
            }),
            ..Default::default()
        })
    }
    pub fn resume_handle(handle: u32) -> Result<(), SysError> {
        assert_eq!(handle, 41);
        step("resume")
    }
    pub fn wait_handle(handle: u32, deadline: u64) -> Result<mnu_abi::ProcessStatus, SysError> {
        assert_eq!(handle, 41);
        assert_eq!(deadline, mnu_abi::PROCESS_WAIT_INFINITE);
        step("wait")?;
        STATE.with_borrow_mut(|state| state.exited = true);
        handle_status(handle)
    }
    pub fn terminate_handle(handle: u32, code: u64) -> Result<(), SysError> {
        assert_eq!((handle, code), (41, 127));
        step("terminate")?;
        STATE.with_borrow_mut(|state| {
            state.terminate_attempts += 1;
            // A successful termination request is not proof of exit.
            state.exited = state.terminate_attempts >= 2;
        });
        Ok(())
    }
}
pub mod thread {
    pub fn sleep_milliseconds(ms: u64) -> Result<(), crate::syscall::SysError> {
        assert_eq!(ms, 1);
        crate::step("yield")
    }
}
pub mod handle {
    pub fn close(handle: u32) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 41);
        crate::STATE.with_borrow(|state| assert!(state.exited));
        crate::step("close child")
    }
}
#[path = "../../../core/examples/user/src/native_launch.rs"]
mod production;

#[test]
fn authorized_image_precedes_creation_and_wait_keeps_the_exact_child_reference() {
    STATE.set(State::default());
    let mut child = production::spawn("/image").unwrap();
    STATE.with_borrow(|state| {
        assert_eq!(
            state.events,
            [
                "discover",
                "random",
                "prepare",
                "create",
                "status",
                "resume",
                "close image"
            ]
        )
    });
    assert_eq!(child.wait(), Ok(0));
    drop(child);
    STATE.with_borrow(|state| {
        assert_eq!(state.events.last(), Some(&"close child"));
        assert_eq!(state.terminate_attempts, 0);
    });
}

#[test]
fn launch_failures_preserve_errors_and_reap_unconfirmed_children_before_close() {
    for stage in [
        "discover", "random", "prepare", "create", "status", "resume",
    ] {
        STATE.set(State {
            fail: Some(stage),
            ..Default::default()
        });
        assert_eq!(
            production::spawn("/image").err(),
            Some(syscall::SysError(mnu_abi::EIO as i64))
        );
        STATE.with_borrow(|state| {
            assert_eq!(
                state.events.contains(&"close child"),
                matches!(stage, "status" | "resume")
            );
            if matches!(stage, "status" | "resume") {
                assert_eq!(state.terminate_attempts, 2);
                assert_eq!(
                    state
                        .events
                        .iter()
                        .filter(|event| **event == "close child")
                        .count(),
                    1
                );
            }
            assert_eq!(
                state.events.contains(&"close image"),
                matches!(stage, "create" | "status" | "resume")
            );
        });
    }
}

#[test]
fn early_drop_and_failed_wait_terminate_and_confirm_exit_before_releasing_owner() {
    for wait in [false, true] {
        STATE.set(State::default());
        let mut child = production::spawn("/image").unwrap();
        if wait {
            STATE.with_borrow_mut(|state| state.fail = Some("wait"));
            assert!(child.wait().is_err());
        }
        drop(child);
        STATE.with_borrow(|state| {
            assert_eq!(state.terminate_attempts, 2);
            assert_eq!(state.events.last(), Some(&"close child"));
        });
    }
}

#[test]
fn sample_does_not_select_child_capabilities_or_keep_the_retired_launch_abi() {
    let source = include_str!("../../../core/examples/user/src/lib.rs");
    assert!(source.contains("native_launch::spawn(path)"));
    assert!(source.contains("matches!(error.errno(), Some(1 | 13))"));
    assert!(source.contains("driver.wait()"));
    for obsolete in ["SYS_EXEC_MANIFEST", "exec_with_capabilities", "caps_buf"] {
        assert!(
            !source.contains(obsolete),
            "legacy sample launch: {obsolete}"
        );
    }
    let launch = include_str!("../../../core/examples/user/src/native_launch.rs");
    assert!(launch.contains("prepare_execution_image("));
    assert!(launch.contains("create_with_rollback("));
    assert!(!launch.contains("open_handle_for_process_id"));
}
