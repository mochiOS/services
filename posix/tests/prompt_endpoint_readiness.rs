extern crate alloc;
extern crate self as mochi_user_platform;
extern crate self as mochi_user_syscall;

use std::collections::VecDeque;
use std::sync::Mutex;

pub use mochi_user_platform_real::syscall::NativeError;
#[derive(Debug)]
pub struct SysError;
impl SysError {
    pub fn raw(&self) -> i64 {
        NativeError::NotReady.into_raw() as i64
    }
    pub fn native_error(&self) -> Option<NativeError> {
        Some(NativeError::NotReady)
    }
}

#[derive(Default)]
struct State {
    messages: VecDeque<(Vec<u8>, mochi_user_platform_real::ipc::IpcObjectHandles)>,
    closed: Vec<u32>,
    ticks: u64,
    exited: bool,
}
static STATE: Mutex<Option<State>> = Mutex::new(None);
extern crate mochi_user_platform as mochi_user_platform_real;

pub mod service_ready {
    pub use mochi_user_platform_real::service_ready::*;
}
pub mod service {
    pub use mochi_user_platform_real::service::*;
}
pub mod handle {
    pub use mochi_user_platform_real::handle::*;
    pub fn close(handle: u32) -> Result<(), super::SysError> {
        super::STATE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .closed
            .push(handle);
        Ok(())
    }
}
pub mod ipc {
    pub use mochi_user_platform_real::ipc::{IpcObjectHandle, IpcObjectHandles};
    pub fn create() -> Result<u64, super::SysError> {
        Ok(999)
    }
    pub fn try_wait_object_handles(
        bytes: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> Result<u64, super::SysError> {
        let mut state = super::STATE.lock().unwrap();
        let Some((message, attached)) = state.as_mut().unwrap().messages.pop_front() else {
            return Err(super::SysError);
        };
        bytes[..message.len()].copy_from_slice(&message);
        *handles = attached;
        Ok((99 << 32) | message.len() as u64)
    }
}
pub mod time {
    pub fn ticks() -> Result<u64, super::SysError> {
        Ok(super::STATE.lock().unwrap().as_ref().unwrap().ticks)
    }
}
pub mod thread {
    pub fn yield_now() {
        super::STATE.lock().unwrap().as_mut().unwrap().ticks += 1000;
    }
}
pub mod process_watch {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ProcessWatchError;
    #[derive(Clone, Copy)]
    pub enum ProcessWatchTarget {
        RetainedHandle(u32),
    }
    impl From<u64> for ProcessWatchTarget {
        fn from(_: u64) -> Self {
            panic!("legacy watch must not be used")
        }
    }
    pub struct ProcessWatch;
    impl ProcessWatch {
        pub fn open(target: impl Into<ProcessWatchTarget>) -> Result<Self, ProcessWatchError> {
            let ProcessWatchTarget::RetainedHandle(handle) = target.into();
            assert_eq!(handle, 7);
            Ok(Self)
        }
        pub fn exit_status(&self) -> Result<Option<i32>, ProcessWatchError> {
            Ok(super::STATE
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .exited
                .then_some(127))
        }
    }
}
#[path = "../../service-manager/src/readiness.rs"]
#[allow(dead_code)]
mod readiness;
#[path = "../../service-manager/src/service_config.rs"]
#[allow(dead_code)]
mod service_config;

fn publication(token: u64, rights: u64) -> (Vec<u8>, ipc::IpcObjectHandles) {
    let mut handles = ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0] = ipc::IpcObjectHandle {
        handle: 41,
        reserved: 0,
        rights,
    };
    (
        service_ready::handle_notification(token, 0).to_vec(),
        handles,
    )
}

#[test]
fn one_shot_publication_preserves_requests_and_fails_closed() {
    let rights = handle::HANDLE_RIGHT_SEND | handle::HANDLE_RIGHT_TRANSFER;
    let target = process_watch::ProcessWatchTarget::RetainedHandle(7);
    let mut deferred = VecDeque::new();
    *STATE.lock().unwrap() = Some(State {
        messages: VecDeque::from([
            (
                b"pending portal request".to_vec(),
                ipc::IpcObjectHandles::default(),
            ),
            publication(123, rights),
        ]),
        ..Default::default()
    });
    assert_eq!(
        readiness::wait_for_published_endpoint(123, target, &mut deferred),
        Ok(41)
    );
    let pending = deferred.pop_front().unwrap();
    assert_eq!(pending.sender, 99);
    assert_eq!(pending.bytes, b"pending portal request");
    assert!(STATE.lock().unwrap().as_ref().unwrap().closed.is_empty());

    for (token, rights) in [(124, rights), (123, rights | handle::HANDLE_RIGHT_RECEIVE)] {
        *STATE.lock().unwrap() = Some(State {
            messages: VecDeque::from([publication(token, rights)]),
            ..Default::default()
        });
        assert_eq!(
            readiness::wait_for_published_endpoint(123, target, &mut deferred),
            Err(readiness::ReadyError::InvalidMessage)
        );
        assert_eq!(STATE.lock().unwrap().as_ref().unwrap().closed, [41]);
    }
    *STATE.lock().unwrap() = Some(State::default());
    assert_eq!(
        readiness::wait_for_published_endpoint(123, target, &mut deferred),
        Err(readiness::ReadyError::TimedOut)
    );
    *STATE.lock().unwrap() = Some(State {
        exited: true,
        ..Default::default()
    });
    assert_eq!(
        readiness::wait_for_published_endpoint(123, target, &mut deferred),
        Err(readiness::ReadyError::ProcessExited(127))
    );
}
