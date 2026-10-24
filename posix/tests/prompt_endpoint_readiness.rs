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
    foreign_sender: bool,
}
static STATE: Mutex<Option<State>> = Mutex::new(None);
static TEST_LOCK: Mutex<()> = Mutex::new(());
extern crate mochi_user_platform as mochi_user_platform_real;

pub mod service_ready {
    pub use mochi_user_platform_real::service_ready::*;
    pub fn generate_token() -> Result<u64, super::SysError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100);
        Ok(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
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
    pub fn endpoint_owner_process(_: u64) -> Result<u64, super::SysError> {
        Ok(
            if super::STATE
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|s| s.foreign_sender)
            {
                124
            } else {
                123
            },
        )
    }
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
        pub fn process_id(&self) -> Result<u64, ProcessWatchError> {
            Ok(123)
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
    let _serial = TEST_LOCK.lock().unwrap();
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

#[test]
fn network_endpoint_survives_interface_failure_without_turning_failed_health_into_ready() {
    let _serial = TEST_LOCK.lock().unwrap();
    let rights =
        handle::HANDLE_RIGHT_SEND | handle::HANDLE_RIGHT_DUPLICATE | handle::HANDLE_RIGHT_TRANSFER;
    for status in [0, -6, -5] {
        *STATE.lock().unwrap() = Some(State::default());
        let mut ready = readiness::ReadyHandshake::create().unwrap();
        let token = ready.target(readiness::ReadyService::Network).token;
        let (mut bytes, handles) = publication(token, rights);
        bytes.copy_from_slice(&service_ready::handle_notification(token, status));
        STATE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .messages
            .push_back((bytes, handles));
        let result = ready.wait_for_service_ready(
            readiness::ReadyService::Network,
            process_watch::ProcessWatchTarget::RetainedHandle(7),
        );
        assert_eq!(
            result,
            if status == 0 {
                Ok(())
            } else {
                Err(readiness::ReadyError::Failed(status))
            }
        );
        assert_eq!(
            ready
                .take_network_endpoint(process_watch::ProcessWatchTarget::RetainedHandle(7))
                .unwrap(),
            Some(41)
        );
        assert_eq!(
            ready
                .take_network_endpoint(process_watch::ProcessWatchTarget::RetainedHandle(7))
                .unwrap(),
            None
        );
        assert!(STATE.lock().unwrap().as_ref().unwrap().closed.is_empty());
    }
}
#[test]
fn early_network_publication_is_retained_while_waiting_for_another_service() {
    let _serial = TEST_LOCK.lock().unwrap();
    *STATE.lock().unwrap() = Some(State::default());
    let mut ready = readiness::ReadyHandshake::create().unwrap();
    let network = ready.target(readiness::ReadyService::Network).token;
    let input = ready.target(readiness::ReadyService::Input).token;
    let (_, handles) = publication(
        network,
        handle::HANDLE_RIGHT_SEND | handle::HANDLE_RIGHT_TRANSFER,
    );
    STATE.lock().unwrap().as_mut().unwrap().messages = VecDeque::from([
        (
            service_ready::handle_notification(network, -6).to_vec(),
            handles,
        ),
        (
            service_ready::notification(input, 0).to_vec(),
            ipc::IpcObjectHandles::default(),
        ),
    ]);
    assert_eq!(
        ready.wait_for_service_ready(
            readiness::ReadyService::Input,
            process_watch::ProcessWatchTarget::RetainedHandle(7)
        ),
        Ok(())
    );
    assert_eq!(
        ready.wait_for_service_ready(
            readiness::ReadyService::Network,
            process_watch::ProcessWatchTarget::RetainedHandle(7)
        ),
        Err(readiness::ReadyError::Failed(-6))
    );
    assert_eq!(
        ready
            .take_network_endpoint(process_watch::ProcessWatchTarget::RetainedHandle(7))
            .unwrap(),
        Some(41)
    );
}
#[test]
fn invalid_network_publications_are_closed_and_cannot_replace_a_retained_endpoint() {
    let _serial = TEST_LOCK.lock().unwrap();
    let rights = handle::HANDLE_RIGHT_SEND | handle::HANDLE_RIGHT_TRANSFER;
    for mode in 0..3 {
        *STATE.lock().unwrap() = Some(State::default());
        let mut ready = readiness::ReadyHandshake::create().unwrap();
        let network = ready.target(readiness::ReadyService::Network).token;
        let (mut bytes, mut handles) = publication(network, rights);
        match mode {
            0 => bytes.copy_from_slice(&service_ready::handle_notification(network, 1)),
            1 => handles.handles[0].rights |= handle::HANDLE_RIGHT_RECEIVE,
            _ => bytes.copy_from_slice(&service_ready::handle_notification(99999, 0)),
        }
        STATE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .messages
            .push_back((bytes, handles));
        assert_eq!(
            ready.wait_for_service_ready(
                readiness::ReadyService::Network,
                process_watch::ProcessWatchTarget::RetainedHandle(7)
            ),
            Err(readiness::ReadyError::InvalidMessage)
        );
        assert_eq!(
            ready
                .take_network_endpoint(process_watch::ProcessWatchTarget::RetainedHandle(7))
                .unwrap(),
            None
        );
        assert_eq!(STATE.lock().unwrap().as_ref().unwrap().closed, [41]);
    }
    *STATE.lock().unwrap() = Some(State::default());
    let mut ready = readiness::ReadyHandshake::create().unwrap();
    let network = ready.target(readiness::ReadyService::Network).token;
    let first = publication(network, rights);
    let (bytes, mut second) = publication(network, rights);
    second.handles[0].handle = 42;
    STATE.lock().unwrap().as_mut().unwrap().messages = VecDeque::from([first, (bytes, second)]);
    assert_eq!(
        ready.wait_for_service_ready(
            readiness::ReadyService::Input,
            process_watch::ProcessWatchTarget::RetainedHandle(7)
        ),
        Err(readiness::ReadyError::InvalidMessage)
    );
    assert_eq!(
        ready
            .take_network_endpoint(process_watch::ProcessWatchTarget::RetainedHandle(7))
            .unwrap(),
        Some(41)
    );
    assert_eq!(STATE.lock().unwrap().as_ref().unwrap().closed, [42]);
}

#[test]
fn a_valid_token_cannot_substitute_for_the_native_network_process_identity() {
    let _serial = TEST_LOCK.lock().unwrap();
    *STATE.lock().unwrap() = Some(State {
        foreign_sender: true,
        ..Default::default()
    });
    let mut ready = readiness::ReadyHandshake::create().unwrap();
    let token = ready.target(readiness::ReadyService::Network).token;
    STATE
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .messages
        .push_back(publication(
            token,
            handle::HANDLE_RIGHT_SEND | handle::HANDLE_RIGHT_TRANSFER,
        ));
    assert_eq!(
        ready.wait_for_service_ready(
            readiness::ReadyService::Network,
            process_watch::ProcessWatchTarget::RetainedHandle(7)
        ),
        Ok(())
    );
    assert_eq!(
        ready.take_network_endpoint(process_watch::ProcessWatchTarget::RetainedHandle(7)),
        Err(readiness::ReadyError::InvalidMessage)
    );
    assert_eq!(STATE.lock().unwrap().as_ref().unwrap().closed, [41]);
    assert_eq!(
        ready.take_network_endpoint(process_watch::ProcessWatchTarget::RetainedHandle(7)),
        Ok(None)
    );
}
