//! Exercise the production filesystem coordinator. Native calls are scripted;
//! the real native FIFO/VM implementation has separate integration probes.
extern crate self as mnu_abi;
extern crate self as mochi_user_platform;
extern crate self as mochios_filesystem_protocol;
#[path = "../../../core/crates/abi/src/status.rs"]
pub mod status;

pub const ERROR_MEMORY_ADMISSION_BUSY: i32 = 0x10002;
pub const HANDLE_SIGNAL_READABLE: u64 = 1;
pub const HANDLE_SIGNAL_PEER_CLOSED: u64 = 8;

use std::cell::RefCell;
use std::collections::VecDeque;

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Create(u64),
    Prepare(u64, u64, u64, u32),
    Poll(u32),
    Close(u32),
}

struct Script {
    prepare: Result<(), i32>,
    poll: Result<u64, i32>,
    create: VecDeque<Result<u32, i32>>,
    calls: Vec<Call>,
}
thread_local! {
    static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
}
fn script<T>(f: impl FnOnce(&mut Script) -> T) -> T {
    SCRIPT.with(|state| f(state.borrow_mut().as_mut().unwrap()))
}
fn setup(prepare: Result<(), i32>, poll: Result<u64, i32>) {
    SCRIPT.with(|state| {
        *state.borrow_mut() = Some(Script {
            prepare,
            poll,
            create: VecDeque::from([Ok(100), Ok(101)]),
            calls: vec![],
        })
    });
}

pub mod syscall {
    #[derive(Clone, Copy)]
    pub struct SysError(pub i32);
    impl SysError {
        pub fn native_error(self) -> Option<crate::status::Error> {
            crate::status::Error::from_raw(i64::from(self.0) as u64)
        }
        pub fn errno(self) -> Option<u64> {
            if crate::status::is_error(i64::from(self.0) as u64) {
                None
            } else {
                Some(self.0 as u64)
            }
        }
    }
    #[derive(Default)]
    pub struct HandleWaitItem {
        pub handle: u32,
        pub interests: u64,
        pub observed: u64,
        pub minimum_write_bytes: u32,
    }
}
pub mod handle {
    use super::{Call, script, syscall::SysError};
    pub type Handle = u32;
    pub struct ProviderMemoryAdmission(pub u32);
    impl ProviderMemoryAdmission {
        pub fn handle(&self) -> u32 {
            self.0
        }
    }
    impl Drop for ProviderMemoryAdmission {
        fn drop(&mut self) {
            script(|s| s.calls.push(Call::Close(self.0)));
        }
    }
    pub struct ProviderMemoryUpdate;
    impl ProviderMemoryUpdate {
        pub fn begin(&mut self) -> Result<(), SysError> {
            panic!("preparation must not BEGIN")
        }
        pub fn publish(&mut self) -> Result<(), SysError> {
            panic!("preparation must not PUBLISH")
        }
    }
    pub fn create_provider_memory_admission(
        endpoint: u32,
        id: u64,
    ) -> Result<ProviderMemoryAdmission, SysError> {
        assert_eq!(endpoint, 77);
        script(|s| {
            s.calls.push(Call::Create(id));
            s.create
                .pop_front()
                .expect("unbounded re-admission")
                .map(ProviderMemoryAdmission)
                .map_err(SysError)
        })
    }
    pub fn prepare_provider_memory_update_admitted(
        endpoint: u32,
        id: u64,
        old: u64,
        new: u64,
        ticket: u32,
    ) -> Result<ProviderMemoryUpdate, SysError> {
        assert_eq!(endpoint, 77);
        script(|s| {
            s.calls.push(Call::Prepare(id, old, new, ticket));
            s.prepare.map(|()| ProviderMemoryUpdate).map_err(SysError)
        })
    }
    pub fn prepare_provider_memory_update(
        _: u32,
        _: u64,
        _: u64,
        _: u64,
    ) -> Result<ProviderMemoryUpdate, SysError> {
        panic!("queued preparation must not use unordered legacy path")
    }
}
pub mod process {
    use super::{
        Call, script,
        syscall::{HandleWaitItem, SysError},
    };
    pub fn wait_many(items: &mut [HandleWaitItem], deadline: u64) -> Result<usize, SysError> {
        assert_eq!(deadline, 0, "filesystem must never sleep");
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].interests,
            super::HANDLE_SIGNAL_READABLE | super::HANDLE_SIGNAL_PEER_CLOSED
        );
        script(|s| {
            s.calls.push(Call::Poll(items[0].handle));
            s.poll
                .map(|signals| {
                    items[0].observed = signals;
                    0
                })
                .map_err(SysError)
        })
    }
}

#[path = "../../filesystem/src/memory_updates.rs"]
mod coordinator;
use coordinator::{MemoryUpdates, Preparation, ProviderUpdates};

fn prepare(incoming: Option<u32>) -> Result<Preparation, i32> {
    ProviderUpdates::new(77).prepare_admitted(9, 8192, 5000, incoming)
}
fn waiting(result: Result<Preparation, i32>) -> coordinator::AdmissionReference {
    match result {
        Ok(Preparation::Wait(ticket)) => ticket,
        _ => panic!("expected wait"),
    }
}
fn calls(expected: &[Call]) {
    script(|s| assert_eq!(s.calls, expected));
}

#[test]
fn fresh_position_is_owned_and_cancellation_closes_it() {
    setup(Err(11), Err(11));
    let ticket = waiting(prepare(None));
    assert_eq!(ticket.handle(), 100);
    drop(ticket);
    calls(&[
        Call::Create(9),
        Call::Prepare(9, 8192, 5000, 100),
        Call::Poll(100),
        Call::Close(100),
    ]);
}

#[test]
fn borrowed_position_survives_pending_or_ready_preparation_contention() {
    for poll in [Err(11), Ok(HANDLE_SIGNAL_READABLE)] {
        setup(Err(11), poll);
        let ticket = waiting(prepare(Some(42)));
        assert_eq!(ticket.handle(), 42);
        drop(ticket);
        calls(&[Call::Prepare(9, 8192, 5000, 42), Call::Poll(42)]);
    }
}

#[test]
fn success_returns_update_without_beginning_storage_or_waiting() {
    for incoming in [None, Some(42)] {
        setup(Ok(()), Err(5));
        assert!(matches!(prepare(incoming), Ok(Preparation::Ready(_))));
        if incoming.is_none() {
            calls(&[
                Call::Create(9),
                Call::Prepare(9, 8192, 5000, 100),
                Call::Close(100),
            ]);
        } else {
            calls(&[Call::Prepare(9, 8192, 5000, 42)]);
        }
    }
}

#[test]
fn consumed_position_is_replaced_before_it_is_returned() {
    for incoming in [None, Some(42)] {
        setup(Err(11), Ok(HANDLE_SIGNAL_PEER_CLOSED));
        let ticket = waiting(prepare(incoming));
        assert_eq!(ticket.handle(), if incoming.is_some() { 100 } else { 101 });
        drop(ticket);
        if incoming.is_none() {
            calls(&[
                Call::Create(9),
                Call::Prepare(9, 8192, 5000, 100),
                Call::Poll(100),
                Call::Create(9),
                Call::Close(100),
                Call::Close(101),
            ]);
        } else {
            calls(&[
                Call::Prepare(9, 8192, 5000, 42),
                Call::Poll(42),
                Call::Create(9),
                Call::Close(100),
            ]);
        }
    }
}

#[test]
fn only_a_borrowed_mismatched_key_can_be_rescoped_after_authorization() {
    setup(Err(13), Err(5));
    drop(waiting(prepare(Some(42))));
    calls(&[
        Call::Prepare(9, 8192, 5000, 42),
        Call::Create(9),
        Call::Close(100),
    ]);
    setup(Err(13), Err(5));
    assert!(matches!(prepare(None), Err(13)));
    calls(&[
        Call::Create(9),
        Call::Prepare(9, 8192, 5000, 100),
        Call::Close(100),
    ]);
}

#[test]
fn errors_do_not_replay_or_close_a_borrowed_reference() {
    for error in [5, 9, 12, 22, 95] {
        setup(Err(error), Err(5));
        assert!(matches!(prepare(Some(42)), Err(actual) if actual == error));
        calls(&[Call::Prepare(9, 8192, 5000, 42)]);
    }
}

#[test]
fn polling_failure_or_invalid_readiness_does_not_leak_owned_position() {
    for poll in [Err(3), Err(5), Ok(0)] {
        setup(Err(11), poll);
        assert!(matches!(prepare(None), Err(3 | 5)));
        calls(&[
            Call::Create(9),
            Call::Prepare(9, 8192, 5000, 100),
            Call::Poll(100),
            Call::Close(100),
        ]);
    }
}

#[test]
fn allocation_failure_does_not_leak_or_reuse_consumed_position() {
    setup(Err(11), Ok(HANDLE_SIGNAL_PEER_CLOSED));
    script(|s| s.create = VecDeque::from([Ok(100), Err(12)]));
    assert!(matches!(prepare(None), Err(12)));
    calls(&[
        Call::Create(9),
        Call::Prepare(9, 8192, 5000, 100),
        Call::Poll(100),
        Call::Create(9),
        Call::Close(100),
    ]);
    setup(Ok(()), Err(5));
    script(|s| s.create = VecDeque::from([Err(12)]));
    assert!(matches!(prepare(None), Err(12)));
    calls(&[Call::Create(9)]);
}

#[test]
fn unsupported_backend_cannot_silently_drop_admission() {
    struct Legacy;
    impl MemoryUpdates for Legacy {
        fn prepare(&self, _: u64, _: u64, _: u64) -> Result<Box<dyn coordinator::Update>, i32> {
            panic!("must not silently fall back")
        }
    }
    assert!(matches!(
        Legacy.prepare_admitted(9, 8192, 5000, None),
        Err(95)
    ));
    assert!(matches!(
        Legacy.prepare_admitted(9, 8192, 5000, Some(42)),
        Err(95)
    ));
}

#[test]
fn native_busy_and_denied_statuses_preserve_borrowed_ticket_policy() {
    setup(Err(status::Error::NotReady.into_raw() as i32), Err(11));
    drop(waiting(prepare(Some(42))));
    calls(&[Call::Prepare(9, 8192, 5000, 42), Call::Poll(42)]);

    setup(Err(status::Error::AccessDenied.into_raw() as i32), Err(5));
    drop(waiting(prepare(Some(42))));
    calls(&[
        Call::Prepare(9, 8192, 5000, 42),
        Call::Create(9),
        Call::Close(100),
    ]);
}

#[test]
fn native_terminal_failures_are_translated_without_retry_or_ticket_replacement() {
    for (native, expected) in [
        (status::Error::LimitExceeded, 75),
        (status::Error::InvalidAddress, 14),
        (status::Error::ResourceUnavailable, 12),
        (status::Error::BackingFailure, 5),
        (status::Error::InvalidArgument, 22),
    ] {
        setup(Err(native.into_raw() as i32), Err(5));
        assert!(matches!(prepare(Some(42)), Err(error) if error == expected));
        calls(&[Call::Prepare(9, 8192, 5000, 42)]);
    }
    setup(Ok(()), Err(5));
    script(|s| {
        s.create = VecDeque::from([Err(status::Error::ResourceUnavailable.into_raw() as i32)])
    });
    assert!(matches!(prepare(None), Err(12)));
    calls(&[Call::Create(9)]);
}
