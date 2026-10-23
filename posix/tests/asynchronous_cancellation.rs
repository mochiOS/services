//! Actual async eligibility and native notification policy. Cleanup after
//! actual upcalls is tested by native_async_cancel.c, not this host model.
#![allow(dead_code)]
use std::{
    ffi::{c_int, c_void},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};
const ESRCH: c_int = 3;
const PTHREAD_CANCEL_ENABLE: u32 = 0;
const PTHREAD_CANCEL_ASYNCHRONOUS: u32 = 1;
struct Resources(AtomicBool);
impl Resources {
    fn is_deferred(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
struct ThreadControl {
    cancel_state: AtomicU32,
    cancel_type: AtomicU32,
    cancel_pending: AtomicU32,
    native_handle: AtomicU32,
    native_delivery_defer: AtomicU32,
    callback_resources: Resources,
}
static CONTROL: ThreadControl = ThreadControl {
    cancel_state: AtomicU32::new(0),
    cancel_type: AtomicU32::new(1),
    cancel_pending: AtomicU32::new(1),
    native_handle: AtomicU32::new(77),
    native_delivery_defer: AtomicU32::new(0),
    callback_resources: Resources(AtomicBool::new(false)),
};
static FOUND: AtomicBool = AtomicBool::new(true);
static INTERRUPTS: AtomicU32 = AtomicU32::new(0);
static ERROR: Mutex<Option<mnu_abi::status::Error>> = Mutex::new(None);
static SERIAL: Mutex<()> = Mutex::new(());
fn current_thread_control() -> Option<(u32, &'static ThreadControl)> {
    FOUND.load(Ordering::Acquire).then_some((64, &CONTROL))
}
#[derive(Debug)]
struct Cancelled;
fn finish_thread(control: &ThreadControl, value: *mut c_void) -> ! {
    assert!(std::ptr::eq(control, &CONTROL));
    assert_eq!(value as usize, usize::MAX);
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire), 0);
    assert!(!CONTROL.callback_resources.is_deferred());
    std::panic::panic_any(Cancelled)
}
fn map_kernel_errno(_: i64) -> c_int {
    13
}
struct Error(mnu_abi::status::Error);
impl Error {
    fn native_error(&self) -> Option<mnu_abi::status::Error> {
        Some(self.0)
    }
    fn raw(&self) -> i64 {
        self.0.into_raw() as i64
    }
}
struct Return(Result<u64, Error>);
impl Return {
    fn into_result(self) -> Result<u64, Error> {
        self.0
    }
}
mod syscall {
    pub enum SyscallNumber {
        ThreadInterrupt,
    }
    pub fn raw_syscall2(_: SyscallNumber, handle: u64, payload: u64) -> super::Return {
        assert_eq!((handle, payload), (77, 0));
        super::INTERRUPTS.fetch_add(1, super::Ordering::AcqRel);
        super::Return(match *super::ERROR.lock().unwrap() {
            Some(error) => Err(super::Error(error)),
            None => Ok(0),
        })
    }
}
#[path = "../../../user/crates/newlib-runtime/src/cancellation.rs"]
mod production;

#[test]
fn async_notifications_and_cleanup_require_enabled_async_pending_and_no_owned_runtime_state() {
    let _serial = SERIAL.lock().unwrap();
    for state in [0, 1] {
        for kind in [0, 1] {
            for pending in [0, 1] {
                for depth in [0, 1] {
                    for resources in [false, true] {
                        CONTROL.cancel_state.store(state, Ordering::Release);
                        CONTROL.cancel_type.store(kind, Ordering::Release);
                        CONTROL.cancel_pending.store(pending, Ordering::Release);
                        CONTROL
                            .native_delivery_defer
                            .store(depth, Ordering::Release);
                        CONTROL
                            .callback_resources
                            .0
                            .store(resources, Ordering::Release);
                        CONTROL.native_handle.store(77, Ordering::Release);
                        FOUND.store(true, Ordering::Release);
                        INTERRUPTS.store(0, Ordering::Release);
                        *ERROR.lock().unwrap() = None;
                        assert_eq!(production::notify_async(&CONTROL), Ok(()));
                        let eligible = state == 0 && kind == 1 && pending == 1;
                        assert_eq!(INTERRUPTS.load(Ordering::Acquire), u32::from(eligible));
                        let outcome = std::panic::catch_unwind(production::test_async);
                        assert_eq!(outcome.is_err(), eligible && depth == 0 && !resources);
                        if let Err(error) = outcome {
                            assert!(error.is::<Cancelled>());
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn full_queue_has_a_notification_but_bad_authority_or_retired_target_is_not_success() {
    let _serial = SERIAL.lock().unwrap();
    CONTROL.cancel_state.store(0, Ordering::Release);
    CONTROL.cancel_type.store(1, Ordering::Release);
    CONTROL.cancel_pending.store(1, Ordering::Release);
    CONTROL.native_handle.store(77, Ordering::Release);
    for (error, expected) in [
        (mnu_abi::status::Error::ResourceUnavailable, Ok(())),
        (mnu_abi::status::Error::NotFound, Err(ESRCH)),
        (mnu_abi::status::Error::AccessDenied, Err(13)),
    ] {
        *ERROR.lock().unwrap() = Some(error);
        assert_eq!(production::notify_async(&CONTROL), expected);
    }
    CONTROL.native_handle.store(0, Ordering::Release);
    assert_eq!(production::notify_async(&CONTROL), Err(ESRCH));
    FOUND.store(false, Ordering::Release);
    production::test_async();
}
