//! Actual importer, local registry and job launcher with controlled pthread
//! creation. Native dispatcher behavior is covered by native_sigev_thread.c.
#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::{
    ffi::{c_char, c_int, c_void},
    ptr,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};
#[path = "../../../user/crates/newlib-runtime/src/pthread_attr.rs"]
mod attr_api;
#[path = "../../../user/crates/newlib-runtime/src/timer_callbacks.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::syscall_errno;
mod syscall {
    pub use super::user_copy_native::syscall::*;
    pub fn raw_syscall0(_: SyscallNumber) -> Result<u64, i32> {
        Ok(0)
    }
}
const EFAULT: c_int = 14;
const EINVAL: c_int = 22;
const EAGAIN: c_int = 11;
const EOVERFLOW: c_int = 139;
const EIO: c_int = 5;
const ENOTSUP: c_int = 134;
struct SchedParam {
    sched_priority: c_int,
}
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
const PTHREAD_CREATE_DETACHED: c_int = 0;
const PTHREAD_CREATE_JOINABLE: c_int = 1;
const PTHREAD_STACK_MIN: usize = 16384;
const PTHREAD_DEFAULT_STACK_SIZE: usize = 131072;
const PTHREAD_CANCEL_DISABLE: u32 = 1;
#[repr(C)]
#[derive(Clone, Copy)]
struct PthreadAttr {
    is_initialized: c_int,
    detachstate: c_int,
    stackaddr: *mut c_void,
    stacksize: usize,
    guardsize: usize,
    reserved: [u32; 2],
}
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}
const THREAD_STARTING: u32 = 1;
const THREAD_RUNNING: u32 = 2;
struct Control {
    state: AtomicU32,
}
static CONTROL: Control = Control {
    state: AtomicU32::new(THREAD_RUNNING),
};
static THREADS: [Control; 0] = [];
fn thread_control(_: u32) -> Option<&'static Control> {
    Some(&CONTROL)
}
fn process_exit(_: c_int) -> ! {
    panic!("unexpected process exit")
}
mod thread_lifecycle {
    pub fn capture() -> Result<(), super::c_int> {
        Ok(())
    }
}
fn register_current_thread() -> Option<(u32, &'static Control)> {
    Some((1, &CONTROL))
}
fn native_mutex_wait(_: &AtomicU32, _: u32) {
    unreachable!()
}
fn native_mutex_wake_all(_: &AtomicU32) {}
fn service_signal_mask(_: &Control, _: u32, _: u64) -> Result<u64, c_int> {
    Ok(0)
}
unsafe fn pthread_setcancelstate(_: c_int, _: *mut c_int) -> c_int {
    0
}
unsafe fn nanosleep(_: *const Timespec, _: *mut Timespec) -> c_int {
    unreachable!()
}
struct Client;
impl Client {
    fn timer_wait_callback(&self) -> Result<posix_protocol::timer_callback::Event, c_int> {
        unreachable!()
    }
}
fn posix_client() -> Result<&'static Client, c_int> {
    Ok(&Client)
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}
mod thread_clock {
    pub fn is_id(id: u64) -> bool {
        id >= 1 << 32
    }
}
struct State {
    timer_callbacks: implementation::Book,
    thread_clocks: mochios_posix_client::thread_clock::Registry<64>,
}
unsafe impl Send for State {}
static STATE: Mutex<State> = Mutex::new(State {
    timer_callbacks: implementation::Book::new(),
    thread_clocks: mochios_posix_client::thread_clock::Registry::new(),
});
fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap()
}
type Start = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
static JOBS: Mutex<Vec<(Start, usize, usize, usize, c_int, u32)>> = Mutex::new(Vec::new());
static FAILURE: AtomicU32 = AtomicU32::new(0);
static VALUE: AtomicU64 = AtomicU64::new(0);
static SERIAL: Mutex<()> = Mutex::new(());
unsafe fn pthread_create(
    thread: *mut u32,
    attr: *const PthreadAttr,
    start: Option<Start>,
    argument: *mut c_void,
) -> c_int {
    assert!(
        STATE.try_lock().is_ok(),
        "no state lock across pthread creation"
    );
    if FAILURE.load(Ordering::Acquire) != 0 {
        return EAGAIN;
    }
    let attr = unsafe { &*attr };
    JOBS.lock().unwrap().push((
        start.unwrap(),
        argument as usize,
        attr.stacksize,
        attr.guardsize,
        attr.detachstate,
        attr.reserved[0],
    ));
    unsafe { thread.write(1) };
    0
}
unsafe extern "C" fn callback(value: usize) {
    assert!(STATE.try_lock().is_ok(), "no lock across C callback");
    VALUE.store(value as u64, Ordering::Release);
}
fn event(value: usize, attr: *const PthreadAttr) -> [usize; 4] {
    [3, value, callback as *const () as usize, attr as usize]
}
fn import(value: usize, attr: *const PthreadAttr) -> implementation::Callback {
    implementation::import(event(value, attr).as_ptr().cast(), value).unwrap()
}
fn reset() -> MutexGuard<'static, ()> {
    let serial = SERIAL.lock().unwrap();
    *state() = State {
        timer_callbacks: implementation::Book::new(),
        thread_clocks: Default::default(),
    };
    JOBS.lock().unwrap().clear();
    FAILURE.store(0, Ordering::Release);
    VALUE.store(0, Ordering::Release);
    serial
}
fn bind(value: usize) -> posix_protocol::timer_callback::Event {
    let token = implementation::reserve(import(value, ptr::null()), None, 4).unwrap();
    state().timer_callbacks.values.bind(token, 101).unwrap();
    posix_protocol::timer_callback::Event {
        timer: 101,
        cookie: token.raw(),
        overrun: 0,
    }
}
fn run_next() {
    let (start, arg, _, _, _, _) = JOBS.lock().unwrap().remove(0);
    unsafe { start(arg as *mut c_void) };
}

#[test]
fn attributes_and_values_are_copied_and_jobs_are_released_before_application_code() {
    let _serial = reset();
    let mut attr = PthreadAttr {
        is_initialized: 1,
        detachstate: 1,
        stackaddr: ptr::null_mut(),
        stacksize: 65536,
        guardsize: 8192,
        reserved: [0; 2],
    };
    assert_eq!(
        unsafe { attr_api::pthread_attr_setinheritsched(&mut attr, 2) },
        0
    );
    let cb = import(usize::MAX, &attr);
    attr.stacksize = 1;
    attr.guardsize = 0;
    assert_eq!(
        unsafe { attr_api::pthread_attr_setinheritsched(&mut attr, 1) },
        0
    );
    let token = implementation::reserve(cb, None, 4).unwrap();
    state().timer_callbacks.values.bind(token, 101).unwrap();
    let e = posix_protocol::timer_callback::Event {
        timer: 101,
        cookie: token.raw(),
        overrun: 0,
    };
    implementation::launch(e).unwrap();
    {
        let jobs = JOBS.lock().unwrap();
        assert_eq!((jobs[0].2, jobs[0].3, jobs[0].4), (65536, 8192, 0));
        assert_eq!(jobs[0].5, 1, "the explicit scheduling selection was copied");
    }
    run_next();
    assert_eq!(VALUE.load(Ordering::Acquire), u64::MAX);
    // Repeated delivery reuses the bounded job storage, not raw heap payloads.
    for _ in 0..256 {
        implementation::launch(e).unwrap();
        run_next();
    }
}
#[test]
fn failure_deletion_fork_and_wrong_tokens_never_invoke_or_leak_queued_jobs() {
    let _serial = reset();
    let e = bind(123);
    FAILURE.store(1, Ordering::Release);
    for _ in 0..256 {
        assert_eq!(implementation::launch(e), Err(EAGAIN));
    }
    FAILURE.store(0, Ordering::Release);
    implementation::launch(e).unwrap();
    state().timer_callbacks.values.retire(101);
    run_next();
    assert_eq!(VALUE.load(Ordering::Acquire), 0);
    implementation::launch(e).unwrap();
    assert!(JOBS.lock().unwrap().is_empty());
    let e = bind(456);
    implementation::launch(e).unwrap();
    state().timer_callbacks.clear_for_fork();
    run_next();
    assert_eq!(VALUE.load(Ordering::Acquire), 0);
    let e = bind(789);
    for bad in [
        posix_protocol::timer_callback::Event { timer: 102, ..e },
        posix_protocol::timer_callback::Event { cookie: 0, ..e },
        posix_protocol::timer_callback::Event {
            cookie: e.cookie + 1,
            ..e
        },
    ] {
        implementation::launch(bad).unwrap();
        assert!(JOBS.lock().unwrap().is_empty());
    }
    implementation::launch(e).unwrap();
    run_next();
    assert_eq!(VALUE.load(Ordering::Acquire), 789);
}
#[test]
fn importer_rejects_faults_null_functions_and_invalid_attributes() {
    let _serial = reset();
    assert!(matches!(
        implementation::import(1usize as *const _, 0),
        Err(EFAULT)
    ));
    let mut ev = event(0, ptr::null());
    ev[2] = 0;
    assert!(matches!(
        implementation::import(ev.as_ptr().cast(), 0),
        Err(EINVAL)
    ));
    let mut attr = PthreadAttr {
        is_initialized: 1,
        detachstate: 0,
        stackaddr: ptr::null_mut(),
        stacksize: 65536,
        guardsize: 4096,
        reserved: [0; 2],
    };
    for mode in 0..5 {
        let old = attr;
        match mode {
            0 => attr.is_initialized = 0,
            1 => attr.detachstate = 7,
            2 => attr.stacksize = 1,
            3 => attr.reserved[0] = 2,
            _ => attr.reserved[1] = 1,
        }
        assert!(matches!(
            implementation::import(event(0, &attr).as_ptr().cast(), 0),
            Err(EINVAL)
        ));
        attr = old;
    }
    assert!(matches!(
        implementation::import(event(0, 1usize as *const _).as_ptr().cast(), 0),
        Err(EFAULT)
    ));
}

#[test]
fn selected_thread_exit_and_fork_retire_callbacks_without_reusing_cookie_values() {
    let _serial = reset();
    let clock = state()
        .thread_clocks
        .get_or_insert(mochios_posix_client::thread_clock::Target {
            thread: 64,
            native_thread: 17,
        })
        .unwrap();
    let cb = import(123, ptr::null());
    assert!(matches!(
        implementation::reserve(cb, Some(18), clock),
        Err(EINVAL)
    ));
    let token = implementation::reserve(cb, Some(17), clock).unwrap();
    state().timer_callbacks.values.bind(token, 101).unwrap();
    state().timer_callbacks.values.retire_owner(17);
    implementation::launch(posix_protocol::timer_callback::Event {
        timer: 101,
        cookie: token.raw(),
        overrun: 0,
    })
    .unwrap();
    assert!(JOBS.lock().unwrap().is_empty());
    state().timer_callbacks.clear_for_fork();
    let next = implementation::reserve(cb, None, 4).unwrap();
    assert!(next.raw() > token.raw());
}
