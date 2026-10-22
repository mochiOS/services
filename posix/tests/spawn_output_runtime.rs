//! The actual publication owner retains a created child on copy failure.
#![allow(dead_code)]
use mochios_posix_client::upcall_guard::Guard;
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering},
};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/spawn_output.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EAGAIN: c_int = 11;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const EOVERFLOW: c_int = 139;
const PAGE_SIZE: usize = 4096;
const HANDLE: u32 = 42;
static SERIAL: Mutex<()> = Mutex::new(());
static REGISTER: AtomicBool = AtomicBool::new(true);
static COPY_MODE: AtomicU32 = AtomicU32::new(0);
static COPY_CALLS: AtomicU32 = AtomicU32::new(0);
static COPIED: AtomicBool = AtomicBool::new(false);
static QUERY_PID: AtomicU64 = AtomicU64::new(37);
static QUERY_STATE: AtomicU32 = AtomicU32::new(mnu_abi::PROCESS_STATE_RUNNING);
static QUERY_REVISION: AtomicU64 = AtomicU64::new(1);
static QUERY_RESERVED: AtomicU32 = AtomicU32::new(0);
static QUERY_ERROR: AtomicI32 = AtomicI32::new(0);
static QUERY_RESULT: AtomicU64 = AtomicU64::new(0);
static QUERY_CALLS: AtomicU32 = AtomicU32::new(0);
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static CLEANED: Mutex<Vec<(u64, bool)>> = Mutex::new(Vec::new());
struct ThreadControl {
    callback_resources: callback_resources::Chain,
    active_signal_scope_id: AtomicU64,
    native: AtomicU32,
}
static CONTROL: ThreadControl = ThreadControl {
    callback_resources: callback_resources::Chain::new(),
    active_signal_scope_id: AtomicU64::new(0),
    native: AtomicU32::new(0),
};
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    REGISTER.load(Ordering::Relaxed).then_some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
fn cleanup_failed_child(handle: u64, registered: bool) {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert_eq!(handle, u64::from(HANDLE));
    CLEANED.lock().unwrap().push((handle, registered));
}
fn close_object_handle(handle: u32) {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert_eq!(handle, HANDLE);
    assert!(
        COPIED.load(Ordering::Relaxed),
        "release must follow accepted PID copy"
    );
    CLOSED.lock().unwrap().push(handle);
}
mod syscall {
    pub use mnu_abi::{PROCESS_STATE_EXITED, PROCESS_STATE_RUNNING, ProcessStatus, SyscallNumber};
    pub fn raw_syscall2(number: SyscallNumber, handle: u64, output: u64) -> Result<u64, i32> {
        use super::*;
        assert_eq!(number, SyscallNumber::ProcessHandleStatus);
        assert_eq!(handle, u64::from(HANDLE));
        assert!(!CONTROL.callback_resources.is_empty());
        assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
        QUERY_CALLS.fetch_add(1, Ordering::Relaxed);
        let error = QUERY_ERROR.load(Ordering::Relaxed);
        if error != 0 {
            return Err(error);
        }
        let status = ProcessStatus {
            process_id: QUERY_PID.load(Ordering::Relaxed),
            state: QUERY_STATE.load(Ordering::Relaxed),
            reserved: QUERY_RESERVED.load(Ordering::Relaxed),
            exit_code: 127,
            image_revision: QUERY_REVISION.load(Ordering::Relaxed),
        };
        unsafe {
            (output as *mut ProcessStatus).write(status);
        }
        Ok(QUERY_RESULT.load(Ordering::Relaxed))
    }
    pub fn raw_syscall3(
        number: SyscallNumber,
        destination: u64,
        source: u64,
        length: u64,
    ) -> Result<u64, i32> {
        assert!(!super::CONTROL.callback_resources.is_empty());
        assert_ne!(super::CONTROL.native.load(super::Ordering::Relaxed), 0);
        super::COPY_CALLS.fetch_add(1, super::Ordering::Relaxed);
        let result = match super::COPY_MODE.load(super::Ordering::Relaxed) {
            1 => Ok(length - 1),
            2 => Err(super::EIO),
            _ => {
                super::user_copy_native::syscall::raw_syscall3(number, destination, source, length)
            }
        };
        if result == Ok(length) {
            super::COPIED.store(true, super::Ordering::Relaxed);
        }
        result
    }
}
fn syscall_errno(result: Result<u64, c_int>) -> Result<u64, c_int> {
    result
}
fn reset() {
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    REGISTER.store(true, Ordering::Relaxed);
    COPY_MODE.store(0, Ordering::Relaxed);
    COPY_CALLS.store(0, Ordering::Relaxed);
    COPIED.store(false, Ordering::Relaxed);
    QUERY_PID.store(37, Ordering::Relaxed);
    QUERY_STATE.store(mnu_abi::PROCESS_STATE_RUNNING, Ordering::Relaxed);
    QUERY_REVISION.store(1, Ordering::Relaxed);
    QUERY_RESERVED.store(0, Ordering::Relaxed);
    QUERY_ERROR.store(0, Ordering::Relaxed);
    QUERY_RESULT.store(0, Ordering::Relaxed);
    QUERY_CALLS.store(0, Ordering::Relaxed);
    CLOSED.lock().unwrap().clear();
    CLEANED.lock().unwrap().clear();
}
fn assert_retired(success: bool) {
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert_eq!(
        *CLOSED.lock().unwrap(),
        if success { vec![HANDLE] } else { vec![] }
    );
    assert_eq!(
        *CLEANED.lock().unwrap(),
        if success {
            vec![]
        } else {
            vec![(u64::from(HANDLE), true)]
        }
    );
}

#[test]
fn success_publishes_exact_pid_before_releasing_the_process_reference() {
    let _serial = SERIAL.lock().unwrap();
    for process_id in [1, 37, c_int::MAX as u64] {
        reset();
        QUERY_PID.store(process_id, Ordering::Relaxed);
        let mut bytes = [0xa5; 6];
        assert_eq!(
            implementation::publish(
                process_id,
                HANDLE,
                bytes.as_mut_ptr().wrapping_add(1).cast()
            ),
            0
        );
        assert_eq!(&bytes[1..5], &(process_id as c_int).to_ne_bytes());
        assert_eq!([bytes[0], bytes[5]], [0xa5; 2]);
        assert_retired(true);
    }
}

#[test]
fn invalid_output_never_releases_a_live_child_as_success() {
    let _serial = SERIAL.lock().unwrap();
    for address in [0usize, 1, usize::MAX] {
        reset();
        assert_eq!(
            implementation::publish(37, HANDLE, address as *mut _),
            EFAULT
        );
        assert_retired(false);
    }
    for mode in [1, 2] {
        reset();
        COPY_MODE.store(mode, Ordering::Relaxed);
        let mut pid = -37;
        assert_eq!(implementation::publish(37, HANDLE, &mut pid), EIO);
        assert_eq!(pid, -37);
        assert_retired(false);
    }
}

#[test]
fn invalid_pid_and_scope_registration_failure_also_roll_back_the_child() {
    let _serial = SERIAL.lock().unwrap();
    for process_id in [0, c_int::MAX as u64 + 1, u64::MAX] {
        reset();
        let mut pid = -37;
        let error = if process_id == 0 { EIO } else { EOVERFLOW };
        assert_eq!(implementation::publish(process_id, HANDLE, &mut pid), error);
        assert_eq!(pid, -37);
        assert_eq!(COPY_CALLS.load(Ordering::Relaxed), 0);
        assert_retired(false);
    }
    reset();
    REGISTER.store(false, Ordering::Relaxed);
    let mut pid = -37;
    assert_eq!(implementation::publish(37, HANDLE, &mut pid), EAGAIN);
    assert_eq!(pid, -37);
    assert_eq!(COPY_CALLS.load(Ordering::Relaxed), 0);
    assert_retired(false);
}

#[test]
fn spawn_success_dispatch_uses_the_checked_owner_instead_of_a_raw_pid_store() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let source = &source[source.find("pub extern \"C\" fn _posix_spawn(").unwrap()..];
    let source = &source[..source.find("pub extern \"C\" fn posix_spawn(").unwrap()];
    let start = source.find("ExecStatus::Succeeded) =>").unwrap();
    let end = source.find("ExecStatus::Failed(").unwrap();
    assert!(source[start..end].contains("spawn_output::publish(child_pid, process_handle, pid)"));
    assert!(!source[start..end].contains("close_object_handle("));
    assert!(!source.contains("*pid ="));
}

#[test]
fn read_only_pid_storage_returns_efault_and_rolls_back_the_owned_child() {
    use std::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: c_int,
            flags: c_int,
            fd: c_int,
            offset: isize,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, length: usize, protection: c_int) -> c_int;
        fn munmap(address: *mut c_void, length: usize) -> c_int;
    }
    struct Page(*mut c_void);
    impl Drop for Page {
        fn drop(&mut self) {
            assert_eq!(unsafe { munmap(self.0, PAGE_SIZE) }, 0);
        }
    }
    let _serial = SERIAL.lock().unwrap();
    reset();
    let page = Page(unsafe { mmap(std::ptr::null_mut(), PAGE_SIZE, 3, 0x22, -1, 0) });
    assert_ne!(page.0 as usize, usize::MAX);
    unsafe { page.0.cast::<c_int>().write(-37) };
    assert_eq!(unsafe { mprotect(page.0, PAGE_SIZE, 1) }, 0);
    assert_eq!(implementation::publish(37, HANDLE, page.0.cast()), EFAULT);
    assert_eq!(unsafe { page.0.cast::<c_int>().read() }, -37);
    assert_retired(false);
}

#[test]
fn eof_without_committed_exec_and_malformed_metadata_cannot_publish_a_pid() {
    let _serial = SERIAL.lock().unwrap();
    for mode in 0..7 {
        reset();
        match mode {
            0 => QUERY_REVISION.store(0, Ordering::Relaxed),
            1 => {
                QUERY_STATE.store(mnu_abi::PROCESS_STATE_EXITED, Ordering::Relaxed);
                QUERY_REVISION.store(0, Ordering::Relaxed);
            }
            2 => QUERY_PID.store(38, Ordering::Relaxed),
            3 => QUERY_RESERVED.store(1, Ordering::Relaxed),
            4 => QUERY_STATE.store(0, Ordering::Relaxed),
            5 => QUERY_STATE.store(u32::MAX, Ordering::Relaxed),
            _ => QUERY_RESULT.store(7, Ordering::Relaxed),
        }
        let mut pid = -37;
        assert_eq!(implementation::publish(37, HANDLE, &mut pid), EIO);
        assert_eq!(pid, -37);
        assert_eq!(QUERY_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(COPY_CALLS.load(Ordering::Relaxed), 0);
        assert_retired(false);
    }
    for error in [5, 9, 13, 88] {
        reset();
        QUERY_ERROR.store(error, Ordering::Relaxed);
        let mut pid = -37;
        assert_eq!(implementation::publish(37, HANDLE, &mut pid), error);
        assert_eq!(pid, -37);
        assert_eq!(COPY_CALLS.load(Ordering::Relaxed), 0);
        assert_retired(false);
    }
}

#[test]
fn committed_exec_succeeds_even_when_the_new_image_has_already_exited() {
    let _serial = SERIAL.lock().unwrap();
    for revision in [1, 2, u64::MAX] {
        for state in [
            mnu_abi::PROCESS_STATE_RUNNING,
            mnu_abi::PROCESS_STATE_EXITED,
        ] {
            reset();
            QUERY_REVISION.store(revision, Ordering::Relaxed);
            QUERY_STATE.store(state, Ordering::Relaxed);
            let mut pid = -37;
            assert_eq!(implementation::publish(37, HANDLE, &mut pid), 0);
            assert_eq!(pid, 37);
            assert_eq!(QUERY_CALLS.load(Ordering::Relaxed), 1);
            assert_retired(true);
        }
    }
}
