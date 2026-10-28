//! Real CRT adapter + faultable memory copying; only the aux lookup is mocked.
#![allow(dead_code)]
use core::{
    ffi::c_int,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::cell::{Cell, RefCell};
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const E2BIG: c_int = 7;
const ENOEXEC: c_int = 8;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
use core::ffi::c_char;
use mochios_posix_protocol as posix_protocol;
#[path = "support/lifecycle_fixture.rs"]
mod fixture;
#[path = "../../../user/crates/newlib-runtime/src/dynamic_lifecycle.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
thread_local! {
    static AUX:Cell<Option<usize>>=const{Cell::new(None)};
    static EVENTS:RefCell<Vec<u8>>=const{RefCell::new(Vec::new())};
}
mod auxiliary {
    pub struct Vector;
    pub fn vector() -> Option<Vector> {
        Some(Vector)
    }
    impl Vector {
        pub fn lookup(&self, key: usize) -> Result<usize, i32> {
            assert_eq!(
                key,
                mochios_posix_client::process_image::AT_LIFECYCLE_IMAGE as usize
            );
            super::AUX.get().ok_or(super::ENOENT)
        }
    }
}
extern "C" fn preinit() {
    EVENTS.with_borrow_mut(|events| events.push(1));
}
extern "C" fn init() {
    EVENTS.with_borrow_mut(|events| events.push(2));
}
extern "C" fn fini() {
    EVENTS.with_borrow_mut(|events| events.push(3));
}
#[test]
fn crt_adapter_consumes_stack_plan_once_and_fails_closed_on_bad_metadata() {
    assert_eq!(implementation::__mochios_lifecycle_v1(), 1);
    assert_eq!(implementation::initialize(), Ok(false));
    AUX.set(Some(1));
    assert_eq!(implementation::initialize(), Err(ENOEXEC));
    let bytes = fixture::encode(
        &[preinit as *const () as u64],
        &[(&[init as *const () as u64], &[fini as *const () as u64])],
    );
    AUX.set(Some(bytes.as_ptr() as usize));
    assert_eq!(implementation::initialize(), Ok(true));
    assert_eq!(implementation::initialize(), Ok(true));
    assert_eq!(implementation::finalize(), Ok(true));
    assert_eq!(implementation::finalize(), Ok(true));
    EVENTS.with_borrow(|events| assert_eq!(*events, [1, 2, 3]));
}
