#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/wait_output.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EFAULT: c_int = 14;
const EOVERFLOW: c_int = 139;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
#[test]
fn status_preserves_every_bit_at_unaligned_c_offsets() {
    for status in [0u32, 37 << 8, 0xffff, 0xffffffff] {
        let mut bytes = [0xa5; 6];
        let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
        assert_eq!(implementation::publish(42, status, pointer), Ok(42));
        assert_eq!(&bytes[1..5], status.to_ne_bytes());
        assert_eq!((bytes[0], bytes[5]), (0xa5, 0xa5));
    }
}
#[test]
fn absent_events_optional_output_and_pid_overflow_do_not_touch_storage() {
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    assert_eq!(implementation::publish(0, 123, 1usize as *mut _), Ok(0));
    assert_eq!(
        implementation::publish(42, 123, std::ptr::null_mut()),
        Ok(42)
    );
    assert_eq!(
        implementation::publish(i32::MAX as u64 + 1, 123, 1usize as *mut _),
        Err(EOVERFLOW)
    );
    user_copy_native::CALLS.with_borrow(|calls| assert!(calls.is_empty()));
}
#[test]
fn invalid_status_output_returns_efault_instead_of_forming_a_rust_reference() {
    for address in [1, usize::MAX] {
        assert_eq!(
            implementation::publish(42, 37 << 8, address as *mut _),
            Err(EFAULT)
        );
    }
}
#[test]
fn runtime_publishes_only_after_the_service_returned_an_event() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("pub extern \"C\" fn _waitpid(").unwrap();
    let end = start
        + source[start..]
            .find("pub extern \"C\" fn waitpid(")
            .unwrap();
    let body = &source[start..end];
    assert!(body.find(".wait_child_since(").unwrap() < body.find("wait_output::publish(").unwrap());
    assert!(body.contains("wait_output::publish(waited.process_id, waited.status, status)"));
    assert!(!body.contains("status.write("));
}
