#![allow(dead_code)]
use core::ffi::{c_char, c_int, c_void};
use mochios_posix_protocol as posix_protocol;
use std::cell::Cell;
#[path = "../../../user/crates/newlib-runtime/src/wall_clock.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}
#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}
thread_local! {
    static ERRNO:Cell<i32> = const { Cell::new(71) };
    static CLOCK:Cell<Result<Timespec,i32>> = const { Cell::new(Ok(Timespec { tv_sec: 1, tv_nsec: 999_999_999 })) };
    static READS:Cell<u32> = const { Cell::new(0) };
}
fn set_errno(value: i32) {
    ERRNO.set(value);
}
fn result_with_errno(result: Result<i32, i32>, failure: i32) -> i32 {
    match result {
        Ok(value) => value,
        Err(error) => {
            set_errno(error);
            failure
        }
    }
}
fn clock_gettime(id: u64, output: *mut Timespec) -> i32 {
    assert_eq!(id, 1);
    READS.set(READS.get() + 1);
    match CLOCK.get() {
        Ok(instant) => {
            unsafe {
                output.write(instant);
            }
            0
        }
        Err(error) => {
            set_errno(error);
            -1
        }
    }
}
#[test]
fn truncates_to_microseconds_preserves_wide_seconds_and_errno() {
    for (seconds, nanoseconds) in [
        (0, 0),
        (1, 999),
        (2, 1000),
        (4, 999_999_999),
        (i64::MAX, 123_456_789),
    ] {
        CLOCK.set(Ok(Timespec {
            tv_sec: seconds,
            tv_nsec: nanoseconds,
        }));
        let mut bytes = [0xa5u8; 18];
        assert_eq!(
            implementation::gettimeofday(
                bytes.as_mut_ptr().wrapping_add(1).cast(),
                std::ptr::null_mut()
            ),
            0
        );
        assert_eq!(&bytes[1..9], &seconds.to_ne_bytes());
        assert_eq!(&bytes[9..17], &(nanoseconds / 1000).to_ne_bytes());
        assert_eq!((bytes[0], bytes[17]), (0xa5, 0xa5));
        assert_eq!(ERRNO.get(), 71);
    }
    assert_eq!(READS.get(), 5);
}
#[test]
fn faults_are_reported_and_clock_failures_do_not_publish_outputs() {
    assert_eq!(
        implementation::gettimeofday(std::ptr::null_mut(), std::ptr::null_mut()),
        -1
    );
    assert_eq!(ERRNO.get(), EFAULT);
    assert_eq!(READS.get(), 0);
    assert_eq!(
        implementation::gettimeofday(1usize as *mut _, std::ptr::null_mut()),
        -1
    );
    assert_eq!(ERRNO.get(), EFAULT);
    let mut bytes = [0xa5u8; 16];
    for error in [5, 13, 75] {
        CLOCK.set(Err(error));
        assert_eq!(
            implementation::gettimeofday(bytes.as_mut_ptr().cast(), std::ptr::null_mut()),
            -1
        );
        assert_eq!(ERRNO.get(), error);
        assert_eq!(bytes, [0xa5; 16]);
    }
}
#[test]
fn obsolete_timezone_pointer_is_never_accessed() {
    let mut output = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    assert_eq!(
        implementation::gettimeofday(&mut output, 1usize as *mut c_void),
        0
    );
    assert_eq!((output.tv_sec, output.tv_usec), (1, 999_999));
    assert_eq!(ERRNO.get(), 71);
}
