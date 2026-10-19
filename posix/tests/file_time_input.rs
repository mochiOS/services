#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use posix_protocol::file_time::{Change, Update};
use std::ffi::{c_char, c_int};

#[path = "../../../user/crates/newlib-runtime/src/file_time_input.rs"]
mod input;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};

type CLong = i64;
const EFAULT: c_int = 14;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
#[repr(C)]
struct Timespec {
    tv_sec: CLong,
    tv_nsec: CLong,
}

fn bytes(first: (i64, i64), second: (i64, i64)) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (field, value) in bytes
        .chunks_exact_mut(8)
        .zip([first.0, first.1, second.0, second.1])
    {
        field.copy_from_slice(&value.to_ne_bytes());
    }
    bytes
}

#[test]
fn null_is_current_and_explicit_signed_times_use_one_faultable_snapshot() {
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    assert_eq!(input::read(std::ptr::null()), Ok(Update::now()));
    assert!(user_copy_native::CALLS.with_borrow(Vec::is_empty));
    let values = bytes((-1, 123_456_789), (2_147_483_648, 999_999_999));
    assert_eq!(
        input::read(values.as_ptr().cast()),
        Ok(Update {
            access: Change::Set {
                seconds: -1,
                nanoseconds: 123_456_789
            },
            modification: Change::Set {
                seconds: 2_147_483_648,
                nanoseconds: 999_999_999
            },
        })
    );
    assert_eq!(user_copy_native::CALLS.with_borrow(Clone::clone), [32]);
}

#[test]
fn sentinel_seconds_are_ignored_and_unaligned_arrays_are_copied_not_dereferenced() {
    for (first, first_expected) in [(-2, Change::Now), (-1, Change::Omit)] {
        for (second, second_expected) in [(-2, Change::Now), (-1, Change::Omit)] {
            let mut buffer = [0xa5; 34];
            buffer[1..33].copy_from_slice(&bytes((i64::MIN, first), (i64::MAX, second)));
            assert_eq!(
                input::read(buffer.as_ptr().wrapping_add(1).cast()),
                Ok(Update {
                    access: first_expected,
                    modification: second_expected,
                })
            );
            assert_eq!((buffer[0], buffer[33]), (0xa5, 0xa5));
        }
    }
}

#[test]
fn invalid_nanoseconds_and_unreadable_second_timespec_do_not_produce_an_update() {
    for nanos in [i64::MIN, -3, 1_000_000_000, i64::MAX] {
        for values in [bytes((0, nanos), (0, 0)), bytes((0, 0), (0, nanos))] {
            assert_eq!(input::read(values.as_ptr().cast()), Err(EINVAL));
        }
    }
    for address in [1, usize::MAX, usize::MAX - 16] {
        assert_eq!(input::read(address as *const Timespec), Err(EFAULT));
    }
    let values = bytes((0, 0), (0, 0));
    let second = values.as_ptr() as usize + 16;
    user_copy_native::DENIED.with_borrow_mut(|denied| *denied = Some(second..second + 16));
    assert_eq!(input::read(values.as_ptr().cast()), Err(EFAULT));
    user_copy_native::DENIED.with_borrow_mut(|denied| *denied = None);
}

#[test]
fn input_layout_and_sentinels_match_runtime_and_mochios_rust_libc() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("struct Timespec {").unwrap();
    let end = start + runtime[start..].find("\n}").unwrap() + 2;
    let compact: String = runtime[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert_eq!(compact, "structTimespec{tv_sec:CLong,tv_nsec:CLong,}");
    assert_eq!(core::mem::size_of::<Timespec>(), 16);
    assert_eq!(core::mem::offset_of!(Timespec, tv_nsec), 8);
    assert_eq!((input::UTIME_NOW, input::UTIME_OMIT), (-2, -1));
    let libc = include_str!("../../../libraries/libc/newlib/mochios.rs");
    assert!(libc.contains("pub const UTIME_NOW: c_long = -2;"));
    assert!(libc.contains("pub const UTIME_OMIT: c_long = -1;"));
}
