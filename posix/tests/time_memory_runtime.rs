#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/time_memory.rs"]
mod memory;
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
type CLong = i64;
#[repr(C)]
struct Timespec {
    tv_sec: CLong,
    tv_nsec: CLong,
}
#[repr(C)]
struct Tms {
    tms_utime: u64,
    tms_stime: u64,
    tms_cutime: u64,
    tms_cstime: u64,
}
#[test]
fn fixture_types_match_production_declarations() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for expected in [
        "struct Timespec { tv_sec: CLong, tv_nsec: CLong, }",
        "struct Tms { tms_utime: u64, tms_stime: u64, tms_cutime: u64, tms_cstime: u64, }",
    ] {
        let name = expected.split_whitespace().nth(1).unwrap();
        let begin = source.find(&format!("struct {name} {{")).unwrap();
        let end = begin + source[begin..].find("\n}").unwrap() + 2;
        let compact = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        assert_eq!(compact(&source[begin..end]), compact(expected));
    }
}
#[test]
fn signed_time_fields_use_c_offsets_and_support_unaligned_callers() {
    let mut bytes = [0xa5; 18];
    let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
    memory::write_timespec(
        pointer,
        Timespec {
            tv_sec: -17,
            tv_nsec: 123456,
        },
    )
    .unwrap();
    assert_eq!(&bytes[1..9], (-17i64).to_ne_bytes());
    assert_eq!(&bytes[9..17], 123456i64.to_ne_bytes());
    let value = memory::read_timespec(pointer).unwrap();
    assert_eq!((value.tv_sec, value.tv_nsec), (-17, 123456));
    assert_eq!((bytes[0], bytes[17]), (0xa5, 0xa5));
}
#[test]
fn accounting_fields_preserve_wide_counters_and_canaries() {
    let mut bytes = [0xa5; 34];
    memory::write_accounting(
        bytes.as_mut_ptr().wrapping_add(1).cast(),
        Tms {
            tms_utime: u64::MAX,
            tms_stime: 2,
            tms_cutime: 3,
            tms_cstime: 4,
        },
    )
    .unwrap();
    for (index, value) in [u64::MAX, 2, 3, 4].into_iter().enumerate() {
        assert_eq!(&bytes[1 + index * 8..9 + index * 8], value.to_ne_bytes());
    }
    assert_eq!((bytes[0], bytes[33]), (0xa5, 0xa5));
}
#[test]
fn invalid_time_inputs_and_outputs_return_efault() {
    for address in [0, 1, usize::MAX] {
        assert!(matches!(
            memory::read_timespec(address as *const _),
            Err(EFAULT)
        ));
        assert_eq!(
            memory::write_timespec(
                address as *mut _,
                Timespec {
                    tv_sec: 0,
                    tv_nsec: 0
                }
            ),
            Err(EFAULT)
        );
        assert_eq!(
            memory::write_accounting(
                address as *mut _,
                Tms {
                    tms_utime: 0,
                    tms_stime: 0,
                    tms_cutime: 0,
                    tms_cstime: 0
                }
            ),
            Err(EFAULT)
        );
    }
}
