#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int, c_void};
#[path = "../../../user/crates/newlib-runtime/src/socket_memory.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const PAGE_SIZE: usize = 4096;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
type CLong = i64;
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct Timeval {
    tv_sec: CLong,
    tv_usec: CLong,
}

#[test]
fn timeout_copy_matches_the_runtime_declaration_and_c_offsets() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let begin = source.find("struct Timeval {").unwrap();
    let end = begin + source[begin..].find("\n}").unwrap() + 2;
    let normalize = |text: &str| {
        text.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
    };
    assert_eq!(
        normalize(&source[begin..end]),
        normalize("struct Timeval { tv_sec: CLong, tv_usec: CLong, }")
    );
    assert_eq!(std::mem::size_of::<Timeval>(), 16);
    let mut bytes = [0xa5; 18];
    bytes[1..9].copy_from_slice(&(-17i64).to_ne_bytes());
    bytes[9..17].copy_from_slice(&123456i64.to_ne_bytes());
    assert_eq!(
        implementation::read_timeout(bytes.as_ptr().wrapping_add(1).cast()),
        Ok(Timeval {
            tv_sec: -17,
            tv_usec: 123456
        })
    );
    assert_eq!((bytes[0], bytes[17]), (0xa5, 0xa5));
}

#[test]
fn unaligned_length_and_truncated_payload_keep_full_reported_length() {
    let mut length = [0xa5; 6];
    length[1..5].copy_from_slice(&3u32.to_ne_bytes());
    let pointer = length.as_mut_ptr().wrapping_add(1).cast();
    assert_eq!(implementation::read_length(pointer), Ok(3));
    let mut destination = [0xa5; 5];
    implementation::write_output(
        destination.as_mut_ptr().wrapping_add(1).cast(),
        pointer,
        b"abc",
        108,
    )
    .unwrap();
    assert_eq!(&destination, b"\xa5abc\xa5");
    assert_eq!(implementation::read_length(pointer), Ok(108));
    assert_eq!((length[0], length[5]), (0xa5, 0xa5));
}

#[test]
fn empty_payload_does_not_access_value_but_still_copies_length() {
    let mut length = 9;
    assert_eq!(
        implementation::write_output(std::ptr::null_mut(), &mut length, &[], 0),
        Ok(())
    );
    assert_eq!(length, 0);
    assert_eq!(
        implementation::write_output(std::ptr::null_mut(), 1usize as *mut _, &[], 0),
        Err(EFAULT)
    );
}

#[test]
fn invalid_addresses_fail_without_a_rust_reference_or_losing_copy_errors() {
    for address in [0, 1, usize::MAX] {
        assert_eq!(
            implementation::read_length(address as *const _),
            Err(EFAULT)
        );
        assert_eq!(
            implementation::read_timeout(address as *const _),
            Err(EFAULT)
        );
        let mut length = 71;
        assert_eq!(
            implementation::write_output(address as *mut _, &mut length, b"x", 1),
            Err(EFAULT)
        );
        assert_eq!(length, 71);
        let mut output = [0; 1];
        assert_eq!(
            implementation::write_output(output.as_mut_ptr().cast(), address as *mut _, b"x", 1),
            Err(EFAULT)
        );
    }
}
