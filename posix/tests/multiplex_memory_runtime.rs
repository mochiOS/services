#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/multiplex_memory.rs"]
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
macro_rules! abi {
    ($name:ident, $definition:ident, {$($fields:tt)*}) => {
        #[repr(C)] #[derive(Clone, Copy, Debug, PartialEq, Eq)] struct $name { $($fields)* }
        const $definition: &str = stringify!(struct $name { $($fields)* });
    };
}
abi!(PollFd, POLL, { fd: c_int, events: i16, revents: i16, });
abi!(FdSet, FDSET, { bits: [u64; 1], });
abi!(Timeval, TIMEVAL, { tv_sec: CLong, tv_usec: CLong, });
abi!(NewlibTimespec, TIMESPEC, { tv_sec: i64, tv_nsec: i64, });
#[test]
fn fixtures_match_runtime_abi_declarations() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for (name, expected) in [
        ("PollFd", POLL),
        ("FdSet", FDSET),
        ("Timeval", TIMEVAL),
        ("NewlibTimespec", TIMESPEC),
    ] {
        let start = source.find(&format!("struct {name} {{")).unwrap();
        let end = start + source[start..].find("\n}").unwrap() + 2;
        let compact = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        assert_eq!(compact(&source[start..end]), compact(expected));
    }
    assert_eq!(std::mem::size_of::<PollFd>(), 8);
    assert_eq!(std::mem::size_of::<FdSet>(), 8);
}
#[test]
fn poll_copy_uses_signed_c_fields_at_checked_unaligned_offsets() {
    let mut bytes = [0xa5; 18];
    let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
    let value = PollFd {
        fd: -7,
        events: 0x1234,
        revents: -8,
    };
    memory::write_pollfd(pointer, 1, value).unwrap();
    assert_eq!(memory::read_pollfd(pointer, 1), Ok(value));
    assert_eq!(&bytes[9..13], (-7i32).to_ne_bytes());
    assert_eq!(&bytes[13..15], 0x1234i16.to_ne_bytes());
    assert_eq!(&bytes[15..17], (-8i16).to_ne_bytes());
    assert_eq!((bytes[0], bytes[17]), (0xa5, 0xa5));
    assert_eq!(memory::read_pollfd(pointer, usize::MAX), Err(EFAULT));
    assert_eq!(
        memory::write_pollfd(pointer, usize::MAX, value),
        Err(EFAULT)
    );
}
#[test]
fn timeout_and_mask_inputs_are_copied_without_normalizing_unvalidated_values() {
    let mut bytes = [0; 17];
    bytes[1..9].copy_from_slice(&(-2i64).to_ne_bytes());
    bytes[9..17].copy_from_slice(&123456i64.to_ne_bytes());
    let pointer = bytes.as_ptr().wrapping_add(1);
    assert_eq!(
        memory::read_timeval(pointer.cast()),
        Ok(Timeval {
            tv_sec: -2,
            tv_usec: 123456
        })
    );
    assert_eq!(
        memory::read_timespec(pointer.cast()),
        Ok(NewlibTimespec {
            tv_sec: -2,
            tv_nsec: 123456
        })
    );
    assert_eq!(memory::read_mask(pointer.cast()), Ok((-2i64) as u64));
}
#[test]
fn invalid_metadata_never_becomes_a_rust_reference() {
    for address in [0, 1, usize::MAX] {
        assert_eq!(memory::read_pollfd(address as *const _, 0), Err(EFAULT));
        assert_eq!(memory::read_timeval(address as *const _), Err(EFAULT));
        assert_eq!(memory::read_timespec(address as *const _), Err(EFAULT));
        assert_eq!(memory::read_mask(address as *const _), Err(EFAULT));
        assert_eq!(
            memory::write_pollfd(
                address as *mut _,
                0,
                PollFd {
                    fd: 0,
                    events: 0,
                    revents: 0
                }
            ),
            Err(EFAULT)
        );
    }
}
