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
const EINVAL: c_int = 22;
const MAX_FDS: usize = 64;
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
    assert!(source.contains(&format!("const MAX_FDS: usize = {MAX_FDS};")));
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
    let values = [
        PollFd {
            fd: 19,
            events: -1,
            revents: 2,
        },
        value,
    ];
    memory::write_pollfds(pointer, &values).unwrap();
    let mut output = [value; 2];
    memory::read_pollfds(pointer, &mut output).unwrap();
    assert_eq!(output, values);
    assert_eq!(&bytes[1..5], 19i32.to_ne_bytes());
    assert_eq!(&bytes[5..7], (-1i16).to_ne_bytes());
    assert_eq!(&bytes[7..9], 2i16.to_ne_bytes());
    assert_eq!(&bytes[9..13], (-7i32).to_ne_bytes());
    assert_eq!(&bytes[13..15], 0x1234i16.to_ne_bytes());
    assert_eq!(&bytes[15..17], (-8i16).to_ne_bytes());
    assert_eq!((bytes[0], bytes[17]), (0xa5, 0xa5));
}
#[test]
fn poll_arrays_use_one_copy_per_direction_including_maximum_size() {
    for count in [0, 1, MAX_FDS] {
        let values: Vec<_> = (0..count)
            .map(|i| PollFd {
                fd: -(i as i32) - 1,
                events: i as i16,
                revents: !(i as i16),
            })
            .collect();
        let mut bytes = vec![0xa5; count * 8 + 2];
        let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
        user_copy_native::CALLS.with_borrow_mut(Vec::clear);
        memory::write_pollfds(pointer, &values).unwrap();
        let mut output = vec![
            PollFd {
                fd: 0,
                events: 0,
                revents: 0
            };
            count
        ];
        memory::read_pollfds(pointer, &mut output).unwrap();
        assert_eq!(output, values);
        assert_eq!((bytes[0], bytes[bytes.len() - 1]), (0xa5, 0xa5));
        user_copy_native::CALLS.with_borrow(|calls| {
            assert_eq!(
                calls.as_slice(),
                if count == 0 {
                    vec![]
                } else {
                    vec![count * 8; 2]
                }
            );
        });
    }
}
#[test]
fn empty_and_oversized_arrays_never_access_caller_memory() {
    let value = PollFd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    for address in [0, 1, usize::MAX] {
        assert_eq!(memory::read_pollfds(address as *const _, &mut []), Ok(()));
        assert_eq!(memory::write_pollfds(address as *mut _, &[]), Ok(()));
        assert_eq!(
            memory::read_pollfds(address as *const _, &mut [value; MAX_FDS + 1]),
            Err(EINVAL)
        );
        assert_eq!(
            memory::write_pollfds(address as *mut _, &[value; MAX_FDS + 1]),
            Err(EINVAL)
        );
    }
    user_copy_native::CALLS.with_borrow(|calls| assert!(calls.is_empty()));
}
#[test]
fn failed_snapshot_does_not_partially_decode_poll_array() {
    let values = [PollFd {
        fd: 7,
        events: 8,
        revents: 9,
    }; MAX_FDS];
    let sentinel = PollFd {
        fd: -2,
        events: -3,
        revents: -4,
    };
    let mut output = [sentinel; MAX_FDS];
    let start = values.as_ptr() as usize;
    user_copy_native::DENIED.with_borrow_mut(|range| *range = Some(start + 511..start + 512));
    let result = memory::read_pollfds(values.as_ptr(), &mut output);
    user_copy_native::DENIED.with_borrow_mut(|range| *range = None);
    assert_eq!(result, Err(EFAULT));
    assert_eq!(output, [sentinel; MAX_FDS]);
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
        assert_eq!(
            memory::read_pollfds(
                address as *const _,
                &mut [PollFd {
                    fd: 0,
                    events: 0,
                    revents: 0
                }]
            ),
            Err(EFAULT)
        );
        assert_eq!(memory::read_timeval(address as *const _), Err(EFAULT));
        assert_eq!(memory::read_timespec(address as *const _), Err(EFAULT));
        assert_eq!(memory::read_mask(address as *const _), Err(EFAULT));
        assert_eq!(
            memory::write_pollfds(
                address as *mut _,
                &[PollFd {
                    fd: 0,
                    events: 0,
                    revents: 0
                }]
            ),
            Err(EFAULT)
        );
    }
}
