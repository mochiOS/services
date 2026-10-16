#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int, c_void};
#[path = "../../../user/crates/newlib-runtime/src/socket_message_memory.rs"]
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
macro_rules! abi {
    ($name:ident, $definition:ident, {$($fields:tt)*}) => {
        #[repr(C)] #[derive(Clone, Copy)] struct $name { $($fields)* }
        const $definition: &str = stringify!(struct $name { $($fields)* });
    };
}
abi!(Message, MESSAGE, {
    name: *mut c_void, name_length: u32,
    vectors: *const IoVecMut, vector_count: usize,
    control: *mut c_void, control_length: usize, flags: c_int,
});
abi!(IoVecMut, IOVEC, { iov_base: *mut c_void, iov_len: usize, });
struct Vector {
    base: *mut u8,
    length: usize,
}
fn sample() -> Message {
    Message {
        name: 0x1234 as *mut _,
        name_length: 108,
        vectors: 0x5678 as *const _,
        vector_count: 3,
        control: 0x9876 as *mut _,
        control_length: 64,
        flags: -7,
    }
}
#[test]
fn fixture_layouts_match_the_actual_c_metadata_declarations() {
    let socket = include_str!("../../../user/crates/newlib-runtime/src/socket_message.rs");
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for (source, name, expected) in [(socket, "Message", MESSAGE), (runtime, "IoVecMut", IOVEC)] {
        let begin = source.find(&format!("struct {name} {{")).unwrap();
        let end = begin + source[begin..].find("\n}").unwrap() + 2;
        let compact = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        assert_eq!(compact(&source[begin..end]), compact(expected));
    }
    assert_eq!(std::mem::size_of::<Message>(), 56);
    assert_eq!(std::mem::size_of::<IoVecMut>(), 16);
}
#[test]
fn message_copy_has_c_offsets_zero_padding_and_unaligned_canaries() {
    let mut bytes = [0xa5; 58];
    let output = bytes.as_mut_ptr().wrapping_add(1).cast();
    memory::write_message(output, sample()).unwrap();
    let decoded = memory::read_message(output).unwrap();
    assert_eq!(
        (
            decoded.name as usize,
            decoded.name_length,
            decoded.vectors as usize,
            decoded.vector_count,
            decoded.control as usize,
            decoded.control_length,
            decoded.flags
        ),
        (0x1234, 108, 0x5678, 3, 0x9876, 64, -7)
    );
    let mut expected = [0; 56];
    for (offset, value) in [
        (0, 0x1234usize),
        (16, 0x5678),
        (24, 3),
        (32, 0x9876),
        (40, 64),
    ] {
        expected[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    expected[8..12].copy_from_slice(&108u32.to_ne_bytes());
    expected[48..52].copy_from_slice(&(-7i32).to_ne_bytes());
    assert_eq!(&bytes[1..57], expected);
    assert_eq!((bytes[0], bytes[57]), (0xa5, 0xa5));
}
#[test]
fn vector_indices_are_checked_before_integer_addressing_and_copy() {
    let mut bytes = [0; 33];
    bytes[17..25].copy_from_slice(&0xabcusize.to_ne_bytes());
    bytes[25..33].copy_from_slice(&17usize.to_ne_bytes());
    let base = bytes.as_ptr().wrapping_add(1).cast();
    let vector = memory::read_vector(base, 1).unwrap();
    assert_eq!((vector.base as usize, vector.length), (0xabc, 17));
    assert!(matches!(memory::read_vector(base, usize::MAX), Err(EFAULT)));
    assert!(matches!(
        memory::read_vector(usize::MAX as *const _, 1),
        Err(EFAULT)
    ));
}
#[test]
fn bad_header_and_vector_pointers_return_efault_without_rust_dereferences() {
    for address in [0, 1, usize::MAX] {
        assert!(matches!(
            memory::read_message(address as *const _),
            Err(EFAULT)
        ));
        assert!(matches!(
            memory::read_vector(address as *const _, 0),
            Err(EFAULT)
        ));
        assert_eq!(
            memory::write_message(address as *mut _, sample()),
            Err(EFAULT)
        );
    }
}
