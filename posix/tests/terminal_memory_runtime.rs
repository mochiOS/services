#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/terminal_memory.rs"]
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
macro_rules! abi_type {
    ($name:ident, $definition:ident, {$($fields:tt)*}) => {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct $name { $($fields)* }
        const $definition: &str = stringify!(pub struct $name { $($fields)* });
    };
}
abi_type!(NewlibTermios, ATTRIBUTES, {
    c_iflag: u32, c_oflag: u32, c_cflag: u32, c_lflag: u32,
    c_cc: [u8; posix_protocol::TERMINAL_CONTROL_CHARACTERS],
    c_ispeed: u32, c_ospeed: u32,
});
abi_type!(NewlibWinSize, WINDOW, {
    ws_row: u16, ws_col: u16, ws_xpixel: u16, ws_ypixel: u16,
});
fn attributes() -> NewlibTermios {
    NewlibTermios {
        c_iflag: 0x12345678,
        c_oflag: 0x90abcdef,
        c_cflag: 0xdeadbeef,
        c_lflag: 0x11223344,
        c_cc: std::array::from_fn(|i| i as u8 + 1),
        c_ispeed: 115200,
        c_ospeed: 9600,
    }
}
fn window() -> NewlibWinSize {
    NewlibWinSize {
        ws_row: 33,
        ws_col: 132,
        ws_xpixel: 1920,
        ws_ypixel: 1080,
    }
}

#[test]
fn fixtures_match_production_c_declarations_and_header_layout() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for (name, definition) in [("NewlibTermios", ATTRIBUTES), ("NewlibWinSize", WINDOW)] {
        let start = source.find(&format!("pub struct {name} {{")).unwrap();
        let body = &source[start..];
        let end = body.find("\n}").unwrap() + 2;
        let normalize = |text: &str| {
            text.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        };
        assert_eq!(normalize(&body[..end]), normalize(definition));
    }
    assert_eq!(std::mem::size_of::<NewlibTermios>(), 56);
    assert_eq!(std::mem::size_of::<NewlibWinSize>(), 8);
}

#[test]
fn attribute_bytes_match_c_offsets_with_unaligned_application_memory_and_canaries() {
    let mut bytes = [0xa5; 58];
    let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
    implementation::write_attributes(pointer, attributes()).unwrap();
    assert_eq!(implementation::read_attributes(pointer), Ok(attributes()));
    let mut expected = [0; 56];
    for (offset, value) in [
        (0, 0x12345678u32),
        (4, 0x90abcdef),
        (8, 0xdeadbeef),
        (12, 0x11223344),
        (48, 115200),
        (52, 9600),
    ] {
        expected[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    expected[16..48].copy_from_slice(&attributes().c_cc);
    assert_eq!(&bytes[1..57], expected);
    assert_eq!((bytes[0], bytes[57]), (0xa5, 0xa5));
}

#[test]
fn window_bytes_match_c_offsets_and_preserve_neighboring_storage() {
    let mut bytes = [0xa5; 10];
    let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
    implementation::write_window(pointer, window()).unwrap();
    assert_eq!(implementation::read_window(pointer), Ok(window()));
    for (index, value) in [33u16, 132, 1920, 1080].into_iter().enumerate() {
        assert_eq!(&bytes[1 + index * 2..3 + index * 2], value.to_ne_bytes());
    }
    assert_eq!((bytes[0], bytes[9]), (0xa5, 0xa5));
}

#[test]
fn unreadable_inputs_and_unwritable_outputs_return_efault_without_raw_access() {
    for address in [0, 1, usize::MAX] {
        assert_eq!(
            implementation::read_attributes(address as *const _),
            Err(EFAULT)
        );
        assert_eq!(
            implementation::read_window(address as *const _),
            Err(EFAULT)
        );
        assert_eq!(
            implementation::write_attributes(address as *mut _, attributes()),
            Err(EFAULT)
        );
        assert_eq!(
            implementation::write_window(address as *mut _, window()),
            Err(EFAULT)
        );
    }
    let source = attributes();
    let start = &source as *const _ as usize;
    user_copy_native::DENIED.set(Some(start + 55..start + 56));
    assert_eq!(implementation::read_attributes(&source), Err(EFAULT));
    user_copy_native::DENIED.set(None);
}
