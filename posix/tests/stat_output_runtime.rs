#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int, c_void};
#[path = "../../../user/crates/newlib-runtime/src/stat_output.rs"]
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
        #[derive(Clone, Copy)]
        struct $name { $($fields)* }
        const $definition: &str = stringify!(struct $name { $($fields)* });
    };
}
abi_type!(NewlibTimespec, TIMESPEC, { tv_sec: i64, tv_nsec: i64, });
abi_type!(NewlibStat, STAT, {
    st_dev: u16, st_ino: u16, st_mode: u32, st_nlink: u16,
    st_uid: u16, st_gid: u16, st_rdev: u16, st_size: i64,
    st_atim: NewlibTimespec, st_mtim: NewlibTimespec, st_ctim: NewlibTimespec,
    st_blksize: i64, st_blocks: i64, st_spare4: [i64; 2],
});
fn sample() -> NewlibStat {
    NewlibStat {
        st_dev: 1,
        st_ino: 2,
        st_mode: 0o100640,
        st_nlink: 3,
        st_uid: 4,
        st_gid: 5,
        st_rdev: 6,
        st_size: -7,
        st_atim: NewlibTimespec {
            tv_sec: -8,
            tv_nsec: 9,
        },
        st_mtim: NewlibTimespec {
            tv_sec: 10,
            tv_nsec: 11,
        },
        st_ctim: NewlibTimespec {
            tv_sec: -12,
            tv_nsec: 13,
        },
        st_blksize: 4096,
        st_blocks: 14,
        st_spare4: [15, -16],
    }
}
#[test]
fn host_fixture_is_the_actual_production_c_layout_definition() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for (name, definition) in [("NewlibStat", STAT), ("NewlibTimespec", TIMESPEC)] {
        let start = source.find(&format!("struct {name} {{")).unwrap();
        let body = &source[start..];
        let end = body.find("\n}").unwrap() + 2;
        let normalize = |text: &str| {
            text.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        };
        assert_eq!(normalize(&body[..end]), normalize(definition));
    }
    assert_eq!(std::mem::size_of::<NewlibStat>(), 104);
}
#[test]
fn every_field_has_the_newlib_byte_offset_and_copyout_preserves_canaries() {
    let mut output = [0xa5u8; 106];
    assert_eq!(
        implementation::write(unsafe { output.as_mut_ptr().add(1) }.cast(), &sample()),
        Ok(0)
    );
    let mut expected = [0; 104];
    for (offset, value) in [(0, 1u16), (2, 2), (8, 3), (10, 4), (12, 5), (14, 6)] {
        expected[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
    }
    expected[4..8].copy_from_slice(&0o100640u32.to_ne_bytes());
    for (offset, value) in [
        (16, -7i64),
        (24, -8),
        (32, 9),
        (40, 10),
        (48, 11),
        (56, -12),
        (64, 13),
        (72, 4096),
        (80, 14),
        (88, 15),
        (96, -16),
    ] {
        expected[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    assert_eq!(&output[1..105], expected);
    assert_eq!((output[0], output[105]), (0xa5, 0xa5));
}
#[test]
fn invalid_stat_output_is_an_error_not_a_host_memory_exception() {
    for address in [0, 1, usize::MAX] {
        assert_eq!(
            implementation::write(address as *mut c_void, &sample()),
            Err(EFAULT)
        );
    }
}
