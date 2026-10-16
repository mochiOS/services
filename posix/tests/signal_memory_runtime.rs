#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
#[path = "../../../user/crates/newlib-runtime/src/signal_memory.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EOVERFLOW: c_int = 139;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
const TEST_SIGNAL: u32 = 30;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalAction {
    handler: usize,
    sa_mask: u64,
    sa_flags: c_int,
}
use mochios_posix_client::signal_context::SigInfo;
fn action() -> SignalAction {
    SignalAction {
        handler: usize::MAX - 1,
        sa_mask: 0x123456789abcdef0,
        sa_flags: -7,
    }
}
fn origin() -> posix_protocol::signal_origin::Origin {
    posix_protocol::signal_origin::Origin {
        source: posix_protocol::signal_origin::USER,
        process_id: 0x112233,
        real_uid: 0x5566,
        child: Default::default(),
    }
}
#[test]
fn signal_action_uses_c_offsets_and_zeroes_padding_without_borrowing_callers() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("pub struct SignalAction {").unwrap();
    let end = start + source[start..].find("\n}").unwrap() + 2;
    let compact = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    assert_eq!(
        compact(&source[start..end]),
        compact("pub struct SignalAction { handler: usize, sa_mask: u64, sa_flags: c_int, }")
    );
    let mut bytes = [0xa5; 26];
    let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
    implementation::write_action(pointer, action()).unwrap();
    assert_eq!(implementation::read_action(pointer), Ok(action()));
    assert_eq!(&bytes[1..9], action().handler.to_ne_bytes());
    assert_eq!(&bytes[9..17], action().sa_mask.to_ne_bytes());
    assert_eq!(&bytes[17..21], (-7i32).to_ne_bytes());
    assert_eq!(&bytes[21..25], [0; 4]);
    assert_eq!((bytes[0], bytes[25]), (0xa5, 0xa5));
}
#[test]
fn signal_sets_and_selected_signal_preserve_full_width_and_neighboring_bytes() {
    let mut bytes = [0xa5; 10];
    let pointer = bytes.as_mut_ptr().wrapping_add(1);
    implementation::write_set(pointer.cast(), u64::MAX).unwrap();
    assert_eq!(implementation::read_set(pointer.cast()), Ok(u64::MAX));
    implementation::write_selected(pointer.cast(), -17).unwrap();
    assert_eq!(&bytes[1..5], (-17i32).to_ne_bytes());
    assert_eq!(&bytes[5..9], [0xff; 4]);
    assert_eq!((bytes[0], bytes[9]), (0xa5, 0xa5));
}
#[test]
fn info_serializes_authenticated_origin_and_zeroes_unused_fields() {
    let mut bytes = [0xa5; 42];
    let pointer = bytes.as_mut_ptr().wrapping_add(1).cast();
    implementation::write_info(pointer, TEST_SIGNAL, origin()).unwrap();
    let mut expected = [0; 40];
    expected[0..4].copy_from_slice(&(TEST_SIGNAL as i32).to_ne_bytes());
    expected[4..8].copy_from_slice(&1i32.to_ne_bytes());
    expected[20..24].copy_from_slice(&0x112233i32.to_ne_bytes());
    expected[24..26].copy_from_slice(&0x5566u16.to_ne_bytes());
    assert_eq!(&bytes[1..41], expected);
    assert_eq!((bytes[0], bytes[41]), (0xa5, 0xa5));
    assert_eq!(std::mem::size_of::<SigInfo>(), 40);
}
#[test]
fn optional_info_still_validates_origin_and_overflow() {
    let mut source = origin();
    source.real_uid = u16::MAX as u32 + 1;
    assert_eq!(
        implementation::write_info(std::ptr::null_mut(), TEST_SIGNAL, source),
        Err(EOVERFLOW)
    );
    assert_eq!(
        implementation::write_info(std::ptr::null_mut(), 0, origin()),
        Err(EIO)
    );
    assert_eq!(
        implementation::write_info(std::ptr::null_mut(), TEST_SIGNAL, origin()),
        Ok(())
    );
}
#[test]
fn invalid_application_memory_returns_efault_for_each_metadata_format() {
    for address in [0, 1, usize::MAX] {
        assert_eq!(
            implementation::read_action(address as *const _),
            Err(EFAULT)
        );
        assert_eq!(
            implementation::write_action(address as *mut _, action()),
            Err(EFAULT)
        );
        assert_eq!(implementation::read_set(address as *const _), Err(EFAULT));
        assert_eq!(implementation::write_set(address as *mut _, 1), Err(EFAULT));
        assert_eq!(
            implementation::write_selected(address as *mut _, 1),
            Err(EFAULT)
        );
        if address != 0 {
            assert_eq!(
                implementation::write_info(
                    address as *mut _,
                    TEST_SIGNAL,
                    origin()
                ),
                Err(EFAULT)
            );
        }
    }
}
#[test]
fn committed_handler_is_published_before_fallible_copyout() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source
        .find("let _update = SIGNAL_ACTION_UPDATE.lock();")
        .unwrap();
    let end = start + source[start..].find("fn service_signal_mask(").unwrap();
    let body = &source[start..end];
    assert!(
        body.find("set_signal_disposition(").unwrap()
            < body.find("actions[index] = replacement").unwrap()
    );
    assert!(
        body.find("actions[index] = replacement").unwrap()
            < body
                .find("signal_memory::write_action(old_action, previous)")
                .unwrap()
    );
    let start = source
        .find("pub unsafe extern \"C\" fn sigaction(")
        .unwrap();
    let end = source
        .find("pub unsafe extern \"C\" fn _signal_r(")
        .unwrap();
    for raw in [
        "action.read()",
        "old_action.write(",
        "set.read()",
        "set.write(",
        "old_set.write(",
        "selected.write(",
        "info.write(",
    ] {
        assert!(!source[start..end].contains(raw), "raw C access: {raw}");
    }
}
