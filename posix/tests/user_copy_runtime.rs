use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int, c_void};
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
unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        size: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: isize,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, size: usize, protection: c_int) -> c_int;
    fn munmap(address: *mut c_void, size: usize) -> c_int;
}
#[test]
fn copyout_and_input_reject_unmapped_addresses_without_dereferencing_them() {
    assert_eq!(user_copy::write(1usize as *mut u8, b"data"), Err(EFAULT));
    let mut output = [0; posix_protocol::MAX_PATH_LEN];
    assert_eq!(
        user_copy::capture(1usize as *const c_char, &mut output),
        Err(EFAULT)
    );
    assert_eq!(
        user_copy::capture(usize::MAX as *const c_char, &mut output),
        Err(EFAULT)
    );
    assert_eq!(user_copy::write(usize::MAX as *mut u8, b"x"), Err(EFAULT));
}
#[test]
fn capture_stops_at_page_end_nul_and_copyout_respects_readonly_pages() {
    unsafe {
        let memory = mmap(std::ptr::null_mut(), PAGE_SIZE * 2, 3, 0x22, -1, 0).cast::<u8>();
        assert_ne!(memory as usize, usize::MAX);
        memory.add(PAGE_SIZE - 2).write(0xff);
        memory.add(PAGE_SIZE - 1).write(0);
        assert_eq!(mprotect(memory.add(PAGE_SIZE).cast(), PAGE_SIZE, 0), 0);
        let mut output = [0; posix_protocol::MAX_PATH_LEN];
        assert_eq!(
            user_copy::capture(memory.add(PAGE_SIZE - 2).cast(), &mut output),
            Ok(1)
        );
        assert_eq!(output[0], 0xff);
        assert_eq!(mprotect(memory.cast(), PAGE_SIZE, 1), 0);
        assert_eq!(user_copy::write(memory, b"bad"), Err(EFAULT));
        assert_eq!(munmap(memory.cast(), PAGE_SIZE * 2), 0);
    }
}
#[test]
fn failed_window_can_still_contain_a_valid_terminated_prefix() {
    let text = b"ok\0not-addressable";
    let start = text.as_ptr() as usize;
    user_copy_native::DENIED.set(Some(start + 3..start + text.len()));
    let mut output = [0; posix_protocol::MAX_PATH_LEN];
    assert_eq!(user_copy::capture(text.as_ptr().cast(), &mut output), Ok(2));
    assert_eq!(&output[..2], b"ok");
    user_copy_native::DENIED.set(None);
}
#[test]
fn ordinary_capture_batches_bytes_and_copyout_splits_at_the_native_limit() {
    let mut text = vec![0xffu8; posix_protocol::MAX_PATH_LEN];
    text.push(0);
    let mut output = [0; posix_protocol::MAX_PATH_LEN];
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    assert_eq!(
        user_copy::capture(text.as_ptr().cast(), &mut output),
        Ok(output.len())
    );
    user_copy_native::CALLS
        .with_borrow(|calls| assert!(calls.len() < 32, "not a syscall per byte"));
    let mut destination = vec![0xa5; output.len() + 2];
    user_copy::write_c_string(destination.as_mut_ptr(), &output).unwrap();
    assert_eq!(&destination[..output.len()], output);
    assert_eq!(&destination[output.len()..], &[0, 0xa5]);
}

#[test]
fn fixed_input_copy_is_bounded_and_keeps_the_callers_storage_unborrowed() {
    let source = vec![0x6b; mnu_abi::memory_copy::MAX_BYTES + 17];
    let mut destination = vec![0; source.len()];
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    user_copy::read(source.as_ptr(), &mut destination).unwrap();
    assert_eq!(destination, source);
    user_copy_native::CALLS.with_borrow(|calls| {
        assert_eq!(calls.as_slice(), &[mnu_abi::memory_copy::MAX_BYTES, 17]);
    });
    assert_eq!(
        user_copy::read(usize::MAX as *const _, &mut destination),
        Err(EFAULT)
    );
    assert_eq!(user_copy::read(std::ptr::null(), &mut []), Ok(()));
}
