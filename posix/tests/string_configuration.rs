//! Execute the runtime confstr implementation against checked host mappings.
#![allow(dead_code)]
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

#[path = "../../../user/crates/newlib-runtime/src/string_configuration.rs"]
mod implementation;
#[path = "support/user_copy_native.rs"]
mod native;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;

const EINVAL: c_int = 22;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
static ERRNO: AtomicI32 = AtomicI32::new(0);
static DEFER: AtomicU32 = AtomicU32::new(0);
static SHORT_COPY: AtomicBool = AtomicBool::new(false);
fn set_errno(error: c_int) {
    ERRNO.store(error, Ordering::Relaxed);
}
fn defer_native_delivery() -> Option<mochios_posix_client::upcall_guard::Guard<'static>> {
    mochios_posix_client::upcall_guard::Guard::enter(&DEFER)
}
fn syscall_errno(result: Result<u64, c_int>) -> Result<u64, c_int> {
    result
}
mod syscall {
    pub use mnu_abi::SyscallNumber;
    pub fn raw_syscall3(
        number: SyscallNumber,
        destination: u64,
        source: u64,
        length: u64,
    ) -> Result<u64, i32> {
        assert_ne!(super::DEFER.load(super::Ordering::Relaxed), 0);
        if super::SHORT_COPY.load(super::Ordering::Relaxed) {
            return Ok(length - 1);
        }
        super::native::syscall::raw_syscall3(number, destination, source, length)
    }
}
unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, length: usize, prot: i32) -> i32;
    fn munmap(address: *mut c_void, length: usize) -> i32;
}

#[test]
fn queries_truncation_faults_and_public_selector_follow_the_same_default_path() {
    use implementation::confstr;
    use mochios_posix_client::configuration::{CS_PATH, DEFAULT_EXECUTABLE_PATH};
    let required = DEFAULT_EXECUTABLE_PATH.len() + 1;
    set_errno(73);
    for buffer in [
        std::ptr::null_mut(),
        1usize as *mut c_char,
        usize::MAX as *mut c_char,
    ] {
        assert_eq!(confstr(CS_PATH, buffer, 0), required);
        assert_eq!(ERRNO.load(Ordering::Relaxed), 73);
    }
    assert!(native::CALLS.with_borrow(|calls| calls.is_empty()));
    for length in 1..=required + 3 {
        let mut bytes = vec![0xa5; required + 5];
        assert_eq!(
            confstr(CS_PATH, bytes[1..].as_mut_ptr().cast(), length),
            required
        );
        let copied = DEFAULT_EXECUTABLE_PATH.len().min(length - 1);
        assert_eq!(&bytes[1..1 + copied], &DEFAULT_EXECUTABLE_PATH[..copied]);
        assert_eq!(bytes[1 + copied], 0);
        assert_eq!(bytes[0], 0xa5);
        assert!(bytes[2 + copied..].iter().all(|&byte| byte == 0xa5));
        assert_eq!(ERRNO.load(Ordering::Relaxed), 73);
    }
    let mut bytes = [0xa5; 32];
    for name in [-1, 1, i32::MAX] {
        assert_eq!(confstr(name, bytes.as_mut_ptr().cast(), bytes.len()), 0);
        assert_eq!(ERRNO.load(Ordering::Relaxed), EINVAL);
        assert_eq!(bytes, [0xa5; 32]);
    }
    for buffer in [
        std::ptr::null_mut(),
        1usize as *mut c_char,
        usize::MAX as *mut c_char,
    ] {
        assert_eq!(confstr(CS_PATH, buffer, required), 0);
        assert_eq!(ERRNO.load(Ordering::Relaxed), EFAULT);
    }
    SHORT_COPY.store(true, Ordering::Relaxed);
    assert_eq!(confstr(CS_PATH, bytes.as_mut_ptr().cast(), bytes.len()), 0);
    assert_eq!(ERRNO.load(Ordering::Relaxed), EIO);
    SHORT_COPY.store(false, Ordering::Relaxed);
    let pages = unsafe { mmap(std::ptr::null_mut(), PAGE_SIZE * 2, 3, 0x22, -1, 0) };
    assert_ne!(pages as usize, usize::MAX);
    assert_eq!(
        unsafe { mprotect(pages.cast::<u8>().add(PAGE_SIZE).cast(), PAGE_SIZE, 0) },
        0
    );
    let last = unsafe { pages.cast::<u8>().add(PAGE_SIZE - 1) };
    // len=1 writes only NUL; it must not inspect or write the next page.
    set_errno(73);
    assert_eq!(confstr(CS_PATH, last.cast(), 1), required);
    assert_eq!(unsafe { last.read() }, 0);
    assert_eq!(ERRNO.load(Ordering::Relaxed), 73);
    assert_eq!(confstr(CS_PATH, last.cast(), 2), 0);
    assert_eq!(ERRNO.load(Ordering::Relaxed), EFAULT);
    assert_eq!(unsafe { mprotect(pages, PAGE_SIZE, 1) }, 0);
    assert_eq!(confstr(CS_PATH, pages.cast(), required), 0);
    assert_eq!(ERRNO.load(Ordering::Relaxed), EFAULT);
    assert_eq!(unsafe { munmap(pages, PAGE_SIZE * 2) }, 0);
    assert_eq!(DEFER.load(Ordering::Relaxed), 0);

    // Read only the standalone selector block: the host does not have the
    // generated SDK headers, and this does not pretend to validate their ABI.
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/unistd.h");
    let block = header
        .split("#if defined (__mochios__)\n")
        .nth(1)
        .unwrap()
        .split("#endif")
        .next()
        .unwrap();
    assert_eq!(
        block.split_whitespace().collect::<Vec<_>>(),
        ["#define", "_CS_PATH", "0"]
    );
}
