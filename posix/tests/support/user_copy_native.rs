//! Host MemoryCopy boundary: Linux's own-process read validates actual mappings
//! without forming Rust references to potentially invalid application memory.
use std::cell::RefCell;
use std::ffi::{c_int, c_void};
thread_local! {
    pub static CALLS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    pub static DENIED: RefCell<Option<std::ops::Range<usize>>> = const { RefCell::new(None) };
}
#[repr(C)]
struct Iovec {
    pointer: *mut c_void,
    length: usize,
}
unsafe extern "C" {
    fn process_vm_readv(
        pid: c_int,
        local: *const Iovec,
        local_count: usize,
        remote: *const Iovec,
        remote_count: usize,
        flags: usize,
    ) -> isize;
}
pub mod syscall {
    pub use mnu_abi::SyscallNumber;
    pub fn raw_syscall3(
        number: SyscallNumber,
        destination: u64,
        source: u64,
        length: u64,
    ) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::MemoryCopy);
        assert!(length <= mnu_abi::memory_copy::MAX_BYTES as u64);
        super::CALLS.with_borrow_mut(|calls| calls.push(length as usize));
        if super::DENIED.with_borrow(|denied| {
            denied.as_ref().is_some_and(|range| {
                let start = source as usize;
                start < range.end && start.saturating_add(length as usize) > range.start
            })
        }) {
            return Err(14);
        }
        let local = super::Iovec {
            pointer: destination as *mut _,
            length: length as usize,
        };
        let remote = super::Iovec {
            pointer: source as *mut _,
            length: length as usize,
        };
        let copied =
            unsafe { super::process_vm_readv(std::process::id() as i32, &local, 1, &remote, 1, 0) };
        if copied < 0 && std::io::Error::last_os_error().raw_os_error() != Some(14) {
            panic!(
                "host self-memory copy unavailable: {}",
                std::io::Error::last_os_error()
            );
        }
        if copied != length as isize {
            Err(14)
        } else {
            Ok(length)
        }
    }
}
pub fn syscall_errno(result: Result<u64, i32>) -> Result<u64, i32> {
    result
}
