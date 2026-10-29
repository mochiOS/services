//! Own-process VM boundary for the actual startup scratch allocator.
use std::cell::{Cell, RefCell};
thread_local! {
    pub static DENIED: Cell<bool> = const { Cell::new(false) };
    pub static ALLOCATIONS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
}
pub struct Limit;
pub fn current() -> Result<Limit, i32> {
    if DENIED.get() { Err(12) } else { Ok(Limit) }
}
impl Limit {
    pub fn map(
        self,
        address: u64,
        length: u64,
        access: u64,
        options: u64,
        backing: u64,
        offset: u64,
    ) -> Result<u64, i32> {
        assert_eq!((address, access, options, backing, offset), (0, 3, 0, 0, 0));
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(12);
        }
        ALLOCATIONS.with_borrow_mut(|a| a.push((p as u64, length)));
        Ok(p as u64)
    }
}
