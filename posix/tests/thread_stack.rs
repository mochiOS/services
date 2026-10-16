#[path = "../../../user/crates/posix-client/src/thread_stack.rs"]
mod layout;

#[allow(non_camel_case_types)]
type c_int = i32;
const EINVAL: c_int = 22;
const PAGE_SIZE: usize = 4096;
const NATIVE_READ_WRITE: u64 = 3;

use std::cell::RefCell;
thread_local! {
    static EVENTS: RefCell<Vec<(u64,u64,u64)>> = const { RefCell::new(Vec::new()) };
    static MAP: RefCell<Result<u64,c_int>> = const { RefCell::new(Ok(0x10000)) };
    static PROTECT: RefCell<Result<u64,c_int>> = const { RefCell::new(Ok(0)) };
}

mod address_space {
    pub struct Limit;
    pub fn current() -> Result<Limit, i32> {
        Ok(Limit)
    }
    impl Limit {
        pub fn map(
            &self,
            address: u64,
            size: u64,
            access: u64,
            options: u64,
            backing: u64,
            offset: u64,
        ) -> Result<u64, i32> {
            assert_eq!((address, access, options, backing, offset), (0, 0, 0, 0, 0));
            super::EVENTS.with_borrow_mut(|v| v.push((1, size, access)));
            super::MAP.with_borrow(|r| *r)
        }
    }
}
mod syscall {
    pub enum SyscallNumber {
        MemoryProtect,
        MemoryUnmap,
    }
    pub fn raw_syscall3(
        number: SyscallNumber,
        address: u64,
        size: u64,
        access: u64,
    ) -> Result<u64, i32> {
        assert!(matches!(number, SyscallNumber::MemoryProtect));
        assert_eq!(access, super::NATIVE_READ_WRITE);
        super::EVENTS.with_borrow_mut(|v| v.push((2, address, size)));
        super::PROTECT.with_borrow(|r| *r)
    }
    pub fn raw_syscall2(number: SyscallNumber, address: u64, size: u64) -> Result<u64, i32> {
        assert!(matches!(number, SyscallNumber::MemoryUnmap));
        super::EVENTS.with_borrow_mut(|v| v.push((3, address, size)));
        Ok(0)
    }
}
fn syscall_errno(result: Result<u64, c_int>) -> Result<u64, c_int> {
    result
}

extern crate self as mochios_posix_client;
pub mod thread_stack {
    pub use super::layout::Layout;
}
#[path = "../../../user/crates/newlib-runtime/src/thread_stack.rs"]
mod runtime;

#[test]
fn layout_keeps_the_requested_usable_size_and_checks_rounding_overflow() {
    use layout::Layout;
    let plan = Layout::new(8193, 1, 4096).unwrap();
    assert_eq!(
        (plan.usable_size, plan.guard_size, plan.mapping_size),
        (12288, 4096, 16384)
    );
    assert_eq!(Layout::new(8192, 0, 4096).unwrap().mapping_size, 8192);
    for (stack, guard, page) in [
        (0, 1, 4096),
        (1, 1, 0),
        (1, 1, 3),
        (usize::MAX, 1, 4096),
        (1, usize::MAX, 4096),
        (usize::MAX - 4095, 4096, 4096),
    ] {
        assert_eq!(Layout::new(stack, guard, page), None);
    }
}

fn run(
    map: Result<u64, c_int>,
    protect: Result<u64, c_int>,
    expected: Result<(usize, usize), c_int>,
    events: &[(u64, u64, u64)],
) {
    MAP.set(map);
    PROTECT.set(protect);
    EVENTS.with_borrow_mut(Vec::clear);
    assert_eq!(runtime::allocate(8193, PAGE_SIZE), expected);
    EVENTS.with_borrow(|v| assert_eq!(v, events));
}

#[test]
fn allocator_reserves_inaccessible_guard_then_protects_only_usable_stack() {
    run(
        Ok(0x10000),
        Ok(0),
        Ok((0x10000, 16384)),
        &[(1, 16384, 0), (2, 0x11000, 12288)],
    );
}

#[test]
fn allocator_supports_disabled_and_rounded_guards() {
    for (guard, size, usable) in [
        (0, 12288, 0x10000),
        (1, 16384, 0x11000),
        (4097, 20480, 0x12000),
    ] {
        MAP.set(Ok(0x10000));
        PROTECT.set(Ok(0));
        EVENTS.with_borrow_mut(Vec::clear);
        assert_eq!(runtime::allocate(8193, guard), Ok((0x10000, size)));
        EVENTS.with_borrow(|v| assert_eq!(v, &[(1, size as u64, 0), (2, usable, 12288)]));
    }
    EVENTS.with_borrow_mut(Vec::clear);
    assert_eq!(runtime::allocate(8193, usize::MAX), Err(EINVAL));
    EVENTS.with_borrow(|v| assert!(v.is_empty()));
}

#[test]
fn failures_do_not_leave_a_partially_initialized_mapping() {
    run(Err(12), Ok(0), Err(12), &[(1, 16384, 0)]);
    run(
        Ok(0x10000),
        Err(13),
        Err(13),
        &[(1, 16384, 0), (2, 0x11000, 12288), (3, 0x10000, 16384)],
    );
    run(
        Ok((usize::MAX - 4095) as u64),
        Ok(0),
        Err(EINVAL),
        &[(1, 16384, 0), (3, (usize::MAX - 4095) as u64, 16384)],
    );
}
