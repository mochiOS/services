//! Execute the actual kernel operation with deterministic CPU/thread hooks.
extern crate self as x86_64;
use mnu_abi::status::Error;
use std::cell::{Cell, RefCell};
thread_local! {
    static PRESENT: Cell<bool> = const { Cell::new(true) };
    static RETAINED: Cell<bool> = const { Cell::new(true) };
    static DISABLED: Cell<bool> = const { Cell::new(false) };
    static SAVED: Cell<u64> = const { Cell::new(4096) };
    static LIVE: Cell<u64> = const { Cell::new(4096) };
    static WRITES: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}
pub mod instructions {
    pub mod interrupts {
        pub fn without_interrupts<T>(operation: impl FnOnce() -> T) -> T {
            assert!(!crate::DISABLED.replace(true));
            let result = operation();
            assert!(crate::DISABLED.replace(false));
            result
        }
    }
}
mod task {
    pub struct Thread;
    impl Thread {
        pub fn set_fs_base(&mut self, base: u64) {
            assert!(super::DISABLED.get());
            super::SAVED.set(base);
        }
    }
    pub fn current_thread_id() -> Option<u32> {
        super::PRESENT.get().then_some(7)
    }
    pub fn with_thread_mut<T>(id: u32, operation: impl FnOnce(&mut Thread) -> T) -> Option<T> {
        assert_eq!(id, 7);
        super::RETAINED.get().then(|| operation(&mut Thread))
    }
}
mod cpu {
    pub unsafe fn write_fs_base(base: u64) {
        assert!(super::DISABLED.get());
        assert_eq!(super::SAVED.get(), base);
        super::LIVE.set(base);
        super::WRITES.with_borrow_mut(|writes| writes.push(base));
    }
}
// The operation validates a register value, not mapped user storage. Address
// boundary validation is also checked against the production helper below.
fn is_canonical_user_range(base: u64, _length: u64) -> bool {
    base != 0 && base <= 0x7fff_ffff_ffff
}
#[path = "../../../core/src/syscall/thread_local.rs"]
mod implementation;

#[test]
fn updates_current_live_and_saved_state_together_without_reading_a_tls_template() {
    WRITES.with_borrow_mut(Vec::clear);
    for base in [0, 1, 4096, 0x7fff_ffff_ffff] {
        assert_eq!(implementation::set_base(base, 0), 0);
        assert_eq!((LIVE.get(), SAVED.get()), (base, base));
    }
    assert!(!DISABLED.get());
    WRITES.with_borrow(|values| assert_eq!(values, &[0, 1, 4096, 0x7fff_ffff_ffff]));
    assert_eq!(mnu_abi::SyscallNumber::ThreadLocalBaseSet as u64, 704);
}

#[test]
fn invalid_context_or_input_never_changes_either_register_representation() {
    WRITES.with_borrow_mut(Vec::clear);
    for base in [0x8000_0000_0000, 0xffff_8000_0000_0000, u64::MAX] {
        assert_eq!(
            implementation::set_base(base, 0),
            Error::InvalidAddress.into_raw()
        );
    }
    assert_eq!(
        implementation::set_base(8192, 1),
        Error::InvalidArgument.into_raw()
    );
    PRESENT.set(false);
    assert_eq!(
        implementation::set_base(8192, 0),
        Error::NotReady.into_raw()
    );
    PRESENT.set(true);
    RETAINED.set(false);
    assert_eq!(
        implementation::set_base(8192, 0),
        Error::NotReady.into_raw()
    );
    RETAINED.set(true);
    assert_eq!((LIVE.get(), SAVED.get()), (4096, 4096));
    assert!(!DISABLED.get());
    WRITES.with_borrow(|values| assert!(values.is_empty()));
}
