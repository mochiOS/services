//! Executes the production syscall with caller/table and usercopy test doubles.
extern crate alloc;

use mnu_abi::status::Error;
use std::cell::{Cell, RefCell};

thread_local! {static FAIL_ALLOCATION:Cell<bool>=const {Cell::new(false)};}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if FAIL_ALLOCATION
            .try_with(|flag| flag.replace(false))
            .unwrap_or(false)
        {
            return std::ptr::null_mut();
        }
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[derive(Default)]
struct Backend {
    owner: Option<u64>,
    locked: bool,
    records: Vec<mnu_abi::HandleInfo>,
    copied: Vec<u8>,
    foreign_reads: usize,
    missing_table: bool,
    copy_failure: Option<Error>,
}
thread_local! { static STATE: RefCell<Backend> = RefCell::default(); }

mod task {
    pub mod handle_table {
        pub const PROCESS_MAX_OBJECT_HANDLES: usize = 4096;
    }
    pub struct Process<'a>(&'a [mnu_abi::HandleInfo]);
    impl Process<'_> {
        pub fn object_handles(&self) -> &Self {
            self
        }
        pub fn describe(&self) -> impl ExactSizeIterator<Item = mnu_abi::HandleInfo> + '_ {
            self.0.iter().copied()
        }
    }
    pub fn with_process<T>(owner: u64, callback: impl FnOnce(&Process) -> T) -> Option<T> {
        let valid = super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.owner != Some(owner) {
                state.foreign_reads += 1;
                return false;
            }
            if state.missing_table {
                return false;
            }
            state.locked = true;
            true
        });
        if !valid {
            return None;
        }
        let result = super::STATE.with(|state| callback(&Process(&state.borrow().records)));
        super::STATE.with(|state| state.borrow_mut().locked = false);
        Some(result)
    }
}
mod syscall {
    pub mod security {
        pub fn current_process_id() -> Option<u64> {
            super::super::STATE.with(|state| state.borrow().owner)
        }
    }
    pub fn copy_to_user_native(output: u64, bytes: &[u8]) -> Result<(), mnu_abi::status::Error> {
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert!(
                !state.locked,
                "usercopy must be outside the process-table lock"
            );
            if output != 0x1000 {
                return Err(mnu_abi::status::Error::InvalidAddress);
            }
            if let Some(error) = state.copy_failure {
                return Err(error);
            }
            state.copied = bytes.to_vec();
            Ok(())
        })
    }
}
#[path = "../../../core/src/syscall/handle/snapshot.rs"]
mod production;

fn setup() {
    STATE.with(|state| {
        *state.borrow_mut() = Backend {
            owner: Some(17),
            records: vec![
                mnu_abi::HandleInfo {
                    handle: 1,
                    reserved: 0,
                    rights: 0,
                },
                mnu_abi::HandleInfo {
                    handle: 41,
                    reserved: 0,
                    rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
                },
            ],
            copied: vec![0xa5; 32],
            ..Default::default()
        }
    });
}

#[test]
fn metadata_layout_and_number_are_native_and_fixed() {
    assert_eq!(core::mem::size_of::<mnu_abi::HandleInfo>(), 16);
    assert_eq!(core::mem::offset_of!(mnu_abi::HandleInfo, rights), 8);
    assert_eq!(mnu_abi::SyscallNumber::HandleTableRead as u64, 680);
}

#[test]
fn query_does_not_copy_or_duplicate_any_reference() {
    setup();
    assert_eq!(production::table_read(0, 0), 2);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.copied, vec![0xa5; 32]);
        assert_eq!(state.records.len(), 2);
        assert_eq!(state.foreign_reads, 0);
    });
}

#[test]
fn snapshot_preserves_zero_rights_and_full_width_transfer_metadata() {
    setup();
    assert_eq!(production::table_read(0x1000, 2), 2);
    STATE.with(|state| {
        let state = state.borrow();
        let bytes = &state.copied;
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(&bytes[4..16], &[0; 12]);
        assert_eq!(&bytes[16..20], &41u32.to_le_bytes());
        assert_eq!(&bytes[20..24], &[0; 4]);
        assert_eq!(&bytes[24..32], &state.records[1].rights.to_le_bytes());
        assert_eq!(state.foreign_reads, 0);
    });
}

#[test]
fn short_buffer_is_rejected_without_truncation_or_write() {
    setup();
    assert_eq!(
        production::table_read(0x1000, 1),
        Error::LimitExceeded.into_raw()
    );
    STATE.with(|state| assert_eq!(state.borrow().copied, vec![0xa5; 32]));
}

#[test]
fn observation_is_not_a_reservation_and_growth_requires_a_retry() {
    setup();
    assert_eq!(production::table_read(0, 0), 2);
    STATE.with(|state| {
        state.borrow_mut().records.push(mnu_abi::HandleInfo {
            handle: 42,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_READ,
        })
    });
    assert_eq!(
        production::table_read(0x1000, 2),
        Error::LimitExceeded.into_raw()
    );
    STATE.with(|state| assert_eq!(state.borrow().copied, vec![0xa5; 32]));
    assert_eq!(production::table_read(0, 0), 3);
    assert_eq!(production::table_read(0x1000, 3), 3);
}

#[test]
fn an_empty_owned_table_returns_no_records() {
    setup();
    STATE.with(|state| state.borrow_mut().records.clear());
    assert_eq!(production::table_read(0, 0), 0);
    assert_eq!(production::table_read(0x1000, 1), 0);
    STATE.with(|state| assert!(state.borrow().copied.is_empty()));
}

#[test]
fn query_pairs_capacity_limits_and_usercopy_faults_are_checked() {
    setup();
    assert_eq!(
        production::table_read(1, 0),
        Error::InvalidArgument.into_raw()
    );
    assert_eq!(
        production::table_read(0, 1),
        Error::InvalidAddress.into_raw()
    );
    assert_eq!(
        production::table_read(0x1000, 4097),
        Error::InvalidArgument.into_raw()
    );
    assert_eq!(
        production::table_read(0x2000, 2),
        Error::InvalidAddress.into_raw()
    );
    STATE.with(|state| assert_eq!(state.borrow().copied, vec![0xa5; 32]));
}

#[test]
fn missing_execution_owner_cannot_read_any_table() {
    setup();
    STATE.with(|state| state.borrow_mut().owner = None);
    assert_eq!(production::table_read(0, 0), Error::NotReady.into_raw());
    STATE.with(|state| assert_eq!(state.borrow().foreign_reads, 0));
}

#[test]
fn count_query_allocates_nothing_and_failed_buffer_allocation_writes_nothing() {
    setup();
    FAIL_ALLOCATION.set(true);
    let count = production::table_read(0, 0);
    let unused_failure = FAIL_ALLOCATION.replace(false);
    assert_eq!(count, 2);
    assert!(unused_failure, "count query must not allocate");
    FAIL_ALLOCATION.set(true);
    let result = production::table_read(0x1000, 2);
    let unused_failure = FAIL_ALLOCATION.replace(false);
    assert_eq!(result, Error::ResourceUnavailable.into_raw());
    assert!(!unused_failure);
    STATE.with(|state| {
        let state = state.borrow();
        assert!(!state.locked);
        assert_eq!(state.copied, vec![0xa5; 32]);
    });
    assert_eq!(production::table_read(0x1000, 2), 2);
}

#[test]
fn vanished_table_and_native_copy_failures_keep_their_own_cause() {
    setup();
    STATE.with(|state| state.borrow_mut().missing_table = true);
    assert_eq!(production::table_read(0, 0), Error::NotReady.into_raw());
    assert_eq!(
        production::table_read(0x1000, 2),
        Error::NotReady.into_raw()
    );
    STATE.with(|state| state.borrow_mut().missing_table = false);
    for error in [
        Error::InvalidAddress,
        Error::BackingFailure,
        Error::NotReady,
    ] {
        STATE.with(|state| state.borrow_mut().copy_failure = Some(error));
        assert_eq!(production::table_read(0x1000, 2), error.into_raw());
        STATE.with(|state| assert_eq!(state.borrow().copied, vec![0xa5; 32]));
    }
}
