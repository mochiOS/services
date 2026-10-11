//! Executes the production syscall with caller/table and usercopy test doubles.
extern crate alloc;

use std::cell::RefCell;

#[derive(Default)]
struct Backend {
    owner: Option<u64>,
    locked: bool,
    records: Vec<mnu_abi::HandleInfo>,
    copied: Vec<u8>,
    foreign_reads: usize,
}
thread_local! { static STATE: RefCell<Backend> = RefCell::default(); }

mod task {
    pub mod handle_table {
        pub const PROCESS_MAX_OBJECT_HANDLES: usize = 4096;
    }
    pub struct Process;
    pub struct Table;
    impl Process {
        pub fn object_handles(&self) -> Table {
            Table
        }
    }
    impl Table {
        pub fn describe(&self) -> Vec<mnu_abi::HandleInfo> {
            super::STATE.with(|state| state.borrow().records.clone())
        }
    }
    pub fn with_process<T>(owner: u64, callback: impl FnOnce(&Process) -> T) -> Option<T> {
        let valid = super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.owner != Some(owner) {
                state.foreign_reads += 1;
                return false;
            }
            state.locked = true;
            true
        });
        if !valid {
            return None;
        }
        let result = callback(&Process);
        super::STATE.with(|state| state.borrow_mut().locked = false);
        Some(result)
    }
}
mod syscall {
    pub const EFAULT: u64 = (-14i64) as u64;
    pub const EINVAL: u64 = (-22i64) as u64;
    pub const ENOSPC: u64 = (-28i64) as u64;
    pub fn copy_to_user(output: u64, bytes: &[u8]) -> Result<(), u64> {
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert!(
                !state.locked,
                "usercopy must be outside the process-table lock"
            );
            if output != 0x1000 {
                return Err(EFAULT);
            }
            state.copied = bytes.to_vec();
            Ok(())
        })
    }
}
fn current_process() -> Result<u64, u64> {
    STATE.with(|state| state.borrow().owner.ok_or(syscall::EINVAL))
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
    assert_eq!(production::table_read(0x1000, 1), syscall::ENOSPC);
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
    assert_eq!(production::table_read(0x1000, 2), syscall::ENOSPC);
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
    assert_eq!(production::table_read(1, 0), syscall::EINVAL);
    assert_eq!(production::table_read(0, 1), syscall::EFAULT);
    assert_eq!(production::table_read(0x1000, 4097), syscall::EINVAL);
    assert_eq!(production::table_read(0x2000, 2), syscall::EFAULT);
    STATE.with(|state| assert_eq!(state.borrow().copied, vec![0xa5; 32]));
}

#[test]
fn missing_execution_owner_cannot_read_any_table() {
    setup();
    STATE.with(|state| state.borrow_mut().owner = None);
    assert_eq!(production::table_read(0, 0), syscall::EINVAL);
    STATE.with(|state| assert_eq!(state.borrow().foreign_reads, 0));
}
