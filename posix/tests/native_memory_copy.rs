//! The production native copy primitive with host resident-copy boundaries.
use mnu_abi::memory_copy::MAX_BYTES;
use std::cell::RefCell;

#[path = "../../../core/src/syscall/memory_copy.rs"]
mod implementation;

mod types {
    pub const EINVAL: u64 = (-22i64) as u64;
}
const EFAULT: u64 = (-14i64) as u64;
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    reads: usize,
    writes: usize,
    fail_read: bool,
    fail_write: bool,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn copy_from_user(source: u64, output: &mut [u8]) -> Result<(), u64> {
    STATE.with_borrow_mut(|state| {
        state.reads += 1;
        if state.fail_read {
            return Err(EFAULT);
        }
        let start = source as usize;
        let end = start.checked_add(output.len()).ok_or(EFAULT)?;
        output.copy_from_slice(state.bytes.get(start..end).ok_or(EFAULT)?);
        Ok(())
    })
}
fn copy_to_user(destination: u64, input: &[u8]) -> Result<(), u64> {
    STATE.with_borrow_mut(|state| {
        state.writes += 1;
        if state.fail_write {
            return Err(EFAULT);
        }
        let start = destination as usize;
        let end = start.checked_add(input.len()).ok_or(EFAULT)?;
        state
            .bytes
            .get_mut(start..end)
            .ok_or(EFAULT)?
            .copy_from_slice(input);
        Ok(())
    })
}
fn reset() {
    STATE.set(State {
        bytes: (0..MAX_BYTES * 2).map(|i| i as u8).collect(),
        ..Default::default()
    });
}

#[test]
fn zero_length_and_oversized_operations_touch_neither_pointer() {
    reset();
    assert_eq!(implementation::copy(u64::MAX, u64::MAX, 0), 0);
    for length in [MAX_BYTES as u64 + 1, u64::MAX] {
        assert_eq!(implementation::copy(0, 0, length), types::EINVAL);
    }
    STATE.with_borrow(|state| assert_eq!((state.reads, state.writes), (0, 0)));
}

#[test]
fn bounded_copy_snapshots_before_writing_even_for_overlap() {
    for (destination, source, length) in
        [(8, 0, 32), (0, 8, 32), (0, 0, 1), (MAX_BYTES, 0, MAX_BYTES)]
    {
        reset();
        let expected = STATE.with_borrow(|state| state.bytes[source..source + length].to_vec());
        assert_eq!(
            implementation::copy(destination as u64, source as u64, length as u64),
            length as u64
        );
        STATE.with_borrow(|state| {
            assert_eq!(&state.bytes[destination..destination + length], expected);
            assert_eq!((state.reads, state.writes), (1, 1));
        });
    }
}

#[test]
fn source_rejection_never_reaches_destination_copy() {
    reset();
    STATE.with_borrow_mut(|state| state.fail_read = true);
    let before = STATE.with_borrow(|state| state.bytes.clone());
    assert_eq!(implementation::copy(128, 0, 32), EFAULT);
    STATE.with_borrow(|state| {
        assert_eq!(state.bytes, before);
        assert_eq!((state.reads, state.writes), (1, 0));
    });
}

#[test]
fn destination_rejection_is_propagated_without_retry_or_policy() {
    reset();
    STATE.with_borrow_mut(|state| state.fail_write = true);
    assert_eq!(implementation::copy(128, 0, 32), EFAULT);
    STATE.with_borrow(|state| assert_eq!((state.reads, state.writes), (1, 1)));
}

#[test]
fn probe_and_dispatch_use_the_same_published_native_abi() {
    assert_eq!(mnu_abi::SyscallNumber::MemoryCopy as u64, 699);
    assert_eq!(MAX_BYTES, 4096);
    let probe = include_str!("native_memory_copy.c");
    assert!(probe.contains(&format!(
        "MEMORY_COPY = {}",
        mnu_abi::SyscallNumber::MemoryCopy as u64
    )));
    assert!(probe.contains(&format!("COPY_LIMIT = {MAX_BYTES}")));
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    assert!(
        dispatch
            .contains("SyscallNumber::MemoryCopy as u64 => memory_copy::copy(arg0, arg1, arg2)")
    );
}
