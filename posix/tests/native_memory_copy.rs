//! The production native copy primitive with host resident-copy boundaries.
use mnu_abi::memory_copy::MAX_BYTES;
use mnu_abi::status::Error;
use std::cell::RefCell;

#[path = "../../../core/src/syscall/memory_copy.rs"]
mod implementation;

const INVALID_ADDRESS: u64 = Error::InvalidAddress.into_raw();
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    reads: usize,
    writes: usize,
    fail_read: Option<Error>,
    fail_write: Option<Error>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn copy_from_user_native(source: u64, output: &mut [u8]) -> Result<(), Error> {
    STATE.with_borrow_mut(|state| {
        state.reads += 1;
        if let Some(error) = state.fail_read {
            return Err(error);
        }
        let start = source as usize;
        let end = start
            .checked_add(output.len())
            .ok_or(Error::InvalidAddress)?;
        output.copy_from_slice(state.bytes.get(start..end).ok_or(Error::InvalidAddress)?);
        Ok(())
    })
}
fn copy_to_user_native(destination: u64, input: &[u8]) -> Result<(), Error> {
    STATE.with_borrow_mut(|state| {
        state.writes += 1;
        if let Some(error) = state.fail_write {
            return Err(error);
        }
        let start = destination as usize;
        let end = start
            .checked_add(input.len())
            .ok_or(Error::InvalidAddress)?;
        state
            .bytes
            .get_mut(start..end)
            .ok_or(Error::InvalidAddress)?
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
        assert_eq!(
            implementation::copy(0, 0, length),
            mnu_abi::status::Error::LimitExceeded.into_raw()
        );
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
    STATE.with_borrow_mut(|state| state.fail_read = Some(Error::InvalidAddress));
    let before = STATE.with_borrow(|state| state.bytes.clone());
    assert_eq!(implementation::copy(128, 0, 32), INVALID_ADDRESS);
    STATE.with_borrow(|state| {
        assert_eq!(state.bytes, before);
        assert_eq!((state.reads, state.writes), (1, 0));
    });
}

#[test]
fn destination_rejection_is_propagated_without_retry_or_policy() {
    reset();
    STATE.with_borrow_mut(|state| state.fail_write = Some(Error::InvalidAddress));
    assert_eq!(implementation::copy(128, 0, 32), INVALID_ADDRESS);
    STATE.with_borrow(|state| assert_eq!((state.reads, state.writes), (1, 1)));
}

#[test]
fn allocation_and_backing_failures_are_not_relabelled_as_bad_addresses() {
    for error in [Error::ResourceUnavailable, Error::BackingFailure] {
        for read in [false, true] {
            reset();
            STATE.with_borrow_mut(|state| {
                if read {
                    state.fail_read = Some(error);
                } else {
                    state.fail_write = Some(error);
                }
            });
            assert_eq!(implementation::copy(128, 0, 32), error.into_raw());
            STATE.with_borrow(|state| {
                assert_eq!((state.reads, state.writes), (1, usize::from(!read)))
            });
        }
    }
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
    assert!(probe.contains(&format!(
        "NATIVE_LIMIT_EXCEEDED INT64_C({})",
        mnu_abi::status::Error::LimitExceeded.into_raw() as i64
    )));
    assert!(probe.contains(&format!(
        "NATIVE_INVALID_ADDRESS INT64_C({})",
        Error::InvalidAddress.into_raw() as i64
    )));
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    assert!(
        dispatch
            .contains("SyscallNumber::MemoryCopy as u64 => memory_copy::copy(arg0, arg1, arg2)")
    );
}
