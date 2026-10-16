use mnu_abi::diagnostic::ReadResult;
use mnu_abi::status::Error;
use std::cell::Cell;

thread_local! {
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static RESPONSE: Cell<(u64, ReadResult)> = const { Cell::new((0, ReadResult { next_cursor: 0, dropped: 0 })) };
    static FAILURE: Cell<Option<i64>> = const { Cell::new(None) };
}

mod syscall {
    pub use mochi_user_syscall::{SysError, SysResult, SyscallNumber};

    pub fn call4(
        number: SyscallNumber,
        _cursor: u64,
        _output: u64,
        _capacity: u64,
        metadata: u64,
    ) -> SysResult<u64> {
        assert_eq!(number as u64, SyscallNumber::DiagnosticRead as u64);
        crate::CALLS.set(crate::CALLS.get() + 1);
        if let Some(error) = crate::FAILURE.get() {
            return Err(SysError::from_raw(error));
        }
        let (bytes, result) = crate::RESPONSE.get();
        // The real wrapper supplies a live, fixed-size metadata array.
        unsafe {
            core::ptr::copy_nonoverlapping(result.to_bytes().as_ptr(), metadata as *mut u8, 16);
        }
        Ok(bytes)
    }
}

#[path = "../../../user/crates/platform/src/diagnostic.rs"]
mod diagnostic;

fn response(bytes: u64, next_cursor: u64, dropped: u64) {
    CALLS.set(0);
    FAILURE.set(None);
    RESPONSE.set((
        bytes,
        ReadResult {
            next_cursor,
            dropped,
        },
    ));
}

#[test]
fn native_result_and_gap_are_returned_without_advancing_shared_state() {
    response(4, 14, 3);
    let mut bytes = [0; 4];
    for _ in 0..2 {
        let (copied, metadata) = diagnostic::read(7, &mut bytes).unwrap();
        assert_eq!(copied, 4);
        assert_eq!(metadata.next_cursor, 14);
        assert_eq!(metadata.dropped, 3);
    }
    assert_eq!(CALLS.get(), 2);
}

#[test]
fn oversized_requests_are_rejected_before_calling_the_kernel() {
    response(0, 0, 0);
    assert_eq!(
        diagnostic::read(0, &mut [0; 4097])
            .unwrap_err()
            .native_error(),
        Some(Error::InvalidArgument)
    );
    assert_eq!(CALLS.get(), 0);
}

#[test]
fn native_failures_are_preserved() {
    for error in [
        Error::AccessDenied,
        Error::InvalidAddress,
        Error::ResourceUnavailable,
        Error::BackingFailure,
        Error::InvalidArgument,
    ] {
        response(0, 0, 0);
        FAILURE.set(Some(error.into_raw() as i64));
        let result = diagnostic::read(0, &mut []).unwrap_err();
        assert_eq!(result.native_error(), Some(error));
        assert_eq!(result.errno(), None);
    }
}

#[test]
fn inconsistent_metadata_is_rejected() {
    for (cursor, copied, next, dropped) in [
        (0, 5, 5, 0),
        (0, 4, 3, 0),
        (7, 4, 10, 0),
        (u64::MAX, 1, 0, 0),
        (1, 0, 0, u64::MAX),
    ] {
        response(copied, next, dropped);
        assert_eq!(
            diagnostic::read(cursor, &mut [0; 4])
                .unwrap_err()
                .native_error(),
            Some(Error::BackingFailure)
        );
    }
}

#[test]
fn empty_queries_can_report_a_gap() {
    response(0, 25, 18);
    let (copied, metadata) = diagnostic::read(7, &mut []).unwrap();
    assert_eq!(copied, 0);
    assert_eq!(metadata.next_cursor, 25);
    assert_eq!(metadata.dropped, 18);
}
