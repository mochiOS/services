mod syscall {
    pub use mochi_user_platform::syscall::{NativeError, SysError};
}
mod package {
    pub use mochi_user_platform::package::MpkgReader;
}
mod handle {
    use super::syscall::SysError;
    pub use mochi_user_platform::handle::Handle;
    use std::cell::RefCell;

    #[derive(Default)]
    pub struct State {
        pub cursor: usize,
        pub calls: usize,
        pub eof: bool,
        pub error: Option<SysError>,
        pub error_after: usize,
        pub invalid_count: bool,
        pub positions: Vec<u64>,
        pub length: Option<u64>,
        pub length_error: Option<SysError>,
        pub length_queries: usize,
    }
    thread_local! { pub static STATE: RefCell<State> = RefCell::new(State::default()); }

    pub fn metadata_length(handle: Handle) -> Result<u64, SysError> {
        assert_eq!(handle, 47);
        STATE.with_borrow_mut(|state| {
            state.calls += 1;
            state.length_queries += 1;
            state
                .length_error
                .map_or(Ok(state.length.unwrap_or(40)), Err)
        })
    }
    pub fn read_at(handle: Handle, output: &mut [u8], offset: u64) -> Result<usize, SysError> {
        assert_eq!(handle, 47);
        STATE.with_borrow_mut(|state| {
            state.calls += 1;
            state.positions.push(offset);
            if let Some(error) = state.error
                && state.positions.len() > state.error_after
            {
                return Err(error);
            }
            if state.invalid_count {
                return Ok(output.len() + 1);
            }
            let count = if state.eof { 0 } else { output.len().min(3) };
            for (index, byte) in output[..count].iter_mut().enumerate() {
                *byte = offset.wrapping_add(index as u64) as u8;
            }
            Ok(count)
        })
    }
}
#[path = "../../../user/crates/platform/src/native_mpkg_reader.rs"]
mod native_mpkg_reader;
use native_mpkg_reader::NativeMpkgReader;
use package::MpkgReader;

#[test]
fn production_reader_handles_offsets_and_short_reads_without_reopening() {
    handle::STATE.set(handle::State {
        cursor: 19,
        ..Default::default()
    });
    let mut reader = NativeMpkgReader::from_borrowed_handle(47, handle::metadata_length);
    assert_eq!(reader.len().unwrap(), 40);
    let mut output = [0; 10];
    reader.read_exact_at(7, &mut output).unwrap();
    assert_eq!(output, [7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    handle::STATE.with_borrow(|state| {
        assert_eq!(state.calls, 5);
        assert_eq!(state.positions, [7, 10, 13, 16]);
        assert_eq!(
            state.cursor, 19,
            "both len and read_exact_at must leave the shared offset alone"
        );
    });
}

#[test]
fn production_reader_rejects_overflow_eof_and_invalid_native_counts() {
    let mut reader = NativeMpkgReader::from_borrowed_handle(47, handle::metadata_length);
    assert_eq!(
        reader.read_exact_at(u64::MAX, &mut [0]).unwrap_err().raw(),
        syscall::NativeError::LimitExceeded.into_raw() as i64
    );
    handle::STATE.with_borrow(|state| assert_eq!(state.calls, 0));
    for state in [
        handle::State {
            eof: true,
            ..Default::default()
        },
        handle::State {
            invalid_count: true,
            ..Default::default()
        },
    ] {
        handle::STATE.set(state);
        assert_eq!(
            reader.read_exact_at(1, &mut [0]).unwrap_err().raw(),
            syscall::NativeError::BackingFailure.into_raw() as i64
        );
        handle::STATE.with_borrow(|state| {
            assert_eq!(state.calls, 1);
            assert_eq!(state.positions, [1]);
        });
    }
}

#[test]
fn positioned_reads_accept_unsigned_offsets_and_empty_reads_do_no_io() {
    let mut reader = NativeMpkgReader::from_borrowed_handle(47, handle::metadata_length);
    reader.read_exact_at(u64::MAX, &mut []).unwrap();
    handle::STATE.with_borrow(|state| assert_eq!(state.calls, 0));
    for offset in [i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX - 10] {
        handle::STATE.set(handle::State {
            cursor: 19,
            ..Default::default()
        });
        let mut output = [0; 10];
        reader.read_exact_at(offset, &mut output).unwrap();
        assert_eq!(
            output,
            core::array::from_fn(|i| offset.wrapping_add(i as u64) as u8)
        );
        handle::STATE.with_borrow(|state| {
            assert_eq!(
                state.positions,
                [offset, offset + 3, offset + 6, offset + 9]
            );
            assert_eq!(state.cursor, 19);
        });
    }
    handle::STATE.set(handle::State::default());
    assert_eq!(
        reader
            .read_exact_at(u64::MAX - 2, &mut [0; 4])
            .unwrap_err()
            .native_error(),
        Some(syscall::NativeError::LimitExceeded)
    );
    handle::STATE.with_borrow(|state| assert_eq!(state.calls, 0));
}

#[test]
fn native_read_failures_are_preserved_without_retry_or_cursor_mutation() {
    use syscall::{NativeError, SysError};
    let mut reader = NativeMpkgReader::from_borrowed_handle(47, handle::metadata_length);
    for raw in [
        NativeError::AccessDenied.into_raw() as i64,
        NativeError::InvalidArgument.into_raw() as i64,
        NativeError::ResourceUnavailable.into_raw() as i64,
        NativeError::PeerClosed.into_raw() as i64,
        NativeError::Unsupported.into_raw() as i64,
        -5,
        -13,
    ] {
        let error = SysError::from_raw(raw);
        handle::STATE.set(handle::State {
            cursor: 23,
            error: Some(error),
            ..Default::default()
        });
        assert_eq!(reader.read_exact_at(7, &mut [0; 10]), Err(error));
        handle::STATE.with_borrow(|state| {
            assert_eq!(state.calls, 1);
            assert_eq!(state.positions, [7]);
            assert_eq!(state.cursor, 23);
        });
    }
}

#[test]
fn a_failure_after_a_short_read_preserves_the_error_and_stops_at_that_offset() {
    let error = syscall::SysError::from_raw(syscall::NativeError::PeerClosed.into_raw() as i64);
    handle::STATE.set(handle::State {
        cursor: 23,
        error: Some(error),
        error_after: 1,
        ..Default::default()
    });
    let mut reader = NativeMpkgReader::from_borrowed_handle(47, handle::metadata_length);
    let mut output = [0x55; 8];
    assert_eq!(reader.read_exact_at(7, &mut output), Err(error));
    assert_eq!(output, [7, 8, 9, 0x55, 0x55, 0x55, 0x55, 0x55]);
    handle::STATE.with_borrow(|state| {
        assert_eq!(state.calls, 2);
        assert_eq!(state.positions, [7, 10]);
        assert_eq!(state.cursor, 23);
    });
}

#[test]
fn package_service_uses_shared_native_reader_and_keeps_handle_cleanup() {
    let source = include_str!("../../package/src/posix_io.rs");
    assert!(!source.contains("struct HandleReader"));
    assert_eq!(
        source
            .matches("NativeMpkgReader::from_borrowed_handle(handle, file_length)")
            .count(),
        2
    );
    assert_eq!(
        source.matches("let close_result = close(handle)").count(),
        2
    );
    let reader = include_str!("../../../user/crates/platform/src/native_mpkg_reader.rs");
    assert!(!reader.contains("file::"));
    assert!(!reader.contains("open("));
    assert!(!reader.contains("handle::seek"));
}

#[test]
fn metadata_queries_preserve_cursor_report_current_length_and_propagate_failures() {
    use syscall::{NativeError, SysError};
    let mut reader = NativeMpkgReader::from_borrowed_handle(47, handle::metadata_length);
    for length in [0, 7, i64::MAX as u64 + 1, u64::MAX] {
        handle::STATE.set(handle::State {
            cursor: 23,
            length: Some(length),
            ..Default::default()
        });
        assert_eq!(reader.len(), Ok(length));
        handle::STATE.with_borrow(|state| {
            assert_eq!(state.cursor, 23);
            assert_eq!(state.length_queries, 1);
            assert!(state.positions.is_empty());
        });
    }
    for raw in [
        NativeError::AccessDenied.into_raw() as i64,
        NativeError::PeerClosed.into_raw() as i64,
        NativeError::BackingFailure.into_raw() as i64,
        -5,
        -13,
    ] {
        let error = SysError::from_raw(raw);
        handle::STATE.set(handle::State {
            cursor: 23,
            length_error: Some(error),
            ..Default::default()
        });
        assert_eq!(reader.len(), Err(error));
        handle::STATE.with_borrow(|state| {
            assert_eq!(state.cursor, 23);
            assert_eq!(state.length_queries, 1);
            assert_eq!(state.calls, 1);
            assert!(state.positions.is_empty());
        });
    }
}
