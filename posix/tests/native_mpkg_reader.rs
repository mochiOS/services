mod syscall {
    pub use mochi_user_platform::syscall::{EIO, ERANGE, SysError};
}
mod package {
    pub use mochi_user_platform::package::MpkgReader;
}
mod handle {
    use super::syscall::{EIO, SysError};
    pub use mochi_user_platform::handle::{HANDLE_SEEK_END, HANDLE_SEEK_START, Handle};
    use std::cell::RefCell;

    #[derive(Default)]
    pub struct State {
        pub cursor: usize,
        pub calls: usize,
        pub eof: bool,
        pub error: bool,
        pub invalid_count: bool,
    }
    thread_local! { pub static STATE: RefCell<State> = RefCell::new(State::default()); }

    pub fn seek(handle: Handle, offset: i64, basis: u64) -> Result<u64, SysError> {
        assert_eq!(handle, 47);
        STATE.with_borrow_mut(|state| {
            state.calls += 1;
            state.cursor = if basis == HANDLE_SEEK_END {
                assert_eq!(offset, 0);
                40
            } else {
                assert_eq!(basis, HANDLE_SEEK_START);
                offset as usize
            };
            Ok(state.cursor as u64)
        })
    }
    pub fn read(handle: Handle, output: &mut [u8]) -> Result<usize, SysError> {
        assert_eq!(handle, 47);
        STATE.with_borrow_mut(|state| {
            state.calls += 1;
            if state.error {
                return Err(SysError::from_raw(EIO as i64));
            }
            if state.invalid_count {
                return Ok(output.len() + 1);
            }
            let count = if state.eof { 0 } else { output.len().min(3) };
            for byte in &mut output[..count] {
                *byte = state.cursor as u8;
                state.cursor += 1;
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
    let mut reader = NativeMpkgReader::from_borrowed_handle(47);
    assert_eq!(reader.len().unwrap(), 40);
    let mut output = [0; 10];
    reader.read_exact_at(7, &mut output).unwrap();
    assert_eq!(output, [7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    handle::STATE.with_borrow(|state| assert_eq!(state.calls, 6));
}

#[test]
fn production_reader_rejects_overflow_eof_and_invalid_native_counts() {
    let mut reader = NativeMpkgReader::from_borrowed_handle(47);
    assert_eq!(
        reader.read_exact_at(u64::MAX, &mut [0]).unwrap_err().raw(),
        syscall::ERANGE as i64
    );
    handle::STATE.with_borrow(|state| assert_eq!(state.calls, 0));
    for state in [
        handle::State {
            eof: true,
            ..Default::default()
        },
        handle::State {
            error: true,
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
            syscall::EIO as i64
        );
    }
}

#[test]
fn package_service_uses_shared_native_reader_and_keeps_handle_cleanup() {
    let source = include_str!("../../package/src/posix_io.rs");
    assert!(!source.contains("struct HandleReader"));
    assert_eq!(
        source
            .matches("NativeMpkgReader::from_borrowed_handle(handle)")
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
}
