use mnu_abi::diagnostic::{READ_MAX_BYTES, RESULT_LEN, ReadResult};
use mnu_abi::status::Error;
use std::cell::{Cell, RefCell};

#[path = "../../../core/src/util/diagnostic_buffer.rs"]
mod buffer;
mod util {
    pub(crate) use crate::buffer as diagnostic_buffer;
}
mod capability {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Capability {
        DiagnosticsRead,
    }
}

thread_local! {
    static AUTHORIZED: Cell<bool> = const { Cell::new(false) };
    static REGIONS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
    static COPY_FAIL: Cell<usize> = const { Cell::new(0) };
    static COPY_ERROR: Cell<Error> = const { Cell::new(Error::InvalidAddress) };
    static COPY_COUNT: Cell<usize> = const { Cell::new(0) };
    static HISTORY: RefCell<buffer::ByteRing<8>> = const { RefCell::new(buffer::ByteRing::new()) };
}

mod audit {
    pub fn read_cursor(
        cursor: u64,
        output: &mut [u8],
    ) -> Result<crate::buffer::ReadResult, crate::buffer::CursorError> {
        crate::HISTORY.with(|history| history.borrow().read(cursor, output))
    }
}
mod syscall {
    pub mod security {
        pub fn caller_has_any_capability(caps: &[crate::capability::Capability]) -> bool {
            assert_eq!(caps, [crate::capability::Capability::DiagnosticsRead]);
            crate::AUTHORIZED.get()
        }
    }
    pub fn validate_user_ptr(pointer: u64, length: u64) -> bool {
        let Some(end) = pointer.checked_add(length) else {
            return false;
        };
        crate::REGIONS.with(|regions| {
            regions
                .borrow()
                .iter()
                .any(|&(base, size)| pointer >= base && end <= base + size)
        })
    }
    pub fn copy_to_user_native(pointer: u64, bytes: &[u8]) -> Result<(), mnu_abi::status::Error> {
        let count = crate::COPY_COUNT.get() + 1;
        crate::COPY_COUNT.set(count);
        if crate::COPY_FAIL.get() == count {
            return Err(crate::COPY_ERROR.get());
        }
        if !validate_user_ptr(pointer, bytes.len() as u64) {
            return Err(mnu_abi::status::Error::InvalidAddress);
        }
        // Only live test-owned mutable ranges registered by the caller reach
        // this stub. It exercises the real syscall's usercopy ordering.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer as *mut u8, bytes.len());
        }
        Ok(())
    }
}
#[path = "../../../core/src/syscall/diagnostic.rs"]
mod diagnostic;

fn initialize() {
    AUTHORIZED.set(true);
    REGIONS.with(|regions| regions.borrow_mut().clear());
    COPY_FAIL.set(0);
    COPY_ERROR.set(Error::InvalidAddress);
    COPY_COUNT.set(0);
    HISTORY.with(|history| {
        *history.borrow_mut() = buffer::ByteRing::new();
        history.borrow_mut().append(b"abcdefghijk").unwrap();
    });
}
fn register(output: &mut [u8]) -> u64 {
    let pointer = output.as_mut_ptr() as u64;
    REGIONS.with(|regions| regions.borrow_mut().push((pointer, output.len() as u64)));
    pointer
}

#[test]
fn native_reads_preserve_reader_ownership_and_report_overwritten_bytes() {
    initialize();
    let mut bytes = [0; 4];
    let mut metadata = [0; RESULT_LEN];
    let output = register(&mut bytes);
    let result = register(&mut metadata);
    for _ in 0..2 {
        assert_eq!(diagnostic::read(0, output, 4, result), 4);
        assert_eq!(&bytes, b"defg");
        assert_eq!(
            ReadResult::from_bytes(&metadata),
            Some(ReadResult {
                next_cursor: 7,
                dropped: 3
            })
        );
    }
    assert_eq!(diagnostic::read(7, output, 4, result), 4);
    assert_eq!(&bytes, b"hijk");
    assert_eq!(diagnostic::read(11, output, 4, result), 0);
}

#[test]
fn authorization_precedes_all_pointer_and_history_access() {
    initialize();
    AUTHORIZED.set(false);
    assert_eq!(
        diagnostic::read(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        Error::AccessDenied.into_raw()
    );
    assert_eq!(COPY_COUNT.get(), 0);
}

#[test]
fn bounds_overlap_and_future_cursors_fail_without_writing_outputs() {
    initialize();
    let mut bytes = [0xaa; 32];
    let output = register(&mut bytes);
    let mut metadata = [0xbb; RESULT_LEN];
    let result = register(&mut metadata);
    for (cursor, data, length, meta, error) in [
        (
            0,
            output,
            READ_MAX_BYTES as u64 + 1,
            result,
            Error::InvalidArgument.into_raw(),
        ),
        (0, 0, 4, result, Error::InvalidAddress.into_raw()),
        (0, output, 4, 0, Error::InvalidAddress.into_raw()),
        (0, output, 4, u64::MAX, Error::InvalidAddress.into_raw()),
        (0, output, 16, output + 8, Error::InvalidArgument.into_raw()),
        (12, output, 4, result, Error::InvalidArgument.into_raw()),
    ] {
        assert_eq!(diagnostic::read(cursor, data, length, meta), error);
    }
    assert_eq!(bytes, [0xaa; 32]);
    assert_eq!(metadata, [0xbb; RESULT_LEN]);
    assert_eq!(COPY_COUNT.get(), 0);
}

#[test]
fn failed_payload_or_metadata_copy_never_advances_a_kernel_owned_cursor() {
    for error in [
        Error::InvalidAddress,
        Error::ResourceUnavailable,
        Error::BackingFailure,
    ] {
        for fail in [1, 2] {
            initialize();
            let mut bytes = [0; 4];
            let mut metadata = [0; RESULT_LEN];
            let output = register(&mut bytes);
            let result = register(&mut metadata);
            COPY_FAIL.set(fail);
            COPY_ERROR.set(error);
            assert_eq!(diagnostic::read(0, output, 4, result), error.into_raw());
            assert_eq!(COPY_COUNT.get(), fail);
            COPY_FAIL.set(0);
            assert_eq!(diagnostic::read(0, output, 4, result), 4);
            assert_eq!(&bytes, b"defg");
            assert_eq!(ReadResult::from_bytes(&metadata).unwrap().next_cursor, 7);
        }
    }
}

#[test]
fn zero_length_queries_need_only_metadata_and_do_not_copy_payload() {
    initialize();
    let mut metadata = [0; RESULT_LEN];
    let result = register(&mut metadata);
    assert_eq!(diagnostic::read(0, 0, 0, result), 0);
    assert_eq!(COPY_COUNT.get(), 1);
    assert_eq!(
        ReadResult::from_bytes(&metadata),
        Some(ReadResult {
            next_cursor: 3,
            dropped: 3
        })
    );
}

#[test]
fn diagnostic_permission_is_system_only_and_wire_metadata_is_exact() {
    let permission = mnu_abi::capability::metadata("diagnostics.read").unwrap();
    assert_eq!(
        permission.classification,
        mnu_abi::capability::CapabilityClassification::SystemOnly
    );
    assert!(!permission.user_grantable && !permission.delegable);
    assert_eq!(core::mem::size_of::<ReadResult>(), RESULT_LEN);
    let result = ReadResult {
        next_cursor: 123,
        dropped: 17,
    };
    assert_eq!(ReadResult::from_bytes(&result.to_bytes()), Some(result));
    assert_eq!(ReadResult::from_bytes(&[0; RESULT_LEN - 1]), None);
    assert_eq!(ReadResult::from_bytes(&[0; RESULT_LEN + 1]), None);
}
