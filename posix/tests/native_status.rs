use mnu_abi::status::{self, Error};
use mochi_user_syscall::{RawSyscallResult, SysError};
use mochios_posix_client::newlib_errno;

#[test]
fn mechanism_failure_is_typed_not_an_errno_and_survives_signed_wire_status() {
    let raw = Error::LimitExceeded.into_raw();
    assert_eq!(raw as i64, -262143);
    assert_eq!(i64::from(raw as i32) as u64, raw);
    assert!(status::is_error(raw));
    let error = RawSyscallResult::new(raw).into_result().unwrap_err();
    assert_eq!(error.raw(), raw as i64);
    assert_eq!(error.native_error(), Some(Error::LimitExceeded));
    assert_eq!(
        error.errno(),
        None,
        "native failure must not invent a C errno"
    );
    for status in [raw as i64, -(raw as i64)] {
        assert_eq!(newlib_errno::from_status(status), newlib_errno::EOVERFLOW);
    }
}

#[test]
fn unknown_native_codes_remain_errors_without_becoming_posix_numbers() {
    let tag = Error::LimitExceeded.into_raw() & !0xffff;
    for code in [0, 11, 0xffff] {
        let raw = tag | code;
        assert!(status::is_error(raw));
        assert_eq!(Error::from_raw(raw), None);
        let error = RawSyscallResult::new(raw).into_result().unwrap_err();
        assert_eq!(error.native_error(), None);
        assert_eq!(newlib_errno::from_status(error.raw()), newlib_errno::EIO);
    }
    // POSIX service policy statuses occupy a different domain.
    for raw in [-0x10001_i64, -0x10002] {
        assert!(!status::is_error(raw as u64));
    }
}

#[test]
fn native_categories_translate_only_at_posix_boundary() {
    for (native, expected) in [
        (Error::InvalidAddress, newlib_errno::EFAULT),
        (Error::ResourceUnavailable, newlib_errno::ENOMEM),
        (Error::BackingFailure, newlib_errno::EIO),
        (Error::InvalidArgument, newlib_errno::EINVAL),
        (Error::AccessDenied, newlib_errno::EACCES),
        (Error::NotReady, newlib_errno::EAGAIN),
        (Error::AlreadyExists, newlib_errno::EEXIST),
        (Error::NotFound, newlib_errno::ENOENT),
        (Error::PeerClosed, newlib_errno::EPIPE),
    ] {
        let raw = native.into_raw();
        assert_eq!(Error::from_raw(raw), Some(native));
        assert_eq!(i64::from(raw as i32) as u64, raw);
        let error = RawSyscallResult::new(raw).into_result().unwrap_err();
        assert_eq!(error.native_error(), Some(native));
        assert_eq!(error.errno(), None);
        assert_eq!(newlib_errno::from_status(error.raw()), expected);
        assert_eq!(newlib_errno::from_status(-error.raw()), expected);
    }
}

#[test]
fn high_bit_success_values_and_legacy_errors_keep_their_existing_contract() {
    let tag = Error::LimitExceeded.into_raw() & !0xffff;
    for raw in [0, 7, 1_u64 << 63, u64::MAX - 4095, tag - 1, tag + 0x10000] {
        assert_eq!(RawSyscallResult::new(raw).into_result(), Ok(raw));
        assert_eq!(Error::from_raw(raw), None);
    }
    for status in [-1, -14, -22] {
        let error = RawSyscallResult::new(status as u64)
            .into_result()
            .unwrap_err();
        assert_eq!(error, SysError::from_raw(status));
        assert_eq!(error.native_error(), None);
        assert_eq!(error.errno(), Some(status.unsigned_abs()));
    }
}

#[test]
fn wire_normalization_is_idempotent_and_distinct_from_c_errno() {
    use mochios_posix_protocol::status::normalize_failure;
    for (native, wire, c_errno) in [
        (Error::LimitExceeded, -75, newlib_errno::EOVERFLOW),
        (Error::AccessDenied, -13, newlib_errno::EACCES),
        (Error::NotReady, -11, newlib_errno::EAGAIN),
        (Error::AlreadyExists, -17, newlib_errno::EEXIST),
        (Error::NotFound, -2, newlib_errno::ENOENT),
        (Error::PeerClosed, -32, newlib_errno::EPIPE),
    ] {
        for raw in [native.into_raw() as i64, -(native.into_raw() as i64)] {
            assert_eq!(normalize_failure(raw), wire);
            assert_eq!(normalize_failure(i64::from(normalize_failure(raw))), wire);
            assert_eq!(
                newlib_errno::from_status(i64::from(normalize_failure(raw))),
                c_errno
            );
        }
    }
    assert_ne!(newlib_errno::EOVERFLOW, 75);
    for raw in [0, i64::MIN, i64::MAX, i64::from(i32::MIN)] {
        assert_eq!(normalize_failure(raw), -5);
    }
    for raw in [13, -13, 75, -75, 0x10001, -0x10001] {
        assert_eq!(normalize_failure(raw), -(raw.unsigned_abs() as i32));
    }
}
