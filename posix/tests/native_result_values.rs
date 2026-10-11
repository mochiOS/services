use mochi_user_platform::syscall::{RawSyscallResult, SysError};

#[test]
fn full_width_native_values_are_not_negative_errno() {
    for value in [
        0,
        1,
        1u64 << 63,
        0xc000_0000_0000_0001,
        i64::MIN as u64,
        (-4096i64) as u64,
    ] {
        assert_eq!(RawSyscallResult::new(value).into_result(), Ok(value));
        assert_eq!(SysError::from_raw(value as i64).errno(), None);
    }
}

#[test]
fn every_reserved_native_errno_remains_an_error() {
    for errno in 1..=4095i64 {
        let error = RawSyscallResult::new((-errno) as u64)
            .into_result()
            .unwrap_err();
        assert_eq!(error.raw(), -errno);
        assert_eq!(error.errno(), Some(errno as u64));
    }
}

#[test]
fn newlib_uses_the_canonical_native_result_decoder() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let decoder = runtime
        .split("fn syscall_errno(")
        .nth(1)
        .unwrap()
        .split("fn result_with_errno")
        .next()
        .unwrap();
    assert!(decoder.contains(".into_result()"));
    assert!(!decoder.contains("as i64"));
}
