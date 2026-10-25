use mochios_posix_client::{memory, newlib_errno};
use std::cell::Cell;

#[test]
fn advice_validates_policy_before_delegating_only_the_byte_range() {
    let calls = Cell::new(0);
    for advice in [
        memory::POSIX_MADV_NORMAL,
        memory::POSIX_MADV_RANDOM,
        memory::POSIX_MADV_SEQUENTIAL,
        memory::POSIX_MADV_WILLNEED,
        memory::POSIX_MADV_DONTNEED,
    ] {
        assert_eq!(
            memory::advise(0x4000, 4097, advice, 4096, |address, length| {
                assert_eq!((address, length), (0x4000, 4097));
                calls.set(calls.get() + 1);
                Ok(())
            }),
            Ok(())
        );
    }
    assert_eq!(calls.get(), 5);
    for (address, length, advice, page_size) in [
        (0x4001, 1, 0, 4096),
        (0x4000, 0, 0, 4096),
        (0x4000, 1, -1, 4096),
        (0x4000, 1, 5, 4096),
        (0x4000, 1, 0, 0),
        (0x4000, 1, 0, 3000),
    ] {
        assert_eq!(
            memory::advise(address, length, advice, page_size, |_, _| panic!()),
            Err(newlib_errno::EINVAL)
        );
    }
    assert_eq!(
        memory::advise(u64::MAX - 4095, 8192, 0, 4096, |_, _| panic!()),
        Err(newlib_errno::ENOMEM)
    );
}

#[test]
fn range_holes_and_native_failures_are_not_reported_as_successful_advice() {
    for (native, expected) in [
        (mnu_abi::status::Error::InvalidAddress, newlib_errno::ENOMEM),
        (mnu_abi::status::Error::NotReady, newlib_errno::EAGAIN),
    ] {
        assert_eq!(
            memory::advise(0x4000, 8192, memory::POSIX_MADV_DONTNEED, 4096, |_, _| Err(
                native.into_raw() as i64
            )),
            Err(expected)
        );
    }
}
