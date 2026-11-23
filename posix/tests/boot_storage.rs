//! Run the initial service's actual readiness policy against controlled
//! discovery outcomes. Successful native reads must not require mDriver.
#[path = "../../core/src/boot_storage.rs"]
mod boot_storage;

use mnu_abi::status::Error;
use mochi_user_syscall::SysError;
use std::cell::Cell;

#[test]
fn ready_disk_does_not_require_discovery() {
    assert_eq!(
        boot_storage::prepare(|| Ok(()), || panic!("unneeded discovery")),
        Ok(())
    );
}

#[test]
fn missing_device_uses_discovery_once_and_preserves_its_error() {
    for status in [Error::NotReady.into_raw() as i64] {
        let calls = Cell::new(0);
        assert_eq!(
            boot_storage::prepare(
                || Err(SysError::from_raw(status)),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                }
            ),
            Ok(())
        );
        assert_eq!(calls.get(), 1);
        let failure = SysError::from_raw(Error::BackingFailure.into_raw() as i64);
        assert_eq!(
            boot_storage::prepare(|| Err(SysError::from_raw(status)), || Err(failure)),
            Err(failure)
        );
    }
}

#[test]
fn denied_or_failed_reads_are_not_retried_via_discovery() {
    for status in [
        Error::AccessDenied.into_raw() as i64,
        Error::ResourceUnavailable.into_raw() as i64,
        Error::BackingFailure.into_raw() as i64,
        mochi_user_syscall::EACCES as i64,
        mochi_user_syscall::EIO as i64,
    ] {
        let failure = SysError::from_raw(status);
        assert_eq!(
            boot_storage::prepare(|| Err(failure), || panic!("must preserve failure")),
            Err(failure)
        );
    }
}
