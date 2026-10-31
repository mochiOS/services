extern crate self as mochi_user_platform;
pub use mochi_user_syscall as syscall;
pub use posix_service::{AttachedObject, AuthenticatedProcess, STATUS_EINVAL};
pub mod process {
    use super::*;
    pub fn handle_status(handle: u32) -> Result<mnu_abi::ProcessStatus, syscall::SysError> {
        if handle == 5 {
            return Err(syscall::SysError::from_raw(
                syscall::NativeError::NotFound.into_raw() as i64,
            ));
        }
        if handle == 6 {
            return Err(syscall::SysError::from_raw(
                syscall::NativeError::AccessDenied.into_raw() as i64,
            ));
        }
        if handle == 7 {
            return Err(syscall::SysError::from_raw(-22));
        }
        Ok(mnu_abi::ProcessStatus {
            process_id: if handle == 2 { 0 } else { 42 },
            state: if handle == 3 {
                mnu_abi::PROCESS_STATE_EXITED
            } else {
                mnu_abi::PROCESS_STATE_RUNNING
            },
            reserved: u32::from(handle == 4),
            ..Default::default()
        })
    }
}
#[path = "../src/process_domain_native.rs"]
mod production;
#[test]
fn only_an_explicit_live_wait_process_with_well_formed_native_status_is_admitted() {
    let call = |handle, rights| production::authenticate(AttachedObject { handle, rights });
    assert_eq!(
        call(1, mnu_abi::HANDLE_RIGHT_WAIT),
        Ok(AuthenticatedProcess {
            handle: 1,
            process_id: 42
        })
    );
    for (handle, error) in [
        (0, -22),
        (2, -22),
        (3, -3),
        (4, -22),
        (5, -3),
        (6, -13),
        (7, -22),
    ] {
        assert_eq!(call(handle, mnu_abi::HANDLE_RIGHT_WAIT), Err(error));
    }
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_SIGNAL,
        mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER,
    ] {
        assert_eq!(call(1, rights), Err(-22));
    }
}
