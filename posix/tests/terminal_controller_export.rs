//! Exercise the real Terminal adapter across the FD/data-metadata boundary.
extern crate mochi_user_platform as platform_real;
extern crate self as mochi_user_platform;
use mochios_posix_protocol::ExportedFdHandle;
pub use platform_real::{application, ipc, process, syscall};
use std::cell::RefCell;
#[derive(Default)]
struct State {
    export_failure: bool,
    duplicate_failure: bool,
    close_failure: bool,
    rights: Vec<u64>,
    closed: Vec<u32>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
pub mod handle {
    pub use crate::platform_real::handle::*;
    pub fn duplicate(source: u32, rights: u64) -> Result<u32, crate::syscall::SysError> {
        assert_eq!(source, 40);
        assert_eq!(
            rights,
            HANDLE_RIGHT_CONTROL | HANDLE_RIGHT_TRANSFER | HANDLE_RIGHT_DUPLICATE
        );
        crate::STATE.with_borrow_mut(|state| {
            state.rights.push(rights);
            if state.duplicate_failure {
                Err(crate::syscall::SysError::from(
                    crate::syscall::NativeError::AccessDenied.into_raw(),
                ))
            } else {
                Ok(41)
            }
        })
    }
    pub fn close(handle: u32) -> Result<(), crate::syscall::SysError> {
        crate::STATE.with_borrow_mut(|state| {
            state.closed.push(handle);
            if handle == 40 && state.close_failure {
                Err(crate::syscall::SysError::from(
                    crate::syscall::NativeError::BackingFailure.into_raw(),
                ))
            } else {
                Ok(())
            }
        })
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn mochi_fd_export(
    fd: libc::c_int,
    rights: u64,
    output: *mut ExportedFdHandle,
) -> libc::c_int {
    assert_eq!(fd, 23);
    // The existing FD API requires data-access metadata. CONTROL-only capture
    // cannot succeed; the local adapter must narrow before IPC delegation.
    assert_eq!(
        rights,
        handle::HANDLE_RIGHT_READ
            | handle::HANDLE_RIGHT_CONTROL
            | handle::HANDLE_RIGHT_TRANSFER
            | handle::HANDLE_RIGHT_DUPLICATE
    );
    if STATE.with_borrow(|state| state.export_failure) {
        return -1;
    }
    unsafe {
        output.write(ExportedFdHandle {
            handle: 40,
            rights,
            ..Default::default()
        });
    }
    0
}
#[allow(dead_code)]
#[path = "../../../applications/terminal/src/native_launch.rs"]
mod production;
#[path = "../../../applications/terminal/src/stdio_access.rs"]
mod stdio_access;
#[test]
fn capture_discards_data_authority_before_exposing_a_controller_reference() {
    STATE.with_borrow_mut(|s| *s = State::default());
    assert_eq!(production::master_reference(23).unwrap(), 41);
    STATE.with_borrow(|state| {
        assert_eq!(state.rights.len(), 1);
        assert_eq!(state.closed, [40]);
    });
}
#[test]
fn failed_capture_or_narrowing_never_publishes_a_reference_and_closes_temporaries() {
    for stage in 0..3 {
        STATE.with_borrow_mut(|s| {
            *s = State {
                export_failure: stage == 0,
                duplicate_failure: stage == 1,
                close_failure: stage == 2,
                ..Default::default()
            }
        });
        assert!(production::master_reference(23).is_err());
        STATE.with_borrow(|state| {
            assert_eq!(
                state.closed,
                match stage {
                    0 => vec![],
                    1 => vec![40],
                    _ => vec![40, 41],
                }
            );
        });
    }
}
