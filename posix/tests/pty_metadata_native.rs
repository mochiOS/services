//! Actual owned-native-reference adapter with deterministic local Handle calls.
extern crate self as mochi_user_platform;
use std::cell::RefCell;
pub mod pty {
    pub use posix_service::pty::{EACCES, EIO};
}
#[path = "../src/filesystem_reference.rs"]
mod implementation;
use mnu_abi::{HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_TRANSFER as T};

#[derive(Debug)]
pub struct Error;
impl Error {
    pub fn raw(&self) -> i64 {
        -5
    }
}
#[derive(Default)]
struct Calls {
    closed: Vec<u32>,
    duplicated: Vec<(u32, u64)>,
    fail: bool,
    zero: bool,
}
thread_local! { static CALLS: RefCell<Calls> = RefCell::new(Calls::default()); }
pub mod handle {
    use super::*;
    pub fn close(handle: u32) -> Result<(), Error> {
        CALLS.with_borrow_mut(|calls| calls.closed.push(handle));
        Ok(())
    }
    pub fn duplicate(handle: u32, rights: u64) -> Result<u32, Error> {
        CALLS.with_borrow_mut(|calls| {
            calls.duplicated.push((handle, rights));
            if calls.fail {
                Err(Error)
            } else if calls.zero {
                Ok(0)
            } else {
                Ok(91)
            }
        })
    }
}
fn attachment(handle: u32, rights: u64) -> mnu_abi::IpcObjectHandle {
    mnu_abi::IpcObjectHandle {
        handle,
        reserved: 0,
        rights,
    }
}

#[test]
fn received_reference_is_owned_until_drop_and_only_checked_rights_reach_native_duplicate() {
    CALLS.set(Calls::default());
    let reference = implementation::Reference::from_received(attachment(73, D | T | C)).unwrap();
    assert_eq!(reference.duplicate(T, T | C), Err(pty::EACCES));
    assert_eq!(reference.duplicate(T, T), Ok(91));
    CALLS.with_borrow(|calls| {
        assert!(calls.closed.is_empty());
        assert_eq!(calls.duplicated, vec![(73, T)]);
    });
    drop(reference);
    CALLS.with_borrow(|calls| assert_eq!(calls.closed, vec![73]));
}

#[test]
fn malformed_or_overpowered_received_references_are_closed_on_rejection() {
    CALLS.set(Calls::default());
    for object in [
        attachment(1, T),
        attachment(2, D | T | mnu_abi::HANDLE_RIGHT_READ),
        mnu_abi::IpcObjectHandle {
            reserved: 1,
            ..attachment(3, D | T)
        },
        attachment(0, D | T),
    ] {
        assert_eq!(
            implementation::Reference::from_received(object).unwrap_err(),
            pty::EACCES
        );
    }
    CALLS.with_borrow(|calls| assert_eq!(calls.closed, vec![1, 2, 3]));
}

#[test]
fn native_failure_or_null_duplicate_is_not_returned_as_a_successful_reference() {
    for fail in [false, true] {
        CALLS.set(Calls {
            fail,
            zero: !fail,
            ..Calls::default()
        });
        let reference = implementation::Reference::from_received(attachment(73, D | T)).unwrap();
        assert_eq!(reference.duplicate(T, T), Err(pty::EIO));
        drop(reference);
        CALLS.with_borrow(|calls| assert_eq!(calls.closed, vec![73]));
    }
}
