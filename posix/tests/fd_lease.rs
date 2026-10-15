//! Deterministically pause after the runtime's actual pin acquisition, before
//! native dispatch, while another thread closes and reuses the descriptor.
#![allow(non_camel_case_types)]
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, mpsc};

use mochios_posix_client::fd::{Entry, FdTable};
use mochios_posix_client::handle_borrow::Book;

type c_int = i32;
const EBADF: c_int = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FdObject {
    lower_handle: u64,
    close_owned: bool,
}
type FdEntry = Entry<FdObject>;

struct RuntimeMutex<T>(Mutex<T>);
impl<T> RuntimeMutex<T> {
    const fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}

static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static NATIVE: Mutex<BTreeMap<u64, &'static str>> = Mutex::new(BTreeMap::new());

fn close_object_handle(handle: u32) {
    assert!(NATIVE.lock().unwrap().remove(&u64::from(handle)).is_some());
    CLOSED.lock().unwrap().push(handle);
}
mod syscall {
    pub use mnu_abi::SyscallNumber;
    pub fn raw_syscall1(number: SyscallNumber, handle: u64) -> Result<u64, i32> {
        assert!(matches!(number, SyscallNumber::HandleClose));
        super::close_object_handle(handle as u32);
        Ok(0)
    }
}
fn syscall_errno(value: Result<u64, c_int>) -> Result<u64, c_int> {
    value
}

#[path = "../../../user/crates/newlib-runtime/src/fd_lease.rs"]
mod fd_lease;

fn entry(handle: u64) -> FdEntry {
    Entry {
        handle: FdObject {
            lower_handle: handle,
            close_owned: true,
        },
        // Deliberately no DUPLICATE or TRANSFER authority.
        rights: mnu_abi::HANDLE_RIGHT_READ,
        descriptor_flags: 0,
    }
}

#[test]
fn book_checks_labels_and_defers_exactly_one_close_to_the_last_pin() {
    let mut book = Book::<3>::new();
    for label in [0, 4, u64::MAX] {
        assert!(book.pin(label).is_none());
        assert_eq!(book.retire(label), None);
    }
    let first = book.pin(1).unwrap();
    let second = book.pin(1).unwrap();
    let other = book.pin(3).unwrap();
    assert_eq!(book.retire(1), Some(false));
    assert!(book.pin(1).is_none());
    assert_eq!(book.retire(1), None);
    assert!(!book.release(second));
    assert!(!book.release(other));
    assert!(book.release(first));
    // After the caller closes the native reference, its label is reusable.
    let reused = book.pin(1).unwrap();
    assert!(!book.release(reused));
    assert_eq!(book.retire(1), Some(true));
    assert_eq!(book.retire(3), Some(true));
}

#[test]
fn retired_descriptors_can_outnumber_the_posix_fd_limit_without_losing_pins() {
    let mut book = Book::<{ mnu_abi::PROCESS_MAX_OBJECT_HANDLES }>::new();
    let mut pins = Vec::new();
    for label in 1..=mnu_abi::PROCESS_MAX_OBJECT_HANDLES as u64 {
        pins.push(book.pin(label).unwrap());
        assert_eq!(book.retire(label), Some(false));
    }
    for pin in pins {
        assert!(book.release(pin));
    }
}

#[test]
fn runtime_pins_escaped_metadata_and_captures_the_book_with_native_handles() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let fork = source
        .split("fn clone_registered_process()")
        .nth(1)
        .unwrap();
    let locked = fork
        .find("let fd_borrows = fd_lease::BORROWS.lock();")
        .unwrap();
    assert!(fork.find("let guard = state();").unwrap() < locked);
    assert!(locked < fork.find("handle_capture::Capture::new()?").unwrap());
    assert!(fork.find("drop(fd_borrows);").unwrap() < fork.find("drop(guard);").unwrap());
    assert!(source.contains("fd_lease::Lease::new(state.fds.get(fd).ok_or(EBADF)?)"));
    assert!(source.contains("let captured = clone_current_fd_table()?;"));
    assert!(source.contains("&scope.as_ref().get_ref().resource().unwrap().0"));
    assert!(source.contains("let mut leases = [const { None }; MAX_FDS];"));
    assert!(source.contains("**leases[poll_index].as_ref().unwrap()"));
    assert!(!source.contains("*with_fd_entry(pollfds[poll_index].fd)?"));
    assert!(source.contains("Ok((base, Some(entry)))"));
    assert!(source.contains("Ok((entry, attachment))"));
    assert!(source.contains("let backing_lease;"));
    let kernel = include_str!("../../../core/src/task/handle_table.rs");
    assert!(
        kernel.contains("PROCESS_MAX_OBJECT_HANDLES: usize = mnu_abi::PROCESS_MAX_OBJECT_HANDLES")
    );
}

#[test]
fn real_runtime_guard_survives_close_replacement_early_error_and_native_label_reuse() {
    let table = Mutex::new(FdTable::new());
    table.lock().unwrap().install(entry(7)).unwrap();
    NATIVE
        .lock()
        .unwrap()
        .insert(7, "original open-file description");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let table_ref = &table;
        scope.spawn(move || {
            let lease = {
                let table = table_ref.lock().unwrap();
                fd_lease::Lease::new(table.get(0).unwrap()).unwrap()
            };
            ready_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            // This is the first native dispatch, after the other thread has
            // closed fd 0 and reused it. It must still access the old object.
            assert_eq!(
                NATIVE.lock().unwrap().get(&lease.handle.lower_handle),
                Some(&"original open-file description")
            );
        });
        ready_rx.recv().unwrap();
        let second_pin = {
            let mut table = table.lock().unwrap();
            let old = table.get(0).unwrap();
            let pin = fd_lease::Lease::new(old).unwrap();
            fd_lease::retire(old.handle).unwrap();
            table.take(0).unwrap();
            NATIVE.lock().unwrap().insert(8, "replacement");
            assert_eq!(table.install(entry(8)), Ok(0));
            pin
        };
        assert!(CLOSED.lock().unwrap().is_empty());
        drop(second_pin);
        assert!(CLOSED.lock().unwrap().is_empty());
        go_tx.send(()).unwrap();
    });
    assert_eq!(*CLOSED.lock().unwrap(), [7]);
    // Error return drops an unretired pin without closing the descriptor.
    let operation = || -> Result<(), i32> {
        let table = table.lock().unwrap();
        let _lease = fd_lease::Lease::new(table.get(0).unwrap()).unwrap();
        Err(123)
    };
    assert_eq!(operation(), Err(123));
    assert_eq!(*CLOSED.lock().unwrap(), [7]);
    let old = table.lock().unwrap().take(0).unwrap();
    fd_lease::retire(old.handle).unwrap();
    assert_eq!(*CLOSED.lock().unwrap(), [7, 8]);
    NATIVE.lock().unwrap().insert(7, "new native slot occupant");
    let lease = fd_lease::Lease::new(entry(7)).unwrap();
    fd_lease::retire(lease.handle).unwrap();
    assert_eq!(
        NATIVE.lock().unwrap().get(&7),
        Some(&"new native slot occupant")
    );
    drop(lease);
    assert_eq!(*CLOSED.lock().unwrap(), [7, 8, 7]);
    let stdio = Entry {
        handle: FdObject {
            lower_handle: 0,
            close_owned: false,
        },
        rights: 0,
        descriptor_flags: 0,
    };
    drop(fd_lease::Lease::new(stdio).unwrap());
    fd_lease::retire(stdio.handle).unwrap();
    assert!(NATIVE.lock().unwrap().is_empty());
}
