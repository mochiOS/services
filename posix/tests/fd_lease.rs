//! Deterministically pause after the runtime's actual pin acquisition, before
//! native dispatch, while another thread closes and reuses the descriptor.
#![allow(non_camel_case_types)]
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, mpsc};

use mochios_posix_client::fd::{Entry, FdTable};
use mochios_posix_client::handle_borrow::Book;

type c_int = i32;
const EBADF: c_int = 9;
const ENOMEM: c_int = 12;
thread_local! {
    static OWNER: std::cell::Cell<u64> = const { std::cell::Cell::new(1) };
}
fn newlib_lock_identity() -> u64 {
    OWNER.get()
}
const MAX_FDS: usize = 256;

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
// These two runtime tests share the process-local BORROWS/native backend.
// Their worker threads still race close/reuse deterministically within a test.
static RUNTIME_TEST: Mutex<()> = Mutex::new(());

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
fn private_reference_admission_is_atomic_and_needs_no_descriptor_owner() {
    use mochios_posix_client::handle_borrow::PinError;
    let mut book = Book::<3>::new();
    assert!(matches!(
        book.pin_private(1, 0),
        Err(PinError::InvalidOwner)
    ));
    let first = book.pin_owned(1, 1).unwrap();
    let second = book.pin_owned(1, 2).unwrap();
    let third = book.pin_owned(1, 3).unwrap();
    assert!(matches!(book.pin_private(2, 4), Err(PinError::Capacity)));
    assert!(matches!(book.pin_private(1, 1), Err(PinError::Retired)));
    assert!(!book.release(third));
    let private = book.pin_private(2, 4).unwrap();
    assert!(book.pin(2).is_none());
    assert_eq!(book.retain(2), None);
    assert_eq!(book.retire(2), None);
    assert!(book.release(private));
    assert!(!book.release(first));
    assert!(!book.release(second));
    let replacement = book.pin_private(2, 1).unwrap();
    assert!(book.release(replacement));
}

#[test]
fn fork_exclusions_apply_only_to_retired_references_without_surviving_pins() {
    use mochios_posix_client::inheritance;
    let mut book = Book::<4>::new();
    let foreign = book.pin_private(1, 2).unwrap();
    let own = book.pin_private(2, 1).unwrap();
    let foreign_shared = book.pin_owned(3, 2).unwrap();
    let own_shared = book.pin_owned(3, 1).unwrap();
    assert_eq!(book.retire(3), Some(false));
    assert!(book.discarded_by_fork(1, 1));
    for label in [0, 2, 3, 4, 5, u64::MAX] {
        assert!(!book.discarded_by_fork(label, 1));
    }
    assert!(!book.discarded_by_fork(1, 0));
    let records = [
        mnu_abi::HandleInfo {
            handle: 1,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WAIT,
        },
        mnu_abi::HandleInfo {
            handle: 4,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_TRANSFER | mnu_abi::HANDLE_RIGHT_READ,
        },
    ];
    let exclusions: Vec<_> = records
        .iter()
        .filter(|record| book.discarded_by_fork(u64::from(record.handle), 1))
        .map(|record| record.handle)
        .collect();
    let mut grants = [mnu_abi::process_create::HandleGrant {
        key: 0,
        source: 0,
        target: 0,
        rights: 0,
    }; 2];
    assert_eq!(
        inheritance::prepare(&records, &exclusions, &mut grants),
        Ok(1)
    );
    assert_eq!(grants[0].source, 4);
    let mut unowned = records;
    unowned[1].rights = mnu_abi::HANDLE_RIGHT_READ;
    assert_eq!(
        inheritance::prepare(&unowned, &exclusions, &mut grants),
        Err(inheritance::Error::NonTransferable(4))
    );
    assert!(!book.release(own_shared));
    assert!(book.discarded_by_fork(3, 1));
    assert!(book.release(foreign_shared));
    assert!(book.release(foreign));
    assert!(book.release(own));
}

#[test]
fn private_runtime_leases_close_on_return_and_child_discard_without_fd_installation() {
    let _runtime = RUNTIME_TEST.lock().unwrap();
    assert!(NATIVE.lock().unwrap().is_empty());
    CLOSED.lock().unwrap().clear();
    *fd_lease::BORROWS.lock() = Book::new();
    OWNER.set(2);
    NATIVE
        .lock()
        .unwrap()
        .insert(27, "foreign private completion");
    let foreign = fd_lease::Lease::adopt_private(entry(27)).unwrap();
    std::mem::forget(foreign);
    OWNER.set(1);
    NATIVE
        .lock()
        .unwrap()
        .insert(28, "surviving private completion");
    let own = fd_lease::Lease::adopt_private(entry(28)).unwrap();
    fd_lease::BORROWS
        .lock()
        .discard_for_fork(1, |label| close_object_handle(label as u32))
        .unwrap();
    assert_eq!(*CLOSED.lock().unwrap(), [27]);
    assert!(NATIVE.lock().unwrap().contains_key(&28));
    drop(own);
    assert_eq!(*CLOSED.lock().unwrap(), [27, 28]);
    assert!(NATIVE.lock().unwrap().is_empty());
}

#[test]
fn book_checks_labels_and_defers_exactly_one_close_to_the_last_pin() {
    let mut book = Book::<3>::new();
    for label in [0, 4, u64::MAX] {
        assert!(book.pin(label).is_none());
        assert_eq!(book.retain(label), None);
        assert_eq!(book.retire(label), None);
    }
    let first = book.pin(1).unwrap();
    let second = book.pin(1).unwrap();
    let other = book.pin(3).unwrap();
    assert_eq!(book.retire(1), Some(false));
    assert_eq!(book.retain(1), None);
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
fn aliased_owners_keep_the_label_pinnable_until_the_last_fd_closes() {
    let mut book = Book::<2>::new();
    book.retain(1).unwrap();
    book.retain(1).unwrap();
    let first = book.pin(1).unwrap();
    assert_eq!(book.retire(1), Some(false));
    let second = book.pin(1).unwrap();
    assert!(!book.release(first));
    assert_eq!(book.retire(1), Some(false));
    assert!(!book.release(second));
    let last = book.pin(1).unwrap();
    assert_eq!(book.retire(1), Some(false));
    assert!(book.pin(1).is_none());
    assert!(book.release(last));
    // No stale owner count may survive native label reuse.
    assert_eq!(book.retire(1), Some(true));
    book.retain(1).unwrap();
    assert_eq!(book.retire(1), Some(false));
    assert_eq!(book.retire(1), Some(true));
}

#[test]
fn restored_aliases_use_real_runtime_ownership_without_duplicate_rights() {
    let _runtime = RUNTIME_TEST.lock().unwrap();
    CLOSED.lock().unwrap().clear();
    assert!(NATIVE.lock().unwrap().is_empty());
    let mut restored = fd_lease::RestoreReferences::new();
    for label in [0, mnu_abi::PROCESS_MAX_OBJECT_HANDLES as u64 + 1, u64::MAX] {
        assert_eq!(restored.register(entry(label).handle), Err(EBADF));
    }
    let file = entry(11);
    NATIVE
        .lock()
        .unwrap()
        .insert(11, "one inherited native reference");
    for _ in 0..3 {
        restored.register(file.handle).unwrap();
    }
    // The first two closes must neither dispatch native close nor retire pins.
    fd_lease::retire(file.handle).unwrap();
    let first = fd_lease::Lease::new(file).unwrap();
    fd_lease::retire(file.handle).unwrap();
    let last = fd_lease::Lease::new(file).unwrap();
    drop(first);
    assert!(CLOSED.lock().unwrap().is_empty());
    fd_lease::retire(file.handle).unwrap();
    assert!(fd_lease::Lease::new(file).is_err());
    assert!(CLOSED.lock().unwrap().is_empty());
    drop(last);
    assert_eq!(*CLOSED.lock().unwrap(), [11]);
    assert!(NATIVE.lock().unwrap().is_empty());

    // A new image and reused label start with exactly one implicit owner.
    let mut restored = fd_lease::RestoreReferences::new();
    NATIVE.lock().unwrap().insert(11, "reused label");
    restored.register(file.handle).unwrap();
    restored.register(file.handle).unwrap();
    fd_lease::retire(file.handle).unwrap();
    assert_eq!(*CLOSED.lock().unwrap(), [11]);
    fd_lease::retire(file.handle).unwrap();
    assert_eq!(*CLOSED.lock().unwrap(), [11, 11]);
    assert!(NATIVE.lock().unwrap().is_empty());
    CLOSED.lock().unwrap().clear();
}

#[test]
fn runtime_pins_escaped_metadata_and_captures_the_book_with_native_handles() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let fork = source
        .split("fn clone_registered_process()")
        .nth(1)
        .unwrap();
    let locked = fork
        .find("let mut fd_borrows = fd_lease::BORROWS.lock();")
        .unwrap();
    assert!(fork.find("let guard = state();").unwrap() < locked);
    assert!(locked < fork.find("handle_capture::Capture::new()?").unwrap());
    assert!(fork.find("drop(fd_borrows);").unwrap() < fork.find("drop(guard);").unwrap());
    assert!(source.contains("fd_lease::Lease::new(state.fds.get(fd).ok_or(EBADF)?)"));
    assert!(source.contains("let captured = clone_current_fd_table()?;"));
    assert!(source.contains("&scope.as_ref().get_ref().resource().unwrap().0"));
    assert!(source.contains("let mut leases = [const { None }; MAX_FDS];"));
    assert!(source.contains("let mut references = fd_lease::RestoreReferences::new();"));
    assert!(source.contains("references.register(object).ok()?;"));
    assert!(source.contains("**leases[poll_index].as_ref().unwrap()"));
    assert!(!source.contains("*with_fd_entry(pollfds[poll_index].fd)?"));
    assert!(source.contains("Ok((base, Some(entry)))"));
    assert!(source.contains("Ok((entry, attachment))"));
    // mmap now keeps the source lease in a callback-safe owner and lends the
    // received backing through a separate owner, rather than a stack local.
    let mapping = source
        .split("pub extern \"C\" fn mmap(")
        .nth(1)
        .unwrap()
        .split("pub extern \"C\" fn munmap(")
        .next()
        .unwrap();
    assert!(mapping.contains("mapping_io::with_source(mapping.anonymous, fd, |entry|"));
    assert!(mapping.contains("return mapping_backing::with(entry, writable, map);"));
    let kernel = include_str!("../../../core/src/task/handle_table.rs");
    assert!(
        kernel.contains("PROCESS_MAX_OBJECT_HANDLES: usize = mnu_abi::PROCESS_MAX_OBJECT_HANDLES")
    );
}

#[test]
fn real_runtime_guard_survives_close_replacement_early_error_and_native_label_reuse() {
    let _runtime = RUNTIME_TEST.lock().unwrap();
    CLOSED.lock().unwrap().clear();
    assert!(NATIVE.lock().unwrap().is_empty());
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
            OWNER.set(2);
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
        assert!(fd_lease::BORROWS.lock().has_foreign_pins(1));
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
    assert!(!fd_lease::BORROWS.lock().has_foreign_pins(1));
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

#[test]
fn vanished_child_operations_release_retired_handles_without_revoking_surviving_fds_or_scopes() {
    let _runtime = RUNTIME_TEST.lock().unwrap();
    assert!(NATIVE.lock().unwrap().is_empty());
    CLOSED.lock().unwrap().clear();
    *fd_lease::BORROWS.lock() = Book::new();
    for (label, name) in [
        (17, "retired foreign"),
        (18, "shared scope"),
        (19, "open descriptor"),
    ] {
        NATIVE.lock().unwrap().insert(label, name);
    }
    OWNER.set(2);
    let foreign_retired = fd_lease::Lease::new(entry(17)).unwrap();
    let foreign_shared = fd_lease::Lease::new(entry(18)).unwrap();
    let foreign_open = fd_lease::Lease::new(entry(19)).unwrap();
    // Model stacks which exist in the snapshot but never resume in the child.
    // Their guards must not later release the child's discarded pins.
    std::mem::forget((foreign_retired, foreign_shared, foreign_open));
    OWNER.set(1);
    let own = fd_lease::Lease::new(entry(18)).unwrap();
    fd_lease::retire(entry(17).handle).unwrap();
    fd_lease::retire(entry(18).handle).unwrap();
    assert!(CLOSED.lock().unwrap().is_empty());
    fd_lease::BORROWS
        .lock()
        .discard_for_fork(1, |label| close_object_handle(label as u32))
        .unwrap();
    assert_eq!(*CLOSED.lock().unwrap(), [17]);
    assert!(NATIVE.lock().unwrap().contains_key(&18));
    assert!(NATIVE.lock().unwrap().contains_key(&19));
    drop(own);
    fd_lease::retire(entry(19).handle).unwrap();
    assert_eq!(*CLOSED.lock().unwrap(), [17, 18, 19]);
    NATIVE.lock().unwrap().insert(17, "new slot occupant");
    let fresh = fd_lease::Lease::new(entry(17)).unwrap();
    fd_lease::retire(entry(17).handle).unwrap();
    assert!(NATIVE.lock().unwrap().contains_key(&17));
    drop(fresh);
    assert_eq!(*CLOSED.lock().unwrap(), [17, 18, 19, 17]);
    assert!(NATIVE.lock().unwrap().is_empty());
}
