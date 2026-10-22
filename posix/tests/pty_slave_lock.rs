#![allow(dead_code, non_camel_case_types)]
use mnu_abi::{HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_READ as R, HANDLE_RIGHT_WRITE as W};
use mochios_posix_protocol as posix_protocol;
use posix_service::pty::{EBADF, EINVAL, EIO, PtyManager};
use std::ffi::c_int;

fn set(manager: &mut PtyManager, object: u64, locked: bool) -> Result<Vec<u8>, i32> {
    manager.control(
        object,
        posix_protocol::PTY_CONTROL_SET_SLAVE_LOCK,
        &u32::from(locked).to_le_bytes(),
        0,
    )
}
fn locked(manager: &mut PtyManager, object: u64) -> bool {
    manager
        .control(object, posix_protocol::PTY_CONTROL_GET_SLAVE_LOCK, &[], 4)
        .unwrap()
        == 1u32.to_le_bytes()
}

#[test]
fn locking_gates_every_new_slave_without_revoking_existing_opens_or_readiness() {
    let mut manager = PtyManager::new();
    let pair = manager.open_with_slave_lock(true).unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    let signals = manager.signals(pair.master_object_id).unwrap();
    assert!(locked(&mut manager, pair.master_object_id));
    for _ in 0..20 {
        assert_eq!(manager.reopen_slave(pair.master_object_id), Err(EIO));
        assert_eq!(manager.open_slave_from_factory(factory), Err(EIO));
    }
    assert_eq!(manager.signals(pair.master_object_id).unwrap(), signals);
    assert_eq!(
        manager.signal_object_ids(pair.master_object_id).unwrap(),
        [pair.master_object_id, pair.slave_object_id]
    );
    // The lock governs new admission, never an already admitted slave's IO.
    manager.write(pair.slave_object_id, b"still\n").unwrap();
    assert_eq!(
        manager.read(pair.master_object_id, 64).unwrap(),
        b"still\r\n"
    );
    set(&mut manager, pair.master_object_id, false).unwrap();
    assert!(!locked(&mut manager, pair.master_object_id));
    let opened = manager.open_slave_from_factory(factory).unwrap();
    // Failed opens have not consumed provider object IDs.
    assert_eq!(opened, factory + 1);
    set(&mut manager, pair.master_object_id, true).unwrap();
    assert_eq!(manager.open_slave_from_factory(factory), Err(EIO));
    manager.write(opened, b"ok\n").unwrap();
    assert_eq!(manager.read(pair.master_object_id, 64).unwrap(), b"ok\r\n");
    manager.release(pair.master_object_id).unwrap();
    assert_eq!(manager.open_slave_from_factory(factory), Err(EBADF));
    assert_eq!(set(&mut manager, pair.master_object_id, false), Err(EBADF));
}

#[test]
fn lock_controls_are_master_only_strictly_framed_and_not_available_as_read_queries() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    assert!(!locked(&mut manager, pair.master_object_id)); // openpty unchanged.
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    for object in [pair.slave_object_id, factory, u64::MAX] {
        assert_eq!(
            set(&mut manager, object, true),
            Err(if object == pair.slave_object_id {
                EINVAL
            } else {
                EBADF
            })
        );
    }
    for (input, capacity) in [
        (&[][..], 0),
        (&[1][..], 0),
        (&[2, 0, 0, 0][..], 0),
        (&[1, 0, 0, 0][..], 1),
    ] {
        assert_eq!(
            manager.control(
                pair.master_object_id,
                posix_protocol::PTY_CONTROL_SET_SLAVE_LOCK,
                input,
                capacity
            ),
            Err(EINVAL)
        );
        assert!(!locked(&mut manager, pair.master_object_id));
    }
    for (input, capacity) in [(&[][..], 3), (&[0][..], 4)] {
        assert_eq!(
            manager.control(
                pair.master_object_id,
                posix_protocol::PTY_CONTROL_GET_SLAVE_LOCK,
                input,
                capacity
            ),
            Err(EINVAL)
        );
    }
    assert!(
        manager
            .query(
                pair.master_object_id,
                posix_protocol::PTY_CONTROL_SET_SLAVE_LOCK,
                &[0; 4],
                0
            )
            .is_err()
    );
}

const EACCES: i32 = 13;
const ENOTTY: i32 = 25;
#[derive(Clone, Copy)]
struct FdEntry {
    rights: u64,
    object: u64,
}
struct Lease(FdEntry);
impl std::ops::Deref for Lease {
    type Target = FdEntry;
    fn deref(&self) -> &FdEntry {
        &self.0
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        LEASES.set(LEASES.get() - 1);
    }
}
thread_local! {
    static MANAGER: std::cell::RefCell<PtyManager> = std::cell::RefCell::new(PtyManager::new());
    static MASTER: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static SLAVE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static LEASES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static BAD_REPLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
fn with_fd_entry(fd: i32) -> Result<Lease, i32> {
    let entry = match fd {
        4 => FdEntry {
            rights: R | W | C,
            object: MASTER.get(),
        },
        5 => FdEntry {
            rights: R | W | C,
            object: SLAVE.get(),
        },
        6 => FdEntry {
            rights: R | C,
            object: MASTER.get(),
        },
        7 => FdEntry {
            rights: R | W | C,
            object: 0,
        },
        8 => FdEntry {
            rights: R | W,
            object: MASTER.get(),
        },
        _ => return Err(EBADF),
    };
    LEASES.set(LEASES.get() + 1);
    Ok(Lease(entry))
}
mod syscall {
    pub const HANDLE_RIGHT_WRITE: u64 = mnu_abi::HANDLE_RIGHT_WRITE;
}
mod io_resources {
    pub fn with<R, T>(
        prepare: impl FnOnce() -> Result<R, i32>,
        operation: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        let mut resource = prepare()?;
        operation(&mut resource)
    }
}
fn terminal_control(
    entry: FdEntry,
    code: u64,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, i32> {
    assert_eq!(LEASES.get(), 1);
    CALLS.set(CALLS.get() + 1);
    if entry.object == 0 {
        return Err(ENOTTY);
    }
    if entry.rights & C == 0 {
        return Err(EACCES);
    }
    let bytes = MANAGER
        .with_borrow_mut(|manager| manager.control(entry.object, code, input, output.len()))?;
    assert!(bytes.is_empty());
    Ok(usize::from(BAD_REPLY.get()))
}
#[path = "../../../user/crates/newlib-runtime/src/terminal_lock.rs"]
mod terminal_lock;

#[test]
fn runtime_unlocks_only_a_pinned_writable_master_and_preserves_backend_errors() {
    MANAGER.with_borrow_mut(|manager| {
        let pair = manager.open_with_slave_lock(true).unwrap();
        MASTER.set(pair.master_object_id);
        SLAVE.set(pair.slave_object_id);
    });
    assert_eq!(terminal_lock::unlock(99), Err(EBADF));
    assert_eq!(terminal_lock::unlock(6), Err(EBADF));
    assert_eq!(CALLS.get(), 0);
    assert_eq!(terminal_lock::unlock(5), Err(EINVAL));
    assert_eq!(terminal_lock::unlock(7), Err(EINVAL));
    assert_eq!(terminal_lock::unlock(8), Err(EACCES));
    MANAGER.with_borrow_mut(|manager| assert!(locked(manager, MASTER.get())));
    assert_eq!(terminal_lock::unlock(4), Ok(0));
    MANAGER.with_borrow_mut(|manager| {
        assert!(!locked(manager, MASTER.get()));
        manager.reopen_slave(MASTER.get()).unwrap();
    });
    assert_eq!(terminal_lock::unlock(4), Ok(0));
    BAD_REPLY.set(true);
    assert_eq!(terminal_lock::unlock(4), Err(EIO));
    assert_eq!(LEASES.get(), 0);
}
