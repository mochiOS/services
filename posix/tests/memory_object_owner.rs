#[path = "../../../user/crates/platform/src/memory_object.rs"]
mod memory_object;

use memory_object::MemoryObject;
use std::cell::RefCell;

#[derive(Default)]
struct State {
    calls: Vec<(syscall::SyscallNumber, Vec<u64>)>,
    fail_create: bool,
    fail_map: bool,
    fail_unmap: bool,
    fail_close: bool,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

fn reset() {
    STATE.with(|state| *state.borrow_mut() = State::default());
}

mod syscall {
    pub use mnu_abi::{SyscallNumber, EINVAL, EIO, MEMORY_ACCESS_ALL, MEMORY_MAP_SHARED};
    pub use mochi_user_platform::syscall::{SysError, SysResult};
    fn call(number: SyscallNumber, args: &[u64]) -> SysResult<u64> {
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.calls.push((number, args.to_vec()));
            match number {
                SyscallNumber::MemoryObjectCreate if state.fail_create => {
                    Err(SysError::from_raw(-12))
                }
                SyscallNumber::MemoryObjectCreate => Ok(7),
                SyscallNumber::MemoryMap if state.fail_map => Err(SysError::from_raw(-13)),
                SyscallNumber::MemoryMap => Ok(0x10000),
                SyscallNumber::MemoryObjectLength => Ok(8192),
                SyscallNumber::MemoryUnmap if state.fail_unmap => Err(SysError::from_raw(-5)),
                SyscallNumber::HandleClose if state.fail_close => Err(SysError::from_raw(-5)),
                _ => Ok(0),
            }
        })
    }
    pub fn call1(number: SyscallNumber, a: u64) -> SysResult<u64> {
        call(number, &[a])
    }
    pub fn call2(number: SyscallNumber, a: u64, b: u64) -> SysResult<u64> {
        call(number, &[a, b])
    }
    pub fn call6(
        number: SyscallNumber,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) -> SysResult<u64> {
        call(number, &[a, b, c, d, e, f])
    }
}
mod handle {
    pub type Handle = u32;
    pub fn close(handle: Handle) -> super::syscall::SysResult<()> {
        super::syscall::call1(super::syscall::SyscallNumber::HandleClose, handle as u64).map(|_| ())
    }
    pub fn rights(_: Handle) -> super::syscall::SysResult<u64> {
        Ok(mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP)
    }
}

#[test]
fn object_close_and_mapping_unmap_have_independent_ownership() {
    reset();
    let object = MemoryObject::create(8192).unwrap();
    assert_eq!(object.handle(), 7);
    assert_eq!(object.length().unwrap(), 8192);
    assert_eq!(
        object.rights().unwrap(),
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP
    );
    let mut mapping = object.map(4096, 1, mnu_abi::MEMORY_ACCESS_READ).unwrap();
    assert_eq!(mapping.address(), 0x10000);
    assert_eq!(mapping.capacity(), 4096);
    assert_eq!(mapping.as_ptr() as u64, 0x10000);
    assert_eq!(mapping.as_mut_ptr() as u64, 0x10000);
    drop(object);
    STATE.with(|state| {
        assert_eq!(
            state.borrow().calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        )
    });
    drop(mapping);
    STATE.with(|state| {
        let state = state.borrow();
        assert!(state.calls.contains(&(
            syscall::SyscallNumber::MemoryMap,
            vec![0, 4096, 1, 2, 7, 4096]
        )));
        assert_eq!(
            state.calls.last().unwrap(),
            &(syscall::SyscallNumber::MemoryUnmap, vec![0x10000, 4096])
        );
        assert_eq!(
            state
                .calls
                .iter()
                .filter(|call| call.0 == syscall::SyscallNumber::HandleClose)
                .count(),
            1
        );
    });
}

#[test]
fn invalid_geometry_and_failed_mapping_never_unmap_or_close_unowned_resources() {
    reset();
    assert!(MemoryObject::create(0).is_err());
    assert!(MemoryObject::create(1).is_err());
    let object = MemoryObject::create(8192).unwrap();
    for (offset, length, access) in [
        (1, 4096, 1),
        (0, 0, 1),
        (0, u64::MAX, 1),
        (u64::MAX - 4095, 4096, 1),
        (0, 4096, 8),
    ] {
        assert!(object.map(offset, length, access).is_err());
    }
    STATE.with(|state| state.borrow_mut().fail_map = true);
    assert!(object.map(0, 4096, 1).is_err());
    drop(object);
    STATE.with(|state| {
        assert!(!state
            .borrow()
            .calls
            .iter()
            .any(|call| call.0 == syscall::SyscallNumber::MemoryUnmap))
    });
}

#[test]
fn failed_creation_and_received_handle_ownership_close_only_valid_owned_handles() {
    reset();
    STATE.with(|state| state.borrow_mut().fail_create = true);
    assert!(MemoryObject::create(4096).is_err());
    // SAFETY: this test relinquishes its single simulated received reference.
    let received = unsafe { MemoryObject::from_owned_handle(19) };
    assert_eq!(received.handle(), 19);
    drop(received);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state
                .calls
                .iter()
                .filter(|call| call.0 == syscall::SyscallNumber::HandleClose)
                .count(),
            1
        );
        assert_eq!(state.calls.last().unwrap().1, [19]);
    });
}

#[test]
fn explicit_release_failures_return_ownership_and_success_does_not_drop_twice() {
    reset();
    let object = MemoryObject::create(4096).unwrap();
    let mapping = object.map(0, 4096, mnu_abi::MEMORY_ACCESS_READ).unwrap();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.fail_unmap = true;
        state.fail_close = true;
    });
    let (mapping, error) = match mapping.unmap() {
        Err(error) => error,
        Ok(()) => panic!("must retain failed mapping"),
    };
    assert_eq!(error.raw(), -5);
    assert_eq!(mapping.address(), 0x10000);
    let (object, error) = match object.close() {
        Err(error) => error,
        Ok(()) => panic!("must retain failed handle"),
    };
    assert_eq!(error.raw(), -5);
    assert_eq!(object.handle(), 7);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.fail_unmap = false;
        state.fail_close = false;
    });
    assert!(mapping.unmap().is_ok());
    assert!(object.close().is_ok());
    STATE.with(|state| {
        let state = state.borrow();
        for number in [
            syscall::SyscallNumber::MemoryUnmap,
            syscall::SyscallNumber::HandleClose,
        ] {
            assert_eq!(
                state.calls.iter().filter(|call| call.0 == number).count(),
                2
            );
        }
    });
}
