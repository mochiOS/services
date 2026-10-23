//! Execute the real runtime adapter with controlled native replies. Any
//! dependency on a POSIX endpoint fails compilation: none exists in this fixture.
use mochios_filesystem_protocol::{self as filesystem, description_flags as wire};
use std::cell::RefCell;
use std::ffi::c_int;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const O_APPEND: c_int = 8;
const O_NONBLOCK: c_int = 0x4000;

#[derive(Clone, Copy)]
struct Handle {
    lower_handle: u64,
    open_flags: c_int,
}
#[derive(Clone, Copy)]
struct FdEntry {
    handle: Handle,
    rights: u64,
}
struct State {
    calls: Vec<(mnu_abi::SyscallNumber, u64, Vec<u8>, u64)>,
    reply: [u8; 4],
    result: Result<u64, c_int>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            calls: vec![],
            reply: [0; 4],
            result: Ok(0),
        }
    }
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State { result: Ok(0), ..State::default() }); }
mod syscall {
    pub use mnu_abi::{SyscallNumber, HANDLE_RIGHT_READ};
    pub fn raw_syscall6(
        op: SyscallNumber,
        handle: u64,
        code: u64,
        input: u64,
        size: u64,
        output: u64,
        capacity: u64,
    ) -> Result<u64, i32> {
        assert_eq!(handle, 73);
        let bytes = if size == 0 {
            vec![]
        } else {
            unsafe { std::slice::from_raw_parts(input as *const u8, size as usize) }.to_vec()
        };
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.calls.push((op, code, bytes, capacity));
            if output != 0 && state.result.is_ok() {
                assert_eq!(capacity, 4);
                unsafe {
                    std::ptr::copy_nonoverlapping(state.reply.as_ptr(), output as *mut u8, 4)
                };
            }
            state.result
        })
    }
}
fn syscall_errno(result: Result<u64, c_int>) -> Result<u64, c_int> {
    result
}
#[path = "../../../user/crates/newlib-runtime/src/file_description_flags.rs"]
mod actual;

fn entry(rights: u64) -> FdEntry {
    FdEntry {
        handle: Handle {
            lower_handle: 73,
            open_flags: 1 | 0x80000,
        },
        rights,
    }
}
fn reset(result: Result<u64, c_int>, flags: u32) {
    STATE.with(|state| {
        *state.borrow_mut() = State {
            result,
            reply: flags.to_le_bytes(),
            calls: vec![],
        }
    });
}

#[test]
fn reads_query_but_write_only_descriptions_use_control_without_changing_access_mode() {
    for (rights, operation) in [
        (
            mnu_abi::HANDLE_RIGHT_READ,
            mnu_abi::SyscallNumber::HandleQuery,
        ),
        (
            mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_WRITE,
            mnu_abi::SyscallNumber::HandleControl,
        ),
    ] {
        for flags in [
            0,
            filesystem::OPEN_STATUS_APPEND,
            filesystem::OPEN_STATUS_NONBLOCK,
            filesystem::OPEN_STATUS_FLAGS_ALL,
        ] {
            reset(Ok(4), flags);
            let expected =
                1 | if flags & filesystem::OPEN_STATUS_APPEND != 0 {
                    O_APPEND
                } else {
                    0
                } | if flags & filesystem::OPEN_STATUS_NONBLOCK != 0 {
                    O_NONBLOCK
                } else {
                    0
                };
            assert_eq!(actual::get(entry(rights)), Ok(expected));
            STATE.with(|state| {
                assert_eq!(state.borrow().calls, [(operation, wire::GET, vec![], 4)])
            });
        }
    }
}

#[test]
fn replacement_and_masked_updates_are_one_native_call_not_read_modify_write() {
    reset(Ok(0), 0);
    assert_eq!(
        actual::set(
            entry(mnu_abi::HANDLE_RIGHT_CONTROL),
            O_APPEND | O_NONBLOCK | 0x80000
        ),
        Ok(())
    );
    STATE.with(|state| {
        assert_eq!(
            state.borrow().calls,
            [(
                mnu_abi::SyscallNumber::HandleControl,
                wire::UPDATE,
                wire::encode_update(
                    filesystem::OPEN_STATUS_FLAGS_ALL,
                    filesystem::OPEN_STATUS_FLAGS_ALL
                )
                .unwrap()
                .to_vec(),
                0
            )]
        )
    });
    for flags in [0, filesystem::OPEN_STATUS_NONBLOCK] {
        reset(Ok(0), 0);
        assert_eq!(
            actual::update(
                entry(mnu_abi::HANDLE_RIGHT_CONTROL),
                filesystem::OPEN_STATUS_NONBLOCK,
                flags
            ),
            Ok(())
        );
        STATE.with(|state| assert_eq!(state.borrow().calls.len(), 1));
    }
    reset(Ok(0), 0);
    assert_eq!(
        actual::update(entry(0), 0, filesystem::OPEN_STATUS_APPEND),
        Err(EINVAL)
    );
    STATE.with(|state| assert!(state.borrow().calls.is_empty()));
}

#[test]
fn errors_and_malformed_replies_are_not_retried_through_another_authority() {
    for result in [Err(13), Err(9), Err(5), Err(88)] {
        reset(result, 0);
        assert_eq!(
            actual::get(entry(mnu_abi::HANDLE_RIGHT_READ)),
            result.map(|_| 0)
        );
        STATE.with(|state| assert_eq!(state.borrow().calls.len(), 1));
        reset(result, 0);
        assert_eq!(
            actual::set(entry(mnu_abi::HANDLE_RIGHT_CONTROL), 0),
            result.map(|_| ())
        );
        STATE.with(|state| assert_eq!(state.borrow().calls.len(), 1));
    }
    for count in [0, 3, 5, u64::MAX] {
        reset(Ok(count), 0);
        assert_eq!(actual::get(entry(mnu_abi::HANDLE_RIGHT_READ)), Err(EIO));
    }
    reset(Ok(4), u32::MAX);
    assert_eq!(actual::get(entry(mnu_abi::HANDLE_RIGHT_READ)), Err(EIO));
    reset(Ok(1), 0);
    assert_eq!(
        actual::set(entry(mnu_abi::HANDLE_RIGHT_CONTROL), 0),
        Err(EIO)
    );
}

#[test]
fn description_wire_accepts_only_exact_masked_updates() {
    for mask in [
        0,
        filesystem::OPEN_STATUS_APPEND,
        filesystem::OPEN_STATUS_NONBLOCK,
        filesystem::OPEN_STATUS_FLAGS_ALL,
        u32::MAX,
    ] {
        for flags in [
            0,
            filesystem::OPEN_STATUS_APPEND,
            filesystem::OPEN_STATUS_NONBLOCK,
            filesystem::OPEN_STATUS_FLAGS_ALL,
            u32::MAX,
        ] {
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&mask.to_le_bytes());
            bytes[4..].copy_from_slice(&flags.to_le_bytes());
            if mask & !filesystem::OPEN_STATUS_FLAGS_ALL != 0 || flags & !mask != 0 {
                assert_eq!(wire::encode_update(mask, flags), None);
                assert_eq!(wire::decode_update(&bytes), None);
            } else {
                assert_eq!(wire::encode_update(mask, flags), Some(bytes));
                assert_eq!(wire::decode_update(&bytes), Some((mask, flags)));
            }
            for length in 0..8 {
                assert_eq!(wire::decode_update(&bytes[..length]), None);
            }
            assert_eq!(
                wire::decode_update(&[bytes.as_slice(), &[0]].concat()),
                None
            );
        }
    }
}
