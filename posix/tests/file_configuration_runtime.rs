//! Run the real adapter with a leased FD and controlled native object replies.
//! There is deliberately no POSIX endpoint or pathname API in this fixture.
#![allow(dead_code)]
use mochios_filesystem_protocol::object_limits as wire;
use mochios_posix_protocol as posix_protocol;
use std::cell::RefCell;
use std::ffi::c_int;
type CLong = i64;
const EBADF: c_int = 9;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const ENOTSUP: c_int = 134;
const ENOSYS: c_int = 88;
const ENOTTY: c_int = 25;
const EOVERFLOW: c_int = 139;
#[derive(Clone, Copy, PartialEq, Eq)]
enum FdKind {
    ObjectFile,
    ObjectDirectory,
    ObjectSpecial,
    ObjectStreamRead,
    ObjectStreamWrite,
    ObjectPty,
    ObjectTerminalFile,
    ObjectSocket,
}
#[derive(Clone, Copy)]
struct Object {
    lower_handle: u64,
    kind: FdKind,
}
#[derive(Clone, Copy)]
struct FdEntry {
    handle: Object,
    rights: u64,
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
        STATE.with_borrow_mut(|s| {
            assert!(s.leased);
            s.leased = false;
        });
    }
}
struct State {
    entry: FdEntry,
    leased: bool,
    errno: i32,
    calls: Vec<syscall::SyscallNumber>,
    reply: wire::Limits,
    result: Result<u64, i32>,
    terminal_reply: Option<[u8; posix_protocol::terminal_limits::RESPONSE_LEN]>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            entry: FdEntry {
                handle: Object {
                    lower_handle: 73,
                    kind: FdKind::ObjectFile,
                },
                rights: mnu_abi::HANDLE_RIGHT_READ,
            },
            leased: false,
            errno: 81,
            calls: vec![],
            reply: wire::Limits {
                name_bytes_max: 255,
                path_bytes_max: 4096,
                link_count_max: 65535,
                filesystem_block_bytes: 4096,
            },
            result: Ok(wire::RESPONSE_LEN as u64),
            terminal_reply: None,
        }
    }
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn with_fd_entry(fd: c_int) -> Result<Lease, c_int> {
    if fd != 3 {
        return Err(EBADF);
    }
    STATE.with_borrow_mut(|s| {
        assert!(!s.leased);
        s.leased = true;
        Ok(Lease(s.entry))
    })
}
fn result_with_errno<T>(result: Result<T, c_int>, error: T) -> T {
    result.unwrap_or_else(|e| {
        STATE.with_borrow_mut(|s| s.errno = e);
        error
    })
}
fn syscall_errno(result: Result<u64, c_int>) -> Result<u64, c_int> {
    result
}
mod io_resources {
    pub fn with<R, T: Copy>(
        prepare: impl FnOnce() -> Result<R, i32>,
        operation: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        let mut lease = prepare()?;
        operation(&mut lease)
    }
}
mod syscall {
    pub use mnu_abi::{HANDLE_RIGHT_READ, SyscallNumber};
    pub fn raw_syscall6(
        op: SyscallNumber,
        handle: u64,
        selector: u64,
        input: u64,
        input_len: u64,
        output: u64,
        capacity: u64,
    ) -> Result<u64, i32> {
        super::STATE.with_borrow_mut(|s| {
            assert!(s.leased);
            let bytes = s
                .terminal_reply
                .map(|v| v.to_vec())
                .unwrap_or_else(|| s.reply.encode().to_vec());
            let expected_selector = if s.terminal_reply.is_some() {
                if matches!(op, SyscallNumber::HandleQuery) {
                    super::posix_protocol::PTY_QUERY_LIMITS
                } else {
                    super::posix_protocol::PTY_CONTROL_GET_LIMITS
                }
            } else {
                super::wire::GET
            };
            assert_eq!(
                (handle, selector, input, input_len, capacity),
                (73, expected_selector, 0, 0, bytes.len() as u64)
            );
            s.calls.push(op);
            if s.result.is_ok() {
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), output as *mut u8, bytes.len());
                }
            }
            s.result
        })
    }
}
#[path = "../../../user/crates/newlib-runtime/src/terminal_observation.rs"]
mod terminal_observation;
use terminal_observation::observe as terminal_observe;
#[path = "../../../user/crates/newlib-runtime/src/file_configuration.rs"]
mod actual;
fn reset() {
    STATE.with_borrow_mut(|s| *s = State::default());
}
fn check(value: i64, name: i32) {
    assert_eq!(actual::fpathconf(3, name), value);
    STATE.with_borrow(|s| {
        assert!(!s.leased);
        assert_eq!(s.errno, 81);
    });
}
#[test]
fn owner_values_and_c_terminator_are_observed_through_the_lease() {
    reset();
    for (selector, value) in [(0, 65535), (3, 255), (4, 4097)] {
        check(value, selector);
    }
    STATE.with_borrow_mut(|s| {
        assert_eq!(s.calls.len(), 3);
        s.reply.path_bytes_max = 1000;
    });
    check(1001, 4);
    STATE.with_borrow_mut(|s| s.reply.path_bytes_max = u32::MAX);
    check(posix_protocol::MAX_PATH_LEN as i64 + 1, 4);
}
#[test]
fn readonly_query_and_writeonly_control_have_no_authority_fallback() {
    for (rights, expected) in [
        (
            mnu_abi::HANDLE_RIGHT_READ,
            syscall::SyscallNumber::HandleQuery,
        ),
        (
            mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_CONTROL,
            syscall::SyscallNumber::HandleControl,
        ),
    ] {
        reset();
        STATE.with_borrow_mut(|s| s.entry.rights = rights);
        check(255, 3);
        STATE.with_borrow(|s| assert_eq!(s.calls, [expected]));
        STATE.with_borrow_mut(|s| s.result = Err(13));
        assert_eq!(actual::fpathconf(3, 3), -1);
        STATE.with_borrow(|s| {
            assert_eq!(s.calls, [expected, expected]);
            assert_eq!(s.errno, 13);
            assert!(!s.leased);
        });
    }
}
#[test]
fn pipe_atomic_limit_is_local_and_never_queries_a_filesystem() {
    for kind in [FdKind::ObjectStreamRead, FdKind::ObjectStreamWrite] {
        reset();
        STATE.with_borrow_mut(|s| s.entry.handle.kind = kind);
        check(mochios_posix_client::stream::PIPE_BUF as i64, 5);
        STATE.with_borrow(|s| assert!(s.calls.is_empty()));
    }
}
#[test]
fn invalid_fd_invalid_name_and_unimplemented_values_are_distinct() {
    reset();
    for (fd, name, error) in [
        (-1, 3, EBADF),
        (4, 12, EBADF),
        (3, -1, EINVAL),
        (3, 21, EINVAL),
        (3, 12, ENOTSUP),
        (3, 5, ENOTSUP),
    ] {
        assert_eq!(actual::fpathconf(fd, name), -1);
        STATE.with_borrow(|s| {
            assert_eq!(s.errno, error);
            assert!(!s.leased);
            assert!(s.calls.is_empty());
        });
    }
}
#[test]
fn malformed_replies_and_zero_limits_are_not_fabricated() {
    for result in [Ok(0), Ok(15), Ok(17), Err(EIO)] {
        reset();
        STATE.with_borrow_mut(|s| s.result = result);
        assert_eq!(actual::fpathconf(3, 3), -1);
        STATE.with_borrow(|s| {
            assert_eq!(s.errno, EIO);
            assert!(!s.leased);
        });
    }
    reset();
    STATE.with_borrow_mut(|s| s.reply.name_bytes_max = 0);
    assert_eq!(actual::fpathconf(3, 3), -1);
    STATE.with_borrow(|s| assert_eq!(s.errno, EIO));
}
#[test]
fn all_newlib_selector_numbers_match_the_headers() {
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/unistd.h");
    for (name, value) in [
        ("_PC_LINK_MAX", 0),
        ("_PC_MAX_CANON", 1),
        ("_PC_MAX_INPUT", 2),
        ("_PC_NAME_MAX", 3),
        ("_PC_PATH_MAX", 4),
        ("_PC_PIPE_BUF", 5),
        ("_PC_VDISABLE", 8),
        ("_PC_TIMESTAMP_RESOLUTION", 20),
    ] {
        assert!(
            header
                .lines()
                .any(|s| s.split_whitespace().collect::<Vec<_>>()
                    == ["#define", name, &value.to_string()])
        );
    }
}

#[test]
fn unavailable_io_is_a_negative_answer_after_fd_validation_without_owner_rpc() {
    for kind in [
        FdKind::ObjectFile,
        FdKind::ObjectDirectory,
        FdKind::ObjectSpecial,
        FdKind::ObjectStreamRead,
        FdKind::ObjectPty,
        FdKind::ObjectSocket,
    ] {
        reset();
        STATE.with_borrow_mut(|s| s.entry.handle.kind = kind);
        for selector in [9, 10, 11] {
            check(-1, selector);
        }
        STATE.with_borrow(|s| assert!(s.calls.is_empty()));
    }
    reset();
    assert_eq!(actual::fpathconf(-1, 9), -1);
    STATE.with_borrow(|s| assert_eq!(s.errno, EBADF));
}

fn terminal() {
    reset();
    STATE.with_borrow_mut(|s| {
        s.entry.handle.kind = FdKind::ObjectPty;
        s.terminal_reply = Some(
            posix_protocol::terminal_limits::Limits {
                canonical_bytes: 511,
                input_bytes: 1024,
                disabled_character: 255,
            }
            .encode(),
        );
        s.result = Ok(posix_protocol::terminal_limits::RESPONSE_LEN as u64);
    });
}

#[test]
fn terminal_values_come_from_the_owner_for_each_access_mode() {
    for kind in [
        FdKind::ObjectPty,
        FdKind::ObjectTerminalFile,
        FdKind::ObjectSpecial,
    ] {
        for (rights, operation) in [
            (
                mnu_abi::HANDLE_RIGHT_READ,
                syscall::SyscallNumber::HandleQuery,
            ),
            (
                mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_WRITE,
                syscall::SyscallNumber::HandleControl,
            ),
        ] {
            terminal();
            STATE.with_borrow_mut(|s| {
                s.entry.handle.kind = kind;
                s.entry.rights = rights;
            });
            for (selector, value) in [(1, 511), (2, 1024), (8, 255)] {
                check(value, selector);
            }
            STATE.with_borrow(|s| assert_eq!(s.calls, [operation; 3]));
        }
    }
}

#[test]
fn terminal_errors_never_fall_back_to_defaults_or_more_rights() {
    for (result, error) in [
        (Ok(0), EIO),
        (Ok(11), EIO),
        (Ok(13), EIO),
        (Err(13), 13),
        (Err(EBADF), EBADF),
    ] {
        terminal();
        STATE.with_borrow_mut(|s| s.result = result);
        assert_eq!(actual::fpathconf(3, 1), -1);
        STATE.with_borrow(|s| {
            assert_eq!(s.errno, error);
            assert_eq!(s.calls, [syscall::SyscallNumber::HandleQuery]);
            assert!(!s.leased);
        });
    }
    terminal();
    STATE.with_borrow_mut(|s| s.terminal_reply.as_mut().unwrap()[10] = 1);
    assert_eq!(actual::fpathconf(3, 2), -1);
    STATE.with_borrow(|s| assert_eq!(s.errno, EIO));
    for kind in [
        FdKind::ObjectFile,
        FdKind::ObjectDirectory,
        FdKind::ObjectSocket,
        FdKind::ObjectStreamRead,
    ] {
        reset();
        STATE.with_borrow_mut(|s| s.entry.handle.kind = kind);
        assert_eq!(actual::fpathconf(3, 1), -1);
        STATE.with_borrow(|s| {
            assert_eq!(s.errno, EINVAL);
            assert!(s.calls.is_empty());
        });
    }
    terminal();
    STATE.with_borrow_mut(|s| {
        s.entry.handle.kind = FdKind::ObjectSpecial;
        s.result = Err(ENOTSUP);
    });
    assert_eq!(actual::fpathconf(3, 8), -1);
    STATE.with_borrow(|s| assert_eq!(s.errno, EINVAL));
    assert_eq!(actual::fpathconf(-1, 1), -1);
    STATE.with_borrow(|s| assert_eq!(s.errno, EBADF));
}
