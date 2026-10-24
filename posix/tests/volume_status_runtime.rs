//! Production statvfs adapter with controlled native/IPC replies and FD leases.
#![allow(dead_code)]
use mochios_filesystem_protocol::volume_status as wire;
use mochios_posix_client::{ObjectHandleAttachment, StatAtBase};
use std::{
    cell::RefCell,
    ffi::{c_char, c_int, c_void},
};
const EIO: i32 = 5;
const EBADF: i32 = 9;
const EFAULT: i32 = 14;
const EOVERFLOW: i32 = 139;
const ENOTSUP: i32 = 134;
#[derive(Clone, Copy, PartialEq)]
enum FdKind {
    ObjectFile,
    ObjectDirectory,
    ObjectSpecial,
    ObjectFifo,
    ObjectTerminalFile,
    ObjectStreamRead,
}
#[derive(Clone, Copy)]
struct Object {
    kind: FdKind,
    lower_handle: u64,
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
    kind: FdKind,
    rights: u64,
    leased: bool,
    errno: i32,
    calls: usize,
    ipc: usize,
    result: Result<u64, i32>,
    status: wire::Status,
}
impl Default for State {
    fn default() -> Self {
        Self {
            kind: FdKind::ObjectFile,
            rights: mnu_abi::HANDLE_RIGHT_READ,
            leased: false,
            errno: 71,
            calls: 0,
            ipc: 0,
            result: Ok(wire::RESPONSE_LEN as u64),
            status: wire::Status {
                block_bytes: 4096,
                flags: wire::READ_ONLY,
                blocks: 1 << 36,
                free_blocks: 1 << 35,
                inodes: 1024,
                free_inodes: 900,
                filesystem_id: 7,
                name_bytes_max: 255,
            },
        }
    }
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
fn with_fd_entry(fd: i32) -> Result<Lease, i32> {
    if fd != 3 {
        return Err(EBADF);
    }
    STATE.with_borrow_mut(|s| {
        assert!(!s.leased);
        s.leased = true;
        Ok(Lease(FdEntry {
            handle: Object {
                kind: s.kind,
                lower_handle: 77,
            },
            rights: s.rights,
        }))
    })
}
fn set_errno(error: i32) {
    STATE.with_borrow_mut(|s| s.errno = error);
}
fn result_with_errno<T>(result: Result<T, i32>, error: T) -> T {
    result.unwrap_or_else(|e| {
        set_errno(e);
        error
    })
}
fn map_posix_client_error(error: i32) -> i32 {
    error
}
fn syscall_errno(result: Result<u64, i32>) -> Result<u64, i32> {
    result
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
mod user_copy {
    pub fn write(output: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        if (output as usize) < 4096 {
            return Err(super::EFAULT);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        }
        Ok(())
    }
}
mod syscall {
    pub use mnu_abi::{HANDLE_RIGHT_READ, SyscallNumber};
    pub fn raw_syscall6(
        op: SyscallNumber,
        handle: u64,
        selector: u64,
        input: u64,
        inputlen: u64,
        output: u64,
        length: u64,
    ) -> Result<u64, i32> {
        super::STATE.with_borrow_mut(|s| {
            assert!(s.leased);
            assert_eq!(
                (handle, selector, input, inputlen, length),
                (77, super::wire::GET, 0, 0, super::wire::RESPONSE_LEN as u64)
            );
            assert_eq!(
                op,
                if s.rights & HANDLE_RIGHT_READ != 0 {
                    SyscallNumber::HandleQuery
                } else {
                    SyscallNumber::HandleControl
                }
            );
            s.calls += 1;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    s.status.encode().as_ptr(),
                    output as *mut u8,
                    super::wire::RESPONSE_LEN,
                )
            };
            s.result
        })
    }
}
struct Client;
fn posix_client() -> Result<Client, i32> {
    Ok(Client)
}
impl Client {
    fn volume_status(&self, object: ObjectHandleAttachment<u32>) -> Result<wire::Status, i32> {
        assert_eq!(object.handle, 77);
        STATE.with_borrow_mut(|s| {
            assert!(s.leased);
            s.ipc += 1;
            Ok(s.status)
        })
    }
    fn volume_status_at(&self, base: StatAtBase<u32>, path: &[u8]) -> Result<wire::Status, i32> {
        assert!(matches!(base, StatAtBase::ProcessCwd));
        assert_eq!(path, b"owned");
        STATE.with_borrow_mut(|s| {
            s.ipc += 1;
            Ok(s.status)
        })
    }
}
mod path_io {
    use super::*;
    pub fn at<T>(
        _: i32,
        path: *const c_char,
        operation: impl FnOnce(StatAtBase<u32>, &[u8]) -> Result<T, i32>,
    ) -> Result<T, i32> {
        if path.is_null() {
            return Err(EFAULT);
        }
        let path = unsafe { std::ffi::CStr::from_ptr(path) };
        operation(StatAtBase::ProcessCwd, path.to_bytes())
    }
}
#[path = "../../../user/crates/newlib-runtime/src/volume_status.rs"]
mod volume_status;
#[test]
fn retained_fd_uses_native_rights_and_initializes_padding() {
    for rights in [mnu_abi::HANDLE_RIGHT_READ, mnu_abi::HANDLE_RIGHT_CONTROL] {
        STATE.with_borrow_mut(|s| {
            *s = State::default();
            s.rights = rights;
        });
        let mut bytes = [0xa5u8; 80];
        assert_eq!(volume_status::fstatvfs(3, bytes.as_mut_ptr().cast()), 0);
        assert_eq!(
            u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            1 << 36
        );
        assert_eq!(&bytes[52..56], &[0; 4]);
        assert_eq!(u64::from_ne_bytes(bytes[64..72].try_into().unwrap()), 1);
        STATE.with_borrow(|s| {
            assert!(!s.leased);
            assert_eq!((s.calls, s.ipc, s.errno), (1, 0, 71));
        });
    }
}
#[test]
fn malformed_overflow_and_invalid_output_retire_lease_without_fabricated_success() {
    for (case, error) in [(0, EIO), (1, EOVERFLOW), (2, EFAULT), (3, EBADF)] {
        STATE.with_borrow_mut(|s| {
            *s = State::default();
            if case == 0 {
                s.result = Ok(55)
            }
            if case == 1 {
                s.status.inodes = 1 << 32;
            }
        });
        let mut bytes = [0xa5u8; 80];
        let output = if case == 2 {
            1usize as *mut c_void
        } else {
            bytes.as_mut_ptr().cast()
        };
        assert_eq!(
            volume_status::fstatvfs(if case == 3 { -1 } else { 3 }, output),
            -1
        );
        assert_eq!(bytes, [0xa5; 80]);
        STATE.with_borrow(|s| {
            assert_eq!(s.errno, error);
            assert!(!s.leased);
        });
    }
}
#[test]
fn fifo_and_terminal_metadata_use_explicit_ipc_while_valid_nonfilesystem_fd_is_unsupported() {
    for kind in [
        FdKind::ObjectFifo,
        FdKind::ObjectTerminalFile,
        FdKind::ObjectStreamRead,
    ] {
        STATE.with_borrow_mut(|s| {
            *s = State::default();
            s.kind = kind;
        });
        let mut bytes = [0; 80];
        let result = volume_status::fstatvfs(3, bytes.as_mut_ptr().cast());
        STATE.with_borrow(|s| {
            assert!(!s.leased);
            assert_eq!(s.calls, 0);
            if kind == FdKind::ObjectStreamRead {
                assert_eq!(result, -1);
                assert_eq!(s.errno, ENOTSUP);
                assert_eq!(s.ipc, 0)
            } else {
                assert_eq!(result, 0);
                assert_eq!(s.ipc, 1);
            }
        });
    }
    STATE.with_borrow_mut(|s| *s = State::default());
    let mut bytes = [0; 80];
    assert_eq!(
        volume_status::statvfs(c"owned".as_ptr(), bytes.as_mut_ptr().cast()),
        0
    );
    STATE.with_borrow(|s| assert_eq!((s.ipc, s.calls, s.errno), (1, 0, 71)));
}
