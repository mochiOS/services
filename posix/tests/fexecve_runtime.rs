#![allow(dead_code)]
use core::ffi::{c_char, c_int};
use mochios_posix_client::newlib_errno::*;
use mochios_posix_client::{
    ObjectHandleAttachment,
    fd::{Entry, FdTable},
};
use mochios_posix_protocol as posix_protocol;
use std::cell::{Cell, RefCell};
const MAX_EXEC_VECTOR_ENTRIES: usize = 256;
const MAX_EXECUTABLE_PATH_LEN: usize = 256;
const MAX_STARTUP_IMAGE_BYTES: usize = mnu_abi::process_image::MAX_IMAGE_BYTES;
const PAGE_SIZE: usize = 4096;
const CAPABILITY_SERVICE_NAME: &[u8] = b"capability.service";
#[derive(Clone, Copy, PartialEq, Eq)]
enum FdKind {
    ObjectFile,
    ObjectDirectory,
}
#[derive(Clone, Copy)]
struct FdObject {
    lower_handle: u64,
    kind: FdKind,
    open_flags: i32,
}
#[derive(Default)]
struct State {
    failure: u8,
    reads: usize,
    checked: usize,
    drops: usize,
    closed: Vec<u32>,
    entered: usize,
    bytes: Vec<u8>,
    mutate: Option<(usize, usize)>,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());static DEFER:Cell<u32>=const{Cell::new(0)};}
#[path = "../../../user/crates/newlib-runtime/src/exec_inputs.rs"]
mod exec_inputs;
#[path = "../../../user/crates/newlib-runtime/src/exec_handle.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
fn syscall_errno(r: Result<u64, i32>) -> Result<u64, i32> {
    r
}
fn map_kernel_errno(raw: i64) -> i32 {
    mochios_posix_client::newlib_errno::from_status(raw)
}
fn map_posix_client_error(e: i32) -> i32 {
    e
}
fn close_object_handle(h: u32) {
    assert!(DEFER.get() > 0);
    STATE.with_borrow_mut(|s| s.closed.push(h));
}
struct Guard;
fn defer_native_delivery() -> Guard {
    DEFER.set(DEFER.get() + 1);
    Guard
}
impl Drop for Guard {
    fn drop(&mut self) {
        DEFER.set(DEFER.get() - 1);
    }
}
mod io_resources {
    pub fn with<R, T: Copy>(
        prepare: impl FnOnce() -> Result<R, i32>,
        op: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        let mut r = prepare()?;
        op(&mut r)
    }
}
mod image_startup {
    pub struct Plan;
    impl Plan {
        pub fn new(_: [u8; 16]) -> Result<Self, i32> {
            Ok(Self)
        }
        pub fn auxiliary(&self) -> [(u64, u64); 0] {
            []
        }
        pub fn mappings(&self) -> [mnu_abi::process_image::InitialMapping; 0] {
            []
        }
    }
    impl Drop for Plan {
        fn drop(&mut self) {
            super::STATE.with_borrow_mut(|s| s.drops += 1);
        }
    }
}
mod address_space {
    pub struct Snapshot;
    pub fn snapshot() -> Result<Snapshot, i32> {
        Ok(Snapshot)
    }
    impl Snapshot {
        pub fn byte_ceiling(&self) -> u64 {
            123456789
        }
    }
}
fn attach_fd_launch_context(_: &FdTable<FdObject>, _: &mut [u8], len: usize) -> Result<usize, i32> {
    Ok(len)
}
struct Client;
fn posix_client() -> Result<Client, i32> {
    Ok(Client)
}
impl Client {
    fn check_executable(&self, file: ObjectHandleAttachment<u32>) -> Result<(), i32> {
        assert_eq!(file.handle, 19);
        STATE.with_borrow_mut(|s| {
            s.checked += 1;
            if let Some((p, n)) = s.mutate {
                unsafe {
                    std::ptr::write_bytes(p as *mut u8, b'X', n);
                }
            }
            if s.failure == 1 { Err(EACCES) } else { Ok(()) }
        })
    }
}
mod syscall {
    pub use mnu_abi::SyscallNumber;
    pub const HANDLE_RIGHT_READ: u64 = mnu_abi::HANDLE_RIGHT_READ;
    pub fn raw_syscall3(n: SyscallNumber, d: u64, s: u64, l: u64) -> Result<u64, i32> {
        super::user_copy_native::syscall::raw_syscall3(n, d, s, l)
    }
    pub fn raw_syscall2(n: SyscallNumber, p: u64, len: u64) -> Result<u64, i32> {
        match n {
            SyscallNumber::RandomFill => {
                unsafe {
                    std::ptr::write_bytes(p as *mut u8, 9, len as usize);
                }
                Ok(len)
            }
            SyscallNumber::FindProcessByName => {
                assert_eq!(
                    unsafe { std::slice::from_raw_parts(p as *const u8, len as usize) },
                    super::CAPABILITY_SERVICE_NAME
                );
                Ok(99)
            }
            _ => panic!("unexpected native call"),
        }
    }
    pub fn raw_syscall4(
        n: SyscallNumber,
        h: u64,
        p: u64,
        len: u64,
        offset: u64,
    ) -> Result<u64, i32> {
        assert_eq!(n, SyscallNumber::HandleReadAt);
        assert_eq!(h, 19);
        assert_eq!(super::DEFER.get(), 0);
        super::STATE.with_borrow_mut(|s| {
            s.reads += 1;
            if s.failure == 2 {
                return Err(super::EIO);
            }
            if s.failure == 3 {
                return Ok(len + 1);
            }
            let start = (offset as usize).min(s.bytes.len());
            let count = (s.bytes.len() - start).min(len as usize).min(17);
            unsafe {
                std::ptr::copy_nonoverlapping(s.bytes[start..].as_ptr(), p as *mut u8, count);
            }
            Ok(count as u64)
        })
    }
    pub fn raw_syscall6(
        n: SyscallNumber,
        endpoint: u64,
        request: u64,
        len: u64,
        reply: u64,
        capacity: u64,
        objects: u64,
    ) -> Result<u64, i32> {
        assert_eq!(n, SyscallNumber::IpcCallObjectHandles);
        assert_eq!(endpoint, 99);
        assert_eq!(capacity, 8);
        assert!(super::DEFER.get() > 0);
        let request = unsafe { std::slice::from_raw_parts(request as *const u8, len as usize) };
        let (digest, key) =
            mochios_capability_protocol::decode_authorize_exec_object_request(request).unwrap();
        assert_eq!(key, "fexecve");
        let objects = unsafe { &mut *(objects as *mut mnu_abi::IpcObjectHandles) };
        assert_eq!(objects.count, 1);
        assert_eq!(objects.handles[0].handle, 19);
        assert_eq!(objects.handles[0].rights, HANDLE_RIGHT_READ);
        super::STATE.with_borrow(|s| {
            use sha2::Digest;
            assert_eq!(digest, <[u8; 32]>::from(sha2::Sha256::digest(&s.bytes)));
            if s.failure == 4 {
                return Err(super::EAGAIN);
            }
            *objects = Default::default();
            if s.failure == 6 {
                objects.count = 2;
                objects.handles[0].handle = 404;
                objects.handles[1].handle = 404;
            }
            if s.failure == 8 {
                objects.delivery_flags = 1;
            }
            let status: u64 = if s.failure == 5 { 13 } else { 0 };
            unsafe {
                std::ptr::copy_nonoverlapping(status.to_le_bytes().as_ptr(), reply as *mut u8, 8);
            }
            Ok(if s.failure == 7 { 7 } else { 8 })
        })
    }
    pub mod image {
        pub fn replace_bounded(
            h: u32,
            key: &str,
            startup: &[u8],
            ceiling: u64,
        ) -> Result<core::convert::Infallible, mochi_user_syscall::SysError> {
            assert_eq!((h, key, ceiling), (19, "fexecve", 123456789));
            assert_eq!(super::super::DEFER.get(), 0);
            mnu_abi::process_image::decode(startup).unwrap();
            super::super::STATE.with_borrow(|state| {
                if state.mutate.is_some() {
                    assert!(startup.windows(9).any(|w| w == b"original\xff"));
                } else {
                    assert!(startup.windows(7).any(|w| w == b"fexecve"));
                }
            });
            super::super::STATE.with_borrow_mut(|s| s.entered += 1);
            Err(mochi_user_syscall::SysError::from_raw(
                mnu_abi::status::Error::InvalidFormat.into_raw() as i64,
            ))
        }
    }
}
fn table() -> FdTable<FdObject> {
    let mut t = FdTable::new();
    assert_eq!(
        t.install(Entry {
            handle: FdObject {
                lower_handle: 19,
                kind: FdKind::ObjectFile,
                open_flags: 0
            },
            rights: posix_protocol::CHECK_EXECUTABLE_RIGHTS,
            descriptor_flags: 1
        })
        .unwrap(),
        0
    );
    t
}
fn reset(failure: u8) {
    STATE.with_borrow_mut(|s| {
        *s = State {
            failure,
            bytes: (0..17001).map(|n| (n % 251) as u8).collect(),
            ..Default::default()
        }
    });
}
#[test]
fn actual_fd_path_preserves_original_references_and_cleans_every_failed_stage() {
    for (failure, error, drops, entered) in [
        (0, ENOEXEC, 1, 1),
        (1, EACCES, 0, 0),
        (2, EIO, 1, 0),
        (3, EIO, 1, 0),
        (4, EAGAIN, 1, 0),
        (5, EACCES, 1, 0),
        (6, EIO, 1, 0),
        (7, EIO, 1, 0),
        (8, EIO, 1, 0),
    ] {
        reset(failure);
        let fds = table();
        assert_eq!(
            implementation::replace(0, std::ptr::null(), std::ptr::null(), &fds),
            Err(error)
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.checked, 1);
            assert_eq!(s.drops, drops);
            assert_eq!(s.entered, entered);
            assert_eq!(s.closed, if failure == 6 { vec![404] } else { vec![] });
        });
        assert_eq!(fds.get(0).unwrap().handle.lower_handle, 19);
        assert_eq!(DEFER.get(), 0);
    }
}
#[test]
fn fd_and_application_memory_are_validated_before_policy_or_loader_callbacks() {
    reset(0);
    let fds = table();
    assert_eq!(
        implementation::replace(-1, std::ptr::null(), std::ptr::null(), &fds),
        Err(EBADF)
    );
    assert_eq!(
        implementation::replace(0, 1usize as *const _, std::ptr::null(), &fds),
        Err(EFAULT)
    );
    STATE.with_borrow(|s| {
        assert_eq!(s.checked, 0);
        assert_eq!(s.entered, 0);
        assert_eq!(s.reads, 0);
    });
    let mut text = b"original\xff\0".to_vec();
    let argv = [text.as_ptr().cast(), std::ptr::null()];
    STATE.with_borrow_mut(|s| s.mutate = Some((text.as_mut_ptr() as usize, text.len() - 1)));
    assert_eq!(
        implementation::replace(0, argv.as_ptr(), std::ptr::null(), &fds),
        Err(ENOEXEC)
    );
    assert!(text[..text.len() - 1].iter().all(|b| *b == b'X'));
}

#[test]
fn nonfile_writeonly_and_attenuated_sources_do_not_reach_io() {
    for (kind, flags, rights, expected) in [
        (
            FdKind::ObjectDirectory,
            0,
            posix_protocol::CHECK_EXECUTABLE_RIGHTS,
            EACCES,
        ),
        (
            FdKind::ObjectFile,
            1,
            posix_protocol::CHECK_EXECUTABLE_RIGHTS,
            EBADF,
        ),
        (
            FdKind::ObjectFile,
            0,
            mnu_abi::HANDLE_RIGHT_TRANSFER,
            EACCES,
        ),
    ] {
        reset(0);
        let mut fds = FdTable::new();
        fds.install(Entry {
            handle: FdObject {
                lower_handle: 19,
                kind,
                open_flags: flags,
            },
            rights,
            descriptor_flags: 1,
        })
        .unwrap();
        assert_eq!(
            implementation::replace(0, std::ptr::null(), std::ptr::null(), &fds),
            Err(expected)
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.checked, 0);
            assert_eq!(s.reads, 0);
            assert_eq!(s.entered, 0);
        });
    }
}
