#![allow(dead_code)]
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
unsafe extern "C" {
    fn malloc(length: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
}
use mochios_posix_client::newlib_errno::*;
use mochios_posix_client::{
    ObjectHandleAttachment, OpenAtBase,
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
    opened: usize,
    path: Vec<u8>,
    open_rights: Option<u64>,
    checked: usize,
    drops: usize,
    closed: Vec<u32>,
    entered: usize,
    bytes: Vec<u8>,
    prepared: Vec<u8>,
    mutate: Option<(usize, usize)>,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());static DEFER:Cell<u32>=const{Cell::new(0)};}
#[path = "../../../user/crates/newlib-runtime/src/exec_image.rs"]
mod exec_image;
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
    fn open_at(
        &self,
        base: OpenAtBase<u32>,
        options: u32,
        mode: u32,
        path: impl AsRef<[u8]>,
    ) -> Result<ObjectHandleAttachment<u32>, i32> {
        assert_eq!(
            options,
            posix_protocol::OPEN_READ | posix_protocol::OPEN_EXECUTE
        );
        assert_eq!(mode, 0);
        STATE.with_borrow_mut(|s| {
            assert_eq!(path.as_ref(), s.path);
            assert_eq!(
                matches!(base, OpenAtBase::ProcessRoot),
                s.path.first() == Some(&b'/')
            );
            s.opened += 1;
            if s.failure == 1 {
                return Err(EACCES);
            }
            Ok(ObjectHandleAttachment {
                handle: 19,
                rights: s
                    .open_rights
                    .unwrap_or(posix_protocol::CHECK_EXECUTABLE_RIGHTS),
            })
        })
    }

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
            SyscallNumber::MemoryObjectCreate => {
                assert!(super::DEFER.get() > 0);
                assert_eq!(len, mnu_abi::MEMORY_OBJECT_RESIZABLE);
                super::STATE.with_borrow_mut(|s| {
                    if s.failure == 9 {
                        return Err(super::ENOMEM);
                    }
                    s.prepared = vec![0; p as usize];
                    Ok(28)
                })
            }
            SyscallNumber::HandleDuplicate => {
                assert!(super::DEFER.get() > 0);
                assert_eq!(
                    (p, len),
                    (28, super::posix_protocol::CHECK_EXECUTABLE_RIGHTS)
                );
                super::STATE.with_borrow(|s| {
                    if s.failure == 11 {
                        Err(super::EACCES)
                    } else {
                        Ok(29)
                    }
                })
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
        if n == SyscallNumber::HandleWriteAt {
            assert_eq!(h, 28);
            assert_eq!(super::DEFER.get(), 0);
            return super::STATE.with_borrow_mut(|s| {
                if s.failure == 10 {
                    return Err(super::EIO);
                }
                let count = (len as usize).min(17);
                let start = offset as usize;
                assert!(start + count <= s.prepared.len());
                s.prepared[start..start + count]
                    .copy_from_slice(unsafe { std::slice::from_raw_parts(p as *const u8, count) });
                Ok(count as u64)
            });
        }
        assert_eq!(n, SyscallNumber::HandleReadAt);
        assert!(h == 19 || h == 29);
        assert_eq!(super::DEFER.get(), 0);
        super::STATE.with_borrow_mut(|s| {
            s.reads += 1;
            if s.failure == 2 {
                return Err(super::EIO);
            }
            if s.failure == 3 {
                return Ok(len + 1);
            }
            let bytes = if h == 19 { &s.bytes } else { &s.prepared };
            let start = (offset as usize).min(bytes.len());
            let count = (bytes.len() - start).min(len as usize).min(17);
            unsafe {
                std::ptr::copy_nonoverlapping(bytes[start..].as_ptr(), p as *mut u8, count);
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
        super::STATE.with_borrow(|s| {
            assert_eq!(
                key,
                if s.path.is_empty() {
                    "fexecve"
                } else {
                    "execve"
                }
            )
        });
        let objects = unsafe { &mut *(objects as *mut mnu_abi::IpcObjectHandles) };
        assert_eq!(objects.count, 1);
        super::STATE.with_borrow(|s| {
            assert_eq!(
                objects.handles[0].handle,
                if s.prepared.is_empty() { 19 } else { 29 }
            )
        });
        assert_eq!(objects.handles[0].rights, HANDLE_RIGHT_READ);
        super::STATE.with_borrow(|s| {
            use sha2::Digest;
            assert_eq!(
                digest,
                <[u8; 32]>::from(sha2::Sha256::digest(if s.prepared.is_empty() {
                    &s.bytes
                } else {
                    &s.prepared
                }))
            );
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
            assert_eq!(ceiling, 123456789);
            super::super::STATE
                .with_borrow(|s| assert_eq!(h, if s.prepared.is_empty() { 19 } else { 29 }));
            super::super::STATE.with_borrow(|s| {
                assert_eq!(
                    key,
                    if s.path.is_empty() {
                        "fexecve"
                    } else {
                        "execve"
                    }
                )
            });
            assert_eq!(super::super::DEFER.get(), 0);
            mnu_abi::process_image::decode(startup).unwrap();
            super::super::STATE.with_borrow(|state| {
                if state.mutate.is_some() {
                    assert!(startup.windows(9).any(|w| w == b"original\xff"));
                } else if !state.path.is_empty() {
                    assert!(startup.windows(state.path.len()).any(|w| w == state.path));
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
        (2, EIO, 0, 0),
        (3, EIO, 0, 0),
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

#[test]
fn pathname_execution_owns_one_open_image_through_every_failure() {
    for path in [&b"/tmp/unregistered\xff"[..], &b"relative-unregistered"[..]] {
        for failure in 0..=8 {
            reset(failure);
            STATE.with_borrow_mut(|s| s.path = path.to_vec());
            let mut cpath = path.to_vec();
            cpath.push(0);
            let mut inputs = exec_inputs::Inputs::new();
            inputs
                .capture(cpath.as_ptr().cast(), std::ptr::null(), std::ptr::null())
                .unwrap();
            let result = implementation::replace_path(&inputs, &FdTable::new());
            assert!(result.is_err());
            STATE.with_borrow(|s| {
                assert_eq!(s.opened, 1);
                assert_eq!(s.checked, 0);
                assert_eq!(
                    s.closed.iter().filter(|h| **h == 19).count(),
                    usize::from(failure != 1)
                );
                assert_eq!(s.entered, usize::from(failure == 0));
            });
        }
    }
}

#[test]
fn executable_open_needs_read_and_transfer_but_no_shared_cursor_authority() {
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_READ,
        mnu_abi::HANDLE_RIGHT_TRANSFER,
        posix_protocol::CHECK_EXECUTABLE_RIGHTS,
        posix_protocol::CHECK_EXECUTABLE_RIGHTS | mnu_abi::HANDLE_RIGHT_SEEK,
    ] {
        reset(0);
        STATE.with_borrow_mut(|s| {
            s.path = b"/tmp/program".to_vec();
            s.open_rights = Some(rights);
        });
        let mut inputs = exec_inputs::Inputs::new();
        inputs
            .capture(c"/tmp/program".as_ptr(), std::ptr::null(), std::ptr::null())
            .unwrap();
        let allowed = rights & posix_protocol::CHECK_EXECUTABLE_RIGHTS
            == posix_protocol::CHECK_EXECUTABLE_RIGHTS;
        assert_eq!(
            implementation::replace_path(&inputs, &FdTable::new()),
            Err(if allowed { ENOEXEC } else { EACCES })
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.entered, usize::from(allowed));
            assert_eq!(s.closed, [19]);
        });
    }
}

#[test]
fn real_compiler_pie_uses_a_readonly_prepared_image_and_closes_all_temporary_handles() {
    real_compiler_pie(false);
}

#[test]
fn real_compiler_relr_pie_uses_a_readonly_prepared_image_and_closes_all_temporary_handles() {
    real_compiler_pie(true);
}

fn real_compiler_pie(packed: bool) {
    struct Temporary(std::path::PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Temporary(std::env::temp_dir().join(format!(
            "mochios-pie-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    std::fs::create_dir(&directory.0).unwrap();
    let binary = directory.0.join("image");
    let compiled = std::process::Command::new("x86_64-elf-gcc")
        .args([
            "-fpie",
            "-ffreestanding",
            "-fno-stack-protector",
            "-nostdlib",
            "-Wl,-pie,--no-dynamic-linker,-e,_start,-z,noexecstack",
        ])
        .arg(if packed {
            "-Wl,-z,pack-relative-relocs"
        } else {
            "-Wl,-z,nopack-relative-relocs"
        })
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/native_static_pie.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let bytes = std::fs::read(&binary).unwrap();
    let pie = mochios_posix_client::pie::Pie::parse(&bytes).unwrap();
    let headers = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    let dynamic = bytes[headers..headers + count * 56]
        .chunks_exact(56)
        .find(|header| u32::from_le_bytes(header[..4].try_into().unwrap()) == 2)
        .unwrap();
    let offset = u64::from_le_bytes(dynamic[8..16].try_into().unwrap()) as usize;
    let length = u64::from_le_bytes(dynamic[32..40].try_into().unwrap()) as usize;
    let has_relr = bytes[offset..offset + length]
        .chunks_exact(16)
        .any(|entry| {
            u64::from_le_bytes(entry[..8].try_into().unwrap()) == 35
                && u64::from_le_bytes(entry[8..].try_into().unwrap()) != 0
        });
    assert_eq!(
        has_relr, packed,
        "linker must actually emit the requested relocation format"
    );
    let tls = bytes[headers..headers + count * 56]
        .chunks_exact(56)
        .find(|header| u32::from_le_bytes(header[..4].try_into().unwrap()) == 7)
        .expect("real compiler must retain the TLS template");
    let word = |offset| u64::from_le_bytes(tls[offset..offset + 8].try_into().unwrap());
    assert!(word(32) >= 4 && word(40) > word(32));
    assert_eq!(word(48), 8192);
    assert_eq!(pie.executable(0x20000000).unwrap().load_bias, 0x20000000);
    assert!(pie.output_length().unwrap() > 4096);
    // Use the compiler/linker's symbol addresses as an independent oracle for
    // data and function pointers, rather than decoding RELR a second time.
    let symbols = std::process::Command::new("x86_64-elf-nm")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8(symbols.stdout).unwrap();
    let address = |name: &str| -> u64 {
        symbols
            .lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.len() == 3 && fields[2] == name)
                    .then(|| u64::from_str_radix(fields[0], 16).unwrap())
            })
            .unwrap_or_else(|| panic!("missing symbol {name}"))
    };
    let bias = 0x20000000u64;
    let mut relocated = vec![0; pie.output_length().unwrap()];
    pie.write(bias, &mut relocated).unwrap();
    for (name, addend) in [
        (
            "modular_value",
            address("__ehdr_start").wrapping_sub(0x40000000),
        ),
        ("value_pointer", address("value")),
        ("function_pointer", address("addition")),
    ] {
        let phnum = u16::from_le_bytes(relocated[56..58].try_into().unwrap()) as usize;
        let target = bias + address(name);
        let actual = relocated[64..64 + phnum * 56]
            .chunks_exact(56)
            .find_map(|header| {
                let word =
                    |offset| u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap());
                let base = word(16);
                if header[0] != 1 || target < base || target + 8 > base + word(32) {
                    return None;
                }
                let offset = (word(8) + target - base) as usize;
                Some(u64::from_le_bytes(
                    relocated[offset..offset + 8].try_into().unwrap(),
                ))
            })
            .expect("relocation target must be loaded");
        assert_eq!(
            actual,
            bias.wrapping_add(addend),
            "symbol={name} packed={packed}"
        );
    }
    for (failure, error) in [
        (0, ENOEXEC),
        (4, EAGAIN),
        (5, EACCES),
        (6, EIO),
        (7, EIO),
        (8, EIO),
        (9, ENOMEM),
        (10, EIO),
        (11, EACCES),
    ] {
        reset(failure);
        STATE.with_borrow_mut(|s| s.bytes = bytes.clone());
        assert_eq!(
            implementation::replace(0, ptr::null(), ptr::null(), &table()),
            Err(error),
            "failure={failure}"
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.bytes, bytes);
            assert!(!s.closed.contains(&19));
            assert_eq!(
                s.closed.iter().filter(|h| **h == 28).count(),
                usize::from(failure != 9)
            );
            assert_eq!(
                s.closed.iter().filter(|h| **h == 29).count(),
                usize::from(![9, 10, 11].contains(&failure))
            );
            assert_eq!(s.entered, usize::from(failure == 0));
            if ![9, 10].contains(&failure) {
                assert_eq!(&s.prepared[16..18], &2u16.to_le_bytes());
            }
        });
    }
}
