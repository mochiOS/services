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
    metadata: Vec<u8>,
    images_created: usize,
    startup: Vec<u8>,
    libraries: Vec<(Vec<u8>, Vec<u8>)>,
    library_paths: Vec<Vec<u8>>,
    secure_identity: u8,
    identity_queries: usize,
    mutate: Option<(usize, usize)>,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());static DEFER:Cell<u32>=const{Cell::new(0)};}
#[path = "../../../user/crates/newlib-runtime/src/exec_image.rs"]
mod exec_image;
#[path = "support/scoped_preparation.rs"]
mod scoped_preparation;
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
        if options == posix_protocol::OPEN_READ | posix_protocol::OPEN_NONBLOCK {
            assert_eq!(mode, 0);
            assert!(DEFER.get() > 0);
            return STATE.with_borrow_mut(|s| {
                let path = path.as_ref();
                s.library_paths.push(path.to_vec());
                if s.failure == 20 {
                    return Err(EACCES);
                }
                let index = s
                    .libraries
                    .iter()
                    .position(|(name, _)| name == path)
                    .ok_or(ENOENT)?;
                Ok(ObjectHandleAttachment {
                    handle: 200 + index as u32,
                    rights: if s.failure == 21 {
                        0
                    } else {
                        posix_protocol::CHECK_EXECUTABLE_RIGHTS
                    },
                })
            });
        }
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

    fn session_info(&self) -> Result<posix_protocol::SessionInfo, i32> {
        STATE.with_borrow_mut(|s| {
            s.identity_queries += 1;
            if s.failure == 28 {
                return Err(EIO);
            }
            Ok(posix_protocol::SessionInfo {
                effective_uid: if s.secure_identity == 1 { 501 } else { 0 },
                effective_gid: if s.secure_identity == 2 { 501 } else { 0 },
                ..Default::default()
            })
        })
    }

    fn fstat(&self, file: ObjectHandleAttachment<u32>) -> Result<posix_protocol::FileStatus, i32> {
        assert!(file.handle >= 200);
        STATE.with_borrow(|s| {
            if s.failure == 22 {
                return Err(EIO);
            }
            if s.failure == 26 {
                return Err(ENOENT);
            }
            if s.failure == 27 {
                return Err(ENOTDIR);
            }
            Ok(posix_protocol::FileStatus {
                mode: if s.failure == 23 { 0o040755 } else { 0o100644 },
                ..Default::default()
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
                    s.images_created += 1;
                    if s.images_created == 1 {
                        s.prepared = vec![0; p as usize];
                        Ok(28)
                    } else {
                        assert_eq!(s.images_created, 2);
                        s.metadata = vec![0; p as usize];
                        Ok(30)
                    }
                })
            }
            SyscallNumber::HandleDuplicate => {
                assert!(super::DEFER.get() > 0);
                if p == 30 {
                    assert_eq!(len, mochios_posix_client::startup_metadata::READER_RIGHTS);
                    return Ok(31);
                }
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
            assert!(h == 28 || h == 30);
            assert_eq!(super::DEFER.get(), 0);
            return super::STATE.with_borrow_mut(|s| {
                if s.failure == 10 {
                    return Err(super::EIO);
                }
                let count = (len as usize).min(17);
                let start = offset as usize;
                let output = if h == 28 {
                    &mut s.prepared
                } else {
                    &mut s.metadata
                };
                assert!(start + count <= output.len());
                output[start..start + count]
                    .copy_from_slice(unsafe { std::slice::from_raw_parts(p as *const u8, count) });
                Ok(count as u64)
            });
        }
        assert_eq!(n, SyscallNumber::HandleReadAt);
        assert!(h == 19 || h == 29 || h >= 200);
        assert_eq!(super::DEFER.get(), 0);
        super::STATE.with_borrow_mut(|s| {
            s.reads += 1;
            if s.failure == 2 {
                return Err(super::EIO);
            }
            if s.failure == 3 {
                return Ok(len + 1);
            }
            if h >= 200 && s.failure == 24 {
                return Err(super::EIO);
            }
            if h >= 200 && s.failure == 25 {
                return Ok(len + 1);
            }
            let bytes = if h == 19 {
                &s.bytes
            } else if h == 29 {
                &s.prepared
            } else {
                &s.libraries[(h - 200) as usize].1
            };
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
            super::super::STATE.with_borrow_mut(|s| {
                s.entered += 1;
                s.startup = startup.to_vec();
            });
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

fn dependency_fixture(root_flags: &[&str], library_flags: &[&str]) -> (Vec<u8>, Vec<u8>) {
    struct Temporary(std::path::PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let temporary = Temporary(std::env::temp_dir().join(
        format!("mochios-exec-deps-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()),
    ));
    std::fs::create_dir(&temporary.0).unwrap();
    let library = temporary.0.join("libscope.so");
    let root = temporary.0.join("root");
    for (source, output, extra) in [
        (
            "elf_scope_dependency.c",
            &library,
            vec!["-Wl,-soname,libscope.so".to_owned()],
        ),
        (
            "elf_scope_root.c",
            &root,
            vec![
                "-Wl,-e,_start".to_owned(),
                format!("-L{}", temporary.0.display()),
                "-l:libscope.so".to_owned(),
            ],
        ),
    ] {
        let result = std::process::Command::new("x86_64-elf-gcc")
            .args([
                "-fPIC",
                "-ffreestanding",
                "-fno-stack-protector",
                "-nostdlib",
                "-Wl,-shared,-z,noexecstack",
            ])
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(source),
            )
            .args(extra)
            .args(if source == "elf_scope_root.c" {
                root_flags
            } else {
                library_flags
            })
            .arg("-o")
            .arg(output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let bytes = std::fs::read(root).unwrap();
    let library = std::fs::read(library).unwrap();
    (bytes, library)
}

fn indirect_fixture(marked: bool, root_flags: &[&str], library_flags: &[&str]) -> [Vec<u8>; 3] {
    struct Temporary(std::path::PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Temporary(std::env::temp_dir().join(format!(
            "mochios-ifunc-exec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    std::fs::create_dir(&directory.0).unwrap();
    let support =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/elf_ifunc.S");
    for (name, define, deps) in [
        ("libprovider.so", "PROVIDER", &[][..]),
        ("libmiddle.so", "MIDDLE", &["libprovider.so"][..]),
        ("root.so", "ROOT", &["libmiddle.so", "libprovider.so"][..]),
    ] {
        let mut c = std::process::Command::new("x86_64-elf-gcc");
        c.args([
            "-fPIC",
            "-nostdlib",
            "-Wl,-z,noexecstack,--no-as-needed,--hash-style=both",
        ])
        .arg(format!("-D{define}"))
        .arg(
            if name == "root.so" && root_flags.contains(&"-DCOPY_ROOT") {
                support.with_file_name("elf_ifunc_copy.S")
            } else {
                support.clone()
            },
        )
        .arg(format!("-L{}", directory.0.display()));
        if name == "root.so" {
            if root_flags.contains(&"-DCOPY_ROOT") {
                c.args([
                    "-fno-pic",
                    "-no-pie",
                    "-Wl,--export-dynamic,--no-dynamic-linker",
                ]);
            } else {
                c.arg("-Wl,-shared");
            }
            c.arg("-Wl,-e,_start,--disable-new-dtags,-rpath,/libraries");
            if marked {
                c.arg("-DCRT_CONTRACT");
            }
            c.args(root_flags);
        } else {
            c.arg("-Wl,-shared");
            c.arg(format!("-Wl,-soname,{name}"));
            c.args(library_flags);
        }
        for name in deps {
            c.arg(format!("-l:{name}"));
        }
        let out = c.arg("-o").arg(directory.0.join(name)).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    ["root.so", "libmiddle.so", "libprovider.so"]
        .map(|name| std::fs::read(directory.0.join(name)).unwrap())
}

#[test]
fn exec_passes_the_child_resolver_plan_only_to_an_explicitly_supporting_runtime() {
    use mochios_posix_client::{
        indirect_image::{Captured, Fixup, Region},
        process_image::AT_INDIRECT_IMAGE,
    };
    for marked in [false, true] {
        let [root, middle, provider] = indirect_fixture(marked, &[], &[]);
        let parsed = mochios_posix_client::pie::Pie::parse_object(&root).unwrap();
        assert_eq!(parsed.has_indirect_runtime().unwrap(), marked);
        assert_eq!(
            search_exec(
                &root,
                &[
                    (b"/libraries/libmiddle.so", &middle),
                    (b"/libraries/libprovider.so", &provider)
                ],
                &[],
                0,
                0
            ),
            Err(ENOEXEC)
        );
        STATE.with_borrow(|state| {
            assert_eq!(state.entered, usize::from(marked));
            assert!(!state.closed.contains(&19));
            if !marked {
                assert!(state.prepared.is_empty());
                return;
            }
            let decoded = mnu_abi::process_image::decode(&state.startup).unwrap();
            let stack = decoded.stack();
            let word = |o| u64::from_le_bytes(stack[o..o + 8].try_into().unwrap()) as usize;
            let mut cursor = (word(0) + 2) * 8;
            while word(cursor) != 0 {
                cursor += 8;
            }
            cursor += 8;
            let mut offset = None;
            while word(cursor) != 0 {
                if word(cursor) == AT_INDIRECT_IMAGE as usize {
                    assert!(offset.replace(word(cursor + 8)).is_none());
                    assert!(
                        decoded
                            .relocations()
                            .any(|r| r.offset as usize == cursor + 8
                                && r.kind == mnu_abi::process_image::RelocationKind::StackAddress)
                    );
                }
                cursor += 16;
            }
            let offset = offset.expect("pending resolver image must reach the new CRT");
            assert_eq!(offset % 8, 0);
            let image = Captured::capture(
                0x7000_0000 + offset as u64,
                stack.len() - offset,
                &mut [Region::EMPTY; 32],
                &mut [Fixup::EMPTY; 32],
                |address, out| -> Result<(), i32> {
                    let o = (address - 0x7000_0000) as usize;
                    out.copy_from_slice(&stack[o..o + out.len()]);
                    Ok(())
                },
            )
            .unwrap()
            .len();
            assert!(image >= 6);
        });
    }
}

#[test]
fn deferred_array_elements_are_rejected_even_with_a_valid_stale_function_address() {
    let [root, middle, provider] = indirect_fixture(true, &["-DLATE_CALLBACKS"], &[]);
    let word = |b: &[u8], o| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let headers = word(&root, 32) as usize;
    let count = u16::from_le_bytes(root[56..58].try_into().unwrap()) as usize;
    let file_offset = |address: u64, length: u64| {
        (headers..headers + count * 56)
            .step_by(56)
            .find_map(|h| {
                let base = word(&root, h + 16);
                (root[h] == 1 && address >= base && address + length <= base + word(&root, h + 32))
                    .then(|| (word(&root, h + 8) + address - base) as usize)
            })
            .unwrap()
    };
    let dynamic = (headers..headers + count * 56)
        .step_by(56)
        .find(|h| root[*h] == 2)
        .unwrap();
    let at = word(&root, dynamic + 8) as usize;
    let len = word(&root, dynamic + 32) as usize;
    let tags: std::collections::BTreeMap<_, _> = root[at..at + len]
        .chunks_exact(16)
        .take_while(|p| word(p, 0) != 0)
        .map(|p| (word(p, 0), word(p, 8)))
        .collect();
    assert_eq!(tags[&27], 8);
    let array = tags[&25];
    let array_offset = file_offset(array, 8);
    let rela = file_offset(tags[&7], tags[&8]);
    let record = (rela..rela + tags[&8] as usize)
        .step_by(24)
        .find(|r| word(&root, *r) == array)
        .unwrap();
    assert_eq!(word(&root, record + 8) as u32, 1);
    let libraries = [
        (b"/libraries/libmiddle.so".as_slice(), middle.as_slice()),
        (b"/libraries/libprovider.so".as_slice(), provider.as_slice()),
    ];
    // A normal RELATIVE array is valid: ordinary relocation produces its final
    // function before the lifecycle snapshot is flattened.
    let mut ordinary = root.clone();
    ordinary[record + 8..record + 16].copy_from_slice(&8u64.to_le_bytes());
    ordinary[record + 16..record + 24].copy_from_slice(&word(&root, 24).to_le_bytes());
    assert_eq!(search_exec(&ordinary, &libraries, &[], 0, 0), Err(ENOEXEC));
    let entry = STATE.with_borrow(|s| {
        assert_eq!(s.entered, 1);
        word(&s.prepared, 24)
    });
    for stale in [0, entry, entry + 1] {
        let mut pending = root.clone();
        pending[array_offset..array_offset + 8].copy_from_slice(&stale.to_le_bytes());
        assert_eq!(search_exec(&pending, &libraries, &[], 0, 0), Err(ENOEXEC));
        STATE.with_borrow(|s| {
            assert_eq!(s.entered, 0, "stale={stale:x}");
            assert!(s.prepared.is_empty());
            assert!(!s.closed.contains(&19));
        });
    }
}

#[test]
fn exec_preserves_late_init_and_fini_recipes_for_a_v2_crt() {
    use mochios_posix_client::{lifecycle_image::deferred, process_image::AT_LIFECYCLE_IMAGE};
    let [root, middle, provider] =
        indirect_fixture(true, &["-DLATE_CALLBACKS", "-DDEFERRED_LIFECYCLE"], &[]);
    assert!(
        mochios_posix_client::pie::Pie::parse_object(&root)
            .unwrap()
            .has_deferred_lifecycle_runtime()
            .unwrap()
    );
    assert_eq!(
        search_exec(
            &root,
            &[
                (b"/libraries/libmiddle.so", &middle),
                (b"/libraries/libprovider.so", &provider),
            ],
            &[],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|s| {
        assert_eq!(s.entered, 1);
        let decoded = mnu_abi::process_image::decode(&s.startup).unwrap();
        let stack = decoded.stack();
        let word = |b: &[u8], o| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let mut cursor = (word(stack, 0) as usize + 2) * 8;
        while word(stack, cursor) != 0 {
            cursor += 8;
        }
        cursor += 8;
        let mut offset = None;
        while word(stack, cursor) != 0 {
            if word(stack, cursor) == AT_LIFECYCLE_IMAGE {
                assert!(offset.replace(word(stack, cursor + 8) as usize).is_none());
                assert!(
                    decoded
                        .relocations()
                        .any(|r| r.offset as usize == cursor + 8
                            && r.kind == mnu_abi::process_image::RelocationKind::StackAddress)
                );
            }
            cursor += 16;
        }
        let start = offset.expect("late lifecycle must be explicitly inherited");
        let length = word(stack, start + 16) as usize;
        let plan = deferred::Plan::parse::<i32>(&stack[start..start + length]).unwrap();
        let mut output = vec![0; plan.flat_length()];
        let mut reads = Vec::new();
        let entry = word(&s.prepared, 24);
        assert_eq!(
            plan.resolve::<i32>(&mut output, |address, b| {
                reads.push(address);
                assert_eq!(b.len(), 8);
                b.copy_from_slice(&entry.to_le_bytes());
                Ok(())
            }),
            Ok(output.len())
        );
        assert_eq!(reads.len(), 2);
        assert_ne!(reads[0], reads[1]);
        assert_eq!(word(&output, 8) as u32, 1);
        assert_eq!(word(&output, output.len() - 16), entry);
        assert_eq!(word(&output, output.len() - 8), entry);
    });
}

#[test]
fn exec_requires_copy_contract_and_inherits_the_complete_ordered_copy_plan() {
    use mochios_posix_client::{
        indirect_image::{Captured, Fixup, Region},
        process_image::AT_INDIRECT_IMAGE,
    };
    for supported in [false, true] {
        let flags = if supported {
            vec!["-DCOPY_ROOT", "-DCOPY_CONTRACT"]
        } else {
            vec!["-DCOPY_ROOT"]
        };
        let [root, middle, provider] = indirect_fixture(true, &flags, &[]);
        assert_eq!(
            search_exec(
                &root,
                &[
                    (b"/libraries/libmiddle.so", &middle),
                    (b"/libraries/libprovider.so", &provider)
                ],
                &[],
                0,
                0
            ),
            Err(ENOEXEC)
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.entered, usize::from(supported));
            if !supported {
                assert!(s.prepared.is_empty());
                return;
            }
            let decoded = mnu_abi::process_image::decode(&s.startup).unwrap();
            let stack = decoded.stack();
            let word = |o| u64::from_le_bytes(stack[o..o + 8].try_into().unwrap());
            let mut cursor = (word(0) as usize + 2) * 8;
            while word(cursor) != 0 {
                cursor += 8;
            }
            cursor += 8;
            let mut start = None;
            while word(cursor) != 0 {
                if word(cursor) == AT_INDIRECT_IMAGE {
                    assert!(start.replace(word(cursor + 8) as usize).is_none());
                }
                cursor += 16;
            }
            let start = start.unwrap();
            assert_eq!(word(start + 8) as u32, 2);
            let mut fixups = [Fixup::EMPTY; 32];
            let count = Captured::capture(
                0x7000_0000 + start as u64,
                stack.len() - start,
                &mut [Region::EMPTY; 32],
                &mut fixups,
                |a, out| {
                    let at = (a - 0x7000_0000) as usize;
                    out.copy_from_slice(&stack[at..at + out.len()]);
                    Ok::<(), i32>(())
                },
            )
            .unwrap()
            .len();
            let copy = fixups[..count]
                .iter()
                .position(|f| f.copy_source().is_some())
                .unwrap();
            assert!(
                copy > 0 && copy + 1 < count,
                "COPY must follow provider resolvers and precede root resolver"
            );
            assert_eq!(fixups[copy].width(), 8);
        });
    }
}

#[test]
fn oversized_resolver_plans_fail_without_materializing_an_executable_object() {
    let [root, middle, provider] = indirect_fixture(true, &[], &["-DMANY_FIXUPS"]);
    assert_eq!(
        search_exec(
            &root,
            &[
                (b"/libraries/libmiddle.so", &middle),
                (b"/libraries/libprovider.so", &provider)
            ],
            &[],
            0,
            0
        ),
        Err(E2BIG)
    );
    STATE.with_borrow(|s| {
        assert_eq!(s.entered, 0);
        assert!(s.prepared.is_empty());
        assert!(!s.closed.contains(&19));
    });
}

#[test]
fn large_resolver_plans_are_mapped_readonly_after_explicit_runtime_support() {
    let [root, middle, provider] =
        indirect_fixture(true, &["-DLARGE_METADATA"], &["-DMANY_FIXUPS"]);
    assert_eq!(
        search_exec(
            &root,
            &[
                (b"/libraries/libmiddle.so", &middle),
                (b"/libraries/libprovider.so", &provider)
            ],
            &[],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|s| {
        assert_eq!(s.entered, 1);
        assert_eq!(s.images_created, 2);
        assert!(s.metadata.len() > 4096);
        let image = mnu_abi::process_image::decode(&s.startup).unwrap();
        let mapping = image.mappings().next().unwrap();
        assert_eq!(mapping.backing_handle, 31);
        assert_eq!(mapping.access, mnu_abi::MEMORY_ACCESS_READ);
        assert_eq!(mapping.options, mnu_abi::MEMORY_MAP_SHARED);
        assert!(image.stack().len() < 4096);
        assert!(s.closed.contains(&30) && s.closed.contains(&31));
        assert!(!s.closed.contains(&19));
        assert_eq!(&s.metadata[..8], b"MIREL001");
    });
}

#[test]
fn dependency_capture_uses_readable_regular_handles_and_preserves_all_failure_ownership() {
    let (bytes, library) = dependency_fixture(&[], &[]);
    for (failure, expected) in [
        (0, ENOEXEC),
        (4, EAGAIN),
        (5, EACCES),
        (9, ENOMEM),
        (10, EIO),
        (11, EACCES),
        (20, EACCES),
        (21, EACCES),
        (22, EIO),
        (23, ENOEXEC),
        (24, EIO),
        (25, EIO),
    ] {
        reset(failure);
        STATE.with_borrow_mut(|s| {
            s.bytes = bytes.clone();
            s.libraries = vec![(b"/usr/lib/libscope.so".to_vec(), library.clone())];
        });
        assert_eq!(
            implementation::replace(0, ptr::null(), ptr::null(), &table()),
            Err(expected),
            "failure={failure}"
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.bytes, bytes);
            assert_eq!(s.libraries[0].1, library);
            assert!(!s.closed.contains(&19));
            assert_eq!(s.entered, usize::from(failure == 0));
            if failure == 20 {
                assert!(!s.closed.contains(&200));
            } else {
                assert_eq!(
                    s.closed.iter().filter(|handle| **handle == 200).count(),
                    1,
                    "failure={failure}"
                );
            }
            assert_eq!(
                s.library_paths,
                vec![
                    b"/lib/libscope.so".to_vec(),
                    b"/usr/lib/libscope.so".to_vec()
                ]
            );
            if failure == 0 {
                let count = u16::from_le_bytes(s.prepared[56..58].try_into().unwrap()) as usize;
                assert!(count > 6, "authorizer must receive the whole linked image");
                assert!(s.closed.contains(&28) && s.closed.contains(&29));
            }
        });
    }
    // Only an open failure may try another search directory. An fstat failure
    // after acquiring a Handle must propagate and close that exact reference.
    for (failure, error) in [(26, ENOENT), (27, ENOTDIR)] {
        reset(failure);
        STATE.with_borrow_mut(|s| {
            s.bytes = bytes.clone();
            s.libraries = vec![
                (b"/lib/libscope.so".to_vec(), library.clone()),
                (b"/usr/lib/libscope.so".to_vec(), library.clone()),
            ];
        });
        assert_eq!(
            implementation::replace(0, ptr::null(), ptr::null(), &table()),
            Err(error)
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.library_paths, vec![b"/lib/libscope.so".to_vec()]);
            assert_eq!(s.closed.iter().filter(|h| **h == 200).count(), 1);
            assert!(!s.closed.contains(&201));
        });
    }

    // Force Node storage to grow while parsing the first captured library.
    // Its bytes stay in a separate owned allocation across that move.
    let mut nested = library.clone();
    let headers = u64::from_le_bytes(nested[32..40].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(nested[56..58].try_into().unwrap()) as usize;
    let dynamic = nested[headers..headers + count * 56]
        .chunks_exact(56)
        .find(|header| u32::from_le_bytes(header[..4].try_into().unwrap()) == 2)
        .unwrap();
    let offset = u64::from_le_bytes(dynamic[8..16].try_into().unwrap()) as usize;
    let length = u64::from_le_bytes(dynamic[32..40].try_into().unwrap()) as usize;
    let soname = (offset..offset + length)
        .step_by(16)
        .find(|&offset| u64::from_le_bytes(nested[offset..offset + 8].try_into().unwrap()) == 14)
        .unwrap();
    nested[soname..soname + 8].copy_from_slice(&1u64.to_le_bytes());
    let name = nested
        .windows(12)
        .position(|bytes| bytes == b"libscope.so\0")
        .unwrap();
    nested[name..name + 12].copy_from_slice(b"libinner.so\0");
    reset(0);
    STATE.with_borrow_mut(|s| {
        s.bytes = bytes.clone();
        s.libraries = vec![
            (b"/usr/lib/libscope.so".to_vec(), nested),
            (b"/usr/lib/libinner.so".to_vec(), library.clone()),
        ];
    });
    assert_eq!(
        implementation::replace(0, ptr::null(), ptr::null(), &table()),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|s| {
        assert_eq!(s.entered, 1);
        for handle in [200, 201, 28, 29] {
            assert_eq!(s.closed.iter().filter(|h| **h == handle).count(), 1);
        }
        assert_eq!(s.library_paths.len(), 4);
    });

    let mut initialized = bytes.clone();
    let headers = u64::from_le_bytes(initialized[32..40].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(initialized[56..58].try_into().unwrap()) as usize;
    let dynamic = initialized[headers..headers + count * 56]
        .chunks_exact(56)
        .find(|header| u32::from_le_bytes(header[..4].try_into().unwrap()) == 2)
        .unwrap();
    let offset = u64::from_le_bytes(dynamic[8..16].try_into().unwrap()) as usize;
    let length = u64::from_le_bytes(dynamic[32..40].try_into().unwrap()) as usize;
    let got = (offset..offset + length)
        .step_by(16)
        .find(|&offset| {
            u64::from_le_bytes(initialized[offset..offset + 8].try_into().unwrap()) == 3
        })
        .unwrap();
    initialized[got..got + 8].copy_from_slice(&12u64.to_le_bytes()); // DT_INIT is unsupported, never ignored.
    reset(0);
    STATE.with_borrow_mut(|s| {
        s.bytes = initialized;
        s.libraries = vec![(b"/usr/lib/libscope.so".to_vec(), library)];
    });
    assert_eq!(
        implementation::replace(0, ptr::null(), ptr::null(), &table()),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|s| {
        assert!(s.library_paths.is_empty() && s.prepared.is_empty());
    });

    reset(0);
    STATE.with_borrow_mut(|s| s.bytes = bytes);
    assert_eq!(
        implementation::replace(0, ptr::null(), ptr::null(), &table()),
        Err(ENOENT)
    );
    STATE.with_borrow(|s| {
        assert!(s.prepared.is_empty());
        assert_eq!(s.entered, 0);
    });
}

fn search_exec(
    root: &[u8],
    available: &[(&[u8], &[u8])],
    environment: &[&std::ffi::CStr],
    secure: u8,
    failure: u8,
) -> Result<(), i32> {
    reset(failure);
    STATE.with_borrow_mut(|s| {
        s.bytes = root.to_vec();
        s.secure_identity = secure;
        s.libraries = available
            .iter()
            .map(|(path, bytes)| (path.to_vec(), bytes.to_vec()))
            .collect();
    });
    let environment: Vec<_> = environment
        .iter()
        .map(|text| text.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect();
    implementation::replace(0, ptr::null(), environment.as_ptr(), &table())
}
fn search_paths(expected: &[&[u8]], entered: usize) {
    STATE.with_borrow(|s| {
        assert_eq!(
            s.library_paths
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(s.entered, entered);
    });
}

#[test]
fn copied_environment_search_handles_secure_identity_empty_entries_and_unsupported_tokens() {
    let (root, library) = dependency_fixture(&[], &[]);
    assert_eq!(
        search_exec(
            &root,
            &[(b"/second/libscope.so", &library)],
            &[c"LD_LIBRARY_PATH=/first;/second"],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    search_paths(&[b"/first/libscope.so", b"/second/libscope.so"], 1);
    STATE.with_borrow(|s| assert_eq!(s.identity_queries, 1));
    assert_eq!(
        search_exec(
            &root,
            &[(b"libscope.so", &library)],
            &[c"LD_LIBRARY_PATH=:/second"],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    search_paths(&[b"libscope.so"], 1);
    assert_eq!(
        search_exec(
            &root,
            &[(b"/usr/lib/libscope.so", &library)],
            &[c"LD_LIBRARY_PATH="],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    search_paths(&[b"/lib/libscope.so", b"/usr/lib/libscope.so"], 1);
    STATE.with_borrow(|s| assert_eq!(s.identity_queries, 1));
    for secure in [1, 2] {
        assert_eq!(
            search_exec(
                &root,
                &[(b"/usr/lib/libscope.so", &library)],
                &[
                    c"LD_LIBRARY_PATH=/untrusted",
                    c"LD_PRELOAD=inject.so",
                    c"LD_AUDIT=audit.so"
                ],
                secure,
                0
            ),
            Err(ENOEXEC)
        );
        search_paths(&[b"/lib/libscope.so", b"/usr/lib/libscope.so"], 1);
        STATE.with_borrow(|s| assert_eq!(s.identity_queries, 1));
    }
    for variable in [
        c"LD_LIBRARY_PATH=$ORIGIN",
        c"LD_PRELOAD=inject.so",
        c"LD_AUDIT=audit.so",
    ] {
        assert_eq!(search_exec(&root, &[], &[variable], 0, 0), Err(ENOEXEC));
        search_paths(&[], 0);
    }
    assert_eq!(
        search_exec(
            &root,
            &[(b"/lib/libscope.so", &library)],
            &[c"LD_LIBRARY_PATH=/override"],
            0,
            28
        ),
        Err(EIO)
    );
    search_paths(&[], 0);
    let mut original = b"LD_LIBRARY_PATH=/captured\0".to_vec();
    let vector = [original.as_ptr().cast(), ptr::null()];
    let mut inputs = exec_inputs::Inputs::new();
    inputs.capture_fd(ptr::null(), vector.as_ptr()).unwrap();
    original.fill(b'X');
    assert_eq!(
        inputs.environment(b"LD_LIBRARY_PATH"),
        Some(b"/captured".as_slice())
    );
    assert_eq!(inputs.environment(b"LD_LIBRARY"), None);
}

#[test]
fn rpath_precedes_environment_runpath_follows_it_and_nodefaultlib_is_honored() {
    let (root, library) = dependency_fixture(&["-Wl,--disable-new-dtags,-rpath,/legacy"], &[]);
    assert_eq!(
        search_exec(
            &root,
            &[
                (b"/legacy/libscope.so", &library),
                (b"/environment/libscope.so", &library)
            ],
            &[c"LD_LIBRARY_PATH=/environment"],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    search_paths(&[b"/legacy/libscope.so"], 1);
    let (root, library) = dependency_fixture(&["-Wl,--enable-new-dtags,-rpath,/modern"], &[]);
    assert_eq!(
        search_exec(
            &root,
            &[
                (b"/modern/libscope.so", &library),
                (b"/environment/libscope.so", &library)
            ],
            &[c"LD_LIBRARY_PATH=/environment"],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    search_paths(&[b"/environment/libscope.so"], 1);
    assert_eq!(
        search_exec(&root, &[(b"/modern/libscope.so", &library)], &[], 0, 0),
        Err(ENOEXEC)
    );
    search_paths(&[b"/modern/libscope.so"], 1);
    let (root, library) = dependency_fixture(&["-Wl,-z,nodefaultlib"], &[]);
    assert_eq!(
        search_exec(&root, &[(b"/lib/libscope.so", &library)], &[], 0, 0),
        Err(ENOENT)
    );
    search_paths(&[], 0);
}

#[test]
fn rpath_is_inherited_by_transitive_dependencies_while_runpath_is_not() {
    for modern in [false, true] {
        let flags = if modern {
            "-Wl,--enable-new-dtags,-rpath,/embedded"
        } else {
            "-Wl,--disable-new-dtags,-rpath,/embedded"
        };
        let (root, library) = dependency_fixture(&[flags], &[]);
        let mut nested = library.clone();
        let headers = u64::from_le_bytes(nested[32..40].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(nested[56..58].try_into().unwrap()) as usize;
        let dynamic = nested[headers..headers + count * 56]
            .chunks_exact(56)
            .find(|header| u32::from_le_bytes(header[..4].try_into().unwrap()) == 2)
            .unwrap();
        let offset = u64::from_le_bytes(dynamic[8..16].try_into().unwrap()) as usize;
        let length = u64::from_le_bytes(dynamic[32..40].try_into().unwrap()) as usize;
        let soname = (offset..offset + length)
            .step_by(16)
            .find(|&offset| {
                u64::from_le_bytes(nested[offset..offset + 8].try_into().unwrap()) == 14
            })
            .unwrap();
        nested[soname..soname + 8].copy_from_slice(&1u64.to_le_bytes());
        let name = nested
            .windows(12)
            .position(|bytes| bytes == b"libscope.so\0")
            .unwrap();
        nested[name..name + 12].copy_from_slice(b"libinner.so\0");
        assert_eq!(
            search_exec(
                &root,
                &[
                    (b"/embedded/libscope.so", &nested),
                    (b"/embedded/libinner.so", &library)
                ],
                &[],
                0,
                0
            ),
            Err(if modern { ENOENT } else { ENOEXEC })
        );
        if modern {
            search_paths(
                &[
                    b"/embedded/libscope.so",
                    b"/lib/libinner.so",
                    b"/usr/lib/libinner.so",
                ],
                0,
            );
        } else {
            search_paths(&[b"/embedded/libscope.so", b"/embedded/libinner.so"], 1);
        }
    }
}

#[test]
fn exec_publishes_authenticated_auxiliary_identity_and_removes_secure_loader_environment() {
    for (secure, expected) in [
        (0, [0, 0, 0, 0, 0]),
        (1, [0, 501, 0, 0, 1]),
        (2, [0, 0, 0, 501, 1]),
    ] {
        assert_eq!(
            search_exec(
                &[],
                &[],
                &[
                    c"KEEP=original",
                    c"LD_LIBRARY_PATH=/untrusted",
                    c"LD_PRELOAD=inject.so",
                    c"LD_AUDIT=audit.so",
                    c"LD_LIBRARY_PATH_SUFFIX=retained"
                ],
                secure,
                0
            ),
            Err(ENOEXEC)
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.identity_queries, 1);
            assert_eq!(s.entered, 1);
            let image = mnu_abi::process_image::decode(&s.startup).unwrap();
            let stack = image.stack();
            let word =
                |offset| u64::from_le_bytes(stack[offset..offset + 8].try_into().unwrap()) as usize;
            let mut cursor = (word(0) + 2) * 8;
            let mut environment = Vec::new();
            while word(cursor) != 0 {
                let text = &stack[word(cursor)..];
                environment.push(&text[..text.iter().position(|byte| *byte == 0).unwrap()]);
                cursor += 8;
            }
            cursor += 8;
            if secure == 0 {
                assert_eq!(environment.len(), 5);
            } else {
                assert_eq!(
                    environment,
                    [
                        b"KEEP=original".as_slice(),
                        b"LD_LIBRARY_PATH_SUFFIX=retained"
                    ]
                );
            }
            for (key, value) in [11, 12, 13, 14, 23].into_iter().zip(expected) {
                let mut matches = 0;
                let mut entry = cursor;
                while word(entry) != 0 {
                    if word(entry) == key {
                        assert_eq!(word(entry + 8), value);
                        matches += 1;
                    }
                    entry += 16;
                }
                assert_eq!(matches, 1, "key={key}");
            }
        });
    }
    assert_eq!(search_exec(&[], &[], &[], 0, 28), Err(EIO));
    STATE.with_borrow(|s| {
        assert!(s.startup.is_empty());
        assert_eq!(s.entered, 0);
    });
}

#[test]
fn exec_embeds_resolved_lifecycle_plan_only_for_a_declared_runtime() {
    use mochios_posix_client::lifecycle_image::{Image, State};
    let (root, library) = dependency_fixture(
        &["-DMOCHIOS_LIFECYCLE_RUNTIME", "-Wl,-rpath,/libraries"],
        &["-DMOCHIOS_LIFECYCLE_CALLBACKS"],
    );
    assert!(
        mochios_posix_client::pie::Pie::parse_object(&root)
            .unwrap()
            .has_lifecycle_runtime()
            .unwrap()
    );
    assert_eq!(
        search_exec(&root, &[(b"/libraries/libscope.so", &library)], &[], 0, 0),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|state| {
        assert_eq!(state.entered, 1);
        assert!(!state.closed.contains(&19));
        let decoded = mnu_abi::process_image::decode(&state.startup).unwrap();
        let stack = decoded.stack();
        let word =
            |offset| u64::from_le_bytes(stack[offset..offset + 8].try_into().unwrap()) as usize;
        let mut cursor = (word(0) + 2) * 8;
        while word(cursor) != 0 {
            cursor += 8;
        }
        cursor += 8;
        let mut payload = None;
        while word(cursor) != 0 {
            if word(cursor) == mochios_posix_client::process_image::AT_LIFECYCLE_IMAGE as usize {
                assert!(payload.replace(word(cursor + 8)).is_none());
                assert!(
                    decoded
                        .relocations()
                        .any(|relocation| relocation.offset as usize == cursor + 8
                            && relocation.kind
                                == mnu_abi::process_image::RelocationKind::StackAddress)
                );
            }
            cursor += 16;
        }
        let offset = payload.expect("lifecycle image must survive native startup encoding");
        assert_eq!(offset % 8, 0);
        let reader = |address: u64, output: &mut [u8]| -> Result<(), i32> {
            let offset = (address - 0x10000) as usize;
            output.copy_from_slice(&stack[offset..offset + output.len()]);
            Ok(())
        };
        let image = Image::read(0x10000 + offset as u64, stack.len() - offset, reader).unwrap();
        let lifecycle = State::new();
        let mut events = Vec::new();
        lifecycle
            .initialize(&image, reader, |address| {
                events.push(address);
                Ok(())
            })
            .unwrap();
        assert_eq!(events.len(), 2);
        lifecycle
            .finalize(&image, reader, |address| {
                events.push(address);
                Ok(())
            })
            .unwrap();
        assert_eq!(events.len(), 4);
        for address in events {
            let count = u16::from_le_bytes(state.prepared[56..58].try_into().unwrap()) as usize;
            assert!(
                state.prepared[64..64 + count * 56]
                    .chunks_exact(56)
                    .any(|header| {
                        let kind = u32::from_le_bytes(header[..4].try_into().unwrap());
                        let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
                        let base = u64::from_le_bytes(header[16..24].try_into().unwrap());
                        let memory = u64::from_le_bytes(header[40..48].try_into().unwrap());
                        kind == 1 && flags & 1 != 0 && address >= base && address < base + memory
                    })
            );
        }
    });
    let (unmarked, library) = dependency_fixture(
        &["-Wl,-rpath,/libraries"],
        &["-DMOCHIOS_LIFECYCLE_CALLBACKS"],
    );
    assert_eq!(
        search_exec(
            &unmarked,
            &[(b"/libraries/libscope.so", &library)],
            &[],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|state| assert_eq!(state.entered, 0));
    let (bad, library) = dependency_fixture(
        &[
            "-DMOCHIOS_LIFECYCLE_RUNTIME",
            "-DMOCHIOS_LIFECYCLE_BAD_CALLBACK",
            "-Wl,-rpath,/libraries",
        ],
        &["-DMOCHIOS_LIFECYCLE_CALLBACKS"],
    );
    assert_eq!(
        search_exec(&bad, &[(b"/libraries/libscope.so", &library)], &[], 0, 0),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|state| {
        assert_eq!(state.entered, 0);
        assert!(state.prepared.is_empty());
        assert!(!state.closed.contains(&19));
        assert_eq!(
            state.closed.iter().filter(|&&handle| handle == 200).count(),
            1
        );
    });
}

#[test]
fn exec_serializes_tls_templates_with_child_addresses_and_the_original_object_indexes() {
    use mochios_posix_client::{
        process_image::{AT_IMAGE_LOAD_BIAS, AT_TLS_IMAGE},
        static_tls::image,
    };
    let (root, library) =
        dependency_fixture(&["-DMOCHIOS_TLS_RUNTIME", "-Wl,-rpath,/libraries"], &[]);
    let parsed = mochios_posix_client::pie::Pie::parse_object(&root).unwrap();
    assert!(parsed.has_static_tls_runtime().unwrap());
    assert_eq!(
        search_exec(&root, &[(b"/libraries/libscope.so", &library)], &[], 0, 0),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|state| {
        assert_eq!(state.entered, 1);
        let decoded = mnu_abi::process_image::decode(&state.startup).unwrap();
        let stack = decoded.stack();
        let word =
            |offset| u64::from_le_bytes(stack[offset..offset + 8].try_into().unwrap()) as usize;
        let mut cursor = (word(0) + 2) * 8;
        while word(cursor) != 0 {
            cursor += 8;
        }
        cursor += 8;
        let mut payload = None;
        let mut bias = None;
        while word(cursor) != 0 {
            match word(cursor) as u64 {
                AT_TLS_IMAGE => {
                    assert!(payload.replace(word(cursor + 8)).is_none());
                    assert!(
                        decoded
                            .relocations()
                            .any(|relocation| relocation.offset as usize == cursor + 8
                                && relocation.kind
                                    == mnu_abi::process_image::RelocationKind::StackAddress)
                    );
                }
                AT_IMAGE_LOAD_BIAS => {
                    bias = Some(word(cursor + 8));
                }
                _ => {}
            }
            cursor += 16;
        }
        let offset = payload.expect("TLS metadata must reach the startup stack");
        let mut templates = [None; 2];
        let count = image::decode(
            0x10000 + offset,
            stack.len() - offset,
            &mut templates,
            |address, output| -> Result<(), i32> {
                let offset = address - 0x10000;
                output.copy_from_slice(&stack[offset..offset + output.len()]);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            templates[0],
            parsed.tls_template(bias.unwrap() as u64).unwrap()
        );
        assert_eq!(templates[1], None);
        let template = templates[0].unwrap();
        let count = u16::from_le_bytes(state.prepared[56..58].try_into().unwrap()) as usize;
        let source = state.prepared[64..64 + count * 56]
            .chunks_exact(56)
            .find_map(|header| {
                let word = |offset| {
                    u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap()) as usize
                };
                if header[0] != 1
                    || template.source < word(16)
                    || template.source + template.file_size > word(16) + word(32)
                {
                    return None;
                }
                Some(word(8) + template.source - word(16))
            })
            .expect("template bytes must name a child LOAD, never producer memory");
        assert_eq!(&state.prepared[source..source + 4], &17u32.to_le_bytes());
        assert!(!state.closed.contains(&19));
    });
}

#[test]
fn dependency_tls_requires_a_declared_module_runtime_before_image_replacement() {
    for marked in [false, true] {
        let root_flags = if marked {
            vec!["-DMOCHIOS_TLS_RUNTIME", "-Wl,-rpath,/libraries"]
        } else {
            vec!["-Wl,-rpath,/libraries"]
        };
        let (root, library) = dependency_fixture(&root_flags, &["-DMOCHIOS_TLS_TEMPLATE"]);
        assert!(
            mochios_posix_client::pie::Pie::parse_object(&library)
                .unwrap()
                .tls_template(0)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            search_exec(&root, &[(b"/libraries/libscope.so", &library)], &[], 0, 0),
            Err(ENOEXEC)
        );
        STATE.with_borrow(|state| {
            assert_eq!(state.entered, usize::from(marked));
            assert!(!state.closed.contains(&19));
        });
    }
}

#[test]
fn fixed_executable_preparation_preserves_entry_bias_and_private_source_headers() {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/native_dynamic.ld");
    let link = format!("-Wl,-T,{}", script.display());
    let (root, library) = dependency_fixture(
        &[
            "-DMOCHIOS_LIFECYCLE_RUNTIME",
            "-Wl,-no-pie,--no-dynamic-linker,--export-dynamic,-rpath,/libraries",
            &link,
        ],
        &["-DMOCHIOS_LIFECYCLE_CALLBACKS"],
    );
    assert_eq!(u16::from_le_bytes(root[16..18].try_into().unwrap()), 2);
    assert_eq!(
        search_exec(&root, &[(b"/libraries/libscope.so", &library)], &[], 0, 0),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|state| {
        assert_eq!(state.entered, 1);
        assert!(!state.prepared.is_empty());
        let image = mnu_abi::process_image::decode(&state.startup).unwrap();
        let words: Vec<_> = image
            .stack()
            .chunks_exact(8)
            .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
            .collect();
        let auxiliary = |key| {
            words[4..]
                .chunks_exact(2)
                .take_while(|pair| pair[0] != 0)
                .find(|pair| pair[0] == key)
                .unwrap()[1]
        };
        assert_eq!(
            auxiliary(9),
            u64::from_le_bytes(root[24..32].try_into().unwrap())
        );
        assert_eq!(
            auxiliary(mochios_posix_client::process_image::AT_IMAGE_LOAD_BIAS),
            0
        );
        let phdr = auxiliary(3);
        let count = u16::from_le_bytes(state.prepared[56..58].try_into().unwrap()) as usize;
        let source_offset = u64::from_le_bytes(root[32..40].try_into().unwrap()) as usize;
        let source_length = u16::from_le_bytes(root[56..58].try_into().unwrap()) as usize * 56;
        let header = state.prepared[64..64 + count * 56]
            .chunks_exact(56)
            .find(|header| {
                let base = u64::from_le_bytes(header[16..24].try_into().unwrap());
                let length = u64::from_le_bytes(header[32..40].try_into().unwrap());
                header[0] == 1 && phdr >= base && phdr + source_length as u64 <= base + length
            })
            .unwrap();
        assert_eq!(u32::from_le_bytes(header[4..8].try_into().unwrap()), 4);
        let base = u64::from_le_bytes(header[16..24].try_into().unwrap());
        let offset = (u64::from_le_bytes(header[8..16].try_into().unwrap()) + phdr - base) as usize;
        assert_eq!(
            &state.prepared[offset..offset + source_length],
            &root[source_offset..source_offset + source_length]
        );
    });
    for (offset, value) in [(32, u64::MAX), (48, 0), (48, 56u64 << 32)] {
        let mut bad = root.clone();
        bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(search_exec(&bad, &[], &[], 0, 0).is_err());
        STATE.with_borrow(|state| assert_eq!(state.entered, 0));
    }
}

#[test]
fn static_fixed_image_keeps_the_original_native_exec_path() {
    struct Temporary(std::path::PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let temporary = Temporary(std::env::temp_dir().join(format!(
            "mochios-static-exec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    std::fs::create_dir(&temporary.0).unwrap();
    let output = temporary.0.join("root");
    let result = std::process::Command::new("x86_64-elf-gcc")
        .args([
            "-O2",
            "-fno-pic",
            "-ffreestanding",
            "-fno-stack-protector",
            "-nostdlib",
            "-static",
            "-Wl,-no-pie,-e,_start,-z,noexecstack",
        ])
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/elf_symbol_fixture.c"))
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(output).unwrap();
    assert_eq!(u16::from_le_bytes(bytes[16..18].try_into().unwrap()), 2);
    for stride in [56usize, 64] {
        let mut source = bytes.clone();
        if stride != 56 {
            let offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
            let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
            let expanded = source.len();
            for entry in bytes[offset..offset + count * 56].chunks_exact(56) {
                source.extend_from_slice(entry);
                source.extend_from_slice(&[0xa5; 8]);
            }
            source[32..40].copy_from_slice(&(expanded as u64).to_le_bytes());
            source[54..56].copy_from_slice(&(stride as u16).to_le_bytes());
        }
        assert_eq!(search_exec(&source, &[], &[], 0, 0), Err(ENOEXEC));
        STATE.with_borrow(|state| {
            assert_eq!(state.entered, 1);
            assert!(state.prepared.is_empty() && state.library_paths.is_empty());
            assert!(
                !state.closed.contains(&19)
                    && !state.closed.contains(&28)
                    && !state.closed.contains(&29)
            );
        });
    }
}

#[test]
fn exec_requires_relro_contract_and_carries_protections_with_or_without_resolvers() {
    use mochios_posix_client::{process_image::AT_INDIRECT_IMAGE, relocation_protection::Image};
    for supported in [false, true] {
        let flags = if supported {
            vec![
                "-DMOCHIOS_RELRO_RUNTIME",
                "-Wl,-z,relro,-z,now",
                "-Wl,-rpath,/libraries",
            ]
        } else {
            vec!["-Wl,-z,relro,-z,now", "-Wl,-rpath,/libraries"]
        };
        let (root, library) = dependency_fixture(&flags, &["-Wl,-z,relro,-z,now"]);
        assert_eq!(
            search_exec(&root, &[(b"/libraries/libscope.so", &library)], &[], 0, 0),
            Err(ENOEXEC)
        );
        STATE.with_borrow(|s| {
            assert_eq!(s.entered, usize::from(supported));
            if !supported {
                assert!(s.prepared.is_empty());
                return;
            }
            let startup = mnu_abi::process_image::decode(&s.startup).unwrap();
            let stack = startup.stack();
            let word = |at| u64::from_le_bytes(stack[at..at + 8].try_into().unwrap());
            let mut at = (word(0) as usize + 2) * 8;
            while word(at) != 0 {
                at += 8;
            }
            at += 8;
            let mut start = None;
            while word(at) != 0 {
                if word(at) == AT_INDIRECT_IMAGE {
                    start = Some(word(at + 8) as usize);
                }
                at += 16;
            }
            let start = start.expect("RELRO cannot silently disappear");
            let length = word(start + 16) as usize;
            let image = Image::parse::<i32>(&stack[start..start + length]).unwrap();
            assert_eq!(image.ranges().count(), 2);
            assert!(image.indirect().is_empty());
            for range in image.ranges() {
                let count = u16::from_le_bytes(s.prepared[56..58].try_into().unwrap()) as usize;
                assert!((0..count).any(|i| {
                    let at = 64 + i * 56;
                    let word = |n| u64::from_le_bytes(s.prepared[n..n + 8].try_into().unwrap());
                    let kind = u32::from_le_bytes(s.prepared[at..at + 4].try_into().unwrap());
                    kind == 1
                        && word(at + 16) & !4095 <= range.address
                        && range.address + range.length <= word(at + 16) + word(at + 40) + 4095
                }));
            }
        });
    }
    let [root, middle, provider] = indirect_fixture(
        true,
        &["-DRELRO_CONTRACT", "-Wl,-z,relro,-z,now"],
        &["-Wl,-z,relro,-z,now"],
    );
    assert_eq!(
        search_exec(
            &root,
            &[
                (b"/libraries/libmiddle.so", &middle),
                (b"/libraries/libprovider.so", &provider)
            ],
            &[],
            0,
            0
        ),
        Err(ENOEXEC)
    );
    STATE.with_borrow(|s| {
        assert_eq!(s.entered, 1);
        let stack = mnu_abi::process_image::decode(&s.startup).unwrap().stack();
        let start = stack.windows(8).position(|p| p == b"MRELRO01").unwrap();
        let length = u64::from_le_bytes(stack[start + 16..start + 24].try_into().unwrap()) as usize;
        let image = Image::parse::<i32>(&stack[start..start + length]).unwrap();
        assert_eq!(image.ranges().count(), 3);
        assert_eq!(&image.indirect()[..8], b"MIREL001");
    });
}
