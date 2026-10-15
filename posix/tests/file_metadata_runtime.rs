//! Execute the production metadata owner with controlled IPC/upcall boundaries.
use std::ffi::{CStr, c_char, c_int};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use mochios_posix_client::upcall_guard::Guard;
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/file_metadata.rs"]
mod implementation;

const EINVAL: i32 = 22;
const EAGAIN: i32 = 11;
const EOVERFLOW: i32 = 75;
const ENOENT: i32 = 2;
const ENAMETOOLONG: i32 = 36;
const AT_SYMLINK_NOFOLLOW: u64 = 2;
const STAT_NOFOLLOW: u32 = 1;
mod posix_protocol {
    pub const MAX_PATH_LEN: usize = 4096;
}
#[derive(Debug, PartialEq)]
struct NewlibStat(u32);
#[derive(Clone, Copy, Debug, PartialEq)]
enum Base {
    Root,
    Cwd,
    Directory(u32),
}
struct ThreadControl {
    native: AtomicU32,
    callback_resources: callback_resources::Chain,
    active_signal_scope_id: AtomicU64,
}
static CONTROL: ThreadControl = ThreadControl {
    native: AtomicU32::new(0),
    callback_resources: callback_resources::Chain::new(),
    active_signal_scope_id: AtomicU64::new(0),
};
static PINS: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
static DRAINS: AtomicU32 = AtomicU32::new(0);
static CURRENT: AtomicU32 = AtomicU32::new(7);
static FAIL: AtomicBool = AtomicBool::new(false);
static FAIL_INIT: AtomicBool = AtomicBool::new(false);
static FAIL_TRANSLATE: AtomicBool = AtomicBool::new(false);
static EXPECTED_FLAGS: AtomicU32 = AtomicU32::new(0);
mod fd_lease {
    use super::*;
    pub struct Lease;
    impl Drop for Lease {
        fn drop(&mut self) {
            assert!(CONTROL.native.load(Ordering::Relaxed) > 0);
            assert!(CONTROL.callback_resources.is_deferred());
            assert_eq!(PINS.fetch_sub(1, Ordering::Relaxed), 1);
        }
    }
}
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
unsafe fn c_bytes<'a>(path: *const c_char) -> &'a [u8] {
    unsafe { CStr::from_ptr(path).to_bytes() }
}
fn rename_posix_base(dirfd: c_int, path: &str) -> Result<(Base, Option<fd_lease::Lease>), i32> {
    assert!(CONTROL.native.load(Ordering::Relaxed) > 0);
    if path.starts_with('/') {
        return Ok((Base::Root, None));
    }
    if dirfd == -2 || dirfd == -100 {
        return Ok((Base::Cwd, None));
    }
    if dirfd != 3 {
        return Err(9);
    }
    PINS.fetch_add(1, Ordering::Relaxed);
    Ok((
        Base::Directory(CURRENT.load(Ordering::Relaxed)),
        Some(fd_lease::Lease),
    ))
}
struct Client;
fn posix_client() -> Result<Client, i32> {
    if FAIL_INIT.load(Ordering::Relaxed) {
        Err(5)
    } else {
        Ok(Client)
    }
}
fn map_posix_client_error(error: i32) -> i32 {
    error
}
fn translate_posix_stat(value: &u32) -> Result<NewlibStat, i32> {
    if FAIL_TRANSLATE.load(Ordering::Relaxed) {
        Err(EOVERFLOW)
    } else {
        Ok(NewlibStat(*value))
    }
}
impl Client {
    fn stat_at(&self, base: Base, flags: u32, path: &str) -> Result<u32, i32> {
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(!CONTROL.callback_resources.is_empty());
        assert!(CONTROL.callback_resources.record_notification());
        assert_eq!(flags, EXPECTED_FLAGS.load(Ordering::Relaxed));
        CALLS.fetch_add(1, Ordering::Relaxed);
        match base {
            Base::Directory(handle) => {
                assert_eq!(PINS.load(Ordering::Relaxed), 1);
                // The numeric descriptor now refers elsewhere, but this
                // operation must retain the old authority until retirement.
                CURRENT.store(99, Ordering::Relaxed);
                assert_eq!(handle, 7);
                assert_eq!(path, "entry");
            }
            Base::Root => assert!(path.starts_with('/')),
            Base::Cwd => assert_eq!(path, "entry"),
        }
        if FAIL.load(Ordering::Relaxed) {
            Err(13)
        } else {
            Ok(42)
        }
    }
}
fn drain_pending_signals() -> Result<(), i32> {
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(!CONTROL.callback_resources.is_deferred());
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(
        CONTROL.callback_resources.take_notification(),
        !FAIL_INIT.load(Ordering::Relaxed)
    );
    DRAINS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

#[test]
fn metadata_keeps_authority_through_ipc_and_releases_it_before_c_callbacks() {
    for (dirfd, path, flags, failure) in [
        (3, c"entry", 0, false),
        (3, c"entry", AT_SYMLINK_NOFOLLOW, false),
        (3, c"entry", 0, true),
        (-123, c"/entry", 0, false),
        (-2, c"entry", 0, false),
        (-100, c"entry", 0, false),
    ] {
        CURRENT.store(7, Ordering::Relaxed);
        EXPECTED_FLAGS.store(u32::from(flags != 0), Ordering::Relaxed);
        FAIL.store(failure, Ordering::Relaxed);
        assert_eq!(
            implementation::at(dirfd, path.as_ptr(), flags),
            if failure { Err(13) } else { Ok(NewlibStat(42)) }
        );
    }
    assert_eq!(CALLS.load(Ordering::Relaxed), 6);
    assert_eq!(DRAINS.load(Ordering::Relaxed), 6);
    assert_eq!(
        implementation::at(3, c"entry".as_ptr(), u64::MAX),
        Err(EINVAL)
    );
    assert_eq!(implementation::at(3, c"".as_ptr(), 0), Err(ENOENT));
    let long = std::ffi::CString::new("x".repeat(4097)).unwrap();
    assert_eq!(implementation::at(3, long.as_ptr(), 0), Err(ENAMETOOLONG));
    assert_eq!(implementation::at(-123, c"entry".as_ptr(), 0), Err(9));
    assert_eq!(CALLS.load(Ordering::Relaxed), 6);
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
    assert!(!CONTROL.callback_resources.is_deferred());
    CURRENT.store(7, Ordering::Relaxed);
    FAIL_INIT.store(true, Ordering::Relaxed);
    assert_eq!(implementation::at(3, c"entry".as_ptr(), 0), Err(5));
    FAIL_INIT.store(false, Ordering::Relaxed);
    FAIL_TRANSLATE.store(true, Ordering::Relaxed);
    assert_eq!(implementation::at(3, c"entry".as_ptr(), 0), Err(EOVERFLOW));
    assert_eq!(CALLS.load(Ordering::Relaxed), 7);
    assert_eq!(DRAINS.load(Ordering::Relaxed), 8);
    assert!(CONTROL.callback_resources.is_empty());
}

#[test]
fn newlib_stat_header_declares_the_mochios_metadata_entry_points() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut compiler = Command::new("cc")
        .args([
            "-std=c11",
            "-D__mochios__",
            "-D_POSIX_C_SOURCE=200809L",
            "-Werror=implicit-function-declaration",
            "-Werror=incompatible-pointer-types",
            "-I",
        ])
        .arg(root.join("out/newlib-port/sdk/sysroot/include"))
        .arg("-include")
        .arg(root.join("libraries/newlib/newlib/libc/include/sys/stat.h"))
        .args(["-x", "c", "-fsyntax-only", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler.stdin.take().unwrap().write_all(b"int (*stat_link)(const char *, struct stat *) = lstat;\nint (*stat_relative)(int, const char *, struct stat *, int) = fstatat;\n").unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
