//! Execute the actual path scope, including input mutation and reentrant close.
#![allow(dead_code)]
use mochios_posix_client::{
    AccessAtBase, ObjectHandleAttachment, OpenAtBase, StatAtBase, upcall_guard::Guard,
};
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/path_io.rs"]
mod implementation;
use implementation as path_io;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const PAGE_SIZE: usize = 4096;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
#[path = "../../../user/crates/newlib-runtime/src/file_metadata.rs"]
mod metadata;
const EAGAIN: c_int = 11;
const EFAULT: c_int = 14;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const EBADF: c_int = 9;
const EOVERFLOW: c_int = 139;
const AT_SYMLINK_NOFOLLOW: u64 = 2;
const STAT_NOFOLLOW: u32 = 1;
#[derive(Clone, Copy, Debug, PartialEq)]
struct NewlibStat(u32);
static STAT_FLAGS: AtomicU32 = AtomicU32::new(0);
static TRANSLATE_FAIL: AtomicU32 = AtomicU32::new(0);
static READLINK_OUTPUT: AtomicU64 = AtomicU64::new(0);
static DRAINS: AtomicU32 = AtomicU32::new(0);
fn translate_posix_stat(value: &u32) -> Result<NewlibStat, c_int> {
    if TRANSLATE_FAIL.load(Ordering::Relaxed) != 0 {
        Err(EOVERFLOW)
    } else {
        Ok(NewlibStat(*value))
    }
}
fn drain_pending_signals() -> Result<(), c_int> {
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
    assert!(!CONTROL.callback_resources.is_deferred());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    DRAINS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}
static SERIAL: Mutex<()> = Mutex::new(());
static PINS: AtomicU32 = AtomicU32::new(0);
static CLOSED: AtomicU32 = AtomicU32::new(0);
static RETIRED: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
static CASE: AtomicU32 = AtomicU32::new(0);
static INPUT: AtomicU64 = AtomicU64::new(0);
static SECOND_INPUT: AtomicU64 = AtomicU64::new(0);
static DROPS: AtomicU32 = AtomicU32::new(0);
static MUTATION: Mutex<Option<(u32, u32, u32, u32)>> = Mutex::new(None);
struct ThreadControl {
    callback_resources: callback_resources::Chain,
    active_signal_scope_id: AtomicU64,
    native: AtomicU32,
}
static CONTROL: ThreadControl = ThreadControl {
    callback_resources: callback_resources::Chain::new(),
    active_signal_scope_id: AtomicU64::new(0),
    native: AtomicU32::new(0),
};
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&CONTROL.native)
}
mod fd_lease {
    use super::*;
    pub struct Lease;
    impl std::ops::Deref for Lease {
        type Target = u32;
        fn deref(&self) -> &u32 {
            &42
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
            let before = PINS.fetch_sub(1, Ordering::Relaxed);
            DROPS.fetch_add(1, Ordering::Relaxed);
            assert_ne!(before, 0);
            if before == 1 && RETIRED.load(Ordering::Relaxed) != 0 {
                CLOSED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
fn with_fd_entry(fd: c_int) -> Result<fd_lease::Lease, c_int> {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    if fd != 7 {
        return Err(EBADF);
    }
    PINS.fetch_add(1, Ordering::Relaxed);
    Ok(fd_lease::Lease)
}
fn change_directory_entry(entry: u32) -> Result<(), c_int> {
    assert_eq!(entry, 42);
    Client.paired(1)
}
fn rename_posix_base(
    fd: c_int,
    path: &[u8],
) -> Result<(StatAtBase<u32>, Option<fd_lease::Lease>), c_int> {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    assert!(!CONTROL.callback_resources.is_empty());
    if path.first() == Some(&b'/') {
        return Ok((StatAtBase::ProcessRoot, None));
    }
    if fd == -2 {
        return Ok((StatAtBase::ProcessCwd, None));
    }
    if fd != 7 {
        return Err(EBADF);
    }
    PINS.fetch_add(1, Ordering::Relaxed);
    Ok((
        StatAtBase::Directory(ObjectHandleAttachment {
            handle: 42,
            rights: 0x15,
        }),
        Some(fd_lease::Lease),
    ))
}
struct Client;
fn posix_client() -> Result<Client, c_int> {
    Ok(Client)
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}
impl Client {
    fn access_at(
        &self,
        base: AccessAtBase<u32>,
        flags: u32,
        modes: u32,
        path: &[u8],
    ) -> Result<(), c_int> {
        let base = match base {
            AccessAtBase::ProcessRoot => StatAtBase::ProcessRoot,
            AccessAtBase::ProcessCwd => StatAtBase::ProcessCwd,
            AccessAtBase::Directory(handle) => StatAtBase::Directory(handle),
        };
        self.mutation(base, path, (9, modes, flags, 0))
    }
    fn stat_at(&self, base: StatAtBase<u32>, flags: u32, path: &[u8]) -> Result<u32, c_int> {
        assert_eq!(flags, STAT_FLAGS.load(Ordering::Relaxed));
        assert!(!CONTROL.callback_resources.is_deferred());
        self.readlink_at(base, path, &mut [])?;
        Ok(42)
    }
    fn chdir_at(&self, base: StatAtBase<u32>, path: &[u8]) -> Result<(), c_int> {
        self.paired(0)?;
        assert_eq!(base, StatAtBase::ProcessCwd);
        assert_eq!(path, b"target");
        Ok(())
    }
    fn chroot_at(&self, base: StatAtBase<u32>, path: &[u8]) -> Result<(), c_int> {
        self.chdir_at(base, path)
    }
    fn paired(&self, pins: u32) -> Result<(), c_int> {
        assert_eq!(PINS.load(Ordering::Relaxed), pins);
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(!CONTROL.callback_resources.is_empty());
        CALLS.fetch_add(1, Ordering::Relaxed);
        match CASE.load(Ordering::Relaxed) {
            1 => return Err(13),
            2 => {
                RETIRED.store(1, Ordering::Relaxed);
                assert_eq!(CLOSED.load(Ordering::Relaxed), 0);
            }
            3 => unsafe {
                (INPUT.load(Ordering::Relaxed) as *mut u8).write(b'X');
                (SECOND_INPUT.load(Ordering::Relaxed) as *mut u8).write(b'Y');
            },
            _ => {}
        }
        Ok(())
    }
    fn rename_at(
        &self,
        old_base: StatAtBase<u32>,
        old: &[u8],
        new_base: StatAtBase<u32>,
        new: &[u8],
    ) -> Result<(), c_int> {
        self.paired(2)?;
        assert_eq!((old, new), (b"target".as_slice(), b"next".as_slice()));
        assert_eq!(old_base, new_base);
        *MUTATION.lock().unwrap() = Some((4, 0, 0, 0));
        Ok(())
    }
    fn link_at(
        &self,
        old_base: StatAtBase<u32>,
        old: &[u8],
        new_base: StatAtBase<u32>,
        new: &[u8],
        flags: u32,
    ) -> Result<(), c_int> {
        self.rename_at(old_base, old, new_base, new)?;
        *MUTATION.lock().unwrap() = Some((5, flags, 0, 0));
        Ok(())
    }
    fn symlink_at(&self, target: &[u8], _: StatAtBase<u32>, path: &[u8]) -> Result<(), c_int> {
        self.paired(1)?;
        assert_eq!(
            (target, path),
            (b"../literal".as_slice(), b"next".as_slice())
        );
        *MUTATION.lock().unwrap() = Some((6, 0, 0, 0));
        Ok(())
    }
    fn mutation(
        &self,
        base: StatAtBase<u32>,
        path: &[u8],
        arguments: (u32, u32, u32, u32),
    ) -> Result<(), c_int> {
        let mut unused = [];
        self.readlink_at(base, path, &mut unused)?;
        *MUTATION.lock().unwrap() = Some(arguments);
        Ok(())
    }
    fn chmod_at(&self, base: StatAtBase<u32>, path: &[u8], mode: u32) -> Result<(), c_int> {
        self.mutation(base, path, (0, mode, 0, 0))
    }
    fn chown_at(
        &self,
        base: StatAtBase<u32>,
        path: &[u8],
        uid: u32,
        gid: u32,
        flags: u32,
    ) -> Result<(), c_int> {
        self.mutation(base, path, (1, uid, gid, flags))
    }
    fn unlink_at(&self, base: StatAtBase<u32>, flags: u32, path: &[u8]) -> Result<(), c_int> {
        self.mutation(base, path, (2, flags, 0, 0))
    }
    fn mkdir_at(&self, base: OpenAtBase<u32>, mode: u32, path: &[u8]) -> Result<(), c_int> {
        let base = match base {
            OpenAtBase::ProcessRoot => StatAtBase::ProcessRoot,
            OpenAtBase::ProcessCwd => StatAtBase::ProcessCwd,
            OpenAtBase::Directory(handle) => StatAtBase::Directory(handle),
        };
        self.mutation(base, path, (3, mode, 0, 0))
    }
    fn readlink_at(
        &self,
        base: StatAtBase<u32>,
        path: &[u8],
        output: &mut [u8],
    ) -> Result<usize, c_int> {
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(!CONTROL.callback_resources.is_empty());
        assert_eq!(PINS.load(Ordering::Relaxed), 1);
        assert_eq!(
            base,
            StatAtBase::Directory(ObjectHandleAttachment {
                handle: 42,
                rights: 0x15
            })
        );
        CALLS.fetch_add(1, Ordering::Relaxed);
        match CASE.load(Ordering::Relaxed) {
            1 => return Err(13),
            2 => {
                RETIRED.store(1, Ordering::Relaxed);
                assert_eq!(CLOSED.load(Ordering::Relaxed), 0);
            }
            3 => unsafe { (INPUT.load(Ordering::Relaxed) as *mut u8).write(b'X') },
            4 => {
                let caller = READLINK_OUTPUT.load(Ordering::Relaxed) as usize;
                let borrowed = output.as_ptr() as usize..output.as_ptr() as usize + output.len();
                assert!(
                    !borrowed.contains(&caller),
                    "caller output borrowed across IPC"
                );
                unsafe { (caller as *mut u8).write(0x5a) };
            }
            5 => return Ok(output.len() + 1),
            7 => return Ok(posix_protocol::MAX_PATH_LEN + 1),
            6 => {
                assert!(output.len() <= posix_protocol::MAX_PATH_LEN);
                output.fill(0xff);
                return Ok(output.len());
            }
            _ => {}
        }
        assert_eq!(path, b"target");
        let count = output.len().min(b"destination".len());
        output[..count].copy_from_slice(&b"destination"[..count]);
        Ok(count)
    }
}
fn reset() {
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    CLOSED.store(0, Ordering::Relaxed);
    RETIRED.store(0, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    DROPS.store(0, Ordering::Relaxed);
}
#[test]
fn access_preserves_all_modes_and_id_follow_options_with_scoped_authority() {
    let _serial = SERIAL.lock().unwrap();
    for mode in 0..8 {
        for flags in 0..4 {
            for case in 0..4 {
                reset();
                CASE.store(case, Ordering::Relaxed);
                *MUTATION.lock().unwrap() = None;
                let mut input = *b"target\0";
                INPUT.store(input.as_mut_ptr() as u64, Ordering::Relaxed);
                assert_eq!(
                    implementation::access(7, input.as_ptr().cast(), mode, flags),
                    if case == 1 { Err(13) } else { Ok(()) }
                );
                assert_eq!(
                    *MUTATION.lock().unwrap(),
                    if case == 1 {
                        None
                    } else {
                        Some((9, mode as u32, flags as u32, 0))
                    }
                );
                assert_eq!(PINS.load(Ordering::Relaxed), 0);
                assert_eq!(CLOSED.load(Ordering::Relaxed), u32::from(case == 2));
                assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
                assert!(CONTROL.callback_resources.is_empty());
            }
        }
    }
    reset();
    for (mode, flags) in [(-1, 0), (8, 0), (0, -1), (0, 4), (0, 16)] {
        assert_eq!(
            implementation::access(7, c"target".as_ptr(), mode, flags),
            Err(EINVAL)
        );
    }
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
}

#[test]
fn metadata_uses_the_actual_path_snapshot_without_deferring_callbacks_across_rpc() {
    let _serial = SERIAL.lock().unwrap();
    for flags in [0, AT_SYMLINK_NOFOLLOW] {
        for case in 0..4 {
            reset();
            CASE.store(case, Ordering::Relaxed);
            STAT_FLAGS.store(u32::from(flags != 0), Ordering::Relaxed);
            DRAINS.store(0, Ordering::Relaxed);
            let mut input = *b"target\0";
            INPUT.store(input.as_mut_ptr() as u64, Ordering::Relaxed);
            assert_eq!(
                metadata::at(7, input.as_ptr().cast(), flags),
                if case == 1 {
                    Err(13)
                } else {
                    Ok(NewlibStat(42))
                }
            );
            assert_eq!(DRAINS.load(Ordering::Relaxed), 1);
            assert_eq!(PINS.load(Ordering::Relaxed), 0);
            assert_eq!(CLOSED.load(Ordering::Relaxed), u32::from(case == 2));
        }
    }
    reset();
    CASE.store(0, Ordering::Relaxed);
    STAT_FLAGS.store(0, Ordering::Relaxed);
    TRANSLATE_FAIL.store(1, Ordering::Relaxed);
    assert_eq!(metadata::at(7, c"target".as_ptr(), 0), Err(EOVERFLOW));
    TRANSLATE_FAIL.store(0, Ordering::Relaxed);
    reset();
    assert_eq!(metadata::at(7, c"target".as_ptr(), u64::MAX), Err(EINVAL));
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn directory_policy_captures_paths_and_keeps_fd_authority_through_reentrant_rpc() {
    let _serial = SERIAL.lock().unwrap();
    for operation in 0..3 {
        for case in 0..4 {
            reset();
            CASE.store(case, Ordering::Relaxed);
            let mut input = *b"target\0";
            let mut second = *b"unused\0";
            INPUT.store(input.as_mut_ptr() as u64, Ordering::Relaxed);
            SECOND_INPUT.store(second.as_mut_ptr() as u64, Ordering::Relaxed);
            let result = match operation {
                0 => implementation::chdir(input.as_ptr().cast()),
                1 => implementation::chroot(input.as_ptr().cast()),
                _ => implementation::fchdir(7),
            };
            assert_eq!(result, if case == 1 { Err(13) } else { Ok(()) });
            assert_eq!(DROPS.load(Ordering::Relaxed), u32::from(operation == 2));
            assert_eq!(
                CLOSED.load(Ordering::Relaxed),
                u32::from(operation == 2 && case == 2)
            );
            assert_eq!(PINS.load(Ordering::Relaxed), 0);
            assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
            assert!(CONTROL.callback_resources.is_empty());
        }
    }
    assert_eq!(implementation::fchdir(-1), Err(EBADF));
}

#[test]
fn paired_operations_capture_both_inputs_and_retire_both_borrows_on_rpc_escape_paths() {
    let _serial = SERIAL.lock().unwrap();
    for operation in 0..3 {
        for case in 0..4 {
            reset();
            CASE.store(case, Ordering::Relaxed);
            *MUTATION.lock().unwrap() = None;
            let mut old = if operation == 2 {
                b"../literal\0".to_vec()
            } else {
                b"target\0".to_vec()
            };
            let mut new = *b"next\0";
            INPUT.store(old.as_mut_ptr() as u64, Ordering::Relaxed);
            SECOND_INPUT.store(new.as_mut_ptr() as u64, Ordering::Relaxed);
            let result = match operation {
                0 => implementation::rename(7, old.as_ptr().cast(), 7, new.as_ptr().cast()),
                1 => implementation::link(
                    7,
                    old.as_ptr().cast(),
                    7,
                    new.as_ptr().cast(),
                    implementation::AT_SYMLINK_FOLLOW,
                ),
                _ => implementation::symlink(old.as_ptr().cast(), 7, new.as_ptr().cast()),
            };
            assert_eq!(result, if case == 1 { Err(13) } else { Ok(()) });
            assert_eq!(
                *MUTATION.lock().unwrap(),
                if case == 1 {
                    None
                } else {
                    Some((4 + operation, u32::from(operation == 1), 0, 0))
                }
            );
            assert_eq!(
                DROPS.load(Ordering::Relaxed),
                if operation == 2 { 1 } else { 2 }
            );
            assert_eq!(PINS.load(Ordering::Relaxed), 0);
            assert_eq!(CLOSED.load(Ordering::Relaxed), u32::from(case == 2));
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
            assert!(CONTROL.callback_resources.is_empty());
            assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn linkat_translates_newlib_flags_and_rejects_foreign_bits_before_reading_paths() {
    let _serial = SERIAL.lock().unwrap();
    for (native, wire) in [
        (0, 0),
        (
            implementation::AT_SYMLINK_FOLLOW,
            posix_protocol::LINK_FOLLOW_SOURCE,
        ),
    ] {
        reset();
        implementation::link(7, c"target".as_ptr(), 7, c"next".as_ptr(), native).unwrap();
        assert_eq!(*MUTATION.lock().unwrap(), Some((5, wire, 0, 0)));
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
    for flags in [-1, 1, 2, 8, 16, 0x400, 0x404, c_int::MAX] {
        reset();
        assert_eq!(
            implementation::link(-1, std::ptr::null(), -1, std::ptr::null(), flags),
            Err(EINVAL)
        );
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
}

#[test]
fn linkat_flag_matches_the_newlib_public_header() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut compiler = Command::new("cc")
        .args([
            "-std=c11",
            "-D__mochios__",
            "-D_POSIX_C_SOURCE=200809L",
            "-I",
        ])
        .arg(root.join("out/newlib-port/sdk/sysroot/include"))
        .arg("-include")
        .arg(root.join("libraries/newlib/newlib/libc/include/sys/_default_fcntl.h"))
        .args(["-x", "c", "-fsyntax-only", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    write!(
        compiler.stdin.take().unwrap(),
        "_Static_assert(AT_SYMLINK_FOLLOW == {}, \"linkat flag ABI mismatch\");\n",
        implementation::AT_SYMLINK_FOLLOW
    )
    .unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn bounded_capture_keeps_raw_bytes_and_accepts_the_exact_wire_limit() {
    for length in [
        1,
        255,
        posix_protocol::MAX_PATH_LEN - 1,
        posix_protocol::MAX_PATH_LEN,
    ] {
        let mut input = vec![0xffu8; length];
        input.push(0);
        let mut output = [0xa5; posix_protocol::MAX_PATH_LEN];
        assert_eq!(
            implementation::capture(input.as_ptr().cast(), &mut output),
            Ok(length)
        );
        assert!(output[..length].iter().all(|byte| *byte == 0xff));
        assert!(output[length..].iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn bounded_capture_rejects_empty_null_and_unterminated_overlong_inputs() {
    let mut output = [0xa5; posix_protocol::MAX_PATH_LEN];
    assert_eq!(
        implementation::capture(std::ptr::null(), &mut output),
        Err(EFAULT)
    );
    assert_eq!(
        implementation::capture(c"".as_ptr(), &mut output),
        Err(ENOENT)
    );
    assert!(output.iter().all(|byte| *byte == 0xa5));
    // Exactly MAX+1 readable non-NUL bytes suffice to prove overflow; there
    // need not be any terminator or readable memory after this snapshot.
    let input = [0xffu8; posix_protocol::MAX_PATH_LEN + 1];
    assert_eq!(
        implementation::capture(input.as_ptr().cast(), &mut output),
        Err(ENAMETOOLONG)
    );
}

#[test]
fn byte_paths_are_snapshotted_without_unicode_conversion_in_both_inputs() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let mut first = *b"name-\xff\0";
    let mut second = *b"next-\xfe\0";
    let first_pointer = first.as_mut_ptr();
    let second_pointer = second.as_mut_ptr();
    assert_eq!(
        implementation::pair(
            7,
            first_pointer.cast(),
            7,
            second_pointer.cast(),
            |_, old, _, new| {
                assert_eq!(PINS.load(Ordering::Relaxed), 2);
                unsafe {
                    first_pointer.write(b'X');
                    second_pointer.write(b'Y');
                }
                assert_eq!(old, b"name-\xff");
                assert_eq!(new, b"next-\xfe");
                Ok(1)
            },
        ),
        Ok(1)
    );
    assert_eq!(first[0], b'X');
    assert_eq!(second[0], b'Y');
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert_eq!(DROPS.load(Ordering::Relaxed), 2);
    assert!(CONTROL.callback_resources.is_empty());
}

#[test]
fn second_input_failures_release_the_first_directory_before_any_rpc() {
    let _serial = SERIAL.lock().unwrap();
    for (fd, path, error) in [
        (7, c"".as_ptr(), ENOENT),
        (7, std::ptr::null(), EFAULT),
        (-9, c"next".as_ptr(), EBADF),
    ] {
        reset();
        assert_eq!(
            implementation::pair(7, c"target".as_ptr(), fd, path, |_, _, _, _| Ok(1)),
            Err(error)
        );
        assert_eq!(DROPS.load(Ordering::Relaxed), 1);
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn mutations_keep_arguments_and_directory_authority_through_all_rpc_outcomes() {
    let _serial = SERIAL.lock().unwrap();
    for operation in 0..4 {
        for case in 0..4 {
            reset();
            *MUTATION.lock().unwrap() = None;
            CASE.store(case, Ordering::Relaxed);
            let mut input = *b"target\0";
            INPUT.store(input.as_mut_ptr() as u64, Ordering::Relaxed);
            let path = input.as_ptr().cast();
            let result = match operation {
                0 => implementation::chmod(7, path, 0o640),
                1 => implementation::chown(7, path, u32::MAX, 20, 1),
                2 => implementation::unlink(7, path, 1),
                _ => implementation::mkdir(7, path, 0o750),
            };
            assert_eq!(result, if case == 1 { Err(13) } else { Ok(()) });
            let expected = match operation {
                0 => (0, 0o640, 0, 0),
                1 => (1, u32::MAX, 20, 1),
                2 => (2, 1, 0, 0),
                _ => (3, 0o750, 0, 0),
            };
            assert_eq!(
                *MUTATION.lock().unwrap(),
                if case == 1 { None } else { Some(expected) }
            );
            assert_eq!(PINS.load(Ordering::Relaxed), 0);
            assert_eq!(CLOSED.load(Ordering::Relaxed), u32::from(case == 2));
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
            assert!(CONTROL.callback_resources.is_empty());
        }
    }
}

#[test]
fn readlink_owns_input_and_directory_through_errors_copyout_and_reentrant_close() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..4 {
        reset();
        CASE.store(case, Ordering::Relaxed);
        let mut input = *b"target\0";
        INPUT.store(input.as_mut_ptr() as u64, Ordering::Relaxed);
        let mut output = [0xa5u8; 8];
        let result = implementation::readlink(
            7,
            input.as_ptr().cast(),
            output.as_mut_ptr().cast(),
            output.len(),
        );
        assert_eq!(result, if case == 1 { Err(13) } else { Ok(8) });
        if case != 1 {
            assert_eq!(&output, b"destinat");
        }
        assert_eq!(input[0], if case == 3 { b'X' } else { b't' });
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert_eq!(CLOSED.load(Ordering::Relaxed), u32::from(case == 2));
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn readlink_receives_into_private_storage_while_handler_writes_caller_output() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    CASE.store(4, Ordering::Relaxed);
    let mut output = [0xa5; 32];
    READLINK_OUTPUT.store(output.as_mut_ptr() as u64, Ordering::Relaxed);
    assert_eq!(
        implementation::readlink(7, c"target".as_ptr(), output.as_mut_ptr().cast(), 8),
        Ok(8)
    );
    assert_eq!(&output[..8], b"destinat");
    assert!(output[8..].iter().all(|byte| *byte == 0xa5));
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
}

#[test]
fn readlink_rejects_malformed_lengths_without_partial_caller_writes() {
    let _serial = SERIAL.lock().unwrap();
    for case in [5, 7] {
        reset();
        CASE.store(case, Ordering::Relaxed);
        let mut output = [0xa5u8; 32];
        assert_eq!(
            implementation::readlink(
                7,
                c"target".as_ptr(),
                output.as_mut_ptr().cast(),
                output.len()
            ),
            Err(EIO)
        );
        assert_eq!(output, [0xa5; 32]);
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
}

#[test]
fn readlink_only_copies_bounded_prefix_bytes_without_nul_even_with_large_capacity() {
    let _serial = SERIAL.lock().unwrap();
    for capacity in [
        1,
        8,
        posix_protocol::MAX_PATH_LEN,
        posix_protocol::MAX_PATH_LEN + 1,
        isize::MAX as usize,
    ] {
        reset();
        CASE.store(6, Ordering::Relaxed);
        let mut output = vec![0xa5u8; posix_protocol::MAX_PATH_LEN + 2];
        let expected = capacity.min(posix_protocol::MAX_PATH_LEN);
        assert_eq!(
            implementation::readlink(7, c"target".as_ptr(), output.as_mut_ptr().cast(), capacity),
            Ok(expected as isize)
        );
        assert!(output[..expected].iter().all(|byte| *byte == 0xff));
        assert!(output[expected..].iter().all(|byte| *byte == 0xa5));
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
}
#[test]
fn invalid_paths_fail_before_borrowing_a_directory_or_calling_the_provider() {
    let _serial = SERIAL.lock().unwrap();
    let mut overlong = vec![b'a'; posix_protocol::MAX_PATH_LEN + 1];
    overlong.push(0);
    for (path, error) in [(b"\0".as_slice(), ENOENT), (&overlong, ENAMETOOLONG)] {
        reset();
        assert_eq!(
            implementation::at(7, path.as_ptr().cast(), |_, _| Ok(0)),
            Err(error)
        );
        assert_eq!(PINS.load(Ordering::Relaxed), 0);
        assert!(CONTROL.callback_resources.is_empty());
    }
    assert_eq!(
        implementation::at(7, std::ptr::null(), |_, _| Ok(0)),
        Err(EFAULT)
    );
    assert_eq!(
        implementation::at(-9, c"target".as_ptr(), |_, _| Ok(0)),
        Err(EBADF)
    );
}
#[test]
fn absolute_and_cwd_paths_ignore_irrelevant_dirfds_and_nested_scopes_keep_parent_pins() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    assert_eq!(
        implementation::at(-9, c"/absolute".as_ptr(), |base, path| {
            assert_eq!(base, StatAtBase::ProcessRoot);
            assert_eq!(path, b"/absolute");
            Ok(1)
        }),
        Ok(1)
    );
    assert_eq!(
        implementation::at(-2, c"relative".as_ptr(), |base, _| {
            assert_eq!(base, StatAtBase::ProcessCwd);
            Ok(2)
        }),
        Ok(2)
    );
    assert_eq!(
        implementation::at(7, c"parent".as_ptr(), |_, _| {
            assert_eq!(PINS.load(Ordering::Relaxed), 1);
            assert_eq!(
                implementation::at(7, c"child".as_ptr(), |_, _| {
                    assert_eq!(PINS.load(Ordering::Relaxed), 2);
                    Ok(3)
                }),
                Ok(3)
            );
            assert_eq!(PINS.load(Ordering::Relaxed), 1);
            Ok(4)
        }),
        Ok(4)
    );
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
}
#[test]
fn the_maximum_wire_path_is_captured_without_requiring_a_shorter_buffer() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let mut input = vec![b'x'; posix_protocol::MAX_PATH_LEN];
    input.push(0);
    assert_eq!(
        implementation::at(7, input.as_ptr().cast(), |_, path| {
            assert_eq!(path.len(), posix_protocol::MAX_PATH_LEN);
            assert!(path.iter().all(|byte| *byte == b'x'));
            Ok(1)
        }),
        Ok(1)
    );
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_output_ranges_are_rejected_before_rust_slice_construction() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let path = c"target".as_ptr();
    assert_eq!(
        implementation::readlink(7, path, std::ptr::null_mut(), 1),
        Err(EFAULT)
    );
    assert_eq!(
        implementation::readlink(7, path, 1usize as *mut c_char, 0),
        Err(EINVAL)
    );
    assert_eq!(
        implementation::readlink(7, path, 1usize as *mut c_char, usize::MAX),
        Err(EINVAL)
    );
    assert_eq!(
        implementation::readlink(7, path, usize::MAX as *mut c_char, 2),
        Err(EFAULT)
    );
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(PINS.load(Ordering::Relaxed), 0);
}
