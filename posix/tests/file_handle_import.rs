//! Execute the production import, FD reservation owners and callback scopes.
#![allow(dead_code)]
use mochi_user_syscall as native;
use mochios_posix_client::{
    ObjectHandleAttachment,
    fd::{self, FdReservation},
    upcall_guard::Guard,
};
use std::ffi::c_int;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/fd_creation.rs"]
mod fd_creation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
use fd_creation::PendingFdReservation;
#[path = "../../../user/crates/newlib-runtime/src/file_handle_import.rs"]
mod implementation;

const EAGAIN: c_int = 11;
const EINVAL: c_int = 22;
const EBADF: c_int = 9;
const EACCES: c_int = 13;
const EIO: c_int = 5;
const EMFILE: c_int = 24;
const O_CLOEXEC: c_int = 0x40000;
const SOURCE: u32 = 7;
const DUPLICATE: u32 = 42;
const BASE: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
static SERIAL: Mutex<()> = Mutex::new(());
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static CALLS: Mutex<Vec<(native::SyscallNumber, u64, u64)>> = Mutex::new(Vec::new());
static ERRNO: AtomicI32 = AtomicI32::new(0);
static MODE: AtomicU32 = AtomicU32::new(0);
static RIGHTS: AtomicU64 = AtomicU64::new(BASE | mnu_abi::HANDLE_RIGHT_READ);
static LIMIT: AtomicI32 = AtomicI32::new(256);
static FSTATS: AtomicU32 = AtomicU32::new(0);
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdKind {
    ObjectFile,
    ObjectDirectory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FdObject {
    lower_handle: u64,
    kind: FdKind,
    open_flags: c_int,
    close_owned: bool,
}
type FdEntry = fd::Entry<FdObject>;
struct Fds(fd::FdTable<FdObject>);
impl Fds {
    fn reserve_from(&mut self, minimum: c_int, limit: c_int) -> Result<FdReservation, ()> {
        self.0.reserve_from(minimum, limit).map_err(|_| ())
    }
    fn cancel_reservation(&mut self, reservation: &FdReservation) {
        self.0.cancel_reservation(reservation);
    }
    fn commit_reservation(
        &mut self,
        reservation: &FdReservation,
        entry: FdEntry,
    ) -> Result<c_int, ()> {
        if MODE.load(Ordering::Relaxed) == 5 {
            return Err(());
        }
        self.0
            .commit_reservation(reservation, entry)
            .map_err(|_| ())
    }
}
struct State {
    fds: Fds,
}
static STATE: Mutex<State> = Mutex::new(State {
    fds: Fds(fd::FdTable::new()),
});
fn state() -> MutexGuard<'static, State> {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    STATE.lock().unwrap()
}
fn process_fd_limit() -> Result<c_int, c_int> {
    if MODE.load(Ordering::Relaxed) == 10 {
        return Err(EIO);
    }
    Ok(LIMIT.load(Ordering::Relaxed))
}
fn close_object_handle(handle: u32) {
    assert_eq!(handle, DUPLICATE, "must never close the borrowed source");
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    CLOSED.lock().unwrap().push(handle);
}
fn object_entry(handle: u64, rights: u64, kind: FdKind, flags: c_int) -> FdEntry {
    FdEntry {
        handle: FdObject {
            lower_handle: handle,
            kind,
            open_flags: flags & !O_CLOEXEC,
            close_owned: true,
        },
        rights,
        descriptor_flags: if flags & O_CLOEXEC != 0 {
            fd::FD_CLOEXEC
        } else {
            0
        },
    }
}
fn result_with_errno<T>(result: Result<T, c_int>, failure: T) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            ERRNO.store(error, Ordering::Relaxed);
            failure
        }
    }
}
fn syscall_errno(result: Result<u64, c_int>) -> Result<u64, c_int> {
    result
}
mod syscall {
    pub use mnu_abi::{
        HANDLE_RIGHT_ALL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_READ, HANDLE_RIGHT_TRANSFER,
        HANDLE_RIGHT_WRITE, SyscallNumber,
    };
    pub fn raw_syscall1(number: SyscallNumber, source: u64) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::HandleRightsGet);
        assert_eq!(source, u64::from(super::SOURCE));
        super::CALLS.lock().unwrap().push((number, source, 0));
        if super::MODE.load(super::Ordering::Relaxed) == 1 {
            Err(super::EBADF)
        } else {
            Ok(super::RIGHTS.load(super::Ordering::Relaxed))
        }
    }
    pub fn raw_syscall2(number: SyscallNumber, source: u64, rights: u64) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::HandleDuplicate);
        assert_eq!(source, u64::from(super::SOURCE));
        assert_eq!(rights, super::RIGHTS.load(super::Ordering::Relaxed));
        super::CALLS.lock().unwrap().push((number, source, rights));
        match super::MODE.load(super::Ordering::Relaxed) {
            2 => Err(super::EACCES),
            6 => Ok(0),
            7 => Ok(source),
            8 => Ok(1u64 << 32),
            _ => Ok(u64::from(super::DUPLICATE)),
        }
    }
}
struct Client;
#[derive(Clone, Copy)]
struct Status {
    mode: u32,
}
fn posix_client() -> Result<Client, c_int> {
    if MODE.load(Ordering::Relaxed) == 11 {
        return Err(EIO);
    }
    Ok(Client)
}
fn map_posix_client_error(error: c_int) -> c_int {
    error
}
impl Client {
    fn fstat(&self, file: ObjectHandleAttachment<u32>) -> Result<Status, c_int> {
        assert_eq!(file.handle, DUPLICATE);
        assert_eq!(file.rights, RIGHTS.load(Ordering::Relaxed));
        assert!(!CONTROL.callback_resources.is_empty());
        assert!(STATE.try_lock().is_ok(), "FD lock held across IPC");
        FSTATS.fetch_add(1, Ordering::Relaxed);
        match MODE.load(Ordering::Relaxed) {
            3 => Err(EIO),
            4 => Ok(Status { mode: 0o020000 }),
            9 => Ok(Status { mode: 0o040000 }),
            _ => Ok(Status { mode: 0o100000 }),
        }
    }
}
mod user_copy {
    pub fn write(_: *mut u8, _: &[u8]) -> Result<(), i32> {
        panic!("import has no user pointers")
    }
}

fn reset(mode: u32, rights: u64) {
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    STATE.lock().unwrap().fds.0 = fd::FdTable::new();
    CLOSED.lock().unwrap().clear();
    CALLS.lock().unwrap().clear();
    ERRNO.store(0, Ordering::Relaxed);
    MODE.store(mode, Ordering::Relaxed);
    RIGHTS.store(rights, Ordering::Relaxed);
    LIMIT.store(256, Ordering::Relaxed);
    FSTATS.store(0, Ordering::Relaxed);
}

#[test]
fn actual_import_derives_access_and_cloexec_without_modifying_the_borrowed_source() {
    let _serial = SERIAL.lock().unwrap();
    for (access, rights) in [
        (0, mnu_abi::HANDLE_RIGHT_READ),
        (1, mnu_abi::HANDLE_RIGHT_WRITE),
        (2, mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE),
    ] {
        for flags in [0, O_CLOEXEC] {
            reset(0, BASE | rights);
            let fd = implementation::mochi_fd_from_file_handle(SOURCE, flags);
            assert_eq!(fd, 0);
            let entry = STATE.lock().unwrap().fds.0.get(fd).unwrap();
            assert_eq!(entry.handle.lower_handle, u64::from(DUPLICATE));
            assert_eq!(entry.handle.kind, FdKind::ObjectFile);
            assert_eq!(entry.handle.open_flags, access);
            assert_eq!(entry.rights, BASE | rights);
            assert_eq!(
                entry.descriptor_flags,
                if flags == 0 { 0 } else { fd::FD_CLOEXEC }
            );
            assert!(CLOSED.lock().unwrap().is_empty());
            assert_eq!(FSTATS.load(Ordering::Relaxed), 1);
            assert!(CONTROL.callback_resources.is_empty());
            assert_eq!(ERRNO.load(Ordering::Relaxed), 0);
            struct Close;
            impl fd::HandleOps<FdObject> for Close {
                type Error = ();
                fn clone_handle(&mut self, _: FdObject, _: u64) -> Result<FdObject, ()> {
                    panic!("not a dup test")
                }
                fn close_handle(&mut self, object: FdObject) {
                    close_object_handle(object.lower_handle as u32);
                }
            }
            {
                let _native = defer_native_delivery();
                state().fds.0.close(fd, &mut Close).unwrap();
            }
            assert_eq!(*CLOSED.lock().unwrap(), vec![DUPLICATE]);
        }
    }
    reset(9, BASE | mnu_abi::HANDLE_RIGHT_READ);
    assert_eq!(implementation::mochi_fd_from_file_handle(SOURCE, 0), 0);
    assert_eq!(
        STATE.lock().unwrap().fds.0.get(0).unwrap().handle.kind,
        FdKind::ObjectDirectory
    );
}

#[test]
fn every_failure_releases_only_temporary_ownership_and_cancels_the_fd_reservation() {
    let _serial = SERIAL.lock().unwrap();
    for (mode, error, closed) in [
        (1, EBADF, false),
        (2, EACCES, false),
        (3, EIO, true),
        (4, mochios_posix_client::newlib_errno::EOPNOTSUPP, true),
        (5, EIO, true),
        (6, EIO, false),
        (7, EIO, false),
        (8, EIO, false),
        (10, EIO, false),
        (11, EIO, true),
    ] {
        reset(mode, BASE | mnu_abi::HANDLE_RIGHT_READ);
        assert_eq!(implementation::mochi_fd_from_file_handle(SOURCE, 0), -1);
        assert_eq!(ERRNO.load(Ordering::Relaxed), error);
        assert_eq!(
            CLOSED.lock().unwrap().as_slice(),
            if closed { &[DUPLICATE][..] } else { &[] }
        );
        assert!(STATE.lock().unwrap().fds.0.get(0).is_none());
        assert!(CONTROL.callback_resources.is_empty());
        let _native = defer_native_delivery();
        let reservation = state().fds.reserve_from(0, 1).unwrap();
        assert_eq!(reservation.descriptor(), 0);
        state().fds.cancel_reservation(&reservation);
    }
}

#[test]
fn public_header_has_the_same_c_and_cpp_scalar_abi_without_a_built_sdk() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let header = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../user/libc-port/include/mochi/handle.h")
        .canonicalize()
        .unwrap();
    for (compiler, language, standard, assertion) in [
        ("cc", "c", "c11", "_Static_assert"),
        ("c++", "c++", "c++17", "static_assert"),
    ] {
        let source = format!(
            "#include {:?}\n{assertion}(sizeof(uint32_t)==4 && sizeof(int)==4, \"ABI\");\nstatic int (*import_handle)(uint32_t,int)=mochi_fd_from_file_handle;\nint check(void){{return import_handle(1,0);}}\n",
            header
        );
        let mut child = Command::new(compiler)
            .args(["-x", language, "-", "-fsyntax-only", "-Werror"])
            .arg(format!("-std={standard}"))
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(source.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn invalid_flags_missing_authority_and_fd_limits_do_not_create_hidden_references() {
    let _serial = SERIAL.lock().unwrap();
    for (source, flags, rights, limit, error, queries) in [
        (0, 0, BASE | 1, 256, EBADF, 0),
        (SOURCE, 0x200, BASE | 1, 256, EINVAL, 0),
        (SOURCE, 0, BASE, 256, EACCES, 1),
        (SOURCE, 0, mnu_abi::HANDLE_RIGHT_READ, 256, EACCES, 1),
        (SOURCE, 0, BASE | 1 | (1 << 20), 256, EIO, 1),
        (SOURCE, 0, BASE | 1, 0, EMFILE, 1),
    ] {
        reset(0, rights);
        LIMIT.store(limit, Ordering::Relaxed);
        assert_eq!(implementation::mochi_fd_from_file_handle(source, flags), -1);
        assert_eq!(ERRNO.load(Ordering::Relaxed), error);
        assert_eq!(CALLS.lock().unwrap().len(), queries);
        assert_eq!(FSTATS.load(Ordering::Relaxed), 0);
        assert!(CLOSED.lock().unwrap().is_empty());
        assert!(STATE.lock().unwrap().fds.0.get(0).is_none());
    }
}
