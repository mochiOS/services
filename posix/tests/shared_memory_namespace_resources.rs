//! Production namespace scopes, receive owner, protocol and FD reservations.
#![allow(dead_code)]
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_client::{fd, upcall_guard::Guard};
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/shared_memory_namespace.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
#[path = "../../../user/crates/newlib-runtime/src/object_reply.rs"]
mod object_reply;
const EAGAIN: c_int = 11;
const EFAULT: c_int = 14;
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const EMFILE: c_int = 24;
const ENAMETOOLONG: c_int = 91;
const O_CLOEXEC: c_int = 0x40000;
static SERIAL: Mutex<()> = Mutex::new(());
static MODE: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
static INPUT: AtomicU64 = AtomicU64::new(0);
static CLOSED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
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
fn close_object_handle(handle: u32) {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    let mut closed = CLOSED.lock().unwrap();
    assert!(!closed.contains(&handle), "duplicate close");
    closed.push(handle);
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdKind {
    ObjectSharedMemory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FdObject {
    lower_handle: u64,
    kind: FdKind,
    open_flags: c_int,
}
type FdEntry = fd::Entry<FdObject>;
struct Fds(fd::FdTable<FdObject>);
impl Fds {
    fn reserve_from(&mut self, minimum: c_int, limit: c_int) -> Result<fd::FdReservation, ()> {
        self.0.reserve_from(minimum, limit).map_err(|_| ())
    }
    fn commit_reservation(
        &mut self,
        reservation: &fd::FdReservation,
        entry: FdEntry,
    ) -> Result<c_int, ()> {
        if MODE.load(Ordering::Relaxed) == 7 {
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
struct PendingFdReservation(fd::FdReservation);
impl Drop for PendingFdReservation {
    fn drop(&mut self) {
        state().fds.0.cancel_reservation(&self.0);
    }
}
fn object_entry(handle: u64, rights: u64, kind: FdKind, flags: c_int) -> FdEntry {
    assert_ne!(CONTROL.native.load(Ordering::Relaxed), 0);
    FdEntry {
        handle: FdObject {
            lower_handle: handle,
            kind,
            open_flags: flags & !O_CLOEXEC,
        },
        rights,
        descriptor_flags: u32::from(flags & O_CLOEXEC != 0),
    }
}
fn process_fd_limit() -> Result<c_int, c_int> {
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    if MODE.load(Ordering::Relaxed) == 15 {
        unsafe { (INPUT.load(Ordering::Relaxed) as *mut u8).write(b'X') };
    }
    Ok(if MODE.load(Ordering::Relaxed) == 8 {
        0
    } else {
        4
    })
}
struct Mock;
impl Mock {
    fn endpoint(&self) -> u32 {
        7
    }
}
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("unscoped IPC")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, _: u32) {
        panic!("unscoped cleanup")
    }
    fn call_with_handles(
        &self,
        _: &[u8],
        _: &mut [u8],
        _: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        panic!("unscoped IPC")
    }
}
fn posix_client() -> Result<Client<Mock>, ClientError<()>> {
    Ok(Client::new(Mock))
}
fn map_posix_client_error(error: ClientError<()>) -> c_int {
    match error {
        ClientError::Remote(value) => -value,
        ClientError::Protocol(_) => EINVAL,
        _ => EIO,
    }
}
fn syscall_errno(value: Result<u64, c_int>) -> Result<u64, c_int> {
    value
}
fn escape() -> ! {
    let _native = defer_native_delivery();
    unsafe { CONTROL.callback_resources.abandon_from(0) };
    panic!("simulated nonlocal exit")
}
mod syscall {
    use super::*;
    pub use mnu_abi::IpcObjectHandles;
    pub type SysError = ();
    pub enum SyscallNumber {
        IpcCallObjectHandles,
    }
    pub fn raw_syscall6(
        _: SyscallNumber,
        endpoint: u64,
        input: u64,
        input_len: u64,
        output: u64,
        capacity: u64,
        envelope: u64,
    ) -> Result<u64, c_int> {
        assert_eq!(endpoint, 7);
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
        assert!(!CONTROL.callback_resources.is_empty());
        assert!(!CONTROL.callback_resources.is_deferred());
        assert!(STATE.try_lock().is_ok(), "FD table held across IPC");
        CALLS.fetch_add(1, Ordering::Relaxed);
        let input = unsafe { std::slice::from_raw_parts(input as *const u8, input_len as usize) };
        let (header, payload) = posix_protocol::decode(input).unwrap();
        let open = header.opcode == posix_protocol::OP_SHARED_MEMORY_OPEN;
        let rights = if open {
            let request = posix_protocol::shared_memory::decode_open(payload).unwrap();
            assert_eq!(request.name, b"/owned");
            assert_eq!(
                request.mode,
                if request.options & posix_protocol::shared_memory::CREATE != 0 {
                    0o600
                } else {
                    0
                }
            );
            posix_protocol::shared_memory::descriptor_rights(
                request.options & posix_protocol::shared_memory::READ_WRITE != 0,
            )
        } else {
            assert_eq!(header.opcode, posix_protocol::OP_SHARED_MEMORY_UNLINK);
            assert_eq!(
                posix_protocol::shared_memory::decode_name(payload).unwrap(),
                b"/owned"
            );
            0
        };
        let native = unsafe { &mut *(envelope as *mut IpcObjectHandles) };
        assert_eq!(native.count, 0);
        let mode = MODE.load(Ordering::Relaxed);
        if mode == 3 {
            escape();
        }
        if open || mode != 0 {
            native.count = 1;
            native.handles[0].handle = 77;
            native.handles[0].rights = rights;
        }
        if mode == 2 {
            escape();
        }
        if mode == 5 {
            native.count = 2;
            native.handles[1] = native.handles[0];
        }
        if mode == 6 {
            native.handles[0].rights ^= mnu_abi::HANDLE_RIGHT_WRITE;
        }
        if mode == 9 {
            return Err(5);
        }
        let output =
            unsafe { std::slice::from_raw_parts_mut(output as *mut u8, capacity as usize) };
        let length = posix_protocol::encode(
            posix_protocol::Header {
                opcode: posix_protocol::OP_STATUS,
                request_id: header.request_id,
                flags: 0,
                status: if mode == 4 { -13 } else { 0 },
                payload_len: 0,
            },
            &[],
            output,
        )
        .unwrap();
        Ok((91 << 32) | length as u64)
    }
}
fn reset(mode: u32) {
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    MODE.store(mode, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    CLOSED.lock().unwrap().clear();
    STATE.lock().unwrap().fds.0 = fd::FdTable::new();
}
fn assert_slot_released() {
    let _native = defer_native_delivery();
    let mut table = state();
    let reservation = table.fds.0.reserve_from(0, 4).unwrap();
    assert_eq!(reservation.descriptor(), 0);
    assert!(table.fds.0.cancel_reservation(&reservation));
}

#[test]
fn successful_open_transfers_reply_into_the_reserved_cloexec_fd() {
    let _serial = SERIAL.lock().unwrap();
    for flags in [0, 2, 0x200, 2 | 0x200 | 0x800] {
        reset(0);
        assert_eq!(
            implementation::open(c"/owned".as_ptr(), flags, 0o600),
            Ok(0)
        );
        assert!(CLOSED.lock().unwrap().is_empty());
        let mut table = STATE.lock().unwrap();
        let opened = table.fds.0.get(0).unwrap();
        assert_eq!(opened.handle.lower_handle, 77);
        assert_eq!(opened.handle.open_flags, flags & 3);
        assert_eq!(opened.descriptor_flags, 1);
        assert_eq!(
            opened.rights,
            posix_protocol::shared_memory::descriptor_rights(flags & 3 == 2)
        );
        let reservation = table.fds.0.reserve_from(1, 4).unwrap();
        assert_eq!(reservation.descriptor(), 1);
        table.fds.0.cancel_reservation(&reservation);
    }
}

#[test]
fn failed_open_releases_pending_slot_and_received_handles_without_replay() {
    let _serial = SERIAL.lock().unwrap();
    for mode in [4, 5, 6, 7, 8, 9] {
        reset(mode);
        assert!(implementation::open(c"/owned".as_ptr(), 2, 0o600).is_err());
        assert_eq!(
            *CLOSED.lock().unwrap(),
            if mode == 8 { vec![] } else { vec![77] }
        );
        assert_eq!(CALLS.load(Ordering::Relaxed), u32::from(mode != 8));
        assert_slot_released();
    }
}

#[test]
fn nonlocal_exit_before_and_after_receive_reclaims_fd_reservations_and_attachments() {
    let _serial = SERIAL.lock().unwrap();
    for mode in [2, 3] {
        reset(mode);
        assert!(
            std::panic::catch_unwind(|| implementation::open(c"/owned".as_ptr(), 2, 0o600))
                .is_err()
        );
        assert_eq!(
            *CLOSED.lock().unwrap(),
            if mode == 2 { vec![77] } else { vec![] }
        );
        assert!(CONTROL.callback_resources.is_empty());
        assert_slot_released();
    }
}

#[test]
fn unlink_rejects_and_reclaims_unexpected_owned_replies() {
    let _serial = SERIAL.lock().unwrap();
    for mode in [0, 4, 5, 9] {
        reset(mode);
        let result = implementation::unlink(c"/owned".as_ptr());
        assert_eq!(result.is_ok(), mode == 0);
        assert_eq!(
            *CLOSED.lock().unwrap(),
            if mode == 0 { vec![] } else { vec![77] }
        );
        assert_slot_released();
    }
}

#[test]
fn name_is_owned_before_policy_callbacks_and_invalid_inputs_never_reserve_or_send() {
    let _serial = SERIAL.lock().unwrap();
    reset(15);
    let mut name = *b"/owned\0";
    INPUT.store(name.as_mut_ptr() as u64, Ordering::Relaxed);
    assert_eq!(implementation::open(name.as_ptr().cast(), 2, 0o600), Ok(0));
    assert_eq!(name[0], b'X');
    for name in [c"", c"/", c"missing-slash", c"/two/names"] {
        reset(0);
        assert_eq!(implementation::open(name.as_ptr(), 2, 0o600), Err(EINVAL));
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        assert_slot_released();
    }
    reset(0);
    assert_eq!(implementation::open(std::ptr::null(), 2, 0), Err(EFAULT));
    let overlong = vec![b'x'; posix_protocol::shared_memory::MAX_NAME_BYTES + 3];
    assert_eq!(
        implementation::open(overlong.as_ptr().cast(), 2, 0),
        Err(ENAMETOOLONG)
    );
    assert_slot_released();
}
