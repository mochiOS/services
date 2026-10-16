//! Execute the production native receive-envelope owner and client validator.
#![allow(dead_code)]
use mochios_posix_client::upcall_guard::Guard;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectTransport, Transport,
};
use mochios_posix_protocol as posix_protocol;
use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/mapping_backing.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
const EAGAIN: c_int = 11;
const EBADF: c_int = 9;
const EIO: c_int = 5;
static SERIAL: Mutex<()> = Mutex::new(());
static MODE: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
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
    assert_ne!(handle, 99, "borrowed source was closed");
    let mut closed = CLOSED.lock().unwrap();
    assert!(!closed.contains(&handle), "received reference closed twice");
    closed.push(handle);
}
#[derive(Clone, Copy)]
struct FdObject {
    lower_handle: u64,
}
#[derive(Clone, Copy)]
struct FdEntry {
    handle: FdObject,
    rights: u64,
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
        panic!("unscoped transport")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, _: u32) {
        panic!("unscoped transport")
    }
    fn call_with_handles(
        &self,
        _: &[u8],
        _: &mut [u8],
        _: &mut mochios_posix_client::ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        panic!("unscoped transport")
    }
}
fn posix_client() -> Result<Client<Mock>, ClientError<()>> {
    Ok(Client::new(Mock))
}
fn map_posix_client_error(error: ClientError<()>) -> c_int {
    match error {
        ClientError::Remote(value) => -value,
        _ => EIO,
    }
}
fn syscall_errno(value: Result<u64, c_int>) -> Result<u64, c_int> {
    value
}
fn entry() -> FdEntry {
    FdEntry {
        handle: FdObject { lower_handle: 99 },
        rights: mochios_posix_client::shared_memory::rights(true),
    }
}
fn escape() -> ! {
    let _native = defer_native_delivery();
    unsafe { CONTROL.callback_resources.abandon_from(0) };
    // Model the no-return transition; never resume the abandoned operation.
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
        CALLS.fetch_add(1, Ordering::Relaxed);
        let input = unsafe { std::slice::from_raw_parts(input as *const u8, input_len as usize) };
        let (header, payload) = posix_protocol::decode(input).unwrap();
        assert_eq!(header.opcode, posix_protocol::OP_SHARED_MEMORY_BACKING);
        let writable = u32::from_le_bytes(payload.try_into().unwrap()) != 0;
        let native = unsafe { &mut *(envelope as *mut IpcObjectHandles) };
        assert_eq!(native.count, 1);
        assert_eq!(native.handles[0].handle, 99);
        assert_eq!(
            native.handles[0].rights & mnu_abi::HANDLE_RIGHT_WRITE != 0,
            writable
        );
        let mode = MODE.load(Ordering::Relaxed);
        if mode == 1 {
            return Err(4);
        }
        *native = IpcObjectHandles::default();
        native.count = 1;
        native.handles[0].handle = 77;
        native.handles[0].rights = posix_protocol::shared_memory::mapping_rights(writable);
        match mode {
            4 => {
                native.count = 5;
                for (slot, handle) in native.handles.iter_mut().zip([77, 78, 77, 99]) {
                    slot.handle = handle;
                }
            }
            5 => native.handles[0].rights ^= mnu_abi::HANDLE_RIGHT_WRITE,
            6 => native.handles[0].handle = 99,
            7 => native.handles[0].reserved = 1,
            8 => native.count = 0,
            12 => native.handles[0].handle = 0,
            13 => native.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
            14 => {
                native.count = 2;
                native.handles[1] = native.handles[0];
            }
            _ => {}
        }
        if mode == 16 {
            escape();
        }
        if mode == 2 {
            return Err(5);
        }
        let output =
            unsafe { std::slice::from_raw_parts_mut(output as *mut u8, capacity as usize) };
        let length = posix_protocol::encode(
            posix_protocol::Header {
                opcode: posix_protocol::OP_STATUS,
                request_id: header.request_id + u64::from(mode == 15),
                flags: u32::from(mode == 3),
                status: if mode == 11 { -38 } else { 0 },
                payload_len: 0,
            },
            &[],
            output,
        )
        .unwrap();
        if mode == 9 {
            output[0] = 0xff;
        }
        if mode == 10 {
            return Ok(capacity + 1);
        }
        Ok((123u64 << 32) | length as u64)
    }
}
fn reset(mode: u32) {
    assert!(CONTROL.callback_resources.is_empty());
    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    MODE.store(mode, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    CLOSED.lock().unwrap().clear();
}

#[test]
fn valid_backing_is_lent_through_consumption_and_closed_on_success_or_map_error() {
    let _serial = SERIAL.lock().unwrap();
    for writable in [false, true] {
        for outcome in [Ok(0x10000), Err(12), Err(13)] {
            reset(0);
            assert_eq!(
                implementation::with(entry(), writable, |handle| {
                    assert_eq!(handle, 77);
                    assert!(CLOSED.lock().unwrap().is_empty());
                    assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
                    assert!(!CONTROL.callback_resources.is_deferred());
                    outcome
                }),
                outcome
            );
            assert_eq!(*CLOSED.lock().unwrap(), vec![77]);
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
            assert!(CONTROL.callback_resources.is_empty());
        }
    }
}

#[test]
fn all_failed_native_and_protocol_shapes_close_only_distinct_new_attachments() {
    let _serial = SERIAL.lock().unwrap();
    for mode in 1..=15 {
        reset(mode);
        assert!(
            implementation::with(entry(), false, |_| -> Result<(), c_int> {
                panic!("invalid reply reached mapper")
            })
            .is_err()
        );
        let expected = match mode {
            1 | 6 | 8 | 12 => vec![],
            4 => vec![77, 78],
            _ => vec![77],
        };
        assert_eq!(*CLOSED.lock().unwrap(), expected, "mode {mode}");
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert!(CONTROL.callback_resources.is_empty());
    }
}

#[test]
fn nonreturning_exit_at_native_return_and_during_map_reclaims_received_ownership() {
    let _serial = SERIAL.lock().unwrap();
    for mode in [16, 17] {
        reset(mode);
        let result = std::panic::catch_unwind(|| {
            implementation::with(entry(), false, |_| -> Result<(), c_int> { escape() })
        });
        assert!(result.is_err());
        assert_eq!(*CLOSED.lock().unwrap(), vec![77]);
        assert!(CONTROL.callback_resources.is_empty());
        assert_eq!(CONTROL.native.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn missing_descriptor_authority_fails_without_entering_ipc_or_closing_the_borrow() {
    let _serial = SERIAL.lock().unwrap();
    reset(0);
    let mut descriptor = entry();
    descriptor.rights &= !mnu_abi::HANDLE_RIGHT_WRITE;
    assert_eq!(implementation::with(descriptor, true, |_| Ok(())), Err(13));
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    assert!(CLOSED.lock().unwrap().is_empty());
}

#[test]
fn prepared_requests_use_the_clients_request_sequence_and_attenuate_authority() {
    let client = Client::new(Mock);
    let descriptor = ObjectHandleAttachment {
        handle: 99,
        rights: mochios_posix_client::shared_memory::rights(true),
    };
    let first = client
        .prepare_shared_memory_backing(descriptor, false)
        .unwrap();
    let second = client
        .prepare_shared_memory_backing(descriptor, true)
        .unwrap();
    let (a, payload_a) = posix_protocol::decode(first.request()).unwrap();
    let (b, payload_b) = posix_protocol::decode(second.request()).unwrap();
    assert_eq!(b.request_id, a.request_id + 1);
    assert_eq!(payload_a, &0u32.to_le_bytes());
    assert_eq!(payload_b, &1u32.to_le_bytes());
    assert_eq!(first.descriptor().rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
    assert_ne!(second.descriptor().rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
    assert_eq!(first.descriptor().rights & mnu_abi::HANDLE_RIGHT_MAP, 0);
}

#[test]
fn backing_replies_reject_positive_and_unrelated_admission_statuses() {
    let client = Client::new(Mock);
    let prepared = client
        .prepare_shared_memory_backing(
            ObjectHandleAttachment {
                handle: 99,
                rights: mochios_posix_client::shared_memory::rights(true),
            },
            false,
        )
        .unwrap();
    let (request, _) = posix_protocol::decode(prepared.request()).unwrap();
    let mut handles = mochios_posix_client::ObjectHandles::new();
    handles
        .push(ObjectHandleAttachment {
            handle: 77,
            rights: posix_protocol::shared_memory::mapping_rights(false),
        })
        .unwrap();
    for status in [1, posix_protocol::STATUS_MEMORY_ADMISSION_BUSY] {
        let mut response = [0; posix_protocol::HEADER_LEN];
        posix_protocol::encode(
            posix_protocol::Header {
                opcode: posix_protocol::OP_STATUS,
                request_id: request.request_id,
                flags: 0,
                status,
                payload_len: 0,
            },
            &[],
            &mut response,
        )
        .unwrap();
        assert_eq!(
            prepared.validate::<()>(&response, &handles),
            Err(ClientError::MismatchedResponse)
        );
        assert_eq!(handles.len(), 1, "validation must not transfer ownership");
    }
}
