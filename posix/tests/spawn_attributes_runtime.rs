//! Copy opaque spawn attributes through the real checked memory boundary.
#![allow(dead_code)]
use mochios_posix_client::{spawn, upcall_guard::Guard};
use mochios_posix_protocol as posix_protocol;
use std::ffi::{c_char, c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
#[path = "../../../user/crates/newlib-runtime/src/spawn_attributes.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EINVAL: c_int = 22;
const ENOSYS: c_int = 88;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SchedParam {
    sched_priority: c_int,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PosixSpawnAttr {
    sa_flags: i16,
    sa_pgroup: c_int,
    sa_schedparam: SchedParam,
    sa_schedpolicy: c_int,
    sa_sigdefault: u64,
    sa_sigmask: u64,
}
static SERIAL: Mutex<()> = Mutex::new(());
static NATIVE: AtomicU32 = AtomicU32::new(0);
static COPY_CALLS: AtomicU32 = AtomicU32::new(0);
static SHORT_COPY_AT: AtomicU32 = AtomicU32::new(0);
fn defer_native_delivery() -> Option<Guard<'static>> {
    Guard::enter(&NATIVE)
}
mod syscall {
    pub use mnu_abi::SyscallNumber;
    pub fn raw_syscall3(
        number: SyscallNumber,
        destination: u64,
        source: u64,
        length: u64,
    ) -> Result<u64, i32> {
        assert_ne!(super::NATIVE.load(super::Ordering::Relaxed), 0);
        let call = super::COPY_CALLS.fetch_add(1, super::Ordering::Relaxed) + 1;
        if call == super::SHORT_COPY_AT.load(super::Ordering::Relaxed) {
            return Ok(length - 1);
        }
        super::user_copy_native::syscall::raw_syscall3(number, destination, source, length)
    }
}
fn syscall_errno(result: Result<u64, c_int>) -> Result<u64, c_int> {
    result
}
fn reset() {
    assert_eq!(NATIVE.load(Ordering::Relaxed), 0);
    COPY_CALLS.store(0, Ordering::Relaxed);
    SHORT_COPY_AT.store(0, Ordering::Relaxed);
    user_copy_native::DENIED.with_borrow_mut(|denied| *denied = None);
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
}
fn read(pointer: *const c_void) -> Result<Option<PosixSpawnAttr>, c_int> {
    let result = implementation::read_optional(pointer);
    assert_eq!(NATIVE.load(Ordering::Relaxed), 0);
    result
}
fn bytes(flags: i16, group: c_int) -> [u8; 32] {
    // Initialized garbage padding must not affect the decoded attributes.
    let mut bytes = [0xcc; 32];
    assert_eq!(std::mem::size_of::<PosixSpawnAttr>(), bytes.len());
    bytes[..2].copy_from_slice(&flags.to_ne_bytes());
    bytes[4..8].copy_from_slice(&group.to_ne_bytes());
    bytes[8..12].copy_from_slice(&17i32.to_ne_bytes());
    bytes[12..16].copy_from_slice(&2i32.to_ne_bytes());
    bytes[16..24].copy_from_slice(&0x1234_5678_90ab_cdefu64.to_ne_bytes());
    bytes[24..].copy_from_slice(&u64::MAX.to_ne_bytes());
    bytes
}

#[test]
fn absent_attributes_do_not_require_a_memory_access() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    assert_eq!(read(std::ptr::null()), Ok(None));
    assert_eq!(COPY_CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn unaligned_handle_and_payload_are_captured_once_without_retaining_caller_memory() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let flags = spawn::SET_PROCESS_GROUP
        | spawn::SET_SIGNAL_MASK
        | spawn::SET_SIGNAL_DEFAULTS
        | spawn::RESET_IDS;
    let mut payload = [0; 33];
    payload[1..].copy_from_slice(&bytes(flags, 73));
    let pointer = payload.as_ptr().wrapping_add(1) as usize;
    let mut handle = [0; 9];
    handle[1..].copy_from_slice(&pointer.to_ne_bytes());
    let value = read(handle.as_ptr().wrapping_add(1).cast())
        .unwrap()
        .unwrap();
    payload.fill(0);
    handle.fill(0);
    assert_eq!(
        value,
        PosixSpawnAttr {
            sa_flags: flags,
            sa_pgroup: 73,
            sa_schedparam: SchedParam { sched_priority: 17 },
            sa_schedpolicy: 2,
            sa_sigdefault: 0x1234_5678_90ab_cdef,
            sa_sigmask: u64::MAX,
        }
    );
    assert_eq!(COPY_CALLS.load(Ordering::Relaxed), 2);
    user_copy_native::CALLS.with_borrow(|calls| assert_eq!(&calls[..], &[8, 32]));
}

#[test]
fn invalid_outer_or_inner_pointers_return_errors_without_raw_loads() {
    let _serial = SERIAL.lock().unwrap();
    for pointer in [1usize, usize::MAX] {
        reset();
        assert_eq!(read(pointer as *const _), Err(EFAULT));
    }
    for pointer in [0usize, 1, usize::MAX] {
        reset();
        let handle = pointer.to_ne_bytes();
        assert_eq!(
            read(handle.as_ptr().cast()),
            Err(if pointer == 0 { EINVAL } else { EFAULT })
        );
    }
}

#[test]
fn unsupported_flags_and_group_validation_keep_existing_error_semantics() {
    let _serial = SERIAL.lock().unwrap();
    for (flags, group, expected) in [
        (spawn::SET_PROCESS_GROUP, -1, Err(EINVAL)),
        (spawn::SET_SCHEDULER, 0, Err(ENOSYS)),
        (spawn::SET_SCHEDULING_PARAMETERS, 0, Err(ENOSYS)),
        (0x40, 0, Err(EINVAL)),
        (i16::MIN, 0, Err(EINVAL)),
        (-1, 0, Err(EINVAL)),
        (
            spawn::SET_SCHEDULER | spawn::SET_PROCESS_GROUP,
            -1,
            Err(EINVAL),
        ),
        (spawn::SET_PROCESS_GROUP, 0, Ok(())),
        (0, -1, Ok(())),
    ] {
        reset();
        let payload = bytes(flags, group);
        let handle = (payload.as_ptr() as usize).to_ne_bytes();
        let result = read(handle.as_ptr().cast());
        assert_eq!(result.map(|_| ()), expected);
        assert_eq!(COPY_CALLS.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn incomplete_payload_or_short_native_copies_cannot_publish_attributes() {
    let _serial = SERIAL.lock().unwrap();
    reset();
    let payload = bytes(0, 0);
    let handle = (payload.as_ptr() as usize).to_ne_bytes();
    user_copy_native::DENIED.with_borrow_mut(|denied| {
        *denied = Some(payload.as_ptr() as usize + 31..payload.as_ptr() as usize + 32);
    });
    assert_eq!(read(handle.as_ptr().cast()), Err(EFAULT));
    for call in [1, 2] {
        reset();
        SHORT_COPY_AT.store(call, Ordering::Relaxed);
        assert_eq!(read(handle.as_ptr().cast()), Err(EIO));
        assert_eq!(COPY_CALLS.load(Ordering::Relaxed), call);
    }
}

#[test]
fn spawn_validates_captured_attributes_before_creating_native_resources() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let source = &source[source.find("pub extern \"C\" fn _posix_spawn(").unwrap()..];
    let source = &source[..source.find("pub extern \"C\" fn posix_spawn(").unwrap()];
    let capture = source
        .find("spawn_attributes::read_optional(attrp)")
        .unwrap();
    assert!(capture < source.find("spawn_resources::with(").unwrap());
    assert!(capture < source.find("resources.clone_registered()").unwrap());
    assert!(!source.contains("attrp.cast"));
}
