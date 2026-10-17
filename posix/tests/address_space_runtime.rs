//! Compile and run the production AS adapter with a controlled native boundary.
extern crate self as mochios_posix_client;
#[path = "../../../user/crates/posix-client/src/memory.rs"]
pub mod memory;
#[path = "../../../user/crates/posix-client/src/newlib_errno.rs"]
pub mod newlib_errno;
use core::ffi::c_int;
use mochios_posix_protocol as posix_protocol;
use std::sync::Mutex;

struct Backend {
    environment: Result<bool, i32>,
    soft: u64,
    policy_error: Option<i32>,
    native_error: Option<i32>,
    reads: usize,
    trims: usize,
    trim_error: Option<i32>,
    calls: Vec<(bool, mnu_abi::memory_map::Request)>,
}
static BACKEND: Mutex<Option<Backend>> = Mutex::new(None);
static SERIAL: Mutex<()> = Mutex::new(());
fn trim_heap_reservation() -> Result<(), i32> {
    let mut backend = BACKEND.lock().unwrap();
    let backend = backend.as_mut().unwrap();
    backend.trims += 1;
    backend.trim_error.map_or(Ok(()), Err)
}
fn has_posix_environment() -> Result<bool, i32> {
    BACKEND.lock().unwrap().as_ref().unwrap().environment
}
mod resource_policy {
    use super::*;
    pub fn read(resource: u32) -> Result<posix_protocol::ResourceLimit, i32> {
        assert_eq!(resource, posix_protocol::RLIMIT_AS);
        let mut backend = BACKEND.lock().unwrap();
        let backend = backend.as_mut().unwrap();
        backend.reads += 1;
        if let Some(error) = backend.policy_error {
            return Err(error);
        }
        Ok(posix_protocol::ResourceLimit {
            soft: backend.soft,
            hard: u64::MAX,
        })
    }
}
mod syscall {
    use super::*;
    #[derive(Debug, PartialEq)]
    pub enum SyscallNumber {
        MemoryMap,
    }
    pub struct RawResult(Result<u64, memory::Error>);
    impl RawResult {
        pub fn into_result(self) -> Result<u64, memory::Error> {
            self.0
        }
    }
    pub fn raw_syscall6(
        number: SyscallNumber,
        address: u64,
        length: u64,
        access: u64,
        options: u64,
        backing_handle: u64,
        backing_offset: u64,
    ) -> RawResult {
        assert_eq!(number, SyscallNumber::MemoryMap);
        RawResult(
            native(
                false,
                mnu_abi::memory_map::Request {
                    address,
                    length,
                    access,
                    options,
                    backing_handle,
                    backing_offset,
                    byte_ceiling: u64::MAX,
                    reserved: 0,
                },
            )
            .map_err(|error| memory::Error(-i64::from(error))),
        )
    }
    pub mod memory {
        pub use mnu_abi::memory_map::Request;
        pub struct Error(pub i64);
        impl Error {
            pub fn raw(self) -> i64 {
                self.0
            }
        }
        pub fn map_bounded(request: Request) -> Result<u64, Error> {
            super::native(true, request).map_err(|error| Error(-i64::from(error)))
        }
    }
    fn native(bounded: bool, request: mnu_abi::memory_map::Request) -> Result<u64, i32> {
        let mut backend = BACKEND.lock().unwrap();
        let backend = backend.as_mut().unwrap();
        backend.calls.push((bounded, request));
        backend.native_error.map_or(Ok(0x4000), Err)
    }
}
#[path = "../../../user/crates/newlib-runtime/src/address_space.rs"]
mod production;

fn reset(environment: Result<bool, i32>, soft: u64) {
    *BACKEND.lock().unwrap() = Some(Backend {
        environment,
        soft,
        policy_error: None,
        native_error: None,
        reads: 0,
        trims: 0,
        trim_error: None,
        calls: Vec::new(),
    });
}
fn map() -> Result<u64, i32> {
    production::current()?.map(0x10000, 8193, 3, 2, 7, 4096)
}

#[test]
fn finite_limits_use_atomic_native_admission_with_every_argument_unchanged() {
    let _serial = SERIAL.lock().unwrap();
    for soft in [0, 1, 1 << 30] {
        reset(Ok(true), soft);
        assert_eq!(map(), Ok(0x4000));
        let backend = BACKEND.lock().unwrap();
        let backend = backend.as_ref().unwrap();
        assert_eq!(backend.reads, 1);
        assert_eq!(backend.trims, 1);
        assert_eq!(
            backend.calls,
            [(
                true,
                mnu_abi::memory_map::Request {
                    address: 0x10000,
                    length: 8193,
                    access: 3,
                    options: 2,
                    backing_handle: 7,
                    backing_offset: 4096,
                    byte_ceiling: soft,
                    reserved: 0
                }
            )]
        );
    }
}

#[test]
fn unlimited_or_non_posix_processes_keep_the_direct_native_path() {
    let _serial = SERIAL.lock().unwrap();
    for (environment, soft, reads) in [(true, u64::MAX, 1), (false, 0, 0)] {
        reset(Ok(environment), soft);
        assert_eq!(map(), Ok(0x4000));
        let backend = BACKEND.lock().unwrap();
        let backend = backend.as_ref().unwrap();
        assert_eq!(backend.reads, reads);
        assert_eq!(backend.trims, 0);
        assert_eq!(backend.calls.len(), 1);
        assert!(!backend.calls[0].0);
    }
}

#[test]
fn live_policy_updates_are_not_cached_as_an_unlimited_admission_fallback() {
    let _serial = SERIAL.lock().unwrap();
    reset(Ok(true), u64::MAX);
    assert_eq!(map(), Ok(0x4000));
    BACKEND.lock().unwrap().as_mut().unwrap().soft = 4096;
    assert_eq!(map(), Ok(0x4000));
    BACKEND.lock().unwrap().as_mut().unwrap().soft = 0;
    BACKEND.lock().unwrap().as_mut().unwrap().native_error = Some(12);
    assert_eq!(map(), Err(12));
    let backend = BACKEND.lock().unwrap();
    let backend = backend.as_ref().unwrap();
    assert_eq!(backend.reads, 3);
    assert_eq!(
        backend
            .calls
            .iter()
            .map(|(bounded, request)| (*bounded, request.byte_ceiling))
            .collect::<Vec<_>>(),
        [(false, u64::MAX), (true, 4096), (true, 0)]
    );
}

#[test]
fn policy_and_native_errors_propagate_without_retrying_an_unbounded_map() {
    let _serial = SERIAL.lock().unwrap();
    reset(Err(5), 4096);
    assert_eq!(map(), Err(5));
    assert!(BACKEND.lock().unwrap().as_ref().unwrap().calls.is_empty());
    reset(Ok(true), 4096);
    BACKEND.lock().unwrap().as_mut().unwrap().trim_error = Some(12);
    assert_eq!(map(), Err(12));
    assert!(BACKEND.lock().unwrap().as_ref().unwrap().calls.is_empty());
    reset(Ok(true), 4096);
    BACKEND.lock().unwrap().as_mut().unwrap().policy_error = Some(5);
    assert_eq!(map(), Err(5));
    assert!(BACKEND.lock().unwrap().as_ref().unwrap().calls.is_empty());
    for (error, expected) in [(12, 12), (13, 13), (38, 88), (22, 22), (14, 14)] {
        reset(Ok(true), 4096);
        BACKEND.lock().unwrap().as_mut().unwrap().native_error = Some(error);
        assert_eq!(map(), Err(expected));
        assert_eq!(BACKEND.lock().unwrap().as_ref().unwrap().calls.len(), 1);
    }
}

#[test]
fn heap_snapshot_does_not_reenter_state_before_the_heap_lock() {
    let _serial = SERIAL.lock().unwrap();
    reset(Ok(true), 4096);
    production::snapshot().unwrap();
    let backend = BACKEND.lock().unwrap();
    let backend = backend.as_ref().unwrap();
    assert_eq!(
        (backend.reads, backend.trims, backend.calls.len()),
        (1, 0, 0)
    );
}

#[test]
fn all_runtime_mapping_sites_are_routed_and_state_held_callbacks_take_a_snapshot() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(!runtime.contains("SyscallNumber::MemoryMap,"));
    let semaphore = include_str!("../../../user/crates/newlib-runtime/src/named_semaphore.rs");
    assert!(!semaphore.contains("SyscallNumber::MemoryMap,"));
    let open = semaphore
        .split("pub unsafe extern \"C\" fn __mochios_sem_open(")
        .nth(1)
        .unwrap();
    assert!(open.find("address_space::current()").unwrap() < open.find("state()").unwrap());
    assert!(semaphore.contains("self.0.ok_or(EINVAL)?.map("));
    let create = runtime
        .split("pub unsafe extern \"C\" fn pthread_create(")
        .nth(1)
        .unwrap()
        .split("pub unsafe extern \"C\" fn pthread_join(")
        .next()
        .unwrap();
    assert!(
        create.find("allocate_signal_stack(control)").unwrap()
            < create.find("SyscallNumber::ThreadCreate").unwrap()
    );
}
