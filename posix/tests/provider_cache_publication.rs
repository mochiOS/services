//! Production VM object/cache code; substitute only IPC, scheduling, physical
//! frames and interrupt locks. Interleave mutations at the actual lock edges.
#![allow(dead_code)]
extern crate alloc;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const EXTENT_NOT_READY: u64 = mnu_abi::status::Error::NotReady.into_raw();
const EXTENT_BACKING_FAILURE: u64 = mnu_abi::status::Error::BackingFailure.into_raw();
const EXTENT_INVALID_ARGUMENT: u64 = mnu_abi::status::Error::InvalidArgument.into_raw();

thread_local! {
    static DENY_COMMIT_ALLOC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static COMMIT_ALLOC_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PHYSICAL_OFFSET: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(Some(0)) };
    static FAIL_MAPPING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CAPTURE_GATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CAPTURED_GATE: RefCell<Option<object_io::IoLock>> = const { RefCell::new(None) };
}
struct FaultAllocator;
unsafe impl std::alloc::GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if DENY_COMMIT_ALLOC.with(|deny| deny.get()) {
            COMMIT_ALLOC_ATTEMPTS.with(|count| count.set(count.get() + 1));
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if DENY_COMMIT_ALLOC.with(|deny| deny.get()) {
            COMMIT_ALLOC_ATTEMPTS.with(|count| count.set(count.get() + 1));
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

#[test]
fn failed_intent_allocation_leaves_backing_admission_unchanged() {
    let lock = object_io::IoLock::from_allocated(Arc::new(object_io::State::new(|_| {})));
    let generation = lock.generation();
    let existing = lock.try_lock().unwrap().unwrap();
    DENY_COMMIT_ALLOC.with(|deny| deny.set(true));
    let result = lock.intent();
    DENY_COMMIT_ALLOC.with(|deny| deny.set(false));
    assert!(matches!(result, Err(object_io::IntentError::NoMemory)));
    assert_eq!(lock.generation(), generation);
    assert!(!lock.is_reserved());
    assert!(lock.try_lock().unwrap().is_none());
    drop(existing);
    assert!(lock.try_lock().unwrap().is_some());
    let mut retry = lock.intent().unwrap();
    assert!(retry.try_acquire().unwrap().is_some());
}

#[test]
fn intent_polling_cancellation_and_guard_handoff_never_allocate() {
    let lock = object_io::IoLock::from_allocated(Arc::new(object_io::State::new(|_| {})));
    let existing = lock.try_lock().unwrap().unwrap();
    let mut first = lock.intent().unwrap();
    let middle = lock.intent().unwrap();
    let mut last = lock.intent().unwrap();
    without_allocations(|| {
        assert!(first.try_acquire().unwrap().is_none());
        drop(middle);
        assert!(last.try_acquire().unwrap().is_none());
        drop(existing);
        assert!(lock.try_lock().unwrap().is_none());
        let owner = first.try_acquire().unwrap().unwrap();
        drop(first);
        assert!(last.try_acquire().unwrap().is_none());
        drop(owner);
        let owner = last.try_acquire().unwrap().unwrap();
        drop(last);
        drop(owner);
        assert!(lock.try_lock().unwrap().is_some());
    });
}

fn without_allocations<T>(operation: impl FnOnce() -> T) -> T {
    COMMIT_ALLOC_ATTEMPTS.with(|count| count.set(0));
    DENY_COMMIT_ALLOC.with(|deny| deny.set(true));
    let result = operation();
    DENY_COMMIT_ALLOC.with(|deny| deny.set(false));
    assert_eq!(COMMIT_ALLOC_ATTEMPTS.with(|count| count.get()), 0);
    result
}

thread_local! {
    static CACHE_EDGE: RefCell<Option<(usize, Box<dyn FnOnce()>)>> = RefCell::new(None);
    static LOWER_EDGE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    static SYNC_ERROR: Cell<Option<u64>> = const { Cell::new(None) };
    static SYNC_CALLS: Cell<usize> = const { Cell::new(0) };
    static INVALID_READ_COUNT: Cell<bool> = const { Cell::new(false) };
    static INVALID_WRITE_COUNT: Cell<bool> = const { Cell::new(false) };
    static READ_FAILURE: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

fn cache_edge<T>() {
    if !std::any::type_name::<T>().contains("CachedPage") {
        return;
    }
    let hook = CACHE_EDGE.with(|edge| {
        let mut edge = edge.borrow_mut();
        match edge.as_mut() {
            Some((remaining, _)) if *remaining > 1 => {
                *remaining -= 1;
                None
            }
            Some(_) => edge.take().map(|(_, hook)| hook),
            None => None,
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T> {
            pub const fn new(value: T) -> Self {
                Self(std::sync::Mutex::new(value))
            }
            pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
                crate::cache_edge::<T>();
                self.0.lock().unwrap()
            }
            pub fn try_lock(&self) -> Option<std::sync::MutexGuard<'_, T>> {
                self.0.try_lock().ok()
            }
        }
    }
}

mod task {
    pub struct MemoryRegion {
        pub start: u64,
        pub length: u64,
        pub object: Option<std::sync::Arc<crate::vm_object::VmObject>>,
    }
    impl MemoryRegion {
        pub fn start(&self) -> u64 {
            self.start
        }
        pub fn end(&self) -> Option<u64> {
            self.start.checked_add(self.length)
        }
        pub fn backing(&self) -> &Self {
            self
        }
        pub fn file_object(&self) -> Option<&std::sync::Arc<crate::vm_object::VmObject>> {
            self.object.as_ref()
        }
    }
    pub struct ProviderObject {
        pub endpoint_thread_id: u64,
        pub endpoint_slot: u16,
        pub endpoint_generation: u64,
    }
    pub fn yield_now() {
        std::thread::yield_now();
    }
    pub mod process {
        pub fn resize_shared_memory(
            _: &crate::shared_memory::SharedMemory,
            _: u64,
        ) -> Result<(), mnu_abi::status::Error> {
            unreachable!("provider-only probe")
        }
    }
}

struct Lower {
    bytes: Vec<u8>,
    reads: usize,
}
static LOWER: Mutex<Lower> = Mutex::new(Lower {
    bytes: Vec::new(),
    reads: 0,
});

mod syscall {
    pub const EACCES: u64 = (-13i64) as u64;
    pub const EINVAL: u64 = (-22i64) as u64;
    pub const ENOMEM: u64 = (-12i64) as u64;
    pub const EIO: u64 = (-5i64) as u64;
    pub const EAGAIN: u64 = (-11i64) as u64;
    pub mod handle {
        pub fn provider_read_at(
            _: &crate::task::ProviderObject,
            offset: u64,
            output: &mut [u8],
        ) -> Result<usize, u64> {
            if let Some((start, error)) = crate::READ_FAILURE.with(|value| value.get()) {
                if offset >= start {
                    return Err(error);
                }
            }
            if crate::INVALID_READ_COUNT.with(|value| value.get()) {
                return Ok(output.len() + 1);
            }
            let count = {
                let mut lower = crate::LOWER.lock().unwrap();
                lower.reads += 1;
                let start = usize::try_from(offset)
                    .map_err(|_| super::EINVAL)?
                    .min(lower.bytes.len());
                let count = output.len().min(lower.bytes.len() - start);
                output[..count].copy_from_slice(&lower.bytes[start..start + count]);
                count
            };
            let hook = crate::LOWER_EDGE.with(|edge| edge.borrow_mut().take());
            if let Some(hook) = hook {
                hook();
            }
            Ok(count)
        }
        pub fn provider_write_at(
            _: &crate::task::ProviderObject,
            offset: u64,
            input: &[u8],
        ) -> Result<usize, u64> {
            if crate::INVALID_WRITE_COUNT.with(|value| value.get()) {
                return Ok(input.len() + 1);
            }
            let start = usize::try_from(offset).map_err(|_| super::EINVAL)?;
            let mut lower = crate::LOWER.lock().unwrap();
            let length = (start + input.len()).max(lower.bytes.len());
            lower.bytes.resize(length, 0);
            lower.bytes[start..start + input.len()].copy_from_slice(input);
            Ok(input.len())
        }
        pub fn provider_sync(_: &crate::task::ProviderObject) -> Result<(), u64> {
            crate::SYNC_CALLS.with(|calls| calls.set(calls.get() + 1));
            crate::SYNC_ERROR.with(|error| error.get().map_or(Ok(()), Err))
        }
    }
}

// Only provider backing is used. RAM is a separate production implementation
// with its own generation/revocation tests.
mod shared_memory {
    pub struct SharedMemory;
    impl SharedMemory {
        pub fn id(&self) -> u64 {
            unreachable!()
        }
        pub fn length(&self) -> u64 {
            unreachable!()
        }
        pub fn generation(&self) -> u64 {
            unreachable!()
        }
        pub fn with_generation_native<T>(
            &self,
            _: u64,
            _: impl FnOnce() -> Result<T, mnu_abi::status::Error>,
        ) -> Result<T, mnu_abi::status::Error> {
            unreachable!()
        }
        pub fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize, mnu_abi::status::Error> {
            unreachable!()
        }
        pub fn write_at(&self, _: u64, _: &[u8]) -> Result<usize, mnu_abi::status::Error> {
            unreachable!()
        }
        pub fn prepare_page(&self, _: u64) -> Result<(u64, u64), mnu_abi::status::Error> {
            unreachable!()
        }
    }
}

static FRAMES: Mutex<BTreeMap<u64, usize>> = Mutex::new(BTreeMap::new());
static MAPPING_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static GATE_ALLOCS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FAIL_GATE_ALLOC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kernel {
    Memory(result::Memory),
}
mod result {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Memory {
        Busy,
        InvalidAddress,
    }
    pub type Result<T> = core::result::Result<T, crate::Kernel>;
}
mod frame {
    pub struct Frame(pub u64);
    impl Frame {
        pub fn start_address(&self) -> Address {
            Address(self.0)
        }
    }
    pub struct Address(u64);
    impl Address {
        pub fn as_u64(&self) -> u64 {
            self.0
        }
    }
    pub fn allocate_zeroed_frame() -> Result<Frame, ()> {
        let frame = Box::into_raw(Box::new([0u8; 4096])) as u64;
        crate::FRAMES.lock().unwrap().insert(frame, 1);
        Ok(Frame(frame))
    }
    pub fn deallocate_frame(frame: Frame) -> Result<(), ()> {
        super::paging::release_user_frame(frame.0);
        Ok(())
    }
}
mod paging {
    pub fn physical_memory_offset() -> Option<u64> {
        crate::PHYSICAL_OFFSET.with(std::cell::Cell::get)
    }
    pub fn retain_shared_user_frame(frame: u64) -> Result<(), ()> {
        *crate::FRAMES.lock().unwrap().get_mut(&frame).ok_or(())? += 1;
        Ok(())
    }
    pub fn user_frame_has_multiple_owners(frame: u64) -> bool {
        crate::FRAMES
            .lock()
            .unwrap()
            .get(&frame)
            .copied()
            .unwrap_or(0)
            > 1
    }
    pub fn release_user_frame(frame: u64) {
        let mut frames = crate::FRAMES.lock().unwrap();
        let count = frames.get_mut(&frame).expect("frame double release");
        *count -= 1;
        if *count == 0 {
            frames.remove(&frame);
            unsafe {
                drop(Box::from_raw(frame as *mut [u8; 4096]));
            }
        }
    }
    pub fn map_shared_frame_to_user(
        _: u64,
        _: u64,
        frame: u64,
        _: bool,
        _: bool,
    ) -> Result<(), ()> {
        assert!(crate::FRAMES.lock().unwrap().contains_key(&frame));
        crate::MAPPING_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if crate::FAIL_MAPPING.get() {
            Err(())
        } else {
            Ok(())
        }
    }
}

#[path = "../../../core/src/mem/byte_extent.rs"]
pub mod byte_extent;
#[path = "../../../core/src/mem/cache_range.rs"]
pub mod cache_range;
#[path = "../../../core/src/mem/mapping_admission.rs"]
mod mapping_admission;
#[path = "../../../core/src/mem/object_io.rs"]
pub mod object_io;
#[path = "../../../core/src/mem/shared_pages.rs"]
pub mod shared_pages;
#[path = "../../../core/src/mem/vm_object.rs"]
pub mod vm_object;
mod mem {
    pub(crate) use crate::{byte_extent, frame, paging, shared_pages};
    pub(crate) mod object_io_native {
        pub fn new_lock() -> Result<crate::object_io::IoLock, mnu_abi::status::Error> {
            crate::GATE_ALLOCS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if crate::FAIL_GATE_ALLOC.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(mnu_abi::status::Error::ResourceUnavailable);
            }
            let gate = crate::object_io::IoLock::from_allocated(std::sync::Arc::new(
                crate::object_io::State::new(|_| {}),
            ));
            if crate::CAPTURE_GATE.with(std::cell::Cell::get) {
                crate::CAPTURED_GATE.with(|slot| *slot.borrow_mut() = Some(gate.clone()));
            }
            Ok(gate)
        }
    }
}

fn provider_object() -> vm_object::VmObject {
    provider_object_for_endpoint(17)
}

fn provider_object_for_endpoint(thread_id: u64) -> vm_object::VmObject {
    vm_object::VmObject::provider(
        Arc::new(task::ProviderObject {
            endpoint_thread_id: thread_id,
            endpoint_slot: 2,
            endpoint_generation: 8,
        }),
        93,
    )
    .unwrap()
}

#[test]
fn scoped_admission_cannot_be_retargeted_or_consumed_twice_and_preserves_guard_identity() {
    let _serial = TEST_LOCK.lock().unwrap();
    let object = provider_object_for_endpoint(117);
    let key = object.object_key();
    let admission = vm_object::ProviderAdmission::new(key).unwrap();
    assert_eq!(admission.signals(), mnu_abi::HANDLE_SIGNAL_READABLE);
    let wrong = vm_object::ObjectKey::Provider {
        endpoint_thread_id: 117,
        endpoint_slot: 2,
        endpoint_generation: 8,
        identity: 94,
    };
    assert!(matches!(
        admission.acquire(wrong),
        Err(mnu_abi::status::Error::AccessDenied)
    ));
    assert_eq!(admission.signals(), mnu_abi::HANDLE_SIGNAL_READABLE);
    let guard = admission.acquire(key).unwrap();
    assert_eq!(guard.key(), key);
    assert_eq!(admission.signals(), mnu_abi::HANDLE_SIGNAL_PEER_CLOSED);
    assert!(matches!(
        admission.acquire(key),
        Err(mnu_abi::status::Error::InvalidArgument)
    ));
    let mut extent =
        vm_object::PreparedExtent::prepare_admitted(guard, 3, 1, |bytes| Ok(Arc::new(bytes)))
            .unwrap();
    // Cancelling an acquired ticket cannot unlock a prepared update.
    drop(admission);
    assert!(matches!(
        object.prepare_extent(3, 1, |_| panic!("must stay excluded")),
        Err(EXTENT_NOT_READY)
    ));
    extent.preflight().unwrap();
    drop(extent);
    assert!(
        object
            .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
            .is_ok()
    );
}

#[test]
fn native_admission_distinguishes_contention_capacity_consumption_and_failure() {
    use mnu_abi::status::Error;
    let _serial = TEST_LOCK.lock().unwrap();
    let provider = Arc::new(task::ProviderObject {
        endpoint_thread_id: 119,
        endpoint_slot: 2,
        endpoint_generation: 8,
    });
    CAPTURE_GATE.set(true);
    let object = vm_object::VmObject::provider(provider.clone(), 93).unwrap();
    CAPTURE_GATE.set(false);
    let gate = CAPTURED_GATE.with(|slot| slot.borrow_mut().take()).unwrap();
    let key = object.object_key();
    let owner = vm_object::lock_provider_io(&provider, 93).unwrap();
    let admission = vm_object::ProviderAdmission::new(key).unwrap();
    assert!(matches!(admission.acquire(key), Err(Error::NotReady)));
    admission.register_waiter(7, 1).unwrap();
    admission.register_waiter(7, 0).unwrap(); // Existing registration is idempotent.
    assert_eq!(admission.register_waiter(8, 1), Err(Error::LimitExceeded));
    admission.remove_waiter(7);
    admission.register_waiter(8, 1).unwrap();
    drop(owner);
    let acquired = admission.acquire(key).unwrap();
    assert!(matches!(admission.acquire(key), Err(Error::InvalidArgument)));
    drop(acquired);
    let reservation = gate.try_lock().unwrap().unwrap().reserve();
    reservation.mark_unavailable();
    assert!(matches!(
        vm_object::ProviderAdmission::new(key),
        Err(Error::BackingFailure)
    ));
    drop(reservation);
    assert!(matches!(
        vm_object::ProviderAdmission::new(vm_object::ObjectKey::Memory(1)),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn admitted_prepare_failure_consumes_position_but_releases_io_without_invalidating_data() {
    let _serial = TEST_LOCK.lock().unwrap();
    let object = provider_object_for_endpoint(118);
    let key = object.object_key();
    let generation = object.memory_generation();
    let first = vm_object::ProviderAdmission::new(key).unwrap();
    let second = vm_object::ProviderAdmission::new(key).unwrap();
    let guard = first.acquire(key).unwrap();
    assert!(matches!(
        vm_object::PreparedExtent::prepare_admitted(guard, 3, 1, |_| Err(syscall::ENOMEM)),
        Err(syscall::ENOMEM)
    ));
    assert_eq!(first.signals(), mnu_abi::HANDLE_SIGNAL_PEER_CLOSED);
    assert_eq!(second.signals(), mnu_abi::HANDLE_SIGNAL_READABLE);
    assert_eq!(object.memory_generation(), generation);
    drop(second);
    assert!(
        object
            .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
            .is_ok()
    );
}

#[test]
fn waiter_allocation_failure_does_not_change_queue_readiness_or_reserve_data() {
    let lock = object_io::IoLock::from_allocated(Arc::new(object_io::State::new(|_| {})));
    let intent = lock.intent().unwrap();
    let generation = lock.generation();
    DENY_COMMIT_ALLOC.with(|deny| deny.set(true));
    let result = intent.register_waiter(1, 10);
    DENY_COMMIT_ALLOC.with(|deny| deny.set(false));
    assert_eq!(result, Err(object_io::IntentError::NoMemory));
    assert!(intent.ready().unwrap());
    assert!(!lock.is_reserved());
    assert_eq!(lock.generation(), generation);
    intent.register_waiter(1, 10).unwrap();
    without_allocations(|| intent.remove_waiter(1));
}

fn reset_lower(bytes: &[u8]) {
    *LOWER.lock().unwrap() = Lower {
        bytes: bytes.to_vec(),
        reads: 0,
    };
}

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn backing_read_errors_preserve_completed_prefix_without_caching_a_false_eof() {
    let _serial = TEST_LOCK.lock().unwrap();
    let object = provider_object_for_endpoint(0x1a03);
    let mut backing = vec![b'a'; 4096];
    backing.extend_from_slice(&[b'b'; 4096]);
    for error in [
        mnu_abi::status::Error::BackingFailure.into_raw(),
        mnu_abi::status::Error::ResourceUnavailable.into_raw(),
        mnu_abi::status::Error::PeerClosed.into_raw(),
        syscall::EIO,
        syscall::EAGAIN,
    ] {
        object.invalidate().unwrap();
        reset_lower(&backing);
        READ_FAILURE.with(|value| value.set(Some((4096, error))));
        let mut output = [0x5a; 8192];
        let result = object.read_at(0, &mut output);
        READ_FAILURE.with(|value| value.set(None));
        assert_eq!(result, Ok(4096));
        assert_eq!(&output[..4096], &[b'a'; 4096]);
        assert_eq!(&output[4096..], &[0x5a; 4096]);

        // A failed later page is not EOF. A new read beginning at that page
        // must still report the error, and recovery must retry its backing.
        READ_FAILURE.with(|value| value.set(Some((4096, error))));
        let result = object.read_at(4096, &mut output[..4096]);
        let fault = object.page(1);
        READ_FAILURE.with(|value| value.set(None));
        assert_eq!(result, Err(error));
        assert!(matches!(fault, Err(vm_object::VmPageError::Operation(value)) if value == error));
        assert_eq!(object.read_at(4096, &mut output[..4096]), Ok(4096));
        assert_eq!(&output[..4096], &[b'b'; 4096]);

        object.invalidate().unwrap();
        READ_FAILURE.with(|value| value.set(Some((4096, error))));
        let mut unaligned = [0x5a; 12];
        let result = object.read_at(4090, &mut unaligned);
        READ_FAILURE.with(|value| value.set(None));
        assert_eq!(result, Ok(6));
        assert_eq!(&unaligned[..6], &[b'a'; 6]);
        assert_eq!(&unaligned[6..], &[0x5a; 6]);

        object.invalidate().unwrap();
        READ_FAILURE.with(|value| value.set(Some((0, error))));
        let mut untouched = [0x5a; 8];
        let result = object.read_at(0, &mut untouched);
        READ_FAILURE.with(|value| value.set(None));
        assert_eq!(result, Err(error));
        assert_eq!(untouched, [0x5a; 8]);
    }
    object.invalidate().unwrap();
}

#[test]
fn native_vm_io_rejects_overflow_before_backing_access_and_empty_writes_do_no_io() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset_lower(b"unchanged");
    let object = provider_object_for_endpoint(0x1a01);
    let mut output = [0x5a; 2];
    for offset in [u64::MAX, u64::MAX - 1] {
        assert_eq!(
            object.read_at(offset, &mut output),
            Err(mnu_abi::status::Error::LimitExceeded.into_raw())
        );
        assert_eq!(
            object.write_at(offset, b"xy"),
            Err(mnu_abi::status::Error::LimitExceeded.into_raw())
        );
    }
    assert_eq!(output, [0x5a; 2]);
    assert_eq!(object.read_at(u64::MAX, &mut []), Ok(0));
    assert_eq!(object.write_at(u64::MAX, &[]), Ok(0));
    let owner = task::ProviderObject {
        endpoint_thread_id: 0x1a01,
        endpoint_slot: 1,
        endpoint_generation: 1,
    };
    assert_eq!(
        vm_object::overlay_provider_range(&owner, 93, u64::MAX, &mut output),
        Err(mnu_abi::status::Error::LimitExceeded.into_raw())
    );
    assert_eq!(output, [0x5a; 2]);
    let lower = LOWER.lock().unwrap();
    assert_eq!(lower.reads, 0);
    assert_eq!(lower.bytes, b"unchanged");
}

#[test]
fn impossible_backing_counts_return_native_failure_without_publishing_cache_bytes() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let object = provider_object_for_endpoint(0x1a02);
    let mut output = [0x5a; 3];
    INVALID_READ_COUNT.with(|value| value.set(true));
    let result = object.read_at(0, &mut output);
    INVALID_READ_COUNT.with(|value| value.set(false));
    assert_eq!(result, Err(mnu_abi::status::Error::BackingFailure.into_raw()));
    assert_eq!(output, [0x5a; 3]);
    assert_eq!(object.read_at(0, &mut output), Ok(3));
    assert_eq!(&output, b"old");

    INVALID_WRITE_COUNT.with(|value| value.set(true));
    let result = object.write_at(0, b"new");
    INVALID_WRITE_COUNT.with(|value| value.set(false));
    assert_eq!(result, Err(mnu_abi::status::Error::BackingFailure.into_raw()));
    assert_eq!(object.read_at(0, &mut output), Ok(3));
    assert_eq!(&output, b"old");
    assert_eq!(LOWER.lock().unwrap().bytes, b"old");
}

#[test]
fn production_cache_never_republishes_invalidated_lower_snapshots() {
    let _test = TEST_LOCK.lock().unwrap();
    let initial_gates = GATE_ALLOCS.load(std::sync::atomic::Ordering::Relaxed);
    let object = provider_object();
    reset_lower(b"old");
    // The lower read has copied old bytes, but a completed write did not find
    // a resident page to update. Epoch rejection must cause a new lower read.
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object().write_at(0, b"new").unwrap();
        }))
    });
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate().unwrap();

    reset_lower(b"old");
    // A new resident page wins over the in-flight lower snapshot instead of
    // forcing another lower read or overwriting the staged dirty bytes.
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object().stage_write_at(0, b"new").unwrap();
        }))
    });
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate().unwrap();

    reset_lower(b"old");
    // The third lock is final shared-frame preparation, after loading and
    // admitting the page. Revoke it before that lock is acquired.
    CACHE_EDGE.with(|edge| {
        *edge.borrow_mut() = Some((
            3,
            Box::new(|| {
                provider_object().invalidate().unwrap();
                LOWER.lock().unwrap().bytes = b"new".to_vec();
            }),
        ))
    });
    let prepared = object.prepare_shared_page(0).unwrap();
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    drop(prepared);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());

    reset_lower(b"old");
    CACHE_EDGE.with(|edge| {
        *edge.borrow_mut() = Some((
            3,
            Box::new(|| {
                provider_object().invalidate().unwrap();
                LOWER.lock().unwrap().bytes = b"new".to_vec();
            }),
        ))
    });
    object.stage_write_at(1, b"X").unwrap();
    assert_eq!(&object.page(0).unwrap()[..3], b"nXw");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate().unwrap();

    // A concurrent shrink to empty must not manufacture a successful page.
    reset_lower(b"old");
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object().invalidate().unwrap();
            LOWER.lock().unwrap().bytes.clear();
        }))
    });
    assert!(matches!(
        object.page(0),
        Err(vm_object::VmPageError::OutsideBacking)
    ));
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate().unwrap();

    // Keep every bounded-cache entry pinned. Capacity bypass must still
    // validate the epoch, retry stale lower data and return a fresh snapshot.
    const CACHE_PAGES: usize = 256;
    reset_lower(&vec![0x11; (CACHE_PAGES + 1) * 4096]);
    let pins: Vec<_> = (0..CACHE_PAGES)
        .map(|index| object.prepare_shared_page(index as u64).unwrap())
        .collect();
    assert_eq!(FRAMES.lock().unwrap().len(), CACHE_PAGES);
    let before = LOWER.lock().unwrap().reads;
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object()
                .write_at((CACHE_PAGES * 4096) as u64, b"new")
                .unwrap();
        }));
    });
    assert_eq!(&object.page(CACHE_PAGES as u64).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, before + 2);
    // No admission was possible: a second read must go back to the provider.
    assert_eq!(&object.page(CACHE_PAGES as u64).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, before + 3);
    assert_eq!(FRAMES.lock().unwrap().len(), CACHE_PAGES);
    drop(pins);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());

    // Private-page preparation must not publish bytes loaded before a cache
    // invalidation. A missing stamp is not permission to bypass validation.
    reset_lower(b"old");
    let generation = object.memory_generation();
    assert!(generation.is_some());
    let private = object.page(0).unwrap();
    object.invalidate().unwrap();
    LOWER.lock().unwrap().bytes = b"new".to_vec();
    assert_eq!(
        object.with_memory_generation_native(generation, || {
            panic!("stale private bytes reached the installer")
        }),
        Err::<(), _>(mnu_abi::status::Error::NotReady)
    );
    assert_eq!(
        object.with_memory_generation_native(None, || {
            panic!("missing generation reached the installer")
        }),
        Err::<(), _>(mnu_abi::status::Error::InvalidArgument)
    );
    assert_eq!(&private[..3], b"old");
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(
        object.with_memory_generation_native(object.memory_generation(), || Ok(37)),
        Ok(37)
    );
    object.invalidate().unwrap();

    // Retaining a frame keeps physical storage alive, but does not authorize
    // installing it after its backing generation has been invalidated.
    reset_lower(b"old");
    let prepared = object.prepare_shared_page(0).unwrap();
    let before = MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed);
    object.invalidate().unwrap();
    assert_eq!(
        prepared.map_to(4096, 8192, false, false),
        Err(mnu_abi::status::Error::NotReady)
    );
    assert_eq!(
        MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed),
        before
    );
    drop(prepared);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());
    LOWER.lock().unwrap().bytes = b"new".to_vec();
    let current = object.prepare_shared_page(0).unwrap();
    assert_eq!(current.map_to(4096, 8192, false, false), Ok(()));
    assert_eq!(
        MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed),
        before + 1
    );
    drop(current);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());
    assert_eq!(
        GATE_ALLOCS.load(std::sync::atomic::Ordering::Relaxed),
        initial_gates + 1
    );
    // The VM object, not a transient read/write, pins the canonical gate.
    let pin = object.prepare_shared_page(0).unwrap();
    FAIL_GATE_ALLOC.store(true, std::sync::atomic::Ordering::Relaxed);
    let alias = provider_object();
    drop(object);
    drop(alias);
    // A prepared page alone must retain the backing generation state too.
    let survivor = provider_object();
    assert_eq!(
        GATE_ALLOCS.load(std::sync::atomic::Ordering::Relaxed),
        initial_gates + 1
    );
    drop(pin);
    survivor.invalidate().unwrap();
    drop(survivor);
    // Once the last owner disappears, a failed replacement is reported as
    // native ResourceUnavailable without publishing a dangling registration.
    let owner = Arc::new(task::ProviderObject {
        endpoint_thread_id: 17,
        endpoint_slot: 2,
        endpoint_generation: 8,
    });
    assert!(matches!(
        vm_object::VmObject::provider(owner.clone(), 93),
        Err(error) if mnu_abi::status::Error::from_raw(error)
            == Some(mnu_abi::status::Error::ResourceUnavailable)
    ));
    assert!(matches!(
        vm_object::lock_provider_io(&owner, 93),
        Err(mnu_abi::status::Error::ResourceUnavailable)
    ));
    FAIL_GATE_ALLOC.store(false, std::sync::atomic::Ordering::Relaxed);
    let retry = vm_object::VmObject::provider(owner, 93).unwrap();
    drop(retry);
}

#[test]
fn unrelated_backing_changes_do_not_invalidate_extent_or_page_installations() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let object = provider_object();
    let other = vm_object::VmObject::provider(
        Arc::new(task::ProviderObject {
            endpoint_thread_id: 17,
            endpoint_slot: 2,
            endpoint_generation: 8,
        }),
        94,
    )
    .unwrap();
    let pinned = object.prepare_shared_page(0).unwrap();
    let prepared = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    let generation = object.memory_generation();
    other.write_at(0, b"x").unwrap();
    assert_eq!(object.memory_generation(), generation);
    assert_eq!(
        object.with_memory_generation_native(generation, || panic!("reserved private install")),
        Err::<(), _>(mnu_abi::status::Error::NotReady)
    );
    assert_eq!(
        pinned.map_to(4096, 8192, false, false),
        Err(mnu_abi::status::Error::NotReady)
    );
    without_allocations(|| prepared.commit()).unwrap();
    assert_eq!(
        pinned.map_to(4096, 8192, false, false),
        Err(mnu_abi::status::Error::NotReady)
    );
    let mut output = [0; 8];
    assert_eq!(object.read_at(0, &mut output).unwrap(), 1);
    drop(pinned);
    let pinned = object.prepare_shared_page(0).unwrap();
    let generation = object.memory_generation();
    other.write_at(0, b"x").unwrap();
    assert_eq!(
        object.with_memory_generation_native(generation, || Ok(37)),
        Ok(37)
    );
    assert_eq!(pinned.map_to(4096, 8192, false, false), Ok(()));
    drop(pinned);
    object.invalidate().unwrap();
    other.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());
}

#[test]
fn extent_geometry_and_allocation_failures_leave_admission_and_cache_unchanged() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let object = provider_object();
    object.page(0).unwrap();
    let generation = object.memory_generation();
    let reads = LOWER.lock().unwrap().reads;
    for (old_length, length) in [(3, u64::MAX), (u64::MAX, 3)] {
        let result = without_allocations(|| {
            object.prepare_extent(old_length, length, |_| panic!("invalid geometry allocated"))
        });
        assert!(
            matches!(result, Err(error) if error == mnu_abi::status::Error::LimitExceeded.into_raw())
        );
        assert_eq!(object.memory_generation(), generation);
    }
    // Allocation is the coordinator's policy. Preserve its error verbatim,
    // including an opaque lower-layer value, and release the acquired gate.
    for error in [
        mnu_abi::status::Error::ResourceUnavailable.into_raw(),
        syscall::ENOMEM,
        0xfedc_ba98,
    ] {
        let result = without_allocations(|| object.prepare_extent(3, 1, |_| Err(error)));
        assert!(matches!(result, Err(actual) if actual == error));
        assert_eq!(object.memory_generation(), generation);
        assert_eq!(&object.page(0).unwrap()[..3], b"old");
    }
    assert_eq!(LOWER.lock().unwrap().reads, reads);
    let retry = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    drop(retry);
    object.invalidate().unwrap();
}

#[test]
fn extent_rejects_stale_epoch_without_publishing_and_releases_reservation() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    CAPTURE_GATE.with(|capture| capture.set(true));
    let object = provider_object();
    CAPTURE_GATE.with(|capture| capture.set(false));
    let gate = CAPTURED_GATE.with(|slot| slot.borrow_mut().take()).unwrap();
    object.page(0).unwrap();
    let mut prepared = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    // Model invalidation of this token at the actual cache-lock boundary.
    CACHE_EDGE
        .with(|edge| *edge.borrow_mut() = Some((0, Box::new(move || gate.advance_generation()))));
    assert_eq!(
        without_allocations(|| prepared.preflight()),
        Err(EXTENT_NOT_READY)
    );
    assert_eq!(
        without_allocations(|| prepared.publish()),
        Err(EXTENT_NOT_READY)
    );
    assert_eq!(&LOWER.lock().unwrap().bytes, b"old");
    drop(prepared);
    assert_eq!(&object.page(0).unwrap()[..3], b"old");
    let retry = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    drop(retry);
    object.invalidate().unwrap();
}

#[test]
fn extent_reservation_excludes_io_without_waiting_or_allocating_on_contention() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let provider = Arc::new(task::ProviderObject {
        endpoint_thread_id: 17,
        endpoint_slot: 2,
        endpoint_generation: 8,
    });
    let object = vm_object::VmObject::provider(provider.clone(), 93).unwrap();
    let alias = vm_object::VmObject::provider(provider.clone(), 93).unwrap();
    let other = vm_object::VmObject::provider(provider.clone(), 94).unwrap();
    let generation = object.memory_generation();
    // Model a caller waiting on this provider, including the interval between
    // its reply and cache publication. The owner must return, never wait here.
    let request = vm_object::lock_provider_io(&provider, 93).unwrap();
    assert!(matches!(
        without_allocations(|| alias.prepare_extent(3, 1, |_| {
            panic!("busy admission must precede boundary allocation")
        })),
        Err(EXTENT_NOT_READY)
    ));
    assert_eq!(object.memory_generation(), generation);
    let independent = other
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    drop(independent);
    drop(request);

    let prepared = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    assert!(matches!(
        alias.prepare_extent(3, 1, |_| panic!("reservation still owns I/O")),
        Err(EXTENT_NOT_READY)
    ));
    // Cancellation releases admission, but never publishes a shorter extent.
    drop(prepared);
    // Snapshots prepared before reservation stay invalid after cancellation.
    assert_ne!(object.memory_generation(), generation);
    assert_eq!(LOWER.lock().unwrap().bytes, b"old");
    let prepared = alias
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    LOWER.lock().unwrap().bytes.truncate(1);
    without_allocations(|| prepared.commit()).unwrap();
    // Successful publication must release the same reservation too.
    let request = vm_object::lock_provider_io(&provider, 93).unwrap();
    drop(request);
    object.invalidate().unwrap();
}

#[test]
fn reserved_backing_rejects_population_dirtying_and_both_final_install_paths() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let object = provider_object();
    let pin = object.prepare_shared_page(0).unwrap();
    let old_generation = object.memory_generation();
    let reads = LOWER.lock().unwrap().reads;
    let mappings = MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed);
    let prepared = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    for page in [0, 1] {
        assert!(matches!(
            object.page(page),
            Err(vm_object::VmPageError::Operation(syscall::EAGAIN))
        ));
        assert!(matches!(
            object.prepare_shared_page(page),
            Err(vm_object::VmPageError::Operation(syscall::EAGAIN))
        ));
    }
    assert_eq!(object.mark_page_dirty(0), Err(syscall::EAGAIN));
    assert_eq!(object.stage_write_at(0, b"new"), Err(syscall::EAGAIN));
    assert_eq!(
        pin.map_to(4096, 8192, false, false),
        Err(mnu_abi::status::Error::NotReady)
    );
    for generation in [old_generation, object.memory_generation()] {
        assert_eq!(
            object.with_memory_generation_native(generation, || panic!(
                "private install must not run"
            )),
            Err::<(), _>(mnu_abi::status::Error::NotReady)
        );
    }
    assert_eq!(LOWER.lock().unwrap().reads, reads);
    assert_eq!(
        MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed),
        mappings
    );
    assert_eq!(LOWER.lock().unwrap().bytes, b"old");
    drop(prepared);
    // Cancellation reopens admission but does not revive old page pins.
    assert_eq!(
        pin.map_to(4096, 8192, false, false),
        Err(mnu_abi::status::Error::NotReady)
    );
    drop(pin);
    assert_eq!(&object.page(0).unwrap()[..3], b"old");
    let pin = object.prepare_shared_page(0).unwrap();
    assert_eq!(pin.map_to(4096, 8192, false, false), Ok(()));
    drop(pin);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());
}

#[test]
fn reservation_wins_at_lower_reply_frame_and_staged_write_admission_edges() {
    let _test = TEST_LOCK.lock().unwrap();
    for mode in 0..3 {
        reset_lower(b"old");
        let object = provider_object();
        let held = std::rc::Rc::new(RefCell::new(None));
        let holder = held.clone();
        let reserve = Box::new(move || {
            *holder.borrow_mut() = Some(
                provider_object()
                    .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
                    .unwrap(),
            );
        });
        if mode != 0 {
            // cached lookup, lower snapshot admission, then frame admission.
            CACHE_EDGE.with(|edge| *edge.borrow_mut() = Some((3, reserve)));
            if mode == 1 {
                assert!(matches!(
                    object.prepare_shared_page(0),
                    Err(vm_object::VmPageError::Operation(syscall::EAGAIN))
                ));
            } else {
                assert_eq!(object.stage_write_at(0, b"new"), Err(syscall::EAGAIN));
            }
        } else {
            LOWER_EDGE.with(|edge| *edge.borrow_mut() = Some(reserve));
            assert!(matches!(
                object.page(0),
                Err(vm_object::VmPageError::Operation(syscall::EAGAIN))
            ));
        }
        assert!(held.borrow().is_some());
        assert!(FRAMES.lock().unwrap().is_empty());
        assert_eq!(LOWER.lock().unwrap().reads, 1);
        drop(held.borrow_mut().take());
        assert_eq!(&object.page(0).unwrap()[..3], b"old");
        object.invalidate().unwrap();
    }
}

#[test]
fn unrelated_cache_pressure_cannot_evict_reserved_boundary_storage() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(&vec![0x11; 256 * 4096]);
    let object = provider_object();
    let other = vm_object::VmObject::provider(
        Arc::new(task::ProviderObject {
            endpoint_thread_id: 17,
            endpoint_slot: 2,
            endpoint_generation: 8,
        }),
        94,
    )
    .unwrap();
    object.page(0).unwrap();
    let prepared = object
        .prepare_extent(4096, 17, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    for index in 0..256 {
        other.page(index).unwrap();
    }
    let reads = LOWER.lock().unwrap().reads;
    drop(prepared);
    assert_eq!(object.page(0).unwrap()[0], 0x11);
    assert_eq!(
        LOWER.lock().unwrap().reads,
        reads,
        "reserved boundary was evicted"
    );
    object.invalidate().unwrap();
    other.invalidate().unwrap();
}

#[test]
fn mapping_edits_preflight_every_overlapping_backing_without_ipc_or_allocation() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let object = Arc::new(provider_object());
    let regions = [
        task::MemoryRegion {
            start: 0x1000,
            length: 4096,
            object: None,
        },
        task::MemoryRegion {
            start: 0x2000,
            length: 4096,
            object: Some(object.clone()),
        },
    ];
    let prepared = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    assert_eq!(
        without_allocations(|| mapping_admission::check_native(&regions, 0x1000, 0x3000)),
        Err(mnu_abi::status::Error::NotReady)
    );
    assert_eq!(
        without_allocations(|| mapping_admission::check_access(&regions, 0x1000, 8192)),
        Err(Kernel::Memory(result::Memory::Busy))
    );
    assert_eq!(
        mapping_admission::check_access(&regions, u64::MAX, 1),
        Err(Kernel::Memory(result::Memory::InvalidAddress))
    );
    assert_eq!(
        without_allocations(|| mapping_admission::check_access(&regions, 0x2000, 0)),
        Ok(())
    );
    // A reservation elsewhere in this address space must not reject an edit
    // which ends exactly at its boundary, including an unbacked/anonymous range.
    assert_eq!(
        without_allocations(|| mapping_admission::check_native(&regions, 0x1000, 0x2000)),
        Ok(())
    );
    assert_eq!(
        without_allocations(|| mapping_admission::check_native(&regions, 0x3000, 0x4000)),
        Ok(())
    );
    assert_eq!(
        mapping_admission::check_native(&regions, 0x2000, 0x2000),
        Err(mnu_abi::status::Error::InvalidArgument)
    );
    assert_eq!(LOWER.lock().unwrap().reads, 0);
    drop(prepared);
    assert_eq!(
        without_allocations(|| mapping_admission::check_native(&regions, 0x1000, 0x3000)),
        Ok(())
    );
    let invalid = [task::MemoryRegion {
        start: u64::MAX,
        length: 1,
        object: None,
    }];
    assert_eq!(
        mapping_admission::check_native(&invalid, 0x1000, 0x2000),
        Err(mnu_abi::status::Error::BackingFailure)
    );
}

#[test]
fn final_mapping_failure_keeps_pin_and_generation_available_for_retry() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let object = provider_object();
    let generation = object.memory_generation();
    let pin = object.prepare_shared_page(0).unwrap();
    FAIL_MAPPING.set(true);
    let failed = pin.map_to(4096, 8192, false, false);
    FAIL_MAPPING.set(false);
    assert_eq!(failed, Err(mnu_abi::status::Error::ResourceUnavailable));
    assert_eq!(object.memory_generation(), generation);
    assert_eq!(pin.map_to(4096, 8192, false, false), Ok(()));
    drop(pin);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());
}

#[test]
fn cache_publication_keeps_backing_reserved_through_journal_completion() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(&vec![0x11; 8192]);
    let object = provider_object();
    let alias = provider_object();
    let pin = object.prepare_shared_page(0).unwrap();
    let mut prepared = object
        .prepare_extent(8192, 17, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    LOWER.lock().unwrap().bytes.truncate(17);
    without_allocations(|| prepared.publish()).unwrap();
    // Publication is not the release of mapping exclusion: a native journal
    // may still own non-present PTEs which have not been restored/released.
    assert_eq!(
        without_allocations(|| prepared.publish()),
        Err(EXTENT_INVALID_ARGUMENT)
    );
    assert!(matches!(
        alias.page(0),
        Err(vm_object::VmPageError::Operation(syscall::EAGAIN))
    ));
    assert_eq!(
        alias.with_memory_generation_native(alias.memory_generation(), || panic!(
            "PTE installation before journal completion"
        )),
        Err::<(), _>(mnu_abi::status::Error::NotReady)
    );
    assert!(matches!(
        alias.prepare_extent(17, 0, |_| panic!(
            "admission released before PTE completion"
        )),
        Err(EXTENT_NOT_READY)
    ));
    drop(prepared);
    assert_eq!(alias.read_at(0, &mut [0; 64]), Ok(17));
    let page = alias.page(0).unwrap();
    assert!(page[..17].iter().all(|byte| *byte == 0x11));
    assert!(page[17..].iter().all(|byte| *byte == 0));
    let next = alias
        .prepare_extent(17, 0, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    drop(next);
    drop(pin);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());
}

#[test]
fn reserved_invalidation_cannot_change_epoch_or_release_publication_admission() {
    let _test = TEST_LOCK.lock().unwrap();
    for changed in [false, true] {
        reset_lower(b"old");
        let object = provider_object();
        let mut prepared = object
            .prepare_extent(3, if changed { 1 } else { 3 }, |bytes| Ok(Arc::new(bytes)))
            .unwrap();
        let generation = object.memory_generation();
        assert_eq!(
            without_allocations(|| object.invalidate()),
            Err(syscall::EAGAIN)
        );
        assert_eq!(object.memory_generation(), generation);
        if changed {
            LOWER.lock().unwrap().bytes.truncate(1);
        }
        assert_eq!(without_allocations(|| prepared.publish()), Ok(()));
        let published_generation = object.memory_generation();
        assert_eq!(
            without_allocations(|| object.invalidate()),
            Err(syscall::EAGAIN)
        );
        assert_eq!(object.memory_generation(), published_generation);
        assert_eq!(prepared.publish(), Err(EXTENT_INVALID_ARGUMENT));
        assert!(matches!(
            object.page(0),
            Err(vm_object::VmPageError::Operation(syscall::EAGAIN))
        ));
        drop(prepared);
        assert_eq!(
            object.read_at(0, &mut [0; 8]),
            Ok(if changed { 1 } else { 3 })
        );
        object.invalidate().unwrap();
    }
}

#[test]
fn provider_writeback_key_is_owned_by_its_live_io_guard() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let provider = Arc::new(task::ProviderObject {
        endpoint_thread_id: 17,
        endpoint_slot: 2,
        endpoint_generation: 8,
    });
    let object = vm_object::VmObject::provider(provider.clone(), 93).unwrap();
    let alias = provider_object();
    let other = vm_object::VmObject::provider(
        Arc::new(task::ProviderObject {
            endpoint_thread_id: 17,
            endpoint_slot: 2,
            endpoint_generation: 9,
        }),
        93,
    )
    .unwrap();
    object.page(0).unwrap();
    other.page(0).unwrap();
    let other_generation = other.memory_generation();
    let guard = vm_object::lock_provider_io(&provider, 93).unwrap();
    assert!(matches!(
        alias.prepare_extent(3, 1, |_| panic!("I/O owner lost")),
        Err(EXTENT_NOT_READY)
    ));
    // The same numeric provider identity in another endpoint generation must
    // remain independent. No separate identity can be supplied for writeback.
    let independent = other
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    drop(independent);
    let other_generation_after_reservation = other.memory_generation();
    assert_ne!(other_generation, other_generation_after_reservation);
    vm_object::update_provider_range(&guard, 0, b"new");
    assert_eq!(&alias.page(0).unwrap()[..3], b"new");
    assert_eq!(&other.page(0).unwrap()[..3], b"old");
    assert_eq!(
        other.memory_generation(),
        other_generation_after_reservation
    );
    drop(guard);
    let next = alias
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    drop(next);
    object.invalidate().unwrap();
    other.invalidate().unwrap();
}

#[test]
fn unavailable_cached_backing_cannot_lose_failure_when_original_owners_drop() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let provider = Arc::new(task::ProviderObject {
        endpoint_thread_id: 17,
        endpoint_slot: 2,
        endpoint_generation: 8,
    });
    CAPTURE_GATE.with(|capture| capture.set(true));
    let object = Arc::new(vm_object::VmObject::provider(provider.clone(), 0xf00d_531).unwrap());
    CAPTURE_GATE.with(|capture| capture.set(false));
    let gate = CAPTURED_GATE.with(|slot| slot.borrow_mut().take()).unwrap();
    let pin = object.prepare_shared_page(0).unwrap();
    let calls = MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed);
    let reads = LOWER.lock().unwrap().reads;
    // No PTE is installed in this fixture, and TEST_LOCK excludes every
    // modeled cache writer while the primitive failure latch is exercised.
    let reservation = gate.try_lock().unwrap().unwrap().reserve();
    without_allocations(|| reservation.mark_unavailable());
    let regions = [task::MemoryRegion {
        start: 0x2000,
        length: 4096,
        object: Some(object.clone()),
    }];
    assert_eq!(
        without_allocations(|| mapping_admission::check_unmap(&regions, 0x1000, 0x3000)),
        Err(mnu_abi::status::Error::NotReady)
    );
    assert_eq!(
        pin.map_to(4096, 8192, false, false),
        Err(mnu_abi::status::Error::BackingFailure)
    );
    assert_eq!(
        MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed),
        calls
    );
    drop(pin);
    drop(reservation);
    assert_eq!(
        without_allocations(|| mapping_admission::check_native(&regions, 0x1000, 0x3000)),
        Err(mnu_abi::status::Error::BackingFailure)
    );
    assert_eq!(
        without_allocations(|| mapping_admission::check_access(&regions, 0x2000, 1)),
        Err(Kernel::Memory(result::Memory::InvalidAddress))
    );
    assert_eq!(
        without_allocations(|| mapping_admission::check_unmap(&regions, 0x1000, 0x3000)),
        Ok(())
    );
    drop(regions);
    drop(object);
    drop(gate);
    // Only the cached page now retains the canonical I/O state. Reopening
    // must reuse its unavailable state rather than a fresh healthy generation.
    let allocations = GATE_ALLOCS.load(std::sync::atomic::Ordering::Relaxed);
    let alias = vm_object::VmObject::provider(provider.clone(), 0xf00d_531).unwrap();
    assert_eq!(
        GATE_ALLOCS.load(std::sync::atomic::Ordering::Relaxed),
        allocations
    );
    assert!(matches!(
        alias.page(0),
        Err(vm_object::VmPageError::Operation(syscall::EIO))
    ));
    assert!(matches!(
        alias.prepare_shared_page(0),
        Err(vm_object::VmPageError::Operation(syscall::EIO))
    ));
    assert_eq!(alias.read_at(0, &mut [0; 8]), Err(syscall::EIO));
    assert!(matches!(
        without_allocations(|| vm_object::lock_provider_io(&provider, 0xf00d_531)),
        Err(mnu_abi::status::Error::BackingFailure)
    ));
    assert_eq!(
        alias.write_at(0, b"new"),
        Err(mnu_abi::status::Error::BackingFailure.into_raw())
    );
    assert_eq!(alias.stage_write_at(0, b"new"), Err(syscall::EIO));
    assert_eq!(alias.mark_page_dirty(0), Err(syscall::EIO));
    assert_eq!(
        alias.flush(),
        Err(mnu_abi::status::Error::BackingFailure.into_raw())
    );
    let syncs = SYNC_CALLS.with(Cell::get);
    assert_eq!(alias.flush_unmapped_range(0, 4096), Ok(()));
    assert_eq!(SYNC_CALLS.with(Cell::get), syncs);
    assert!(matches!(
        alias.prepare_extent(3, 1, |_| panic!("unavailable backing allocated boundary")),
        Err(EXTENT_BACKING_FAILURE)
    ));
    assert_eq!(
        alias.with_memory_generation_native(alias.memory_generation(), || panic!(
            "failed backing installed PTE"
        )),
        Err::<(), _>(mnu_abi::status::Error::BackingFailure)
    );
    assert_eq!(LOWER.lock().unwrap().reads, reads);
    assert_eq!(&LOWER.lock().unwrap().bytes, b"old");
    let other = provider_object();
    assert_eq!(other.read_at(0, &mut [0; 8]), Ok(3));
    other.invalidate().unwrap();
    // Explicit eviction can discard unusable cached data, but cannot repair
    // an existing object's failure. No provider is called by this cleanup.
    alias.invalidate().unwrap();
    assert!(matches!(
        alias.page(0),
        Err(vm_object::VmPageError::Operation(syscall::EIO))
    ));
    assert!(FRAMES.lock().unwrap().is_empty());
}

#[test]
fn unmap_writeback_does_not_hide_io_errors_on_an_available_backing() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(b"old");
    let object = provider_object();
    for failure in [
        syscall::EIO,
        mnu_abi::status::Error::BackingFailure.into_raw(),
        mnu_abi::status::Error::NotReady.into_raw(),
    ] {
        SYNC_ERROR.with(|error| error.set(Some(failure)));
        assert_eq!(object.flush_unmapped_range(0, 4096), Err(failure));
    }
    SYNC_ERROR.with(|error| error.set(None));
    assert_eq!(object.flush_unmapped_range(0, 4096), Ok(()));
    assert_eq!(object.read_at(0, &mut [0; 3]), Ok(3));
    object.invalidate().unwrap();
}

#[test]
fn preflight_does_not_retain_cache_positions_across_unrelated_eviction() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(&vec![0x11; 8192]);
    let object = provider_object();
    let other = vm_object::VmObject::provider(
        Arc::new(task::ProviderObject {
            endpoint_thread_id: 17,
            endpoint_slot: 2,
            endpoint_generation: 8,
        }),
        94,
    )
    .unwrap();
    // Remove an earlier entry between preflight and publication, moving the
    // reserved boundary inside the shared Vec without changing its identity.
    other.page(0).unwrap();
    object.page(0).unwrap();
    let mut prepared = object
        .prepare_extent(8192, 17, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    without_allocations(|| prepared.preflight()).unwrap();
    other.invalidate().unwrap();
    LOWER.lock().unwrap().bytes.truncate(17);
    without_allocations(|| prepared.publish()).unwrap();
    drop(prepared);
    assert_eq!(object.read_at(0, &mut [0; 64]), Ok(17));
    let bytes = object.page(0).unwrap();
    assert!(bytes[..17].iter().all(|byte| *byte == 0x11));
    assert!(bytes[17..].iter().all(|byte| *byte == 0));
    object.invalidate().unwrap();
}

#[test]
fn cache_preflight_and_failed_publication_preserve_boundary_buffer_for_retry() {
    let _test = TEST_LOCK.lock().unwrap();
    reset_lower(&vec![0x11; 8192]);
    let object = provider_object();
    let pin = object.prepare_shared_page(0).unwrap();
    object.mark_page_dirty(0).unwrap();
    let frame = *FRAMES.lock().unwrap().keys().next().unwrap();
    let mut prepared = object
        .prepare_extent(8192, 17, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    let generation = object.memory_generation();
    for offset in [None, Some(u64::MAX - 4096)] {
        PHYSICAL_OFFSET.with(|value| value.set(offset));
        let preflight = without_allocations(|| prepared.preflight());
        let publication = without_allocations(|| prepared.publish());
        PHYSICAL_OFFSET.with(|value| value.set(Some(0)));
        assert_eq!(preflight, Err(EXTENT_BACKING_FAILURE));
        assert_eq!(publication, Err(EXTENT_BACKING_FAILURE));
        assert_eq!(object.memory_generation(), generation);
        assert_eq!(LOWER.lock().unwrap().bytes.len(), 8192);
        assert!(
            unsafe { std::slice::from_raw_parts(frame as *const u8, 4096) }
                .iter()
                .all(|byte| *byte == 0x11)
        );
    }
    without_allocations(|| prepared.preflight()).unwrap();
    without_allocations(|| prepared.preflight()).unwrap();
    assert_eq!(object.memory_generation(), generation);
    // Preflight does not snapshot bytes. Preserve even the last modeled user
    // store before the coordinator's TLB barrier/publication contract.
    unsafe {
        std::ptr::write_volatile((frame + 8) as *mut u8, b'Q');
    }
    LOWER.lock().unwrap().bytes.truncate(17);
    without_allocations(|| prepared.publish()).unwrap();
    assert_eq!(prepared.preflight(), Err(EXTENT_INVALID_ARGUMENT));
    drop(prepared);
    let bytes = object.page(0).unwrap();
    assert_eq!(bytes[8], b'Q');
    assert!(bytes[17..].iter().all(|byte| *byte == 0));
    object.flush().unwrap();
    assert_eq!(LOWER.lock().unwrap().bytes[8], b'Q');
    assert_eq!(LOWER.lock().unwrap().bytes.len(), 17);
    drop(pin);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());
}

#[test]
fn production_extent_commit_preserves_dirty_prefix_and_discards_removed_storage() {
    let _test = TEST_LOCK.lock().unwrap();
    let object = provider_object();
    reset_lower(&vec![0x11; 8192]);
    object.page(1).unwrap();
    let pinned = object.prepare_shared_page(0).unwrap();
    object.mark_page_dirty(0).unwrap();
    let prepared = object
        .prepare_extent(8192, 17, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    let frame = *FRAMES.lock().unwrap().keys().next().unwrap();
    // Model a final userspace store before the coordinator's TLB barrier.
    // The pin keeps this mock physical allocation alive through commit.
    unsafe {
        core::ptr::write_volatile((frame + 8) as *mut u8, b'Q');
    }
    LOWER.lock().unwrap().bytes.truncate(17);
    // The host owns all mappings; no hardware PTE is installed by this probe.
    without_allocations(|| prepared.commit()).unwrap();
    let page = object.page(0).unwrap();
    assert_eq!(page[8], b'Q');
    assert!(page[17..].iter().all(|byte| *byte == 0));
    assert!(matches!(
        object.page(1),
        Err(vm_object::VmPageError::OutsideBacking)
    ));
    let mut output = [0; 64];
    assert_eq!(object.read_at(0, &mut output).unwrap(), 17);
    // A formerly full dirty page must not re-extend the shortened backing.
    object.flush().unwrap();
    assert_eq!(LOWER.lock().unwrap().bytes.len(), 17);
    assert_eq!(LOWER.lock().unwrap().bytes[8], b'Q');
    assert_eq!(
        pinned.map_to(4096, 8192, false, false),
        Err(mnu_abi::status::Error::NotReady)
    );
    drop(pinned);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());

    reset_lower(b"old");
    let generation = object.memory_generation();
    assert!(matches!(
        object.prepare_extent(3, 1, |_| Err(syscall::ENOMEM)),
        Err(syscall::ENOMEM)
    ));
    assert_eq!(
        object.with_memory_generation_native(generation, || Ok(())),
        Ok(())
    );
    let shared = Arc::new([0; 4096]);
    assert!(matches!(
        object.prepare_extent(3, 1, |_| Ok(shared.clone())),
        Err(EXTENT_INVALID_ARGUMENT)
    ));
    let prepared = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    // Invalidation cannot destroy a live reservation. Explicit owner drop
    // cancels preparation without changing cache bytes or backing length.
    assert_eq!(
        without_allocations(|| object.invalidate()),
        Err(syscall::EAGAIN)
    );
    drop(prepared);
    assert_eq!(&object.page(0).unwrap()[..3], b"old");
    assert_eq!(object.read_at(0, &mut output).unwrap(), 3);
    object.invalidate().unwrap();

    reset_lower(b"old");
    // Negative EOF cache entries must be forgotten when backing grows.
    assert!(matches!(
        object.page(1),
        Err(vm_object::VmPageError::OutsideBacking)
    ));
    let pinned = object.prepare_shared_page(0).unwrap();
    object.mark_page_dirty(0).unwrap();
    let prepared = object
        .prepare_extent(3, 8192, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    let frame = *FRAMES.lock().unwrap().keys().next().unwrap();
    unsafe {
        core::ptr::write_volatile((frame + 2) as *mut u8, b'Z');
        core::ptr::write_volatile((frame + 3) as *mut u8, b'x');
        core::ptr::write_volatile((frame + 4095) as *mut u8, b'x');
    }
    LOWER.lock().unwrap().bytes.resize(8192, 0);
    without_allocations(|| prepared.commit()).unwrap();
    let page = object.page(0).unwrap();
    assert_eq!(&page[..3], b"olZ");
    assert!(page[3..].iter().all(|byte| *byte == 0));
    assert!(object.page(1).unwrap().iter().all(|byte| *byte == 0));
    object.flush().unwrap();
    assert_eq!(&LOWER.lock().unwrap().bytes[..3], b"olZ");
    assert_eq!(LOWER.lock().unwrap().bytes.len(), 8192);
    drop(pinned);
    object.invalidate().unwrap();
    assert!(FRAMES.lock().unwrap().is_empty());

    reset_lower(&[]);
    assert!(matches!(
        object.page(0),
        Err(vm_object::VmPageError::OutsideBacking)
    ));
    let prepared = object
        .prepare_extent(0, 4096, |_| panic!("no partial boundary buffer needed"))
        .unwrap();
    LOWER.lock().unwrap().bytes.resize(4096, 0);
    without_allocations(|| prepared.commit()).unwrap();
    assert!(object.page(0).unwrap().iter().all(|byte| *byte == 0));
    let prepared = object
        .prepare_extent(4096, 0, |_| {
            panic!("aligned shrink must not allocate a boundary")
        })
        .unwrap();
    LOWER.lock().unwrap().bytes.clear();
    without_allocations(|| prepared.commit()).unwrap();
    assert!(matches!(
        object.page(0),
        Err(vm_object::VmPageError::OutsideBacking)
    ));
    object.invalidate().unwrap();
}
