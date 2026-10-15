//! Production VM object/cache code; substitute only IPC, scheduling, physical
//! frames and interrupt locks. Interleave mutations at the actual lock edges.
#![allow(dead_code)]
extern crate alloc;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

thread_local! {
    static DENY_COMMIT_ALLOC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static COMMIT_ALLOC_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
        ) -> Result<(), u64> {
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
            let start = usize::try_from(offset).map_err(|_| super::EINVAL)?;
            let mut lower = crate::LOWER.lock().unwrap();
            let length = (start + input.len()).max(lower.bytes.len());
            lower.bytes.resize(length, 0);
            lower.bytes[start..start + input.len()].copy_from_slice(input);
            Ok(input.len())
        }
        pub fn provider_sync(_: &crate::task::ProviderObject) -> Result<(), u64> {
            Ok(())
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
        pub fn with_generation<T>(
            &self,
            _: u64,
            _: impl FnOnce() -> Result<T, u64>,
        ) -> Result<T, u64> {
            unreachable!()
        }
        pub fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize, u64> {
            unreachable!()
        }
        pub fn write_at(&self, _: u64, _: &[u8]) -> Result<usize, u64> {
            unreachable!()
        }
        pub fn prepare_page(&self, _: u64) -> Result<(u64, u64), u64> {
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
        Some(0)
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
        Ok(())
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
    pub(crate) use crate::{byte_extent, frame, paging};
    pub(crate) mod object_io_native {
        pub fn new_lock() -> Result<crate::object_io::IoLock, u64> {
            crate::GATE_ALLOCS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if crate::FAIL_GATE_ALLOC.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(crate::syscall::ENOMEM);
            }
            Ok(crate::object_io::IoLock::from_allocated(
                std::sync::Arc::new(crate::object_io::State::new()),
            ))
        }
    }
}

fn provider_object() -> vm_object::VmObject {
    vm_object::VmObject::provider(
        Arc::new(task::ProviderObject {
            endpoint_thread_id: 17,
            endpoint_slot: 2,
            endpoint_generation: 8,
        }),
        93,
    )
    .unwrap()
}

fn reset_lower(bytes: &[u8]) {
    *LOWER.lock().unwrap() = Lower {
        bytes: bytes.to_vec(),
        reads: 0,
    };
}

static TEST_LOCK: Mutex<()> = Mutex::new(());

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
    object.invalidate();

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
    object.invalidate();

    reset_lower(b"old");
    // The third lock is final shared-frame preparation, after loading and
    // admitting the page. Revoke it before that lock is acquired.
    CACHE_EDGE.with(|edge| {
        *edge.borrow_mut() = Some((
            3,
            Box::new(|| {
                provider_object().invalidate();
                LOWER.lock().unwrap().bytes = b"new".to_vec();
            }),
        ))
    });
    let prepared = object.prepare_shared_page(0).unwrap();
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    drop(prepared);
    object.invalidate();
    assert!(FRAMES.lock().unwrap().is_empty());

    reset_lower(b"old");
    CACHE_EDGE.with(|edge| {
        *edge.borrow_mut() = Some((
            3,
            Box::new(|| {
                provider_object().invalidate();
                LOWER.lock().unwrap().bytes = b"new".to_vec();
            }),
        ))
    });
    object.stage_write_at(1, b"X").unwrap();
    assert_eq!(&object.page(0).unwrap()[..3], b"nXw");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate();

    // A concurrent shrink to empty must not manufacture a successful page.
    reset_lower(b"old");
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object().invalidate();
            LOWER.lock().unwrap().bytes.clear();
        }))
    });
    assert!(matches!(
        object.page(0),
        Err(vm_object::VmPageError::OutsideBacking)
    ));
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate();

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
    object.invalidate();
    assert!(FRAMES.lock().unwrap().is_empty());

    // Private-page preparation must not publish bytes loaded before a cache
    // invalidation. A missing stamp is not permission to bypass validation.
    reset_lower(b"old");
    let generation = object.memory_generation();
    assert!(generation.is_some());
    let private = object.page(0).unwrap();
    object.invalidate();
    LOWER.lock().unwrap().bytes = b"new".to_vec();
    assert_eq!(
        object.with_memory_generation(generation, || {
            panic!("stale private bytes reached the installer")
        }),
        Err::<(), _>(syscall::EAGAIN)
    );
    assert_eq!(
        object.with_memory_generation(None, || {
            panic!("missing generation reached the installer")
        }),
        Err::<(), _>(syscall::EINVAL)
    );
    assert_eq!(&private[..3], b"old");
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(
        object.with_memory_generation(object.memory_generation(), || Ok(37)),
        Ok(37)
    );
    object.invalidate();

    // Retaining a frame keeps physical storage alive, but does not authorize
    // installing it after its backing generation has been invalidated.
    reset_lower(b"old");
    let prepared = object.prepare_shared_page(0).unwrap();
    let before = MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed);
    object.invalidate();
    assert_eq!(
        prepared.map_to(4096, 8192, false, false),
        Err(syscall::EAGAIN)
    );
    assert_eq!(
        MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed),
        before
    );
    drop(prepared);
    object.invalidate();
    assert!(FRAMES.lock().unwrap().is_empty());
    LOWER.lock().unwrap().bytes = b"new".to_vec();
    let current = object.prepare_shared_page(0).unwrap();
    assert_eq!(current.map_to(4096, 8192, false, false), Ok(()));
    assert_eq!(
        MAPPING_CALLS.load(std::sync::atomic::Ordering::Relaxed),
        before + 1
    );
    drop(current);
    object.invalidate();
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
    survivor.invalidate();
    drop(survivor);
    // Once the last owner disappears, a failed replacement is reported as
    // ENOMEM without publishing an object or a dangling live registration.
    let owner = Arc::new(task::ProviderObject {
        endpoint_thread_id: 17,
        endpoint_slot: 2,
        endpoint_generation: 8,
    });
    assert!(matches!(
        vm_object::VmObject::provider(owner.clone(), 93),
        Err(syscall::ENOMEM)
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
        object.with_memory_generation(generation, || panic!("reserved private install")),
        Err::<(), _>(syscall::EAGAIN)
    );
    assert_eq!(
        pinned.map_to(4096, 8192, false, false),
        Err(syscall::EAGAIN)
    );
    without_allocations(|| prepared.commit()).unwrap();
    assert_eq!(
        pinned.map_to(4096, 8192, false, false),
        Err(syscall::EAGAIN)
    );
    let mut output = [0; 8];
    assert_eq!(object.read_at(0, &mut output).unwrap(), 1);
    drop(pinned);
    let pinned = object.prepare_shared_page(0).unwrap();
    let generation = object.memory_generation();
    other.write_at(0, b"x").unwrap();
    assert_eq!(object.with_memory_generation(generation, || Ok(37)), Ok(37));
    assert_eq!(pinned.map_to(4096, 8192, false, false), Ok(()));
    drop(pinned);
    object.invalidate();
    other.invalidate();
    assert!(FRAMES.lock().unwrap().is_empty());
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
        Err(syscall::EAGAIN)
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
        Err(syscall::EAGAIN)
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
    object.invalidate();
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
    assert_eq!(pin.map_to(4096, 8192, false, false), Err(syscall::EAGAIN));
    for generation in [old_generation, object.memory_generation()] {
        assert_eq!(
            object.with_memory_generation(generation, || panic!("private install must not run")),
            Err::<(), _>(syscall::EAGAIN)
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
    assert_eq!(pin.map_to(4096, 8192, false, false), Err(syscall::EAGAIN));
    drop(pin);
    assert_eq!(&object.page(0).unwrap()[..3], b"old");
    let pin = object.prepare_shared_page(0).unwrap();
    assert_eq!(pin.map_to(4096, 8192, false, false), Ok(()));
    drop(pin);
    object.invalidate();
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
        object.invalidate();
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
    object.invalidate();
    other.invalidate();
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
        without_allocations(|| mapping_admission::check(&regions, 0x1000, 0x3000)),
        Err(syscall::EAGAIN)
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
        without_allocations(|| mapping_admission::check(&regions, 0x1000, 0x2000)),
        Ok(())
    );
    assert_eq!(
        without_allocations(|| mapping_admission::check(&regions, 0x3000, 0x4000)),
        Ok(())
    );
    assert_eq!(
        mapping_admission::check(&regions, 0x2000, 0x2000),
        Err(syscall::EINVAL)
    );
    assert_eq!(LOWER.lock().unwrap().reads, 0);
    drop(prepared);
    assert_eq!(
        without_allocations(|| mapping_admission::check(&regions, 0x1000, 0x3000)),
        Ok(())
    );
    let invalid = [task::MemoryRegion {
        start: u64::MAX,
        length: 1,
        object: None,
    }];
    assert_eq!(
        mapping_admission::check(&invalid, 0x1000, 0x2000),
        Err(syscall::EINVAL)
    );
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
        Err(syscall::EINVAL)
    );
    assert!(matches!(
        alias.page(0),
        Err(vm_object::VmPageError::Operation(syscall::EAGAIN))
    ));
    assert_eq!(
        alias.with_memory_generation(alias.memory_generation(), || panic!(
            "PTE installation before journal completion"
        )),
        Err::<(), _>(syscall::EAGAIN)
    );
    assert!(matches!(
        alias.prepare_extent(17, 0, |_| panic!(
            "admission released before PTE completion"
        )),
        Err(syscall::EAGAIN)
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
    object.invalidate();
    assert!(FRAMES.lock().unwrap().is_empty());
}

#[test]
fn unchanged_or_failed_cache_publication_retains_admission_until_owner_drop() {
    let _test = TEST_LOCK.lock().unwrap();
    for fail in [false, true] {
        reset_lower(b"old");
        let object = provider_object();
        let mut prepared = object
            .prepare_extent(3, if fail { 1 } else { 3 }, |bytes| Ok(Arc::new(bytes)))
            .unwrap();
        if fail {
            object.invalidate();
        }
        let generation = object.memory_generation();
        assert_eq!(
            without_allocations(|| prepared.publish()),
            if fail { Err(syscall::EAGAIN) } else { Ok(()) }
        );
        assert_eq!(object.memory_generation(), generation);
        if !fail {
            assert_eq!(prepared.publish(), Err(syscall::EINVAL));
        }
        assert!(matches!(
            object.page(0),
            Err(vm_object::VmPageError::Operation(syscall::EAGAIN))
        ));
        drop(prepared);
        assert_eq!(object.read_at(0, &mut [0; 8]), Ok(3));
        object.invalidate();
    }
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
        Err(syscall::EAGAIN)
    );
    drop(pinned);
    object.invalidate();
    assert!(FRAMES.lock().unwrap().is_empty());

    reset_lower(b"old");
    let generation = object.memory_generation();
    assert!(matches!(
        object.prepare_extent(3, 1, |_| Err(syscall::ENOMEM)),
        Err(syscall::ENOMEM)
    ));
    assert_eq!(object.with_memory_generation(generation, || Ok(())), Ok(()));
    let shared = Arc::new([0; 4096]);
    assert!(matches!(
        object.prepare_extent(3, 1, |_| Ok(shared.clone())),
        Err(syscall::EINVAL)
    ));
    let prepared = object
        .prepare_extent(3, 1, |bytes| Ok(Arc::new(bytes)))
        .unwrap();
    // Explicit invalidation still cancels a reservation's publication stamp.
    object.invalidate();
    assert_eq!(
        without_allocations(|| prepared.commit()),
        Err(syscall::EAGAIN)
    );
    assert_eq!(&object.page(0).unwrap()[..3], b"old");
    assert_eq!(object.read_at(0, &mut output).unwrap(), 3);
    object.invalidate();

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
    object.invalidate();
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
    object.invalidate();
}
