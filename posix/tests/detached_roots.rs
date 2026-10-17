#![feature(allocator_api)]
extern crate alloc;
use std::sync::{Mutex, OnceLock};
thread_local! {
    static FAIL_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
struct FaultAllocator;
unsafe impl std::alloc::GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        let fail = FAIL_AFTER.with(|state| match state.get() {
            Some(0) => {
                state.set(None);
                true
            }
            Some(count) => {
                state.set(Some(count - 1));
                false
            }
            None => false,
        });
        if fail {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;
mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T> {
            pub const fn new(value: T) -> Self {
                Self(std::sync::Mutex::new(value))
            }
            pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
                self.0.lock().unwrap()
            }
        }
    }
}
#[macro_export]
macro_rules! warn { ($($args:tt)*) => { let _ = format_args!($($args)*); }; }
mod task {
    pub struct Object(pub super::vm_object::ObjectKey);
    impl Object {
        pub fn object_key(&self) -> super::vm_object::ObjectKey {
            self.0
        }
    }
    pub struct MemoryRegion {
        pub shared: bool,
        pub object: Option<Object>,
        pub start: u64,
        pub length: u64,
        pub offset: u64,
    }
    impl MemoryRegion {
        pub fn is_shared(&self) -> bool { self.shared }
        pub fn backing(&self) -> &Self {
            self
        }
        pub fn file_object(&self) -> Option<&Object> {
            self.object.as_ref()
        }
        pub fn start(&self) -> u64 {
            self.start
        }
        pub fn len(&self) -> u64 {
            self.length
        }
        pub fn file_offset(&self) -> u64 {
            self.offset
        }
    }
}
// Key construction/isolation is exercised against the production VmObject in
// kernel_vm_cache_surface; this probe exercises actual detached-root ownership.
mod vm_object {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ObjectKey {
        Memory(u64),
        Provider {
            endpoint_thread_id: u64,
            endpoint_slot: u16,
            endpoint_generation: u64,
            identity: u64,
        },
    }
}
fn destroyed() -> &'static Mutex<Vec<u64>> {
    static STATE: OnceLock<Mutex<Vec<u64>>> = OnceLock::new();
    STATE.get_or_init(Default::default)
}
mod paging {
    pub fn destroy_user_page_table(table: u64) -> Result<(), ()> {
        if super::root_lifetime::retire(table) {
            return Ok(());
        }
        destroy_user_page_table_unpinned(table)
    }
    pub fn destroy_user_page_table_unpinned(table: u64) -> Result<(), ()> {
        let mut destroyed = super::destroyed().lock().unwrap();
        assert!(!destroyed.contains(&table), "double page-table destruction");
        destroyed.push(table);
        Ok(())
    }
}
#[path = "../../../core/src/mem/root_lifetime.rs"]
mod root_lifetime;
mod root_lifetime_native {
    pub static FAIL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    pub fn pin(table: u64) -> Result<super::root_lifetime::Pin, ()> {
        if FAIL.swap(false, std::sync::atomic::Ordering::AcqRel) {
            return Err(());
        }
        super::root_lifetime::pin_with(table, |state| {
            std::sync::Arc::try_new(state).map_err(|_| ())
        })
    }
}
#[path = "../../../core/src/mem/detached_roots.rs"]
mod detached_roots;

#[test]
fn weak_discovery_pins_physical_ownership_until_revocation_and_hands_off_at_publication() {
    use detached_roots::{snapshot, Root};
    let region = task::MemoryRegion {
        shared: true,
        object: Some(task::Object(vm_object::ObjectKey::Memory(7))),
        start: 0x5000,
        length: 4096,
        offset: 8192,
    };
    let provider = vm_object::ObjectKey::Provider {
        endpoint_thread_id: 17,
        endpoint_slot: 2,
        endpoint_generation: 8,
        identity: 7,
    };
    let replacement = vm_object::ObjectKey::Provider {
        endpoint_thread_id: 17,
        endpoint_slot: 2,
        endpoint_generation: 9,
        identity: 7,
    };
    let provider_region = task::MemoryRegion {
        shared: false,
        object: Some(task::Object(provider)),
        start: 0xa000,
        length: 8192,
        offset: 4096,
    };
    let replacement_region = task::MemoryRegion {
        shared: true,
        object: Some(task::Object(replacement)),
        start: 0xc000,
        length: 4096,
        offset: 0,
    };
    let anonymous = task::MemoryRegion {
        shared: false,
        object: None,
        start: 0xd000,
        length: 4096,
        offset: 0,
    };
    let root = Root::new(
        0x1000,
        &[region, provider_region, replacement_region, anonymous],
    )
    .unwrap();
    assert_eq!(root.mappings().len(), 3);
    assert!(root.mappings()[0].shared);
    assert!(!root.mappings()[1].shared);
    assert!(root.mappings()[2].shared);
    let mapping = &root.mappings()[0];
    assert_eq!(
        (
            mapping.identity,
            mapping.start,
            mapping.length,
            mapping.offset
        ),
        (vm_object::ObjectKey::Memory(7), 0x5000, 4096, 8192)
    );
    let mapping = &root.mappings()[1];
    assert_eq!(
        (
            mapping.identity,
            mapping.start,
            mapping.length,
            mapping.offset
        ),
        (provider, 0xa000, 8192, 4096)
    );
    assert_eq!(root.mappings()[2].identity, replacement);
    assert_ne!(root.mappings()[0].identity, provider);
    assert_ne!(root.mappings()[1].identity, replacement);
    let alias = root.clone();
    let pins = snapshot().unwrap();
    assert_eq!(pins.len(), 1);
    drop(root);
    drop(alias);
    assert!(destroyed().lock().unwrap().is_empty());
    drop(pins);
    assert_eq!(&*destroyed().lock().unwrap(), &[0x1000]);
    assert!(snapshot().unwrap().is_empty());

    let image = Root::new(0x2000, &[]).unwrap();
    // Taking an image from its Handle and installing it into an unpublished
    // process transfers an owning reference without a gap in discovery.
    let staged_process = image.clone();
    drop(image);
    assert_eq!(snapshot().unwrap().len(), 1);
    staged_process.publish();
    assert!(snapshot().unwrap().is_empty());
    drop(staged_process);
    assert_eq!(&*destroyed().lock().unwrap(), &[0x1000]);
    // The published process/creation-failure guard now owns raw-table cleanup.
    paging::destroy_user_page_table(0x2000).unwrap();
    assert_eq!(&*destroyed().lock().unwrap(), &[0x1000, 0x2000]);

    // A revocation snapshot can cross publication and owner retirement without
    // freeing the physical root out from under the retained snapshot.
    let image = Root::new(0x3000, &[]).unwrap();
    let pins = snapshot().unwrap();
    image.publish();
    drop(image);
    paging::destroy_user_page_table(0x3000).unwrap();
    assert_eq!(&*destroyed().lock().unwrap(), &[0x1000, 0x2000]);
    assert_eq!(pins[0].table(), 0x3000);
    drop(pins);
    assert_eq!(&*destroyed().lock().unwrap(), &[0x1000, 0x2000, 0x3000]);

    root_lifetime_native::FAIL.store(true, std::sync::atomic::Ordering::Release);
    assert!(Root::new(0x4000, &[]).is_err());
    assert_eq!(
        &*destroyed().lock().unwrap(),
        &[0x1000, 0x2000, 0x3000, 0x4000]
    );
    assert!(snapshot().unwrap().is_empty());

    // Warm registry capacity first, then fail every actual allocation for one
    // mapped root: lifetime state, mapping records and the root's own Arc.
    fn backing_region() -> task::MemoryRegion {
        task::MemoryRegion {
            shared: false,
            object: Some(task::Object(vm_object::ObjectKey::Memory(7))),
            start: 0x5000,
            length: 4096,
            offset: 8192,
        }
    }
    ALLOCATIONS.with(|count| count.set(0));
    let root = Root::new(0x5000, &[backing_region()]).unwrap();
    let allocations = ALLOCATIONS.with(std::cell::Cell::get);
    assert!(allocations >= 3);
    let references = std::sync::Arc::strong_count(&root);
    FAIL_AFTER.with(|state| state.set(Some(0)));
    assert!(snapshot().is_err());
    assert_eq!(FAIL_AFTER.with(std::cell::Cell::get), None);
    assert_eq!(std::sync::Arc::strong_count(&root), references);
    drop(root);
    for allocation in 0..allocations {
        let table = 0x6000 + allocation as u64 * 4096;
        let before = destroyed().lock().unwrap().len();
        FAIL_AFTER.with(|state| state.set(Some(allocation)));
        let result = Root::new(table, &[backing_region()]);
        assert_eq!(FAIL_AFTER.with(std::cell::Cell::get), None);
        assert!(result.is_err());
        let destroyed = destroyed().lock().unwrap();
        assert_eq!(destroyed.len(), before + 1);
        assert_eq!(destroyed.last(), Some(&table));
        drop(destroyed);
        assert!(snapshot().unwrap().is_empty());
    }
}
