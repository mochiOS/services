use crate::{paging as frames, task::MemoryRegion, vm_object, Kernel};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::interrupt::spinlock::SpinLock;

#[macro_export]
macro_rules! warn { ($($args:tt)*) => { let _ = format_args!($($args)*); }; }
thread_local! { static VM_HELD: Cell<bool> = const { Cell::new(false) }; }

#[path = "../../../../core/src/task/deferred.rs"]
pub(crate) mod deferred;
#[path = "../../../../core/src/mem/detached_roots.rs"]
mod detached_roots;
#[path = "../../../../core/src/mem/extent_transaction.rs"]
pub(crate) mod extent_transaction;
#[path = "../../../../core/src/mem/mapping_preservation_native.rs"]
mod mapping_preservation_native;
#[path = "../../../../core/src/mem/mapping_revocation.rs"]
mod mapping_revocation;
#[path = "../../../../core/src/mem/mapping_revocation_native.rs"]
mod mapping_revocation_native;
#[path = "../../../../core/src/mem/mapping_targets.rs"]
pub(crate) mod mapping_targets;
#[path = "../../../../core/src/mem/root_lifetime.rs"]
mod root_lifetime;
#[path = "../../../../core/src/mem/root_lifetime_native.rs"]
mod root_lifetime_native;

impl MemoryRegion {
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn file_offset(&self) -> u64 {
        0
    }
}

pub(crate) mod process {
    use super::*;
    pub struct Process {
        pub root: u64,
        pub regions: Vec<MemoryRegion>,
    }
    impl Process {
        pub fn page_table(&self) -> Option<u64> {
            Some(self.root)
        }
        pub fn memory_regions(&self) -> &[MemoryRegion] {
            &self.regions
        }
    }
    pub struct ProcessTable(pub Vec<Process>);
    impl ProcessTable {
        pub fn iter(&self) -> impl Iterator<Item = &Process> {
            self.0.iter()
        }
    }
    static TABLE: SpinLock<ProcessTable> = SpinLock::new(ProcessTable(Vec::new()));
    struct Context;
    impl Context {
        fn new() -> Self {
            assert!(!VM_HELD.with(Cell::get));
            VM_HELD.with(|slot| slot.set(true));
            Self
        }
    }
    impl Drop for Context {
        fn drop(&mut self) {
            VM_HELD.with(|slot| slot.set(false));
        }
    }
    pub fn with_mapping_table<R>(f: impl FnOnce(&ProcessTable) -> R) -> R {
        let table = TABLE.lock();
        let _context = Context::new();
        f(&table)
    }
    pub fn try_with_mapping_table<R>(f: impl FnOnce(&ProcessTable) -> R) -> Option<R> {
        let table = TABLE.try_lock()?;
        let _context = Context::new();
        Some(f(&table))
    }
    pub fn replace(table: ProcessTable) {
        *TABLE.lock() = table;
    }
}

pub(crate) mod paging {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Memory {
        InvalidAddress,
        NotMapped,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Kernel {
        Memory(Memory),
    }
    type Result<T> = std::result::Result<T, Kernel>;
    #[derive(Clone, Copy)]
    struct PageTableFlags(u64);
    impl PageTableFlags {
        const PRESENT: Self = Self(1);
        const USER_ACCESSIBLE: Self = Self(4);
        const ACCESSED: Self = Self(32);
        const DIRTY: Self = Self(64);
        fn bits(self) -> u64 {
            self.0
        }
        fn contains(self, other: Self) -> bool {
            self.0 & other.0 == other.0
        }
        fn remove(&mut self, other: Self) {
            self.0 &= !other.0;
        }
    }
    impl std::ops::BitOr for PageTableFlags {
        type Output = Self;
        fn bitor(self, other: Self) -> Self {
            Self(self.0 | other.0)
        }
    }
    impl std::ops::BitAnd for PageTableFlags {
        type Output = Self;
        fn bitand(self, other: Self) -> Self {
            Self(self.0 & other.0)
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Address(u64);
    impl Address {
        fn as_u64(self) -> u64 {
            self.0
        }
    }
    #[derive(Clone, Copy)]
    struct PageTableEntry {
        frame: u64,
        flags: PageTableFlags,
    }
    impl PageTableEntry {
        fn addr(&self) -> Address {
            Address(self.frame)
        }
        fn flags(&self) -> PageTableFlags {
            self.flags
        }
        fn is_unused(&self) -> bool {
            self.frame == 0 && self.flags.0 == 0
        }
        fn set_addr(&mut self, address: Address, flags: PageTableFlags) {
            self.frame = address.0;
            self.flags = flags;
        }
        fn set_unused(&mut self) {
            self.frame = 0;
            self.flags = PageTableFlags(0);
        }
    }
    static ENTRIES: Mutex<BTreeMap<(u64, u64), Box<PageTableEntry>>> = Mutex::new(BTreeMap::new());
    pub static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
    pub static FAIL_LOOKUP: AtomicUsize = AtomicUsize::new(0);
    pub static DESTROYED: AtomicUsize = AtomicUsize::new(0);
    fn physical_memory_offset() -> Option<u64> {
        frames::physical_memory_offset()
    }
    fn with_user_leaf_entry_mut<T>(
        root: u64,
        address: u64,
        f: impl FnOnce(&mut PageTableEntry) -> T,
    ) -> Option<T> {
        assert!(VM_HELD.with(Cell::get));
        let lookup = LOOKUPS.fetch_add(1, Ordering::Relaxed) + 1;
        if lookup == FAIL_LOOKUP.load(Ordering::Relaxed) {
            return None;
        }
        ENTRIES
            .lock()
            .unwrap()
            .get_mut(&(root, address))
            .map(|entry| f(entry))
    }
    fn release_user_frame(frame: u64) {
        assert!(VM_HELD.with(Cell::get));
        frames::release_user_frame(frame);
    }
    #[path = "../../../../../core/src/mem/paging/suspension.rs"]
    mod suspension;
    pub(crate) use suspension::{RecordedUserPage, SuspendedUserPage, suspend_user_page};
    pub unsafe fn next_user_page_entry(root: u64, start: u64, end: u64) -> Result<Option<u64>> {
        assert!(VM_HELD.with(Cell::get));
        Ok(ENTRIES
            .lock()
            .unwrap()
            .range((root, start)..(root, end))
            .find(|(_, entry)| !entry.is_unused())
            .map(|(&(r, a), _)| {
                assert_eq!(r, root);
                a
            }))
    }
    pub fn install(root: u64, address: u64, frame: u64) {
        ENTRIES.lock().unwrap().insert(
            (root, address),
            Box::new(PageTableEntry {
                frame,
                flags: PageTableFlags(0x805),
            }),
        );
    }
    pub fn flags(root: u64, address: u64) -> Option<u64> {
        ENTRIES
            .lock()
            .unwrap()
            .get(&(root, address))
            .filter(|entry| !entry.is_unused())
            .map(|entry| entry.flags.0)
    }
    pub fn destroy_user_page_table(root: u64) -> Result<()> {
        if root_lifetime::retire(root) {
            return Ok(());
        }
        destroy_user_page_table_unpinned(root)
    }
    pub fn destroy_user_page_table_unpinned(root: u64) -> Result<()> {
        loop {
            let entry = {
                let mut entries = ENTRIES.lock().unwrap();
                let Some(key) = entries.keys().find(|(r, _)| *r == root).copied() else {
                    break;
                };
                entries.remove(&key).unwrap()
            };
            if !entry.is_unused() {
                frames::release_user_frame(entry.frame);
            }
        }
        DESTROYED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

pub(crate) mod tlb_shootdown {
    use super::*;
    pub static FAIL: AtomicBool = AtomicBool::new(false);
    pub static DROP_OFFSET_AFTER_ACK: AtomicBool = AtomicBool::new(false);
    pub fn invalidate_all() -> std::result::Result<(), ()> {
        assert!(VM_HELD.with(Cell::get));
        if FAIL.load(Ordering::Relaxed) {
            Err(())
        } else {
            if DROP_OFFSET_AFTER_ACK.load(Ordering::Relaxed) {
                crate::PHYSICAL_OFFSET.with(|offset| offset.set(None));
            }
            Ok(())
        }
    }
}

const ROOT: u64 = 0x1000;
const BASE: u64 = 0x4000;
type CachePin = crate::vm_object::PreparedSharedPage;
fn setup() -> (Arc<crate::vm_object::VmObject>, CachePin, [u64; 2]) {
    assert!(crate::FRAMES.lock().unwrap().is_empty());
    crate::reset_lower(&vec![0x11; 8192]);
    let object = Arc::new(crate::provider_object());
    let pin = object.prepare_shared_page(0).unwrap();
    let physical = core::array::from_fn(|index| {
        let frame = crate::frame::allocate_zeroed_frame()
            .unwrap()
            .start_address()
            .as_u64();
        unsafe {
            std::ptr::write_bytes(frame as *mut u8, if index == 0 { 0x5a } else { 0xb7 }, 4096);
        }
        paging::install(ROOT, BASE + index as u64 * 4096, frame);
        frame
    });
    process::replace(process::ProcessTable(vec![process::Process {
        root: ROOT,
        regions: vec![MemoryRegion {
            start: BASE,
            length: 8192,
            object: Some(object.clone()),
        }],
    }]));
    paging::LOOKUPS.store(0, Ordering::Relaxed);
    paging::FAIL_LOOKUP.store(0, Ordering::Relaxed);
    (object, pin, physical)
}
fn cleanup(object: Arc<crate::vm_object::VmObject>, pin: CachePin) {
    extent_transaction::flush();
    process::replace(process::ProcessTable(Vec::new()));
    paging::destroy_user_page_table(ROOT).unwrap();
    drop(pin);
    object.invalidate().unwrap();
    drop(object);
    assert!(crate::FRAMES.lock().unwrap().is_empty());
}

#[test]
fn cache_preflight_failure_after_tlb_ack_keeps_records_until_deferred_rollback() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    let (object, pin, physical) = setup();
    let reads = crate::LOWER.lock().unwrap().reads;
    tlb_shootdown::DROP_OFFSET_AFTER_ACK.store(true, Ordering::Relaxed);
    let owner = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17);
    tlb_shootdown::DROP_OFFSET_AFTER_ACK.store(false, Ordering::Relaxed);
    crate::PHYSICAL_OFFSET.with(|offset| offset.set(Some(0)));
    assert!(matches!(owner, Err(crate::syscall::EIO)));
    assert_eq!(crate::LOWER.lock().unwrap().reads, reads);
    assert_eq!(crate::LOWER.lock().unwrap().bytes.len(), 8192);
    assert_eq!(paging::flags(ROOT, BASE), Some(0x804));
    assert_eq!(paging::flags(ROOT, BASE + 4096), Some(0x804));
    assert!(matches!(
        object.page(0),
        Err(crate::vm_object::VmPageError::Operation(
            crate::syscall::EAGAIN
        ))
    ));
    crate::without_allocations(extent_transaction::flush);
    assert_eq!(paging::flags(ROOT, BASE), Some(0x805));
    assert_eq!(paging::flags(ROOT, BASE + 4096), Some(0x805));
    assert!(
        unsafe { std::slice::from_raw_parts(physical[0] as *const u8, 4096) }
            .iter()
            .all(|byte| *byte == 0x5a)
    );
    assert_eq!(object.read_at(0, &mut [0; 8192]), Ok(8192));
    cleanup(object, pin);
}

#[test]
fn owner_drop_inside_vm_lock_only_enqueues_then_restores_without_allocations() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    let (object, pin, physical) = setup();
    let owner = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17).unwrap();
    // A retained owner must not retain the VM guard. Another thread can enter
    // that lock while the first owner waits for external work.
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        process::with_mapping_table(|_| sender.send(()).unwrap());
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    worker.join().unwrap();
    assert!(matches!(
        object.page(0),
        Err(crate::vm_object::VmPageError::Operation(
            crate::syscall::EAGAIN
        ))
    ));
    crate::without_allocations(|| {
        process::with_mapping_table(|_| {
            drop(owner);
            crate::actual_scheduler::yield_now(); // try-lock must not recurse
            assert_eq!(paging::flags(ROOT, BASE), Some(0x804));
        })
    });
    crate::without_allocations(crate::actual_scheduler::yield_now);
    assert_eq!(paging::flags(ROOT, BASE), Some(0x805));
    assert_eq!(paging::flags(ROOT, BASE + 4096), Some(0x805));
    assert!(
        unsafe { std::slice::from_raw_parts(physical[0] as *const u8, 4096) }
            .iter()
            .all(|b| *b == 0x5a)
    );
    assert_eq!(object.read_at(0, &mut [0; 8192]), Ok(8192));
    cleanup(object, pin);
}

#[test]
fn successful_local_publication_keeps_private_prefix_and_completes_once() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    let (object, pin, physical) = setup();
    let mut owner = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17).unwrap();
    crate::LOWER.lock().unwrap().bytes.truncate(17);
    let result = crate::without_allocations(|| owner.publish_local());
    assert_eq!(result, Ok(()));
    assert_eq!(owner.publish_local(), Err(crate::syscall::EINVAL));
    assert_eq!(paging::flags(ROOT, BASE), Some(0x805));
    assert_eq!(paging::flags(ROOT, BASE + 4096), None);
    let bytes = unsafe { std::slice::from_raw_parts(physical[0] as *const u8, 4096) };
    assert!(bytes[..17].iter().all(|b| *b == 0x5a));
    assert!(bytes[17..].iter().all(|b| *b == 0));
    assert!(!crate::FRAMES.lock().unwrap().contains_key(&physical[1]));
    assert_eq!(object.read_at(0, &mut [0; 8192]), Ok(17));
    drop(owner);
    cleanup(object, pin);
}

#[test]
fn failed_tlb_ack_and_reserved_invalidation_preserve_cancellation_ownership() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    for fail_tlb in [false, true] {
        let (object, pin, physical) = setup();
        tlb_shootdown::FAIL.store(fail_tlb, Ordering::Relaxed);
        let owner = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17);
        tlb_shootdown::FAIL.store(false, Ordering::Relaxed);
        if fail_tlb {
            assert!(matches!(owner, Err(crate::syscall::EIO)));
        } else {
            let owner = owner.unwrap();
            let generation = object.memory_generation();
            assert_eq!(
                crate::without_allocations(|| object.invalidate()),
                Err(crate::syscall::EAGAIN)
            );
            assert_eq!(object.memory_generation(), generation);
            drop(owner);
        }
        assert_eq!(paging::flags(ROOT, BASE), Some(0x804));
        crate::without_allocations(extent_transaction::flush);
        assert_eq!(paging::flags(ROOT, BASE), Some(0x805));
        assert_eq!(paging::flags(ROOT, BASE + 4096), Some(0x805));
        assert!(
            unsafe { std::slice::from_raw_parts(physical[0] as *const u8, 4096) }
                .iter()
                .all(|b| *b == 0x5a)
        );
        cleanup(object, pin);
    }
}

#[test]
fn published_owner_death_retries_remaining_finish_instead_of_restoring_old_extent() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    for fail_lookup in [4, 6] {
        let (object, pin, physical) = setup();
        let mut owner = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17).unwrap();
        crate::LOWER.lock().unwrap().bytes.truncate(17);
        paging::LOOKUPS.store(0, Ordering::Relaxed);
        paging::FAIL_LOOKUP.store(fail_lookup, Ordering::Relaxed);
        assert_eq!(
            crate::without_allocations(|| owner.publish_local()),
            Err(crate::syscall::EFAULT)
        );
        let generation = object.memory_generation();
        assert_eq!(
            crate::without_allocations(|| object.invalidate()),
            Err(crate::syscall::EAGAIN)
        );
        assert_eq!(object.memory_generation(), generation);
        assert!(matches!(
            object.page(0),
            Err(crate::vm_object::VmPageError::Operation(
                crate::syscall::EAGAIN
            ))
        ));
        crate::without_allocations(|| drop(owner));
        paging::FAIL_LOOKUP.store(0, Ordering::Relaxed);
        crate::without_allocations(extent_transaction::flush);
        assert_eq!(paging::flags(ROOT, BASE), Some(0x805));
        assert_eq!(paging::flags(ROOT, BASE + 4096), None);
        let bytes = unsafe { std::slice::from_raw_parts(physical[0] as *const u8, 4096) };
        assert!(bytes[..17].iter().all(|b| *b == 0x5a));
        assert!(bytes[17..].iter().all(|b| *b == 0));
        assert_eq!(object.read_at(0, &mut [0; 8192]), Ok(17));
        cleanup(object, pin);
    }
}

#[test]
fn retired_root_stays_alive_until_deferred_mapping_cancellation_finishes() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    let (object, pin, physical) = setup();
    let owner = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17).unwrap();
    let destroyed = paging::DESTROYED.load(Ordering::Relaxed);
    process::replace(process::ProcessTable(Vec::new()));
    paging::destroy_user_page_table(ROOT).unwrap();
    assert_eq!(paging::DESTROYED.load(Ordering::Relaxed), destroyed);
    assert!(
        physical
            .iter()
            .all(|frame| crate::FRAMES.lock().unwrap().contains_key(frame))
    );
    crate::without_allocations(|| drop(owner));
    crate::without_allocations(extent_transaction::flush);
    assert_eq!(paging::DESTROYED.load(Ordering::Relaxed), destroyed + 1);
    assert!(
        physical
            .iter()
            .all(|frame| !crate::FRAMES.lock().unwrap().contains_key(frame))
    );
    assert_eq!(object.read_at(0, &mut [0; 8192]), Ok(8192));
    drop(pin);
    object.invalidate().unwrap();
    assert!(crate::FRAMES.lock().unwrap().is_empty());
}

#[test]
fn deferred_rejection_retains_original_ticket_roots_and_admission_for_retry() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    let (object, pin, _) = setup();
    let owner = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17).unwrap();
    drop(owner);
    paging::LOOKUPS.store(0, Ordering::Relaxed);
    paging::FAIL_LOOKUP.store(1, Ordering::Relaxed);
    crate::without_allocations(extent_transaction::flush);
    assert_eq!(paging::flags(ROOT, BASE), Some(0x804));
    assert_eq!(paging::flags(ROOT, BASE + 4096), Some(0x804));
    assert!(matches!(
        object.page(0),
        Err(crate::vm_object::VmPageError::Operation(
            crate::syscall::EAGAIN
        ))
    ));
    paging::FAIL_LOOKUP.store(0, Ordering::Relaxed);
    crate::without_allocations(extent_transaction::flush);
    assert_eq!(paging::flags(ROOT, BASE), Some(0x805));
    assert_eq!(paging::flags(ROOT, BASE + 4096), Some(0x805));
    assert_eq!(object.read_at(0, &mut [0; 8192]), Ok(8192));
    cleanup(object, pin);
}

#[test]
fn pte_preflight_failure_precedes_cache_publication_and_node_failure_precedes_all_edits() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    let (object, pin, physical) = setup();
    let generation = object.memory_generation();
    crate::COMMIT_ALLOC_ATTEMPTS.with(|count| count.set(0));
    crate::DENY_COMMIT_ALLOC.with(|deny| deny.set(true));
    let failed = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17);
    crate::DENY_COMMIT_ALLOC.with(|deny| deny.set(false));
    assert!(matches!(failed, Err(crate::syscall::ENOMEM)));
    assert_eq!(crate::COMMIT_ALLOC_ATTEMPTS.with(|count| count.get()), 1);
    assert_eq!(object.memory_generation(), generation);
    assert_eq!(paging::flags(ROOT, BASE), Some(0x805));
    let mut owner = extent_transaction::ExtentTransaction::prepare(&object, 8192, 17).unwrap();
    let generation = object.memory_generation();
    paging::LOOKUPS.store(0, Ordering::Relaxed);
    paging::FAIL_LOOKUP.store(2, Ordering::Relaxed);
    assert_eq!(
        crate::without_allocations(|| owner.publish_local()),
        Err(crate::syscall::EFAULT)
    );
    assert_eq!(object.memory_generation(), generation);
    drop(owner);
    paging::FAIL_LOOKUP.store(0, Ordering::Relaxed);
    crate::without_allocations(extent_transaction::flush);
    assert!(
        unsafe { std::slice::from_raw_parts(physical[0] as *const u8, 4096) }
            .iter()
            .all(|byte| *byte == 0x5a)
    );
    assert_eq!(object.read_at(0, &mut [0; 8192]), Ok(8192));
    cleanup(object, pin);
}

#[test]
fn aligned_growth_unchanged_extent_and_full_shrink_do_not_invent_boundary_mappings() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    for length in [0, 8192, 12288] {
        let (object, pin, physical) = setup();
        let mut owner =
            extent_transaction::ExtentTransaction::prepare(&object, 8192, length).unwrap();
        crate::LOWER
            .lock()
            .unwrap()
            .bytes
            .resize(length as usize, 0);
        assert_eq!(crate::without_allocations(|| owner.publish_local()), Ok(()));
        assert_eq!(
            paging::flags(ROOT, BASE),
            if length == 0 { None } else { Some(0x805) }
        );
        if length > 0 {
            assert!(
                unsafe { std::slice::from_raw_parts(physical[0] as *const u8, 4096) }
                    .iter()
                    .all(|byte| *byte == 0x5a)
            );
        }
        assert_eq!(object.read_at(0, &mut [0; 16384]), Ok(length as usize));
        cleanup(object, pin);
    }
}

#[test]
fn partial_growth_zeros_only_the_newly_valid_private_boundary_suffix() {
    let _test = crate::TEST_LOCK.lock().unwrap();
    let (object, pin, physical) = setup();
    crate::LOWER.lock().unwrap().bytes.truncate(5000);
    let mut owner = extent_transaction::ExtentTransaction::prepare(&object, 5000, 8192).unwrap();
    assert_eq!(paging::flags(ROOT, BASE), Some(0x805));
    assert_eq!(paging::flags(ROOT, BASE + 4096), Some(0x804));
    crate::LOWER.lock().unwrap().bytes.resize(8192, 0);
    assert_eq!(crate::without_allocations(|| owner.publish_local()), Ok(()));
    let boundary = unsafe { std::slice::from_raw_parts(physical[1] as *const u8, 4096) };
    assert!(boundary[..904].iter().all(|byte| *byte == 0xb7));
    assert!(boundary[904..].iter().all(|byte| *byte == 0));
    assert_eq!(paging::flags(ROOT, BASE + 4096), Some(0x805));
    cleanup(object, pin);
}
