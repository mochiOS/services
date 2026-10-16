//! Runs the production image ownership code with a mock page-table backend.
extern crate alloc;

use std::sync::Arc;

mod vm_object {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ObjectKey {
        Memory(u64),
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
                self.0.lock().unwrap()
            }
        }
    }
}

#[macro_export]
macro_rules! warn {
    ($($args:tt)*) => { let _ = format_args!($($args)*); };
}

mod task {
    use super::Arc;
    pub mod process {
        pub struct PendingExecSecurity;
    }
    pub mod image_origin {
        thread_local! {
            pub static FAILURE: std::cell::Cell<Option<mnu_abi::status::Error>> = const { std::cell::Cell::new(None) };
        }
        #[derive(Clone)]
        pub struct ImageOrigin;
        impl ImageOrigin {
            pub fn capture(
                process: &super::Process,
            ) -> Result<Option<Self>, mnu_abi::status::Error> {
                if let Some(error) = FAILURE.with(std::cell::Cell::get) {
                    return Err(error);
                }
                Ok(process.measured.then_some(Self))
            }
            pub fn permits(&self, _: &super::process::PendingExecSecurity) -> bool {
                true
            }
        }
    }
    #[derive(Clone)]
    pub struct MemoryRegion {
        pub start: u64,
        pub shared: bool,
        pub backing: Arc<()>,
        pub object: Option<Arc<VmObject>>,
    }
    impl MemoryRegion {
        pub fn start(&self) -> u64 {
            self.start
        }
        pub fn len(&self) -> u64 {
            4096
        }
        pub fn backing(&self) -> &Self {
            self
        }
        pub fn file_offset(&self) -> u64 {
            0
        }
        pub fn file_object(&self) -> Option<&VmObject> {
            self.object.as_deref()
        }
        pub fn contains(&self, address: u64) -> bool {
            address == self.start
        }
        pub fn is_shared(&self) -> bool {
            self.shared
        }
    }
    pub struct VmObject {
        pub reserved: std::sync::atomic::AtomicBool,
        pub failure: std::sync::atomic::AtomicU64,
    }
    impl VmObject {
        pub fn memory_identity(&self) -> Option<u64> {
            None
        }
        pub fn object_key(&self) -> crate::vm_object::ObjectKey {
            crate::vm_object::ObjectKey::Memory(7)
        }
        pub fn memory_generation(&self) -> Option<u64> {
            Some(1)
        }
        pub fn with_memory_generation_native<T>(
            &self,
            generation: Option<u64>,
            install: impl FnOnce() -> Result<T, mnu_abi::status::Error>,
        ) -> Result<T, mnu_abi::status::Error> {
            assert_eq!(generation, Some(1));
            if let Some(error) = mnu_abi::status::Error::from_raw(
                self.failure.load(std::sync::atomic::Ordering::Acquire),
            ) {
                return Err(error);
            }
            if self.reserved.load(std::sync::atomic::Ordering::Acquire) {
                Err(mnu_abi::status::Error::NotReady)
            } else {
                install()
            }
        }
    }
    pub struct DmaBuffer {
        pub start: u64,
        pub end: Option<u64>,
    }
    impl DmaBuffer {
        pub fn virt_start(&self) -> u64 {
            self.start
        }
        pub fn end(&self) -> Option<u64> {
            self.end
        }
    }
    #[derive(Default)]
    pub struct Process {
        pub measured: bool,
        pub table: Option<u64>,
        pub regions: Vec<MemoryRegion>,
        pub dma: Vec<DmaBuffer>,
        pub mmio: bool,
        pub bounds: [u64; 5],
        pub root: Option<Arc<crate::detached_roots::Root>>,
    }
    impl Process {
        pub fn set_pending_image_root(&mut self, root: Arc<crate::detached_roots::Root>) {
            self.root = Some(root);
        }
        pub fn has_mmio_mappings(&self) -> bool {
            self.mmio
        }
        pub fn page_table(&self) -> Option<u64> {
            self.table
        }
        pub fn memory_regions(&self) -> &[MemoryRegion] {
            &self.regions
        }
        pub fn dma_buffers(&self) -> &[DmaBuffer] {
            &self.dma
        }
        pub fn heap_start(&self) -> u64 {
            self.bounds[0]
        }
        pub fn heap_end(&self) -> u64 {
            self.bounds[1]
        }
        pub fn ipc_mapping_end(&self) -> u64 {
            self.bounds[2]
        }
        pub fn stack_bottom(&self) -> u64 {
            self.bounds[3]
        }
        pub fn stack_top(&self) -> u64 {
            self.bounds[4]
        }
        pub fn set_page_table(&mut self, table: u64) {
            self.table = Some(table);
        }
        pub fn set_memory_regions(&mut self, regions: Vec<MemoryRegion>) {
            self.regions = regions;
        }
        pub fn set_heap_start(&mut self, value: u64) {
            self.bounds[0] = value;
        }
        pub fn set_heap_end(&mut self, value: u64) {
            self.bounds[1] = value;
        }
        pub fn set_ipc_mapping_end(&mut self, value: u64) {
            self.bounds[2] = value;
        }
        pub fn set_stack_bottom(&mut self, value: u64) {
            self.bounds[3] = value;
        }
        pub fn set_stack_top(&mut self, value: u64) {
            self.bounds[4] = value;
        }
    }
}

mod paging {
    use std::cell::RefCell;
    static NEXT_TABLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0xc000);
    static LIVE_TABLES: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
    thread_local! {
        static CLONED_TABLE: u64 = NEXT_TABLE.fetch_add(4096, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn cloned_table() -> u64 {
        CLONED_TABLE.with(|table| *table)
    }
    #[derive(Debug, PartialEq, Eq)]
    pub enum ForkPagePolicy {
        Exclude,
        Shared,
        PrivateWritable,
        Private,
    }
    #[derive(Default)]
    pub struct Backend {
        pub destroyed: Vec<u64>,
        pub failed: bool,
        pub calls: usize,
        pub context_walks: usize,
    }
    thread_local! { pub static STATE: RefCell<Backend> = RefCell::default(); }
    pub fn clone_user_page_table(
        table: u64,
        policy: impl Fn(u64) -> ForkPagePolicy,
    ) -> Result<u64, ()> {
        assert_eq!(table, 0xbeef);
        assert_eq!(policy(0x1000), ForkPagePolicy::PrivateWritable);
        assert_eq!(policy(0x2000), ForkPagePolicy::Shared);
        assert_eq!(policy(0x3000), ForkPagePolicy::Exclude);
        assert_eq!(policy(0x9000), ForkPagePolicy::Private);
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.calls += 1;
            if state.failed {
                Err(())
            } else {
                let table = cloned_table();
                let mut live = LIVE_TABLES.lock().unwrap();
                assert!(!live.contains(&table));
                live.push(table);
                Ok(table)
            }
        })
    }
    pub fn destroy_user_page_table(table: u64) -> Result<(), ()> {
        if super::root_lifetime::retire(table) {
            return Ok(());
        }
        destroy_user_page_table_unpinned(table)
    }
    pub fn destroy_user_page_table_unpinned(table: u64) -> Result<(), ()> {
        let mut live = LIVE_TABLES.lock().unwrap();
        let index = live
            .iter()
            .position(|existing| *existing == table)
            .expect("double or unknown root destruction");
        live.swap_remove(index);
        drop(live);
        STATE.with(|state| state.borrow_mut().destroyed.push(table));
        Ok(())
    }
    pub fn is_user_initial_context_in_table(
        table: u64,
        context: &mnu_abi::ThreadCreateContext,
    ) -> bool {
        STATE.with(|state| state.borrow_mut().context_walks += 1);
        LIVE_TABLES.lock().unwrap().contains(&table)
            && context.entry == 0x9000
            && context.stack_pointer == 0xa000
    }
}

#[path = "../../../core/src/mem/root_lifetime.rs"]
mod root_lifetime;
mod root_lifetime_native {
    pub fn pin(table: u64) -> Result<super::root_lifetime::Pin, ()> {
        super::root_lifetime::pin_with(table, |state| Ok(std::sync::Arc::new(state)))
    }
}

#[path = "../../../core/src/mem/address_space.rs"]
mod address_space;
#[path = "../../../core/src/mem/detached_roots.rs"]
mod detached_roots;

fn source() -> task::Process {
    paging::STATE.with(|state| *state.borrow_mut() = paging::Backend::default());
    task::Process {
        measured: false,
        table: Some(0xbeef),
        regions: vec![
            task::MemoryRegion {
                start: 0x1000,
                shared: false,
                backing: Arc::new(()),
                object: None,
            },
            task::MemoryRegion {
                start: 0x2000,
                shared: true,
                backing: Arc::new(()),
                object: None,
            },
        ],
        dma: vec![task::DmaBuffer {
            start: 0x3000,
            end: Some(0x4000),
        }],
        mmio: false,
        bounds: [1, 2, 3, 4, 5],
        root: None,
    }
}

fn sealed_object() -> Arc<address_space::AddressSpaceObject> {
    let mut source = source();
    source.measured = true;
    Arc::new(address_space::AddressSpaceObject::new(
        address_space::CloneSource::capture(&source)
            .ok()
            .unwrap()
            .clone_image()
            .ok()
            .unwrap(),
    ))
}

fn initial_context() -> mnu_abi::ThreadCreateContext {
    mnu_abi::ThreadCreateContext {
        entry: 0x9000,
        stack_pointer: 0xa000,
        ..Default::default()
    }
}

#[test]
fn one_shot_consumption_is_shared_across_duplicate_references() {
    let object = sealed_object();
    let alias = object.clone();
    let image = object
        .consume(&task::process::PendingExecSecurity, &initial_context())
        .unwrap();
    assert!(matches!(
        alias.consume(&task::process::PendingExecSecurity, &initial_context()),
        Err(address_space::ConsumeError::Consumed)
    ));
    drop(object);
    drop(alias);
    paging::STATE.with(|state| assert!(state.borrow().destroyed.is_empty()));
    drop(image);
    paging::STATE.with(|state| {
        assert_eq!(
            state.borrow().destroyed,
            vec![crate::paging::cloned_table()]
        )
    });
}

#[test]
fn concurrent_aliases_have_exactly_one_vm_owner() {
    let object = sealed_object();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let object = object.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                object.consume(&task::process::PendingExecSecurity, &initial_context())
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(address_space::ConsumeError::Consumed)))
            .count(),
        7
    );
    drop(object);
    paging::STATE.with(|state| assert!(state.borrow().destroyed.is_empty()));
    drop(results);
    paging::STATE.with(|state| {
        assert_eq!(
            state.borrow().destroyed,
            vec![crate::paging::cloned_table()]
        )
    });
}

#[test]
fn image_captured_before_reservation_is_not_consumed_or_walked_until_retry() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for (selected, measured) in [(0, false), (1, false), (0, true), (1, true)] {
        let mut source = source();
        source.measured = measured;
        let backing = Arc::new(task::VmObject {
            reserved: AtomicBool::new(false),
            failure: std::sync::atomic::AtomicU64::new(0),
        });
        source.regions[selected].object = Some(backing.clone());
        let captured = address_space::CloneSource::capture(&source)
            .ok()
            .unwrap()
            .clone_image()
            .ok()
            .unwrap();
        let object = Arc::new(address_space::AddressSpaceObject::new(captured));
        let alias = object.clone();
        let mut invalid = initial_context();
        invalid.entry = 0;
        backing.reserved.store(true, Ordering::Release);
        for context in [initial_context(), invalid] {
            assert_eq!(
                alias
                    .consume(&task::process::PendingExecSecurity, &context)
                    .err(),
                Some(if measured {
                    address_space::ConsumeError::Backing(mnu_abi::status::Error::NotReady)
                } else {
                    address_space::ConsumeError::Authorization
                })
            );
        }
        paging::STATE.with(|state| {
            assert_eq!(state.borrow().context_walks, 0);
            assert!(state.borrow().destroyed.is_empty());
        });
        backing.reserved.store(false, Ordering::Release);
        if !measured {
            assert!(matches!(
                alias.consume(&task::process::PendingExecSecurity, &initial_context()),
                Err(address_space::ConsumeError::Authorization)
            ));
            drop(alias);
            drop(object);
            paging::STATE
                .with(|state| assert_eq!(state.borrow().destroyed, [paging::cloned_table()]));
            continue;
        }
        assert!(matches!(
            object.consume(&task::process::PendingExecSecurity, &invalid),
            Err(address_space::ConsumeError::Context)
        ));
        let image = alias
            .consume(&task::process::PendingExecSecurity, &initial_context())
            .unwrap();
        assert!(matches!(
            object.consume(&task::process::PendingExecSecurity, &initial_context()),
            Err(address_space::ConsumeError::Consumed)
        ));
        paging::STATE.with(|state| assert_eq!(state.borrow().context_walks, 2));
        drop(alias);
        drop(object);
        paging::STATE.with(|state| assert!(state.borrow().destroyed.is_empty()));
        drop(image);
        paging::STATE.with(|state| assert_eq!(state.borrow().destroyed, [paging::cloned_table()]));
    }
}

#[test]
fn invalid_target_context_does_not_consume_the_image() {
    let object = sealed_object();
    let mut invalid = initial_context();
    invalid.entry = 0xbeef;
    assert!(matches!(
        object.consume(&task::process::PendingExecSecurity, &invalid),
        Err(address_space::ConsumeError::Context)
    ));
    let image = object
        .consume(&task::process::PendingExecSecurity, &initial_context())
        .unwrap();
    drop(image);
    drop(object);
    paging::STATE.with(|state| {
        assert_eq!(
            state.borrow().destroyed,
            vec![crate::paging::cloned_table()]
        )
    });
}

#[test]
fn anonymous_image_is_not_consumed_on_authorization_failure() {
    let source = source();
    let object = address_space::AddressSpaceObject::new(
        address_space::CloneSource::capture(&source)
            .ok()
            .unwrap()
            .clone_image()
            .ok()
            .unwrap(),
    );
    for _ in 0..2 {
        assert!(matches!(
            object.consume(&task::process::PendingExecSecurity, &initial_context()),
            Err(address_space::ConsumeError::Authorization)
        ));
    }
    drop(object);
    paging::STATE.with(|state| {
        assert_eq!(
            state.borrow().destroyed,
            vec![crate::paging::cloned_table()]
        )
    });
}

#[test]
fn final_reference_releases_table_and_backing_once() {
    let source = source();
    let image = Arc::new(
        address_space::CloneSource::capture(&source)
            .ok()
            .unwrap()
            .clone_image()
            .ok()
            .unwrap(),
    );
    assert_eq!(Arc::strong_count(&source.regions[0].backing), 2);
    let duplicate = image.clone();
    assert!(!image.permits(&task::process::PendingExecSecurity));
    drop(image);
    paging::STATE.with(|state| assert!(state.borrow().destroyed.is_empty()));
    drop(duplicate);
    assert_eq!(Arc::strong_count(&source.regions[0].backing), 1);
    paging::STATE.with(|state| {
        assert_eq!(
            state.borrow().destroyed,
            vec![crate::paging::cloned_table()]
        )
    });
}

#[test]
fn installation_moves_only_vm_state_into_empty_container() {
    let source = source();
    let image = address_space::CloneSource::capture(&source)
        .ok()
        .unwrap()
        .clone_image()
        .ok()
        .unwrap();
    let mut target = task::Process::default();
    image.install(&mut target).unwrap();
    assert_eq!(target.table, Some(crate::paging::cloned_table()));
    assert_eq!(target.bounds, source.bounds);
    assert_eq!(target.regions.len(), 2);
    assert!(target.dma.is_empty() && !target.mmio);
    paging::STATE.with(|state| assert!(state.borrow().destroyed.is_empty()));
}

#[test]
fn occupied_target_is_unchanged_and_caller_retains_image() {
    let mut target = source();
    let image = address_space::CloneSource::capture(&target)
        .ok()
        .unwrap()
        .clone_image()
        .ok()
        .unwrap();
    let image = image.install(&mut target).unwrap_err();
    assert_eq!(target.table, Some(0xbeef));
    paging::STATE.with(|state| assert!(state.borrow().destroyed.is_empty()));
    drop(image);
    paging::STATE.with(|state| {
        assert_eq!(
            state.borrow().destroyed,
            vec![crate::paging::cloned_table()]
        )
    });
}

#[test]
fn origin_capture_failure_is_not_an_unmeasured_clone() {
    let source = source();
    let pins = Arc::strong_count(&source.regions[0].backing);
    task::image_origin::FAILURE
        .with(|failure| failure.set(Some(mnu_abi::status::Error::ResourceUnavailable)));
    let result = address_space::CloneSource::capture(&source);
    task::image_origin::FAILURE.with(|failure| failure.set(None));
    assert!(matches!(
        result,
        Err(address_space::CloneError::Backing(
            mnu_abi::status::Error::ResourceUnavailable
        ))
    ));
    assert_eq!(Arc::strong_count(&source.regions[0].backing), pins);
    paging::STATE.with(|state| {
        assert_eq!(state.borrow().calls, 0);
        assert!(state.borrow().destroyed.is_empty());
    });
}

#[test]
fn borrowed_mapping_and_absent_source_are_rejected_before_allocation() {
    let mut source = source();
    source.mmio = true;
    assert!(matches!(
        address_space::CloneSource::capture(&source),
        Err(address_space::CloneError::BorrowedMapping)
    ));
    source.mmio = false;
    source.dma[0].end = None;
    assert!(matches!(
        address_space::CloneSource::capture(&source),
        Err(address_space::CloneError::BorrowedMapping)
    ));
    source.dma.clear();
    source.table = None;
    assert!(matches!(
        address_space::CloneSource::capture(&source),
        Err(address_space::CloneError::MissingPageTable)
    ));
    paging::STATE.with(|state| assert_eq!(state.borrow().calls, 0));
}

#[test]
fn reserved_shared_or_private_backing_rejects_capture_before_cow_and_root_creation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for selected in 0..2 {
        let mut source = source();
        let object = Arc::new(task::VmObject {
            reserved: AtomicBool::new(true),
            failure: std::sync::atomic::AtomicU64::new(0),
        });
        source.regions[selected].object = Some(object.clone());
        assert!(matches!(
            address_space::CloneSource::capture(&source),
            Err(address_space::CloneError::Backing(
                mnu_abi::status::Error::NotReady
            ))
        ));
        paging::STATE.with(|state| {
            assert_eq!(state.borrow().calls, 0);
            assert!(state.borrow().destroyed.is_empty());
        });
        assert_eq!(source.table, Some(0xbeef));
        assert_eq!(Arc::strong_count(&source.regions[0].backing), 1);
        object.reserved.store(false, Ordering::Release);
        let image = address_space::CloneSource::capture(&source)
            .ok()
            .unwrap()
            .clone_image()
            .ok()
            .unwrap();
        paging::STATE.with(|state| assert_eq!(state.borrow().calls, 1));
        drop(image);
        paging::STATE
            .with(|state| assert_eq!(state.borrow().destroyed, [crate::paging::cloned_table()]));
    }
}

#[test]
fn backing_failures_keep_their_native_cause_and_do_not_consume_the_image() {
    use mnu_abi::status::Error;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    for selected in 0..2 {
        for failure in [
            Error::BackingFailure,
            Error::AccessDenied,
            Error::ResourceUnavailable,
        ] {
            let mut source = source();
            source.measured = true;
            let backing = Arc::new(task::VmObject {
                reserved: AtomicBool::new(false),
                failure: AtomicU64::new(failure.into_raw()),
            });
            source.regions[selected].object = Some(backing.clone());
            assert!(matches!(address_space::CloneSource::capture(&source),
                Err(address_space::CloneError::Backing(error)) if error==failure));
            paging::STATE.with(|state| assert_eq!(state.borrow().calls, 0));
            backing.failure.store(0, Ordering::Release);
            let image = address_space::CloneSource::capture(&source)
                .ok()
                .unwrap()
                .clone_image()
                .ok()
                .unwrap();
            let object = address_space::AddressSpaceObject::new(image);
            backing.failure.store(failure.into_raw(), Ordering::Release);
            for _ in 0..2 {
                assert!(
                    matches!(object.consume(&task::process::PendingExecSecurity, &initial_context()),
                    Err(address_space::ConsumeError::Backing(error)) if error==failure)
                );
            }
            paging::STATE.with(|state| {
                assert_eq!(state.borrow().context_walks, 0);
                assert!(state.borrow().destroyed.is_empty());
            });
            // Failure retained ownership: discarding the object still reclaims
            // the complete image exactly once, without needing a retry loop.
            drop(object);
            paging::STATE
                .with(|state| assert_eq!(state.borrow().destroyed, [paging::cloned_table()]));
        }
    }
}

#[test]
fn failed_clone_publishes_no_owner_and_leaves_source_intact() {
    let source = source();
    paging::STATE.with(|state| state.borrow_mut().failed = true);
    assert!(matches!(
        address_space::CloneSource::capture(&source)
            .ok()
            .unwrap()
            .clone_image(),
        Err(address_space::CloneError::Allocation)
    ));
    assert_eq!(source.table, Some(0xbeef));
    assert_eq!(Arc::strong_count(&source.regions[0].backing), 1);
    paging::STATE.with(|state| assert!(state.borrow().destroyed.is_empty()));
}

#[test]
fn native_entrypoint_does_not_create_execution_or_capture_other_processes() {
    let source = include_str!("../../../core/src/syscall/process.rs");
    let clone = source
        .split("pub fn clone_address_space() -> u64 {")
        .nth(1)
        .unwrap()
        .split("pub fn suspend_current_process(")
        .next()
        .unwrap();
    assert!(clone.contains("caller_has_process_spawn_capability()"));
    assert!(clone.contains("current_process_id()"));
    assert!(clone.contains("begin_image_transition(pid)"));
    assert!(clone.contains("quiesce_image_siblings(pid, owner)"));
    for forbidden in [
        "add_process(",
        "add_thread(",
        "clone_object_handles",
        "set_capabilities",
        "new_user_resume",
    ] {
        assert!(!clone.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn native_probe_numbers_match_authoritative_abi() {
    let probe = include_str!("native_clone_cow.c");
    for (name, number) in [
        ("SPACE_CLONE", mnu_abi::SyscallNumber::AddressSpaceClone),
        ("RIGHTS_GET", mnu_abi::SyscallNumber::HandleRightsGet),
        ("DUPLICATE", mnu_abi::SyscallNumber::HandleDuplicate),
        ("SAME_OBJECT", mnu_abi::SyscallNumber::HandleSameObject),
        (
            "MEMORY_OBJECT_CREATE",
            mnu_abi::SyscallNumber::MemoryObjectCreate,
        ),
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
    ] {
        assert!(probe.contains(&format!("{name} = {}", number as u64)));
    }
}

#[test]
fn execution_creation_consumes_a_detached_vm_image_without_implicit_clone() {
    let source = include_str!("../../../core/src/syscall/process.rs");
    assert!(!source.contains("fn clone_current_process("));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    assert!(exec.contains("KernelObject::AddressSpace"));
    assert!(exec.contains("image.install(&mut process)"));
    assert!(!exec.contains("clone_user_page_table("));
    assert!(!exec.contains("clone_object_handles"));
    let process = include_str!("../../../core/src/task/process.rs");
    assert!(!process.contains("clone_memory_regions_for_fork"));
}
