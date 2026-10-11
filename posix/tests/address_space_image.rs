//! Runs the production image ownership code with a mock page-table backend.
extern crate alloc;

use std::sync::Arc;

#[macro_export]
macro_rules! warn {
    ($($args:tt)*) => { let _ = format_args!($($args)*); };
}

mod task {
    use super::Arc;
    #[derive(Clone)]
    pub struct MemoryRegion {
        pub start: u64,
        pub shared: bool,
        pub backing: Arc<()>,
    }
    impl MemoryRegion {
        pub fn contains(&self, address: u64) -> bool {
            address == self.start
        }
        pub fn is_shared(&self) -> bool {
            self.shared
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
        pub table: Option<u64>,
        pub regions: Vec<MemoryRegion>,
        pub dma: Vec<DmaBuffer>,
        pub mmio: bool,
        pub bounds: [u64; 5],
    }
    impl Process {
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
                Ok(0xcafe)
            }
        })
    }
    pub fn destroy_user_page_table(table: u64) -> Result<(), ()> {
        STATE.with(|state| state.borrow_mut().destroyed.push(table));
        Ok(())
    }
}

#[path = "../../../core/src/mem/address_space.rs"]
mod address_space;

fn source() -> task::Process {
    paging::STATE.with(|state| *state.borrow_mut() = paging::Backend::default());
    task::Process {
        table: Some(0xbeef),
        regions: vec![
            task::MemoryRegion {
                start: 0x1000,
                shared: false,
                backing: Arc::new(()),
            },
            task::MemoryRegion {
                start: 0x2000,
                shared: true,
                backing: Arc::new(()),
            },
        ],
        dma: vec![task::DmaBuffer {
            start: 0x3000,
            end: Some(0x4000),
        }],
        mmio: false,
        bounds: [1, 2, 3, 4, 5],
    }
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
    drop(image);
    paging::STATE.with(|state| assert!(state.borrow().destroyed.is_empty()));
    drop(duplicate);
    assert_eq!(Arc::strong_count(&source.regions[0].backing), 1);
    paging::STATE.with(|state| assert_eq!(state.borrow().destroyed, vec![0xcafe]));
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
    assert_eq!(target.table, Some(0xcafe));
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
    paging::STATE.with(|state| assert_eq!(state.borrow().destroyed, vec![0xcafe]));
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
        .split("fn clone_current_process(")
        .next()
        .unwrap();
    assert!(clone.contains("caller_has_process_spawn_capability()"));
    assert!(clone.contains("current_process_id()"));
    assert!(clone.contains("if live_threads != 1"));
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
    ] {
        assert!(probe.contains(&format!("{name} = {}", number as u64)));
    }
}
