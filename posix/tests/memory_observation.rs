//! Exercise the production syscall policy with controlled page tables and
//! revocation failure. The real revocation transaction has separate tests.
#![allow(dead_code)]
extern crate self as mnu_abi;
#[path = "../../../core/crates/abi/src/status.rs"]
pub mod status;
pub const SUCCESS: u64 = 0;
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
thread_local! {
    static PROCESS: RefCell<task::Process> = RefCell::new(task::Process { regions: vec![] });
    static LOCKED: Cell<bool> = const { Cell::new(false) };
    static RESIDENT: RefCell<BTreeSet<u64>> = RefCell::new(BTreeSet::new());
    static FAIL_REVOKE: Cell<bool> = const { Cell::new(false) };
    static REVOKES: Cell<usize> = const { Cell::new(0) };
}
fn current_pid() -> Option<u64> {
    Some(1)
}
fn memory_range_is_mapped(process: &task::Process, _: u64, start: u64, end: u64) -> bool {
    (start..end)
        .step_by(4096)
        .all(|page| process.find_memory_region(page).is_some())
}
mod task {
    pub mod process {
        pub enum MemoryBacking {
            Anonymous { data: Vec<u8>, shared: bool },
            File,
        }
    }
    pub struct Region {
        pub start: u64,
        pub length: u64,
        pub backing: process::MemoryBacking,
    }
    impl Region {
        pub fn start(&self) -> u64 {
            self.start
        }
        pub fn end(&self) -> Option<u64> {
            self.start.checked_add(self.length)
        }
        pub fn backing(&self) -> &process::MemoryBacking {
            &self.backing
        }
        pub fn backing_mut(&mut self) -> &mut process::MemoryBacking {
            &mut self.backing
        }
        pub fn is_shared(&self) -> bool {
            matches!(
                self.backing,
                process::MemoryBacking::Anonymous { shared: true, .. }
            )
        }
        pub fn backing_page_is_resident(&self, address: u64) -> Result<bool, crate::status::Error> {
            Ok(
                matches!(&self.backing, process::MemoryBacking::Anonymous { data, .. } if (address-self.start) < data.len() as u64),
            )
        }
    }
    pub struct Process {
        pub regions: Vec<Region>,
    }
    impl Process {
        pub fn page_table(&self) -> Option<u64> {
            Some(17)
        }
        pub fn find_memory_region(&self, address: u64) -> Option<&Region> {
            self.regions
                .iter()
                .find(|r| r.start <= address && r.end().unwrap() > address)
        }
        pub fn memory_regions(&self) -> &[Region] {
            &self.regions
        }
        pub fn memory_regions_mut(&mut self) -> &mut [Region] {
            &mut self.regions
        }
    }
    pub fn with_process<T>(id: u64, apply: impl FnOnce(&Process) -> T) -> Option<T> {
        assert_eq!(id, 1);
        super::LOCKED.set(true);
        let result = super::PROCESS.with(|p| apply(&p.borrow()));
        super::LOCKED.set(false);
        Some(result)
    }
    pub fn with_process_mut<T>(id: u64, apply: impl FnOnce(&mut Process) -> T) -> Option<T> {
        assert_eq!(id, 1);
        super::LOCKED.set(true);
        let result = super::PROCESS.with(|p| apply(&mut p.borrow_mut()));
        super::LOCKED.set(false);
        Some(result)
    }
}
mod syscall {
    pub fn is_canonical_user_range(address: u64, length: u64) -> bool {
        address != 0
            && address
                .checked_add(length)
                .is_some_and(|end| end <= 0x800000000000)
    }
    pub fn copy_to_user_native(output: u64, bytes: &[u8]) -> Result<(), crate::status::Error> {
        assert!(
            !crate::LOCKED.get(),
            "output faults must not run under PROC"
        );
        if output < 4096 {
            return Err(crate::status::Error::InvalidAddress);
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output as *mut u8, bytes.len()) };
        Ok(())
    }
}
mod mem {
    pub mod paging {
        pub fn user_page_is_resident(table: u64, address: u64) -> bool {
            assert_eq!(table, 17);
            crate::RESIDENT.with(|r| r.borrow().contains(&address))
        }
    }
    pub mod mapping_admission {
        pub fn check_native(
            _: &[crate::task::Region],
            _: u64,
            _: u64,
        ) -> Result<(), crate::status::Error> {
            Ok(())
        }
    }
    pub mod mapping_revocation_native {
        pub struct Native;
        impl Native {
            pub unsafe fn for_process(_: &crate::task::Process, owns_ram: bool) -> Self {
                assert!(owns_ram);
                Self
            }
        }
    }
    pub mod mapping_revocation {
        pub enum Error {
            InvalidRange,
            Allocation,
            Backend(crate::status::Error),
        }
        pub fn revoke(
            ranges: [(u64, u64, u64); 1],
            _: &mut super::mapping_revocation_native::Native,
        ) -> Result<(), Error> {
            assert!(crate::LOCKED.get());
            assert_eq!(ranges[0].0, 17);
            crate::REVOKES.set(crate::REVOKES.get() + 1);
            if crate::FAIL_REVOKE.get() {
                return Err(Error::Backend(crate::status::Error::NotReady));
            }
            crate::RESIDENT.with(|r| {
                r.borrow_mut()
                    .retain(|page| *page < ranges[0].1 || *page >= ranges[0].2)
            });
            Ok(())
        }
    }
}
#[path = "../../../core/src/syscall/memory_observation.rs"]
mod implementation;
fn setup(backing: task::process::MemoryBacking) {
    PROCESS.with(|p| {
        p.borrow_mut().regions = vec![task::Region {
            start: 0x4000,
            length: 8192,
            backing,
        }]
    });
    RESIDENT.with(|r| *r.borrow_mut() = [0x4000].into_iter().collect());
}
#[test]
fn residency_reports_absent_and_retained_ram_without_faulting_source_or_copying_under_proc() {
    setup(task::process::MemoryBacking::Anonymous {
        data: vec![],
        shared: false,
    });
    let mut output = [99u8; 2];
    assert_eq!(
        implementation::residency(0x4000, 8192, output.as_mut_ptr() as u64, 2),
        2
    );
    assert_eq!(output, [1, 0]);
    assert_eq!(RESIDENT.with(|r| r.borrow().len()), 1);
    assert_eq!(
        implementation::residency(0x4001, 1, 0, 1),
        status::Error::InvalidArgument.into_raw()
    );
    assert_eq!(
        implementation::residency(0x4000, 8192, 0, 1),
        status::Error::InvalidArgument.into_raw()
    );
    assert_eq!(
        implementation::residency(0x4000, 12288, 0, 3),
        status::Error::InvalidAddress.into_raw()
    );
    assert_eq!(
        implementation::residency(0x4000, 4096, 1, 1),
        status::Error::InvalidAddress.into_raw()
    );
}
#[test]
fn discard_requires_complete_private_anonymous_coverage_and_only_clears_backing_after_success() {
    for backing in [
        task::process::MemoryBacking::File,
        task::process::MemoryBacking::Anonymous {
            data: vec![7; 8192],
            shared: true,
        },
    ] {
        setup(backing);
        assert_eq!(
            implementation::discard(0x4000, 4096),
            status::Error::Unsupported.into_raw()
        );
        assert_eq!(REVOKES.get(), 0);
    }
    setup(task::process::MemoryBacking::Anonymous {
        data: vec![7; 8192],
        shared: false,
    });
    assert_eq!(
        implementation::discard(0x4000, 12288),
        status::Error::InvalidAddress.into_raw()
    );
    assert_eq!(REVOKES.get(), 0);
    FAIL_REVOKE.set(true);
    assert_eq!(
        implementation::discard(0x4000, 4096),
        status::Error::NotReady.into_raw()
    );
    PROCESS.with(|p| {
        if let task::process::MemoryBacking::Anonymous { data, .. } =
            p.borrow().regions[0].backing()
        {
            assert_eq!(data, &vec![7; 8192]);
        }
    });
    FAIL_REVOKE.set(false);
    assert_eq!(implementation::discard(0x4000, 4096), 0);
    PROCESS.with(|p| {
        let p = p.borrow();
        assert_eq!(p.regions.len(), 1);
        if let task::process::MemoryBacking::Anonymous { data, .. } = p.regions[0].backing() {
            assert_eq!(&data[..4096], &vec![0; 4096]);
            assert_eq!(&data[4096..], &vec![7; 4096]);
        }
    });
    assert!(RESIDENT.with(|r| r.borrow().is_empty()));
}
