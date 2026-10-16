extern crate alloc;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
    static COPIES: Cell<usize> = const { Cell::new(0) };
    static COPY_ERROR: Cell<Option<u64>> = const { Cell::new(None) };
    static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    static MAPS: Cell<usize> = const { Cell::new(0) };
}

struct FaultAllocator;
fn reject() -> bool {
    if FAIL_NEXT
        .try_with(|value| value.replace(false))
        .unwrap_or(false)
    {
        return true;
    }
    FAIL_AFTER
        .try_with(|value| match value.get() {
            Some(0) => {
                value.set(None);
                true
            }
            Some(count) => {
                value.set(Some(count - 1));
                false
            }
            None => false,
        })
        .unwrap_or(false)
}
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if reject() {
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if reject() {
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if reject() {
            core::ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

#[path = "../../../core/src/util/object_snapshot.rs"]
pub mod snapshot;
mod util {
    pub(crate) use crate::snapshot as object_snapshot;
}
mod syscall {
    pub mod types {
        pub const EINVAL: u64 = mnu_abi::EINVAL;
        pub const ENOMEM: u64 = mnu_abi::ENOMEM;
    }
    pub fn copy_from_user(pointer: u64, bytes: &mut [u8]) -> Result<(), u64> {
        assert_eq!(pointer, 42);
        crate::COPIES.with(|copies| copies.set(copies.get() + 1));
        bytes.fill(0xa5);
        crate::COPY_ERROR.with(|error| error.get().map_or(Ok(()), Err))
    }
    pub fn copy_from_user_native(
        pointer: u64,
        bytes: &mut [u8],
    ) -> Result<(), mnu_abi::status::Error> {
        copy_from_user(pointer, bytes).map_err(|raw| {
            mnu_abi::status::Error::from_raw(raw)
                .unwrap_or(mnu_abi::status::Error::InvalidAddress)
        })
    }
}
#[path = "../../../core/src/syscall/exec/storage.rs"]
mod storage;

struct InitialUserStack {
    stack_base_vaddr: u64,
    stack_end_vaddr: u64,
    initial_rsp: u64,
    page_data: Vec<u8>,
}
#[path = "../../../core/src/syscall/exec/bootstrap_stack.rs"]
mod bootstrap_stack;

#[test]
fn bootstrap_entry_is_empty_aligned_bounded_and_fallible() {
    let stack = bootstrap_stack::empty(0x800000, 32).unwrap();
    assert_eq!(
        (stack.stack_base_vaddr, stack.stack_end_vaddr),
        (0x7e0000, 0x800000)
    );
    assert_eq!(stack.initial_rsp, 0x7ff000);
    assert!(stack.page_data.len() == 4096 && stack.page_data.iter().all(|&byte| byte == 0));
    for (end, pages) in [
        (0, 32),
        (4096, 32),
        (0x800001, 32),
        (1u64 << 48, 32),
        (0x800000, 0),
        (0x800000, 1),
        (0x800000, usize::MAX),
    ] {
        assert_eq!(
            bootstrap_stack::empty(end, pages).err(),
            Some(mnu_abi::EINVAL)
        );
    }
    FAIL_NEXT.with(|fail| fail.set(true));
    let result = bootstrap_stack::empty(0x800000, 32);
    let consumed = FAIL_NEXT.with(|fail| !fail.replace(false));
    assert!(consumed);
    assert_eq!(result.err(), Some(mnu_abi::ENOMEM));
}

// Fixed ELF/page-table doubles keep every observed allocation in the actual
// production segment/reservation preparation, not in the test backend.
#[allow(dead_code)]
mod elf {
    pub const PT_LOAD: u32 = 1;
    pub struct Elf64Ehdr {
        pub e_entry: u64,
        pub e_machine: u16,
        pub e_phoff: u64,
        pub e_phentsize: u16,
        pub e_phnum: u16,
    }
    pub struct Elf64Phdr {
        pub p_type: u32,
        pub p_flags: u32,
        pub p_offset: u64,
        pub p_vaddr: u64,
        pub p_filesz: u64,
        pub p_memsz: u64,
        pub p_align: u64,
    }
    pub fn parse_elf_header(_: &[u8]) -> Option<Elf64Ehdr> {
        Some(Elf64Ehdr {
            e_entry: 0x400000,
            e_machine: 0x3e,
            e_phoff: 64,
            e_phentsize: 64,
            e_phnum: 2,
        })
    }
    pub fn parse_phdr(_: &[u8], offset: usize) -> Option<Elf64Phdr> {
        Some(if offset == 64 {
            Elf64Phdr {
                p_type: 1,
                p_flags: 1,
                p_offset: 0,
                p_vaddr: 0x400000,
                p_filesz: 4096,
                p_memsz: 4096,
                p_align: 4096,
            }
        } else {
            Elf64Phdr {
                p_type: 1,
                p_flags: 2,
                p_offset: 4096,
                p_vaddr: 0x500000,
                p_filesz: 4096,
                p_memsz: 8192,
                p_align: 4096,
            }
        })
    }
}
mod task {
    #[allow(dead_code)]
    pub struct MemoryRegion(u64);
    impl MemoryRegion {
        pub fn anonymous(_: u64, _: u64, _: u64, _: u64, _: bool, _: bool) -> Self {
            Self(0)
        }
    }
}
mod mem {
    pub mod paging {
        pub fn map_and_copy_segment_to(
            _: u64,
            _: u64,
            _: u64,
            _: u64,
            _: &[u8],
            _: bool,
            _: bool,
        ) -> Result<(), ()> {
            crate::MAPS.with(|maps| maps.set(maps.get() + 1));
            Ok(())
        }
    }
}
struct ExecMeasurement;
impl ExecMeasurement {
    fn parse<T>(&mut self, f: impl FnOnce() -> T) -> T {
        f()
    }
    fn load<T>(&mut self, f: impl FnOnce() -> T) -> T {
        f()
    }
}
fn mapping_error_errno(_: ()) -> u64 {
    mnu_abi::EFAULT
}
#[path = "../../../core/src/syscall/exec/image.rs"]
mod image;

#[test]
fn elf_metadata_allocation_failures_precede_page_table_mutation() {
    for successful_allocations in 0..2 {
        MAPS.with(|maps| maps.set(0));
        FAIL_AFTER.with(|fail| fail.set(Some(successful_allocations)));
        let result = image::map_elf_image(&[0; 8192], 1, &mut ExecMeasurement);
        let consumed = FAIL_AFTER.with(|fail| fail.replace(None).is_none());
        assert!(consumed);
        assert_eq!(result.err(), Some(mnu_abi::ENOMEM));
        assert_eq!(MAPS.with(Cell::get), 0);
    }
    let layout = image::map_elf_image(&[0; 8192], 1, &mut ExecMeasurement).unwrap();
    assert_eq!(layout.entry, 0x400000);
    assert_eq!(
        (layout.phdr_vaddr, layout.phentsize, layout.phnum),
        (0x400040, 64, 2)
    );
    assert_eq!(layout.deferred_zero_regions.len(), 1);
    assert_eq!(MAPS.with(Cell::get), 2);
}

#[test]
fn allocator_failure_returns_enomem_without_copy_or_allocation_error_handler() {
    COPIES.with(|copies| copies.set(0));
    for length in [1, 256, 4096, 8192, 65536] {
        FAIL_NEXT.with(|fail| fail.set(true));
        let result = storage::from_user(42, length);
        let consumed = FAIL_NEXT.with(|fail| !fail.replace(false));
        assert!(consumed);
        assert_eq!(result, Err(mnu_abi::ENOMEM));
        assert_eq!(COPIES.with(Cell::get), 0);
    }
    // Fault injection is scoped to the failed allocation, not a persistent
    // process limit: a subsequent preparation can allocate and copy normally.
    assert_eq!(storage::from_user(42, 8).unwrap(), [0xa5; 8]);
}

#[test]
fn zeroing_capacity_overflow_copy_errors_and_empty_storage_are_explicit() {
    assert_eq!(snapshot::zeroed(usize::MAX), Err(mnu_abi::ENOMEM));
    assert_eq!(snapshot::zeroed(32).unwrap(), [0; 32]);
    COPY_ERROR.with(|error| error.set(Some(mnu_abi::EFAULT)));
    let result = storage::from_user(42, 256);
    COPY_ERROR.with(|error| error.set(None));
    assert_eq!(result, Err(mnu_abi::EFAULT));
    assert_eq!(storage::from_user(42, 0).unwrap(), []);
    assert_eq!(storage::from_user(42, 256).unwrap(), [0xa5; 256]);
}

#[test]
fn native_storage_keeps_allocation_and_usercopy_failure_categories() {
    use mnu_abi::status::Error;

    assert_eq!(
        snapshot::zeroed_native(usize::MAX),
        Err(Error::ResourceUnavailable)
    );
    assert_eq!(snapshot::zeroed_native(32).unwrap(), [0; 32]);
    COPIES.with(|copies| copies.set(0));
    FAIL_NEXT.with(|fail| fail.set(true));
    let result = storage::from_user_native(42, 256);
    assert!(!FAIL_NEXT.with(|fail| fail.replace(false)));
    assert_eq!(result, Err(Error::ResourceUnavailable));
    assert_eq!(COPIES.with(Cell::get), 0);
    for error in [
        Error::InvalidAddress,
        Error::ResourceUnavailable,
        Error::BackingFailure,
    ] {
        COPY_ERROR.with(|value| value.set(Some(error.into_raw())));
        let result = storage::from_user_native(42, 256);
        COPY_ERROR.with(|value| value.set(None));
        assert_eq!(result, Err(error));
    }
    assert_eq!(storage::from_user_native(42, 8).unwrap(), [0xa5; 8]);
}

#[test]
fn borrowed_identity_preparation_is_fallible_and_preserves_exact_opaque_text() {
    let identity = "opaque:image/日本語#42";
    FAIL_NEXT.with(|fail| fail.set(true));
    assert_eq!(storage::text(identity), Err(mnu_abi::ENOMEM));
    assert!(!FAIL_NEXT.with(|fail| fail.replace(false)));
    assert_eq!(storage::text(identity).unwrap(), identity);
    FAIL_NEXT.with(|fail| fail.set(true));
    assert_eq!(storage::text("").unwrap(), "");
    // Empty text needs no allocation, so the injected failure is still pending.
    assert!(FAIL_NEXT.with(|fail| fail.replace(false)));
}

#[test]
fn object_snapshot_does_not_call_backend_after_allocation_failure() {
    FAIL_NEXT.with(|fail| fail.set(true));
    let result = snapshot::read(4096, 4096, |_| panic!("copy after ENOMEM"));
    let consumed = FAIL_NEXT.with(|fail| !fail.replace(false));
    assert!(consumed);
    assert_eq!(result, Err(mnu_abi::ENOMEM));
}

#[test]
fn native_image_preparation_routes_owned_storage_through_fallible_paths() {
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let replace = exec
        .split("fn process_image_replace_impl(")
        .nth(1)
        .unwrap()
        .split("pub fn process_create_syscall(")
        .next()
        .unwrap();
    for buffer in ["identity", "startup"] {
        assert!(replace.contains(&format!("storage::from_user({buffer}_ptr, {buffer}_len)")));
    }
    let create = exec.split("pub fn process_create_syscall(").nth(1).unwrap();
    assert!(create.contains("storage::from_user_native(request_ptr, length)"));
    assert!(create.contains("specs.try_reserve_exact(request.handles().count())"));
    assert!(create.contains("values.try_reserve_exact(request.values().count())"));
    for name in ["map_initial_tls", "build_relocatable_user_stack"] {
        let body = exec
            .split(&format!("fn {name}("))
            .nth(1)
            .unwrap()
            .split("\nfn ")
            .next()
            .unwrap();
        assert!(body.contains("object_snapshot::zeroed("));
        assert!(!body.contains("vec!["));
    }
    let image = include_str!("../../../core/src/syscall/exec/image.rs");
    let reserve = image.find(".try_reserve_exact(segments.len())").unwrap();
    assert!(reserve < image.find("let mapped = measurement.load(").unwrap());
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    let read = handles
        .split("pub(crate) fn read_all(")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    assert!(read.contains("object_snapshot::zeroed(length)?"));
    assert!(!read.contains("vec!["));
}
