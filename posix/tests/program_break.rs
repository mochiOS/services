//! Execute the production break allocator against a fault-injected native VM.
use std::sync::Mutex;

const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;
const NATIVE_READ_WRITE: u64 = 3;
const BASE: usize = 0x1000_0000;
const RESERVE: usize = 256 * 1024 * 1024;
const INFINITY: u64 = u64::MAX;
static SERIAL: Mutex<()> = Mutex::new(());
static VM: Mutex<Vm> = Mutex::new(Vm::new());

struct Vm {
    maps: usize,
    protects: Vec<(usize, usize)>,
    unmaps: Vec<(usize, usize)>,
    revoked: Vec<(usize, usize)>,
    address: usize,
    fail_map: bool,
    fail_protect: bool,
    writable_end: usize,
    regions: Vec<(usize, usize)>,
    map_requests: Vec<(u64, u64, u64)>,
    map_error: Option<i32>,
    fail_unmap: bool,
}
impl Vm {
    const fn new() -> Self {
        Self {
            maps: 0,
            protects: Vec::new(),
            unmaps: Vec::new(),
            revoked: Vec::new(),
            address: BASE,
            fail_map: false,
            fail_protect: false,
            writable_end: BASE,
            regions: Vec::new(),
            map_requests: Vec::new(),
            map_error: None,
            fail_unmap: false,
        }
    }
}
fn syscall_errno(result: Result<u64, i32>) -> Result<u64, i32> {
    result
}
fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}
mod address_space {
    #[derive(Clone, Copy)]
    pub struct Limit(pub u64);
    impl Limit {
        pub const UNLIMITED: Self = Self(u64::MAX);
        pub fn is_finite(self) -> bool {
            self.0 != u64::MAX
        }
        pub fn map(
            self,
            address: u64,
            length: u64,
            access: u64,
            options: u64,
            handle: u64,
            offset: u64,
        ) -> Result<u64, i32> {
            let used: usize = super::VM
                .lock()
                .unwrap()
                .regions
                .iter()
                .map(|(a, b)| b - a)
                .sum();
            if (used as u64)
                .checked_add(length)
                .is_none_or(|total| total > self.0)
            {
                return Err(super::ENOMEM);
            }
            super::syscall::raw_syscall6(
                super::syscall::SyscallNumber::MemoryMap,
                address,
                length,
                access,
                options,
                handle,
                offset,
            )
        }
    }
}
mod syscall {
    use super::*;
    #[derive(Debug, PartialEq, Eq)]
    pub enum SyscallNumber {
        MemoryMap,
        MemoryUnmap,
        MemoryProtect,
    }
    pub fn raw_syscall6(
        number: SyscallNumber,
        address: u64,
        length: u64,
        access: u64,
        options: u64,
        handle: u64,
        offset: u64,
    ) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::MemoryMap);
        assert_eq!((access, handle, offset), (0, 0, 0));
        assert!(options == 0 || options == mnu_abi::MEMORY_MAP_EXACT);
        let mut vm = VM.lock().unwrap();
        vm.maps += 1;
        vm.map_requests.push((address, length, options));
        if let Some(error) = vm.map_error {
            return Err(error);
        }
        if vm.fail_map {
            Err(ENOMEM)
        } else {
            let start = if options == 0 {
                vm.address
            } else {
                address as usize
            };
            if let Some(end) = start.checked_add(length as usize) {
                if vm.regions.iter().any(|&(a, b)| start < b && a < end) {
                    return Err(EINVAL);
                }
                vm.regions.push((start, end));
            }
            Ok(start as u64)
        }
    }
    pub fn raw_syscall3(
        number: SyscallNumber,
        address: u64,
        length: u64,
        access: u64,
    ) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::MemoryProtect);
        let mut vm = VM.lock().unwrap();
        if access == 0 {
            vm.revoked.push((address as usize, length as usize));
            vm.writable_end = address as usize;
            return Ok(0);
        }
        assert_eq!(access, NATIVE_READ_WRITE);
        if vm.fail_protect {
            // Model a native failure after changing the first page, not an
            // unrealistically atomic error before any permissions change.
            vm.writable_end = address as usize + 4096;
            return Err(ENOMEM);
        }
        vm.writable_end = (address + length) as usize;
        vm.protects.push((address as usize, length as usize));
        Ok(0)
    }
    pub fn raw_syscall2(number: SyscallNumber, address: u64, length: u64) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::MemoryUnmap);
        let mut vm = VM.lock().unwrap();
        if vm.fail_unmap {
            return Err(ENOMEM);
        }
        vm.unmaps.push((address as usize, length as usize));
        let start = address as usize;
        let end = start.checked_add(length as usize).unwrap_or(usize::MAX);
        let mut retained = Vec::new();
        for (a, b) in vm.regions.drain(..) {
            if b <= start || a >= end {
                retained.push((a, b));
            } else {
                if a < start {
                    retained.push((a, start));
                }
                if b > end {
                    retained.push((end, b));
                }
            }
        }
        vm.regions = retained;
        vm.writable_end = vm.writable_end.min(start);
        Ok(0)
    }
}
#[path = "../../../user/crates/newlib-runtime/src/heap.rs"]
mod heap;
use heap::HeapState;

fn initial() -> HeapState {
    *VM.lock().unwrap() = Vm::new();
    HeapState {
        initialized: true,
        base: 0,
        current_break: 0,
        mapped_end: 0,
        reserved_end: 0,
        pending_release: None,
        maximum_end: usize::MAX,
        page_size: 4096,
    }
}
fn snapshot(heap: &HeapState) -> [usize; 7] {
    [
        heap.initialized as usize,
        heap.base,
        heap.current_break,
        heap.mapped_end,
        heap.reserved_end,
        heap.maximum_end,
        heap.page_size,
    ]
}

#[test]
fn finite_limit_reclaims_unused_reservation_before_attempting_growth() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let before = snapshot(&heap);
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit(0)),
        Err(ENOMEM)
    );
    assert_eq!(
        heap.adjust(0, 0, INFINITY, address_space::Limit(0)),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().maps, 0);
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit::UNLIMITED),
        Ok(BASE)
    );
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit(0)),
        Ok(BASE + 1)
    );
    assert_eq!(
        heap.adjust(4096, 0, INFINITY, address_space::Limit(0)),
        Err(ENOMEM)
    );
    assert_eq!(
        heap.adjust(-2, 0, INFINITY, address_space::Limit(0)),
        Ok(BASE + 2)
    );
    assert_eq!(VM.lock().unwrap().maps, 1);
}

#[test]
fn growing_past_the_preferred_span_rolls_back_old_permissions_and_only_the_new_tail() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let limit = address_space::Limit::UNLIMITED;
    assert_eq!(heap.adjust(1, 0, INFINITY, limit), Ok(BASE));
    let before = snapshot(&heap);
    VM.lock().unwrap().fail_protect = true;
    assert_eq!(
        heap.adjust(RESERVE as isize, 0, INFINITY, limit),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().regions, [(BASE, BASE + RESERVE)]);
    assert_eq!(VM.lock().unwrap().revoked, [(BASE + 4096, RESERVE - 4096)]);
    assert_eq!(VM.lock().unwrap().unmaps, [(BASE + RESERVE, 4096)]);
    VM.lock().unwrap().fail_protect = false;
    assert_eq!(
        heap.adjust(RESERVE as isize, 0, INFINITY, limit),
        Ok(BASE + 1)
    );
    assert_eq!(heap.current_break, BASE + RESERVE + 1);
    assert_eq!(heap.reserved_end, BASE + RESERVE + 4096);
}

#[test]
fn initial_break_can_exceed_the_placement_preference_without_a_fixed_size_cap() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let length = RESERVE + 1;
    assert_eq!(
        heap.adjust(
            length as isize,
            0,
            INFINITY,
            address_space::Limit::UNLIMITED
        ),
        Ok(BASE)
    );
    assert_eq!(heap.current_break, BASE + length);
    assert_eq!(heap.reserved_end, BASE + RESERVE + 4096);
    assert_eq!(heap.maximum_end, usize::MAX);
    assert_eq!(
        VM.lock().unwrap().map_requests,
        [(0, (RESERVE + 4096) as u64, 0)]
    );
}

#[test]
fn failed_initial_rollback_retains_ownership_and_releases_it_before_retry() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    VM.lock().unwrap().fail_unmap = true;
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit(8192)),
        Err(ENOMEM)
    );
    assert_eq!(heap.current_break, 0);
    assert_eq!(heap.pending_release, Some((BASE, 8192)));
    assert_eq!(VM.lock().unwrap().regions, [(BASE, BASE + 8192)]);
    VM.lock().unwrap().fail_unmap = false;
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit(8192)),
        Ok(BASE)
    );
    assert_eq!(heap.pending_release, None);
    assert_eq!(VM.lock().unwrap().regions, [(BASE, BASE + 4096)]);
}

#[test]
fn failed_extension_rollback_retains_only_the_uncommitted_tail() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let limit = address_space::Limit(16384);
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Ok(BASE));
    VM.lock().unwrap().fail_protect = true;
    VM.lock().unwrap().fail_unmap = true;
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Err(ENOMEM));
    assert_eq!(heap.current_break, BASE + 4096);
    assert_eq!(heap.reserved_end, BASE + 4096);
    assert_eq!(heap.pending_release, Some((BASE + 4096, 4096)));
    VM.lock().unwrap().fail_protect = false;
    VM.lock().unwrap().fail_unmap = false;
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Ok(BASE + 4096));
    assert_eq!(heap.pending_release, None);
    assert_eq!(heap.current_break, BASE + 8192);
}

#[test]
fn small_first_reservation_is_trimmed_then_extended_at_an_exact_free_address() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let limit = address_space::Limit(8192);
    assert_eq!(heap.adjust(1, 0, INFINITY, limit), Ok(BASE));
    assert_eq!(
        (heap.reserved_end, heap.mapped_end),
        (BASE + 4096, BASE + 4096)
    );
    assert_eq!(VM.lock().unwrap().map_requests, [(0, 8192, 0)]);
    assert_eq!(VM.lock().unwrap().unmaps, [(BASE + 4096, 4096)]);
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Ok(BASE + 1));
    assert_eq!(
        VM.lock().unwrap().map_requests.last().copied(),
        Some(((BASE + 4096) as u64, 4096, mnu_abi::MEMORY_MAP_EXACT))
    );
    let before = snapshot(&heap);
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert_eq!(heap.adjust(-4097, 0, INFINITY, limit), Ok(BASE + 4097));
    heap.trim_unused().unwrap();
    assert_eq!((heap.reserved_end, heap.mapped_end), (BASE, BASE));
    assert!(VM.lock().unwrap().regions.is_empty());
    assert_eq!(heap.adjust(1, 0, INFINITY, limit), Ok(BASE));
}

#[test]
fn failed_extension_activation_releases_only_new_pages_and_retains_the_prefix() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let limit = address_space::Limit(16384);
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Ok(BASE));
    let before = snapshot(&heap);
    VM.lock().unwrap().fail_protect = true;
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().regions, [(BASE, BASE + 4096)]);
    assert_eq!(VM.lock().unwrap().writable_end, BASE + 4096);
    VM.lock().unwrap().fail_protect = false;
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Ok(BASE + 4096));
}

#[test]
fn occupied_tail_is_never_unmapped_or_overwritten_and_can_be_retried_after_release() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let limit = address_space::Limit(16384);
    assert_eq!(heap.adjust(4096, 0, INFINITY, limit), Ok(BASE));
    let before = snapshot(&heap);
    VM.lock().unwrap().regions.push((BASE + 4096, BASE + 8192));
    let unmaps = VM.lock().unwrap().unmaps.clone();
    assert_eq!(heap.adjust(1, 0, INFINITY, limit), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().unmaps, unmaps);
    assert_eq!(
        VM.lock().unwrap().regions,
        [(BASE, BASE + 4096), (BASE + 4096, BASE + 8192)]
    );
    VM.lock().unwrap().regions.pop();
    assert_eq!(heap.adjust(1, 0, INFINITY, limit), Ok(BASE + 4096));
}

#[test]
fn trim_failure_preserves_metadata_and_does_not_retry_unbounded_mapping() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    assert_eq!(
        heap.adjust(4096, 0, INFINITY, address_space::Limit::UNLIMITED),
        Ok(BASE)
    );
    let before = snapshot(&heap);
    VM.lock().unwrap().fail_unmap = true;
    assert_eq!(heap.trim_unused(), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().regions, [(BASE, BASE + RESERVE)]);
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit(8192)),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().maps, 1);
}

#[test]
fn adaptive_reservation_does_not_retry_authority_or_backend_errors() {
    let _serial = SERIAL.lock().unwrap();
    for error in [5, 13, 22, 38] {
        let mut heap = initial();
        VM.lock().unwrap().map_error = Some(error);
        let before = snapshot(&heap);
        assert_eq!(
            heap.adjust(1, 0, INFINITY, address_space::Limit(RESERVE as u64)),
            Err(error)
        );
        assert_eq!(snapshot(&heap), before);
        assert_eq!(VM.lock().unwrap().maps, 1);
    }
}

#[test]
fn image_and_byte_limit_are_checked_before_any_reservation() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let before = snapshot(&heap);
    assert_eq!(
        heap.adjust(1, 8192, 8192, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(
        heap.adjust(1, 8192, 0, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().maps, 0);
    assert_eq!(
        heap.adjust(1, 8192, 8193, address_space::Limit::UNLIMITED),
        Ok(BASE)
    );
    assert_eq!(heap.current_break, BASE + 1);
    assert_eq!(VM.lock().unwrap().protects, [(BASE, 4096)]);
    // The rest of this already writable page cannot bypass a byte limit.
    assert_eq!(
        heap.adjust(1, 8192, 8193, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(heap.current_break, BASE + 1);
}

#[test]
fn lowered_limit_allows_query_and_shrink_but_not_regrowth() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    assert_eq!(
        heap.adjust(8193, 0, INFINITY, address_space::Limit::UNLIMITED),
        Ok(BASE)
    );
    assert_eq!(
        heap.adjust(0, 8192, 0, address_space::Limit::UNLIMITED),
        Ok(BASE + 8193)
    );
    assert_eq!(
        heap.adjust(-8193, 8192, 0, address_space::Limit::UNLIMITED),
        Ok(BASE + 8193)
    );
    assert_eq!(heap.current_break, BASE);
    assert_eq!(
        heap.adjust(1, 8192, 0, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(
        heap.adjust(1, 8192, 8193, address_space::Limit::UNLIMITED),
        Ok(BASE)
    );
    assert_eq!(VM.lock().unwrap().protects, [(BASE, 12288)]);
}

#[test]
fn failed_first_mapping_and_protection_leave_no_published_arena() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let before = snapshot(&heap);
    VM.lock().unwrap().fail_map = true;
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert!(VM.lock().unwrap().unmaps.is_empty());
    VM.lock().unwrap().fail_map = false;
    VM.lock().unwrap().fail_protect = true;
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().unmaps, [(BASE, RESERVE)]);
    VM.lock().unwrap().fail_protect = false;
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit::UNLIMITED),
        Ok(BASE)
    );
}

#[test]
fn failed_existing_growth_preserves_break_and_committed_extent() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    assert_eq!(
        heap.adjust(4096, 0, INFINITY, address_space::Limit::UNLIMITED),
        Ok(BASE)
    );
    let before = snapshot(&heap);
    VM.lock().unwrap().fail_protect = true;
    assert_eq!(
        heap.adjust(8192, 0, INFINITY, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert!(VM.lock().unwrap().unmaps.is_empty());
    assert_eq!(VM.lock().unwrap().revoked, [(BASE + 4096, 8192)]);
    assert_eq!(VM.lock().unwrap().writable_end, BASE + 4096);
    VM.lock().unwrap().fail_protect = false;
    assert_eq!(
        heap.adjust(1, 0, 4097, address_space::Limit::UNLIMITED),
        Ok(BASE + 4096)
    );
    assert_eq!(
        VM.lock().unwrap().protects,
        [(BASE, 4096), (BASE + 4096, 4096)]
    );
}

#[test]
fn arithmetic_and_arena_bounds_fail_without_mutation() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let before = snapshot(&heap);
    assert_eq!(
        heap.adjust(isize::MIN, 0, INFINITY, address_space::Limit::UNLIMITED),
        Err(EINVAL)
    );
    assert_eq!(
        heap.adjust(1, usize::MAX, INFINITY, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().maps, 0);
    for address in [usize::MAX - RESERVE + 1, 0] {
        VM.lock().unwrap().address = address;
        assert_eq!(
            heap.adjust(1, 0, INFINITY, address_space::Limit::UNLIMITED),
            Err(ENOMEM)
        );
        assert_eq!(snapshot(&heap), before);
    }
    assert_eq!(VM.lock().unwrap().unmaps.len(), 2);
}

#[test]
fn stack_ceiling_and_uninitialized_heap_are_respected() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    heap.initialized = false;
    assert_eq!(
        heap.adjust(0, 0, INFINITY, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(VM.lock().unwrap().maps, 0);
    heap.initialized = true;
    heap.maximum_end = BASE + RESERVE - 1;
    let before = snapshot(&heap);
    assert_eq!(
        heap.adjust(1, 0, INFINITY, address_space::Limit::UNLIMITED),
        Err(ENOMEM)
    );
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().unmaps, [(BASE, RESERVE)]);
}

#[test]
fn querying_an_empty_arena_does_not_commit_pages() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    assert_eq!(
        heap.adjust(0, 8192, 0, address_space::Limit::UNLIMITED),
        Ok(BASE)
    );
    assert_eq!(heap.current_break, BASE);
    assert_eq!(heap.mapped_end, BASE);
    assert!(VM.lock().unwrap().protects.is_empty());
    assert_eq!(
        heap.adjust(-1, 0, INFINITY, address_space::Limit::UNLIMITED),
        Err(EINVAL)
    );
}

#[test]
fn wrapper_discovers_policy_before_state_and_sdk_exports_image_extent() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let wrapper = source
        .split("pub extern \"C\" fn _sbrk(")
        .nth(1)
        .unwrap()
        .split("pub extern \"C\" fn sbrk(")
        .next()
        .unwrap();
    assert!(wrapper.find("resource_policy::read").unwrap() < wrapper.find("state()").unwrap());
    assert!(wrapper.contains("increment > 0 && has_posix_environment()?"));
    assert!(wrapper.contains(".adjust(increment, image_data_bytes, data_limit, memory_limit)"));
    assert!(wrapper.find("address_space::snapshot()").unwrap() < wrapper.find("state()").unwrap());
    let script = include_str!("../../../user/runtime/linker.ld");
    assert!(
        script.find("__mochios_data_start").unwrap() < script.find("*(.data .data.*)").unwrap()
    );
    assert!(script.find("__mochios_data_end").unwrap() > script.find("*(.bss .bss.*)").unwrap());
}
