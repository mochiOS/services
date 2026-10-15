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
        assert_eq!((address, access, options, handle, offset), (0, 0, 0, 0, 0));
        assert_eq!(length as usize, RESERVE);
        let mut vm = VM.lock().unwrap();
        vm.maps += 1;
        if vm.fail_map {
            Err(ENOMEM)
        } else {
            Ok(vm.address as u64)
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
        vm.unmaps.push((address as usize, length as usize));
        vm.writable_end = BASE;
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
        maximum_end: usize::MAX,
        page_size: 4096,
    }
}
fn snapshot(heap: &HeapState) -> [usize; 6] {
    [
        heap.initialized as usize,
        heap.base,
        heap.current_break,
        heap.mapped_end,
        heap.maximum_end,
        heap.page_size,
    ]
}

#[test]
fn image_and_byte_limit_are_checked_before_any_reservation() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let before = snapshot(&heap);
    assert_eq!(heap.adjust(1, 8192, 8192), Err(ENOMEM));
    assert_eq!(heap.adjust(1, 8192, 0), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().maps, 0);
    assert_eq!(heap.adjust(1, 8192, 8193), Ok(BASE));
    assert_eq!(heap.current_break, BASE + 1);
    assert_eq!(VM.lock().unwrap().protects, [(BASE, 4096)]);
    // The rest of this already writable page cannot bypass a byte limit.
    assert_eq!(heap.adjust(1, 8192, 8193), Err(ENOMEM));
    assert_eq!(heap.current_break, BASE + 1);
}

#[test]
fn lowered_limit_allows_query_and_shrink_but_not_regrowth() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    assert_eq!(heap.adjust(8193, 0, INFINITY), Ok(BASE));
    assert_eq!(heap.adjust(0, 8192, 0), Ok(BASE + 8193));
    assert_eq!(heap.adjust(-8193, 8192, 0), Ok(BASE + 8193));
    assert_eq!(heap.current_break, BASE);
    assert_eq!(heap.adjust(1, 8192, 0), Err(ENOMEM));
    assert_eq!(heap.adjust(1, 8192, 8193), Ok(BASE));
    assert_eq!(VM.lock().unwrap().protects, [(BASE, 12288)]);
}

#[test]
fn failed_first_mapping_and_protection_leave_no_published_arena() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    let before = snapshot(&heap);
    VM.lock().unwrap().fail_map = true;
    assert_eq!(heap.adjust(1, 0, INFINITY), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert!(VM.lock().unwrap().unmaps.is_empty());
    VM.lock().unwrap().fail_map = false;
    VM.lock().unwrap().fail_protect = true;
    assert_eq!(heap.adjust(1, 0, INFINITY), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().unmaps, [(BASE, RESERVE)]);
    VM.lock().unwrap().fail_protect = false;
    assert_eq!(heap.adjust(1, 0, INFINITY), Ok(BASE));
}

#[test]
fn failed_existing_growth_preserves_break_and_committed_extent() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    assert_eq!(heap.adjust(4096, 0, INFINITY), Ok(BASE));
    let before = snapshot(&heap);
    VM.lock().unwrap().fail_protect = true;
    assert_eq!(heap.adjust(8192, 0, INFINITY), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert!(VM.lock().unwrap().unmaps.is_empty());
    assert_eq!(VM.lock().unwrap().revoked, [(BASE + 4096, 8192)]);
    assert_eq!(VM.lock().unwrap().writable_end, BASE + 4096);
    VM.lock().unwrap().fail_protect = false;
    assert_eq!(heap.adjust(1, 0, 4097), Ok(BASE + 4096));
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
    assert_eq!(heap.adjust(isize::MIN, 0, INFINITY), Err(EINVAL));
    assert_eq!(heap.adjust(1, usize::MAX, INFINITY), Err(ENOMEM));
    assert_eq!(heap.adjust(RESERVE as isize + 1, 0, INFINITY), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().maps, 0);
    for address in [usize::MAX - RESERVE + 1, 0] {
        VM.lock().unwrap().address = address;
        assert_eq!(heap.adjust(1, 0, INFINITY), Err(ENOMEM));
        assert_eq!(snapshot(&heap), before);
    }
    assert_eq!(VM.lock().unwrap().unmaps.len(), 2);
}

#[test]
fn stack_ceiling_and_uninitialized_heap_are_respected() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    heap.initialized = false;
    assert_eq!(heap.adjust(0, 0, INFINITY), Err(ENOMEM));
    assert_eq!(VM.lock().unwrap().maps, 0);
    heap.initialized = true;
    heap.maximum_end = BASE + RESERVE - 1;
    let before = snapshot(&heap);
    assert_eq!(heap.adjust(1, 0, INFINITY), Err(ENOMEM));
    assert_eq!(snapshot(&heap), before);
    assert_eq!(VM.lock().unwrap().unmaps, [(BASE, RESERVE)]);
}

#[test]
fn querying_an_empty_arena_does_not_commit_pages() {
    let _serial = SERIAL.lock().unwrap();
    let mut heap = initial();
    assert_eq!(heap.adjust(0, 8192, 0), Ok(BASE));
    assert_eq!(heap.current_break, BASE);
    assert_eq!(heap.mapped_end, BASE);
    assert!(VM.lock().unwrap().protects.is_empty());
    assert_eq!(heap.adjust(-1, 0, INFINITY), Err(EINVAL));
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
    assert!(wrapper.contains(".adjust(increment, image_data_bytes, data_limit)"));
    let script = include_str!("../../../user/runtime/linker.ld");
    assert!(
        script.find("__mochios_data_start").unwrap() < script.find("*(.data .data.*)").unwrap()
    );
    assert!(script.find("__mochios_data_end").unwrap() > script.find("*(.bss .bss.*)").unwrap());
}
