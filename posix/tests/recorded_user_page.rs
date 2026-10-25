//! Production PTE suspension/record implementation. The entry type and leaf
//! walker model architecture memory; no native exclusion across IPC is implied.
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, PartialEq, Eq)]
enum Memory {
    InvalidAddress,
    NotMapped,
}
#[derive(Debug, PartialEq, Eq)]
enum Kernel {
    Memory(Memory),
}
type Result<T> = std::result::Result<T, Kernel>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageTableFlags(u64);
impl PageTableFlags {
    fn empty() -> Self { Self(0) }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Address(u64);
impl Address {
    fn as_u64(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

thread_local! {
    static VM_HELD: Cell<bool> = const { Cell::new(false) };
    static DENY: Cell<bool> = const { Cell::new(false) };
    static ATTEMPTS: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if DENY.try_with(Cell::get).unwrap_or(false) {
            ATTEMPTS.with(|count| count.set(count.get() + 1));
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if DENY.try_with(Cell::get).unwrap_or(false) {
            ATTEMPTS.with(|count| count.set(count.get() + 1));
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.realloc(p, layout, size) }
        }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(p, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn without_allocations<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DENY.with(|slot| slot.set(false));
        }
    }
    ATTEMPTS.with(|slot| slot.set(0));
    DENY.with(|slot| slot.set(true));
    let reset = Reset;
    let result = f();
    drop(reset);
    assert_eq!(ATTEMPTS.with(Cell::get), 0);
    result
}
fn with_vm<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            VM_HELD.with(|slot| slot.set(false));
        }
    }
    assert!(!VM_HELD.with(Cell::get));
    VM_HELD.with(|slot| slot.set(true));
    let reset = Reset;
    let result = f();
    drop(reset);
    result
}
mod cpu {
    pub struct SmapSmepGuard;
    impl SmapSmepGuard {
        pub fn new() -> Self {
            Self
        }
    }
}
struct State {
    entries: BTreeMap<(u64, u64), Box<PageTableEntry>>,
    offset: Option<u64>,
    releases: usize,
}
fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(State {
            entries: BTreeMap::new(),
            offset: Some(0),
            releases: 0,
        })
    })
}
static TEST_LOCK: Mutex<()> = Mutex::new(());
const LOCATION: (u64, u64) = (0x1000, 0x4000);
const FRAME: u64 = 0x9000;
fn physical_memory_offset() -> Option<u64> {
    state().lock().unwrap().offset
}
fn with_user_leaf_entry_mut<T>(
    table: u64,
    address: u64,
    f: impl FnOnce(&mut PageTableEntry) -> T,
) -> Option<T> {
    assert!(VM_HELD.with(Cell::get), "PTE walk outside VM exclusion");
    let mut state = state().lock().unwrap();
    state.offset?;
    state
        .entries
        .get_mut(&(table, address))
        .map(|entry| f(entry))
}
#[path = "../../../core/src/mem/residency.rs"]
mod residency;
thread_local! {
    static RESIDENCY: std::cell::RefCell<residency::Counter> = const { std::cell::RefCell::new(residency::Counter::new()) };
}
fn record_user_leaf_change(table: u64, before: PageTableFlags, after: PageTableFlags) {
    assert_eq!(table, LOCATION.0);
    RESIDENCY.with_borrow_mut(|counter| counter.transition(before.bits(), after.bits()));
}
fn release_user_frame(frame: u64) {
    assert!(VM_HELD.with(Cell::get));
    assert_eq!(frame, FRAME);
    let mut state = state().lock().unwrap();
    assert!(
        state.entries[&LOCATION].is_unused(),
        "frame released before detaching PTE"
    );
    state.releases += 1;
}
#[path = "../../../core/src/mem/paging/suspension.rs"]
mod suspension;
use suspension::{RecordedUserPage, suspend_user_page};

fn reset(flags: u64) {
    RESIDENCY.with_borrow_mut(|counter| {
        *counter = residency::Counter::new();
        counter.transition(0, flags);
    });
    *state().lock().unwrap() = State {
        entries: BTreeMap::from([(
            LOCATION,
            Box::new(PageTableEntry {
                frame: FRAME,
                flags: PageTableFlags(flags),
            }),
        )]),
        offset: Some(0x1000_0000),
        releases: 0,
    };
}
fn prepare() -> RecordedUserPage {
    without_allocations(|| {
        with_vm(|| unsafe {
            suspend_user_page(LOCATION.0, LOCATION.1)
                .unwrap()
                .unwrap()
                .into_record()
        })
    })
}

#[test]
fn recorded_restore_rewalks_relocated_entry_and_preserves_flags_and_hardware_bits() {
    let _test = TEST_LOCK.lock().unwrap();
    fn transferable<T: Send + Sync>() {}
    transferable::<RecordedUserPage>();
    // Includes COW/software, write-disable, NX and pre-existing non-PRESENT.
    for flags in [0x805, 0x8000_0000_0000_0605, 0x8000_0000_0000_0204] {
        reset(flags);
        let record = prepare();
        assert_eq!(record.location(), LOCATION);
        {
            let mut state = state().lock().unwrap();
            let mut replacement = **state.entries.get(&LOCATION).unwrap();
            replacement.flags.0 |= 32 | 64;
            // Allocate the replacement BEFORE freeing the original slot. A
            // retained raw pointer would now target freed/unrelated storage.
            let replacement = Box::new(replacement);
            let new_pointer = &*replacement as *const _;
            let old = state.entries.insert(LOCATION, replacement).unwrap();
            assert_ne!(&*old as *const _, new_pointer);
            drop(old);
        }
        without_allocations(|| {
            with_vm(|| unsafe {
                assert!(record.is_current());
                assert!(record.try_restore().is_ok());
            })
        });
        let state = state().lock().unwrap();
        assert_eq!(state.entries[&LOCATION].flags.0, flags | 32 | 64);
        assert_eq!(state.entries[&LOCATION].frame, FRAME);
        assert_eq!(state.releases, 0);
    }
}

#[test]
fn rejected_release_retains_record_and_never_edits_or_releases_foreign_storage() {
    let _test = TEST_LOCK.lock().unwrap();
    for mode in 0..5 {
        reset(0x805);
        let record = prepare();
        {
            let mut state = state().lock().unwrap();
            match mode {
                0 => {
                    state.entries.remove(&LOCATION);
                }
                1 => {
                    state.entries.get_mut(&LOCATION).unwrap().frame = FRAME + 4096;
                }
                2 => {
                    state.entries.get_mut(&LOCATION).unwrap().flags.0 |= 1;
                }
                3 => {
                    state.entries.get_mut(&LOCATION).unwrap().flags.0 ^= 0x200;
                }
                _ => {
                    state.offset = None;
                }
            }
        }
        let before = state()
            .lock()
            .unwrap()
            .entries
            .get(&LOCATION)
            .map(|entry| **entry);
        let current = without_allocations(|| with_vm(|| unsafe { record.is_current() }));
        assert!(!current);
        let result = without_allocations(|| with_vm(|| unsafe { record.try_release() }));
        let record = result.err().expect("a failed edit must return ownership");
        assert_eq!(
            state()
                .lock()
                .unwrap()
                .entries
                .get(&LOCATION)
                .map(|entry| **entry),
            before
        );
        assert_eq!(state().lock().unwrap().releases, 0);
        {
            let mut state = state().lock().unwrap();
            state.offset = Some(0x1000_0000);
            state.entries.insert(
                LOCATION,
                Box::new(PageTableEntry {
                    frame: FRAME,
                    flags: PageTableFlags(0x804),
                }),
            );
        }
        without_allocations(|| {
            with_vm(|| unsafe {
                assert!(record.try_release().is_ok());
            })
        });
        assert_eq!(state().lock().unwrap().releases, 1);
    }
}

#[test]
fn rejected_restore_and_external_detach_return_ownership_without_freeing_frames() {
    let _test = TEST_LOCK.lock().unwrap();
    for detach in [false, true] {
        reset(0x105);
        let record = prepare();
        state()
            .lock()
            .unwrap()
            .entries
            .get_mut(&LOCATION)
            .unwrap()
            .frame = FRAME + 4096;
        let record = without_allocations(|| {
            with_vm(|| unsafe {
                let result = if detach {
                    record.try_detach()
                } else {
                    record.try_restore()
                };
                result.err().unwrap()
            })
        });
        assert_eq!(
            state().lock().unwrap().entries[&LOCATION].frame,
            FRAME + 4096
        );
        state()
            .lock()
            .unwrap()
            .entries
            .get_mut(&LOCATION)
            .unwrap()
            .frame = FRAME;
        without_allocations(|| {
            with_vm(|| unsafe {
                let result = if detach {
                    record.try_detach()
                } else {
                    record.try_restore()
                };
                assert!(result.is_ok());
            })
        });
        assert_eq!(
            state().lock().unwrap().entries[&LOCATION].is_unused(),
            detach
        );
        assert_eq!(state().lock().unwrap().releases, 0);
    }
}

#[test]
fn geometry_is_checked_before_edits_and_suffix_validation_never_accesses_memory() {
    let _test = TEST_LOCK.lock().unwrap();
    reset(5);
    for location in [
        (0, 4096),
        (4097, 4096),
        (4096, 4097),
        (4096, 0x8000_0000_0000),
    ] {
        with_vm(|| unsafe {
            assert!(suspend_user_page(location.0, location.1).is_err());
        });
        assert_eq!(state().lock().unwrap().entries[&LOCATION].flags.0, 5);
    }
    let record = prepare();
    assert_eq!(record.suffix_address(17), Ok((0x1000_9011, 4079)));
    assert_eq!(record.suffix_address(4096), Ok((0x1000_a000, 0)));
    assert_eq!(
        record.suffix_address(4097),
        Err(Kernel::Memory(Memory::InvalidAddress))
    );
    state().lock().unwrap().offset = Some(u64::MAX - 4096);
    assert_eq!(
        record.suffix_address(17),
        Err(Kernel::Memory(Memory::NotMapped))
    );
    state().lock().unwrap().offset = Some(0x1000_0000);
    without_allocations(|| {
        with_vm(|| unsafe {
            assert!(record.try_restore().is_ok());
        })
    });
}

#[test]
fn immediate_tokens_keep_original_locked_restore_release_and_mmio_detach_behavior() {
    let _test = TEST_LOCK.lock().unwrap();
    for mode in 0..3 {
        reset(0x805);
        without_allocations(|| {
            with_vm(|| unsafe {
                let page = suspend_user_page(LOCATION.0, LOCATION.1).unwrap().unwrap();
                assert_eq!(page.suffix_address(17), Ok((0x1000_9011, 4079)));
                match mode {
                    0 => page.restore(),
                    1 => page.release(),
                    _ => page.detach(),
                }
            })
        });
        let state = state().lock().unwrap();
        assert_eq!(state.entries[&LOCATION].is_unused(), mode != 0);
        if mode == 0 {
            assert_eq!(state.entries[&LOCATION].flags.0, 0x805);
        }
        assert_eq!(state.releases, usize::from(mode == 1));
    }
}

#[test]
fn retained_ram_counts_survive_suspension_and_only_detach_reduces_residency() {
    let _test = TEST_LOCK.lock().unwrap();
    for recorded in [false, true] {
        for restore in [false, true] {
            reset(residency::RAM_LEAF | 4 | 1);
            let current = || RESIDENCY.with_borrow(|counter| counter.snapshot().unwrap());
            assert_eq!(current().current_bytes, 4096);
            with_vm(|| unsafe {
                let page = suspend_user_page(LOCATION.0, LOCATION.1).unwrap().unwrap();
                assert_eq!(current().current_bytes, 4096);
                if recorded {
                    let record = page.into_record();
                    if restore {
                        assert!(record.try_restore().is_ok());
                    } else {
                        assert!(record.try_release().is_ok());
                    }
                } else if restore {
                    page.restore();
                } else {
                    page.release();
                }
            });
            assert_eq!(current().current_bytes, if restore { 4096 } else { 0 });
            assert_eq!(current().peak_bytes, 4096);
        }
    }
}
