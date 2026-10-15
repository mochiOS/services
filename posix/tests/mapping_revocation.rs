extern crate alloc;
#[path = "../../../core/src/mem/mapping_revocation.rs"]
mod mapping_revocation;
use mapping_revocation::{revoke, revoke_with, virtual_overlap, Backend, Error};

thread_local! {
    static DENY_FINISH_ALLOC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FINISH_ALLOC_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if DENY_FINISH_ALLOC
            .try_with(|value| value.get())
            .unwrap_or(false)
        {
            FINISH_ALLOC_ATTEMPTS.with(|value| value.set(value.get() + 1));
            core::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if DENY_FINISH_ALLOC
            .try_with(|value| value.get())
            .unwrap_or(false)
        {
            FINISH_ALLOC_ATTEMPTS.with(|value| value.set(value.get() + 1));
            core::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn without_allocations<T>(operation: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DENY_FINISH_ALLOC.with(|value| value.set(false));
        }
    }
    FINISH_ALLOC_ATTEMPTS.with(|value| value.set(0));
    DENY_FINISH_ALLOC.with(|value| value.set(true));
    let reset = Reset;
    let result = operation();
    drop(reset);
    assert_eq!(FINISH_ALLOC_ATTEMPTS.with(|value| value.get()), 0);
    result
}
use mapping_revocation::Suspension;

#[derive(Default)]
struct Vm {
    events: Vec<(&'static str, u64)>,
    fail_page: Option<u64>,
    fail_sync: bool,
    completed: bool,
}
impl Backend for Vm {
    type Page = (u64, u64);
    type Error = u8;
    fn next_page(&mut self, _: u64, start: u64, end: u64) -> Result<Option<u64>, u8> {
        Ok((start < end).then_some(start))
    }
    fn suspend(&mut self, table: u64, address: u64) -> Result<Option<Self::Page>, u8> {
        if self.fail_page == Some(address) {
            return Err(5);
        }
        self.events.push(("suspend", address));
        Ok(Some((table, address)))
    }
    fn restore(&mut self, (_, address): Self::Page) {
        self.events.push(("restore", address));
    }
    fn synchronize(&mut self) -> Result<(), u8> {
        self.events.push(("synchronize", 0));
        if self.fail_sync {
            return Err(7);
        }
        self.completed = true;
        Ok(())
    }
    fn release(&mut self, (_, address): Self::Page) {
        assert!(
            self.completed,
            "never free frames before remote acknowledgement"
        );
        self.events.push(("release", address));
    }
}

struct Owned {
    state: std::sync::Arc<std::sync::Mutex<Vm>>,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Drop for Owned {
    fn drop(&mut self) {
        let state = self.state.lock().unwrap();
        let suspended = state
            .events
            .iter()
            .filter(|(event, _)| *event == "suspend")
            .count();
        let resolved = state
            .events
            .iter()
            .filter(|(event, _)| matches!(*event, "restore" | "release"))
            .count();
        assert_eq!(
            suspended, resolved,
            "backend leases released before every PTE resolved"
        );
        assert!(self.alive.swap(false, std::sync::atomic::Ordering::AcqRel));
    }
}
impl Backend for Owned {
    type Page = (u64, u64);
    type Error = u8;
    fn next_page(&mut self, table: u64, start: u64, end: u64) -> Result<Option<u64>, u8> {
        self.state.lock().unwrap().next_page(table, start, end)
    }
    fn suspend(&mut self, table: u64, address: u64) -> Result<Option<Self::Page>, u8> {
        self.state.lock().unwrap().suspend(table, address)
    }
    fn restore(&mut self, page: Self::Page) {
        assert!(self.alive.load(std::sync::atomic::Ordering::Acquire));
        self.state.lock().unwrap().restore(page);
    }
    fn synchronize(&mut self) -> Result<(), u8> {
        self.state.lock().unwrap().synchronize()
    }
    fn release(&mut self, page: Self::Page) {
        assert!(self.alive.load(std::sync::atomic::Ordering::Acquire));
        self.state.lock().unwrap().release(page);
    }
}

#[test]
fn owned_journal_keeps_backend_leases_until_cancel_or_commit_resolves_every_page() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    fn handoff(journal: Suspension<Owned>) -> Suspension<Owned> {
        journal
    }
    for mode in 0..3 {
        let state = Arc::new(Mutex::new(Vm {
            events: Vec::with_capacity(16),
            ..Default::default()
        }));
        let alive = Arc::new(AtomicBool::new(true));
        let journal = Suspension::new(
            [(4096, 4096, 12288)],
            Owned {
                state: state.clone(),
                alive: alive.clone(),
            },
        )
        .unwrap();
        assert!(alive.load(Ordering::Acquire));
        assert_eq!(
            state.lock().unwrap().events,
            [("suspend", 4096), ("suspend", 8192), ("synchronize", 0)]
        );
        let journal = handoff(journal);
        if mode == 0 {
            without_allocations(|| drop(journal));
        } else {
            let result = without_allocations(|| {
                journal.commit_with(|backend| {
                    assert!(backend.alive.load(Ordering::Acquire));
                    backend.state.lock().unwrap().events.push(("commit", 0));
                    if mode == 1 {
                        Err(23)
                    } else {
                        Ok(37)
                    }
                })
            });
            assert_eq!(
                result,
                if mode == 1 {
                    Err(Error::Backend(23))
                } else {
                    Ok(37)
                }
            );
        }
        assert!(!alive.load(Ordering::Acquire));
        let state = state.lock().unwrap();
        let expected = if mode == 2 {
            [("release", 4096), ("release", 8192)]
        } else {
            [("restore", 8192), ("restore", 4096)]
        };
        assert_eq!(&state.events[state.events.len() - 2..], expected);
    }
}

#[test]
fn owned_constructor_failures_and_callback_unwind_restore_before_backend_drop() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    for mode in 0..3 {
        let state = Arc::new(Mutex::new(Vm {
            events: Vec::with_capacity(16),
            fail_page: (mode == 0).then_some(8192),
            fail_sync: mode == 1,
            ..Default::default()
        }));
        let alive = Arc::new(AtomicBool::new(true));
        let result = Suspension::new(
            [(4096, 4096, 12288)],
            Owned {
                state: state.clone(),
                alive: alive.clone(),
            },
        );
        if mode < 2 {
            assert!(result.is_err());
        } else {
            let journal = result.unwrap();
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = journal.commit_with(|_| -> Result<(), u8> {
                    panic!("cancel while local publication unwinds")
                });
            }))
            .is_err());
        }
        assert!(!alive.load(Ordering::Acquire));
        let state = state.lock().unwrap();
        assert!(!state.events.iter().any(|(event, _)| *event == "release"));
        assert_eq!(state.events.last(), Some(&("restore", 4096)));
    }
}

#[test]
fn successful_revocation_batches_all_tables_before_sync_and_release() {
    let mut vm = Vm::default();
    revoke([(4096, 0x1000, 0x3000), (8192, 0x9000, 0xa000)], &mut vm).unwrap();
    assert_eq!(
        vm.events,
        [
            ("suspend", 0x1000),
            ("suspend", 0x2000),
            ("suspend", 0x9000),
            ("synchronize", 0),
            ("release", 0x1000),
            ("release", 0x2000),
            ("release", 0x9000),
        ]
    );
}
#[test]
fn editing_and_sync_failures_restore_ownership_without_freeing() {
    let ranges = [(4096, 0x1000, 0x4000)];
    let mut vm = Vm {
        fail_page: Some(0x3000),
        ..Default::default()
    };
    assert_eq!(revoke(ranges, &mut vm), Err(Error::Backend(5)));
    assert_eq!(
        vm.events,
        [
            ("suspend", 0x1000),
            ("suspend", 0x2000),
            ("restore", 0x2000),
            ("restore", 0x1000)
        ]
    );
    let mut vm = Vm {
        fail_sync: true,
        ..Default::default()
    };
    assert_eq!(revoke(ranges, &mut vm), Err(Error::Backend(7)));
    assert_eq!(
        &vm.events[3..],
        [
            ("synchronize", 0),
            ("restore", 0x3000),
            ("restore", 0x2000),
            ("restore", 0x1000)
        ]
    );
    assert!(!vm.events.iter().any(|(event, _)| *event == "release"));
}

#[test]
fn failed_local_commit_restores_every_frame_without_releasing_ownership() {
    let mut vm = Vm::default();
    let mut called = 0;
    let result = revoke_with([(4096, 4096, 12288)], &mut vm, || {
        called += 1;
        Err::<(), _>(11)
    });
    assert_eq!(result, Err(Error::Backend(11)));
    assert_eq!(called, 1);
    assert_eq!(
        vm.events,
        [
            ("suspend", 4096),
            ("suspend", 8192),
            ("synchronize", 0),
            ("restore", 8192),
            ("restore", 4096),
        ]
    );
}

#[test]
fn preparation_failures_never_enter_commit_and_empty_plans_still_commit() {
    for mut vm in [
        Vm {
            fail_page: Some(8192),
            ..Default::default()
        },
        Vm {
            fail_sync: true,
            ..Default::default()
        },
    ] {
        assert!(
            revoke_with([(4096, 4096, 12288)], &mut vm, || -> Result<(), u8> {
                panic!("commit before preparation succeeded")
            })
            .is_err()
        );
    }
    let mut vm = Vm::default();
    assert_eq!(revoke_with([], &mut vm, || Ok(37)), Ok(37));
    assert!(vm.events.is_empty());
    assert_eq!(
        revoke_with([], &mut vm, || Err::<(), _>(11)),
        Err(Error::Backend(11))
    );
    assert!(vm.events.is_empty());
}
#[test]
fn all_ranges_are_validated_before_the_first_edit() {
    let mut vm = Vm::default();
    for invalid in [
        (4097, 0x1000, 0x2000),
        (4096, 1, 4096),
        (4096, 4096, 4096),
        (4096, 8192, 4096),
    ] {
        assert_eq!(
            revoke([(4096, 0x1000, 0x2000), invalid], &mut vm),
            Err(Error::InvalidRange)
        );
        assert!(vm.events.is_empty());
    }
    revoke([], &mut vm).unwrap();
    assert!(vm.events.is_empty());
    assert_eq!(
        revoke([(4096, 4096, 12288), (4096, 8192, 16384)], &mut vm),
        Err(Error::InvalidRange)
    );
    assert!(vm.events.is_empty());
}
#[test]
fn backing_offsets_select_only_overlapping_virtual_pages_without_overflow() {
    assert_eq!(
        virtual_overlap(0x10000, 0x4000, 0x8000, 0xa000, 0xd000),
        Ok(Some((0x12000, 0x14000)))
    );
    assert_eq!(
        virtual_overlap(0x10000, 0x4000, 0x8000, 0, 0x8000),
        Ok(None)
    );
    assert_eq!(
        virtual_overlap(0x10000, 0x4000, 0x8000, 0xc000, 0xd000),
        Ok(None)
    );
    assert_eq!(virtual_overlap(u64::MAX, 4096, 0, 0, 4096), Err(()));
    assert_eq!(virtual_overlap(4096, 4096, u64::MAX, 0, 4096), Err(()));
    assert_eq!(virtual_overlap(4096, 4096, 0, 2, 1), Err(()));
}

#[test]
fn sparse_discovery_scales_with_owned_leaves_and_finishes_before_edits() {
    struct Sparse {
        vm: Vm,
        queries: usize,
        fail_discovery: bool,
    }
    impl Backend for Sparse {
        type Page = (u64, u64);
        type Error = u8;
        fn next_page(&mut self, _: u64, start: u64, end: u64) -> Result<Option<u64>, u8> {
            assert!(self.vm.events.is_empty(), "discovery precedes every edit");
            self.queries += 1;
            if self.fail_discovery && self.queries == 2 {
                return Err(9);
            }
            Ok([4096, 1 << 39]
                .into_iter()
                .find(|&page| page >= start && page < end))
        }
        fn suspend(&mut self, table: u64, address: u64) -> Result<Option<Self::Page>, u8> {
            self.vm.suspend(table, address)
        }
        fn restore(&mut self, page: Self::Page) {
            self.vm.restore(page);
        }
        fn synchronize(&mut self) -> Result<(), u8> {
            self.vm.synchronize()
        }
        fn release(&mut self, page: Self::Page) {
            self.vm.release(page);
        }
    }
    let mut sparse = Sparse {
        vm: Vm::default(),
        queries: 0,
        fail_discovery: true,
    };
    assert_eq!(
        revoke([(4096, 0, 1 << 40)], &mut sparse),
        Err(Error::Backend(9))
    );
    assert!(sparse.vm.events.is_empty());
    sparse.fail_discovery = false;
    sparse.queries = 0;
    revoke([(4096, 0, 1 << 40)], &mut sparse).unwrap();
    assert_eq!(sparse.queries, 3);
    assert_eq!(sparse.vm.events.len(), 5);
}

#[test]
fn malformed_discovery_never_edits_or_loops_backwards() {
    struct Invalid(u64);
    impl Backend for Invalid {
        type Page = ();
        type Error = ();
        fn next_page(&mut self, _: u64, _: u64, _: u64) -> Result<Option<u64>, ()> {
            Ok(Some(self.0))
        }
        fn suspend(&mut self, _: u64, _: u64) -> Result<Option<()>, ()> {
            panic!()
        }
        fn restore(&mut self, _: ()) {
            panic!()
        }
        fn synchronize(&mut self) -> Result<(), ()> {
            panic!()
        }
        fn release(&mut self, _: ()) {
            panic!()
        }
    }
    for address in [0, 4097, 8192] {
        assert_eq!(
            revoke([(4096, 4096, 8192)], &mut Invalid(address)),
            Err(Error::InvalidRange)
        );
    }
}
