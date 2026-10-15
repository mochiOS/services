extern crate alloc;
#[path = "../../../core/src/mem/detached_roots.rs"]
mod detached_roots;
#[path = "../../../core/src/mem/mapping_preservation_native.rs"]
mod mapping_preservation_native;
#[path = "../../../core/src/mem/mapping_revocation.rs"]
mod mapping_revocation;
#[path = "../../../core/src/mem/mapping_revocation_native.rs"]
mod mapping_revocation_native;
#[path = "../../../core/src/mem/mapping_targets.rs"]
mod mapping_targets;
#[path = "../../../core/src/mem/root_lifetime.rs"]
mod root_lifetime;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
static TEST_LOCK: Mutex<()> = Mutex::new(());

mod syscall {
    pub const EFAULT: u64 = (-14i64) as u64;
    pub const EIO: u64 = (-5i64) as u64;
    pub const EINVAL: u64 = (-22i64) as u64;
    pub const ENOMEM: u64 = (-12i64) as u64;
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
macro_rules! warn { ($($args:tt)*) => { let _ = format_args!($($args)*); }; }

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
mod root_lifetime_native {
    pub static FAIL_ROOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    pub fn pin(table: u64) -> Result<super::root_lifetime::Pin, ()> {
        if FAIL_ROOT.load(std::sync::atomic::Ordering::Relaxed) == table {
            return Err(());
        }
        super::root_lifetime::pin_with(table, |state| Ok(std::sync::Arc::new(state)))
    }
}
mod task {
    pub struct Object(pub super::vm_object::ObjectKey);
    impl Object {
        pub fn object_key(&self) -> super::vm_object::ObjectKey {
            self.0
        }
    }
    pub struct MemoryRegion {
        pub object: Option<Object>,
        pub start: u64,
        pub length: u64,
        pub offset: u64,
    }
    impl MemoryRegion {
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
    pub mod process {
        pub struct Process(pub u64, pub Vec<super::MemoryRegion>);
        impl Process {
            pub fn empty(table: u64) -> Self {
                Self(table, Vec::new())
            }
            pub fn page_table(&self) -> Option<u64> {
                Some(self.0)
            }
            pub fn memory_regions(&self) -> &[super::MemoryRegion] {
                &self.1
            }
        }
        pub struct ProcessTable(pub Vec<Process>);
        impl ProcessTable {
            pub fn iter(&self) -> impl Iterator<Item = &Process> {
                self.0.iter()
            }
        }
    }
}
#[derive(Default)]
struct State {
    entries: BTreeMap<(u64, u64), u64>,
    synchronized: bool,
    fail_sync: bool,
    released: usize,
    frames: BTreeMap<(u64, u64), Box<[u8; 4096]>>,
    destroyed: Vec<u64>,
}
fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
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
        let mut state = super::state().lock().unwrap();
        assert!(!state.destroyed.contains(&table), "double root destruction");
        state.destroyed.push(table);
        Ok(())
    }
    pub unsafe fn next_user_page_entry(
        table: u64,
        start: u64,
        end: u64,
    ) -> Result<Option<u64>, ()> {
        Ok(super::state()
            .lock()
            .unwrap()
            .entries
            .range((table, start)..(table, end))
            .next()
            .map(|(&(root, address), _)| {
                assert_eq!(root, table);
                address
            }))
    }
    pub struct SuspendedUserPage {
        table: u64,
        address: u64,
        flags: u64,
    }
    pub unsafe fn suspend_user_page(
        table: u64,
        address: u64,
    ) -> Result<Option<SuspendedUserPage>, ()> {
        let mut state = super::state().lock().unwrap();
        let Some(flags) = state.entries.get_mut(&(table, address)) else {
            return Ok(None);
        };
        let original = *flags;
        *flags &= !1;
        Ok(Some(SuspendedUserPage {
            table,
            address,
            flags: original,
        }))
    }
    impl SuspendedUserPage {
        pub fn suffix_address(&self, offset: usize) -> Result<(u64, usize), ()> {
            if offset > 4096 {
                return Err(());
            }
            let mut state = super::state().lock().unwrap();
            let frame = state
                .frames
                .get_mut(&(self.table, self.address))
                .ok_or(())?;
            Ok((frame.as_mut_ptr() as u64 + offset as u64, 4096 - offset))
        }
        pub unsafe fn restore(self) {
            super::state()
                .lock()
                .unwrap()
                .entries
                .insert((self.table, self.address), self.flags);
        }
        pub unsafe fn release(self) {
            let mut state = super::state().lock().unwrap();
            assert!(
                state.synchronized,
                "frame release requires all-CPU acknowledgement"
            );
            assert_eq!(
                state.entries.remove(&(self.table, self.address)),
                Some(self.flags & !1)
            );
            state.released += 1;
        }
        pub unsafe fn detach(self) {
            let mut state = super::state().lock().unwrap();
            assert!(state.synchronized);
            state.entries.remove(&(self.table, self.address)).unwrap();
        }
    }
}
mod tlb_shootdown {
    pub fn invalidate_all() -> Result<(), ()> {
        let mut state = super::state().lock().unwrap();
        assert!(state.entries.values().all(|flags| flags & 1 == 0));
        if state.fail_sync {
            return Err(());
        }
        state.synchronized = true;
        Ok(())
    }
}

#[test]
fn native_local_commit_is_ordered_after_tlb_ack_before_frame_release_and_can_roll_back() {
    let _test = TEST_LOCK.lock().unwrap();
    use mapping_revocation::{revoke_with, Error};
    use mapping_revocation_native::Native;
    use task::process::{Process, ProcessTable};
    let table = ProcessTable(vec![Process::empty(4096)]);
    let original = BTreeMap::from([((4096, 4096), 0x105), ((4096, 8192), 0x207)]);
    let suspended = BTreeMap::from([((4096, 4096), 0x104), ((4096, 8192), 0x206)]);
    for fail_commit in [true, false] {
        *state().lock().unwrap() = State {
            entries: original.clone(),
            ..Default::default()
        };
        // As in production, the caller retains mapping exclusion and table
        // ownership while the local commit inspects suspended PTEs.
        let mut native = unsafe { Native::new(&table) };
        let result = revoke_with([(4096, 4096, 12288)], &mut native, || {
            let state = state().lock().unwrap();
            assert!(state.synchronized);
            assert_eq!(state.released, 0);
            assert_eq!(state.entries, suspended);
            if fail_commit { Err(17) } else { Ok(37) }
        });
        let state = state().lock().unwrap();
        if fail_commit {
            assert_eq!(result, Err(Error::Backend(17)));
            assert_eq!(state.entries, original);
            assert_eq!(state.released, 0);
        } else {
            assert_eq!(result, Ok(37));
            assert!(state.entries.is_empty());
            assert_eq!(state.released, 2);
        }
    }
}

#[test]
fn boundary_private_bytes_and_flags_survive_success_but_never_change_on_failure() {
    let _test = TEST_LOCK.lock().unwrap();
    use mapping_preservation_native::{PreservedPage, Preserving};
    use mapping_revocation::{revoke_with, Error};
    use mapping_revocation_native::Native;
    use task::process::{Process, ProcessTable};
    let table = ProcessTable(vec![Process::empty(4096)]);
    let original = BTreeMap::from([((4096, 4096), 0x405), ((4096, 8192), 0x207)]);
    for mode in 0..4 {
        *state().lock().unwrap() = State {
            entries: original.clone(),
            frames: BTreeMap::from([
                ((4096, 4096), Box::new([0x5a; 4096])),
                ((4096, 8192), Box::new([0xb7; 4096])),
            ]),
            fail_sync: mode == 1,
            ..Default::default()
        };
        let preserved = [PreservedPage {
            table: 4096,
            address: if mode == 3 { 8192 } else { 4096 },
            zero_from: if mode == 3 { 4097 } else { 17 },
        }];
        // The test owns the complete mock table throughout this transaction.
        let native = unsafe { Native::new(&table) };
        let mut backend = Preserving::new(native, &preserved).unwrap();
        let result = revoke_with([(4096, 4096, 12288)], &mut backend, || {
            assert!(mode != 1 && mode != 3, "preparation failed before commit");
            let state = state().lock().unwrap();
            assert!(state.synchronized);
            assert_eq!(state.released, 0);
            assert!(state.entries.values().all(|flags| flags & 1 == 0));
            assert!(state.frames[&(4096, 4096)].iter().all(|byte| *byte == 0x5a));
            if mode == 2 { Err(17) } else { Ok(37) }
        });
        let state = state().lock().unwrap();
        if mode == 0 {
            assert_eq!(result, Ok(37));
            assert_eq!(state.entries, BTreeMap::from([((4096, 4096), 0x405)]));
            assert_eq!(state.released, 1);
            assert!(
                state.frames[&(4096, 4096)][..17]
                    .iter()
                    .all(|byte| *byte == 0x5a)
            );
            assert!(
                state.frames[&(4096, 4096)][17..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        } else {
            assert_eq!(
                result,
                Err(Error::Backend(match mode {
                    1 => syscall::EIO,
                    2 => 17,
                    _ => syscall::EFAULT,
                }))
            );
            assert_eq!(state.entries, original);
            assert_eq!(state.released, 0);
            assert!(state.frames[&(4096, 4096)].iter().all(|byte| *byte == 0x5a));
            assert!(state.frames[&(4096, 8192)].iter().all(|byte| *byte == 0xb7));
        }
    }
}

#[test]
fn owned_backend_and_boundary_plan_outlive_every_journal_finish_action() {
    use mapping_preservation_native::{FrameBackend, PreservedPage, Preserving};
    use mapping_revocation::{Backend, Suspension};
    use mapping_revocation_native::Native;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use task::process::{Process, ProcessTable};
    struct Leased<'a> {
        native: Native<'a>,
        alive: Arc<AtomicBool>,
        published: bool,
    }
    impl Drop for Leased<'_> {
        fn drop(&mut self) {
            let state = state().lock().unwrap();
            assert_eq!(state.released, usize::from(self.published));
            assert_eq!(state.entries.len(), if self.published { 1 } else { 2 });
            assert!(self.alive.swap(false, Ordering::AcqRel));
        }
    }
    impl Backend for Leased<'_> {
        type Page = paging::SuspendedUserPage;
        type Error = u64;
        fn next_page(&mut self, t: u64, s: u64, e: u64) -> Result<Option<u64>, u64> {
            self.native.next_page(t, s, e)
        }
        fn suspend(&mut self, t: u64, a: u64) -> Result<Option<Self::Page>, u64> {
            self.native.suspend(t, a)
        }
        fn restore(&mut self, p: Self::Page) {
            assert!(self.alive.load(Ordering::Acquire));
            self.native.restore(p)
        }
        fn synchronize(&mut self) -> Result<(), u64> {
            self.native.synchronize()
        }
        fn release(&mut self, p: Self::Page) {
            assert!(self.alive.load(Ordering::Acquire));
            self.native.release(p)
        }
    }
    impl FrameBackend for Leased<'_> {
        fn owns_ram_frames(&self) -> bool {
            self.native.owns_ram_frames()
        }
    }
    let _test = TEST_LOCK.lock().unwrap();
    let table = ProcessTable(vec![Process::empty(4096)]);
    for mode in 0..3 {
        let commit = mode == 1;
        *state().lock().unwrap() = State {
            entries: BTreeMap::from([((4096, 4096), 0x405), ((4096, 8192), 0x207)]),
            frames: BTreeMap::from([
                ((4096, 4096), Box::new([0x5a; 4096])),
                ((4096, 8192), Box::new([0xb7; 4096])),
            ]),
            ..Default::default()
        };
        let alive = Arc::new(AtomicBool::new(true));
        // Only the fake table owner is borrowed; the adapter owns the plan and
        // the backend-specific lease, just as a persistent owner will need to.
        let native = unsafe { Native::new(&table) };
        let backend = Preserving::new(
            Leased {
                native,
                alive: alive.clone(),
                published: false,
            },
            vec![PreservedPage {
                table: 4096,
                address: 4096,
                zero_from: 17,
            }],
        )
        .unwrap();
        let journal = Suspension::new([(4096, 4096, 12288)], backend).unwrap();
        assert!(alive.load(Ordering::Acquire));
        if commit {
            journal
                .commit_with(|backend| {
                    backend.inner_mut().published = true;
                    Ok(())
                })
                .unwrap();
        } else if mode == 2 {
            assert_eq!(
                journal.commit_with(|backend| {
                    assert!(backend.inner_mut().alive.load(Ordering::Acquire));
                    Err::<(), _>(17)
                }),
                Err(mapping_revocation::Error::Backend(17))
            );
        } else {
            drop(journal);
        }
        assert!(!alive.load(Ordering::Acquire));
        let state = state().lock().unwrap();
        assert!(
            state.frames[&(4096, 4096)][..17]
                .iter()
                .all(|byte| *byte == 0x5a)
        );
        assert!(
            state.frames[&(4096, 4096)][17..]
                .iter()
                .all(|byte| *byte == if commit { 0 } else { 0x5a })
        );
        assert_eq!(state.entries[&(4096, 4096)], 0x405);
    }
}

#[test]
fn boundary_selection_checks_offset_geometry_without_interpreting_backing_identity() {
    use mapping_preservation_native::PreservedPage;
    let page = PreservedPage::for_mapping(4096, 0x5000, 8192, 4096, 5000)
        .unwrap()
        .unwrap();
    assert_eq!(
        (page.table, page.address, page.zero_from),
        (4096, 0x5000, 904)
    );
    assert!(
        PreservedPage::for_mapping(4096, 0x5000, 4096, 8192, 5000)
            .unwrap()
            .is_none()
    );
    assert!(
        PreservedPage::for_mapping(4096, 0x5000, 8192, 4096, 4096)
            .unwrap()
            .is_none()
    );
    assert!(PreservedPage::for_mapping(4096, 0x5001, 8192, 4096, 5000).is_err());
    assert!(PreservedPage::for_mapping(4096, 0x5000, 8192, 1, 5000).is_err());
    let process = task::process::Process::empty(4096);
    let borrowed = unsafe { mapping_revocation_native::Native::for_process(&process, false) };
    assert!(mapping_preservation_native::Preserving::new(borrowed, &[]).is_err());
}

#[test]
fn actual_native_adapter_checks_owned_roots_restores_on_sync_failure_and_releases_only_after_ack() {
    let _test = TEST_LOCK.lock().unwrap();
    use mapping_revocation::{revoke, Backend, Error};
    use mapping_revocation_native::Native;
    use task::process::{Process, ProcessTable};
    let table = ProcessTable(vec![Process::empty(4096), Process::empty(8192)]);
    // Host owns the entire mock table and PTE map throughout this transaction.
    let mut native = unsafe { Native::new(&table) };
    assert!(matches!(
        native.next_page(12288, 4096, 8192),
        Err(syscall::EFAULT)
    ));
    assert!(matches!(native.suspend(12288, 4096), Err(syscall::EFAULT)));
    assert_eq!(native.suspend(4096, 4096).unwrap().is_none(), true);
    *state().lock().unwrap() = State {
        entries: BTreeMap::from([((4096, 4096), 0x104), ((8192, 8192), 0x205)]),
        fail_sync: true,
        ..Default::default()
    };
    let ranges = [(4096, 0, 1 << 40), (8192, 0, 1 << 40)];
    assert_eq!(
        revoke(ranges, &mut native),
        Err(Error::Backend(syscall::EIO))
    );
    {
        let state = state().lock().unwrap();
        assert_eq!(
            state.entries,
            BTreeMap::from([((4096, 4096), 0x104), ((8192, 8192), 0x205)])
        );
        assert_eq!(state.released, 0);
    }
    state().lock().unwrap().fail_sync = false;
    revoke(ranges, &mut native).unwrap();
    {
        let state = state().lock().unwrap();
        assert!(state.entries.is_empty());
        assert_eq!(state.released, 2);
    }
    // A one-process MMIO mapping detaches its PTE but must not free a device
    // aperture as an allocator-owned RAM frame.
    state().lock().unwrap().entries.insert((4096, 4096), 0x105);
    let mut device = unsafe { Native::for_process(&table.0[0], false) };
    assert!(matches!(device.suspend(8192, 4096), Err(syscall::EFAULT)));
    revoke([(4096, 4096, 8192)], &mut device).unwrap();
    assert_eq!(state().lock().unwrap().released, 2);
    let roots = [
        detached_roots::Root::new(12288, &[]).ok().unwrap(),
        detached_roots::Root::new(16384, &[]).ok().unwrap(),
    ];
    roots[1].publish();
    let mut staging = unsafe { Native::with_detached(&table, &roots) };
    assert!(matches!(staging.suspend(16384, 4096), Err(syscall::EFAULT)));
    state().lock().unwrap().entries.insert((12288, 4096), 0x105);
    revoke([(12288, 4096, 8192)], &mut staging).unwrap();
    assert_eq!(state().lock().unwrap().released, 3);
}

fn region(
    identity: vm_object::ObjectKey,
    start: u64,
    length: u64,
    offset: u64,
) -> task::MemoryRegion {
    task::MemoryRegion {
        object: Some(task::Object(identity)),
        start,
        length,
        offset,
    }
}

#[test]
fn owned_targets_bind_exact_spans_and_pin_published_and_detached_roots() {
    use mapping_revocation::Backend;
    use mapping_revocation_native::Native;
    use mapping_targets::Targets;
    use task::process::{Process, ProcessTable};
    use vm_object::ObjectKey;
    let _test = TEST_LOCK.lock().unwrap();
    *state().lock().unwrap() = State::default();
    let identity = ObjectKey::Provider {
        endpoint_thread_id: 7,
        endpoint_slot: 3,
        endpoint_generation: 11,
        identity: 41,
    };
    let foreign = ObjectKey::Provider {
        endpoint_thread_id: 7,
        endpoint_slot: 3,
        endpoint_generation: 12,
        identity: 41,
    };
    let table = ProcessTable(vec![
        Process(4096, vec![region(identity, 0x4000, 0x4000, 0x1000)]),
        Process(8192, vec![region(identity, 0x8000, 0x2000, 0x2000)]),
        Process(16384, vec![region(foreign, 0x8000, 0x2000, 0x2000)]),
    ]);
    let detached = detached_roots::Root::new(12288, &[region(identity, 0x10000, 0x3000, 0x1000)])
        .ok()
        .unwrap();
    let targets = Targets::capture(&table, identity, 0x2000, 0x4000, 0x2345).unwrap();
    assert_eq!(targets.identity(), identity);
    assert_eq!(
        targets.ranges().collect::<Vec<_>>(),
        [
            (4096, 0x5000, 0x7000),
            (8192, 0x8000, 0xa000),
            (12288, 0x11000, 0x13000),
        ]
    );
    let mut preserved = targets
        .preserved()
        .iter()
        .map(|page| (page.table, page.address, page.zero_from))
        .collect::<Vec<_>>();
    preserved.sort_unstable();
    assert_eq!(
        preserved,
        [
            (4096, 0x5000, 0x345),
            (8192, 0x8000, 0x345),
            (12288, 0x11000, 0x345)
        ]
    );
    // Neither process records nor the not-yet-published image own the captured
    // plan. Publication/retirement does not discard the selected physical roots.
    detached.publish();
    drop(detached);
    drop(table);
    for root in [4096, 8192, 12288] {
        paging::destroy_user_page_table(root).unwrap();
    }
    assert!(state().lock().unwrap().destroyed.is_empty());
    let table = ProcessTable(Vec::new());
    let mut native = unsafe { Native::for_targets(&table, &targets) };
    {
        let mut state = state().lock().unwrap();
        state.entries = BTreeMap::from([
            ((4096, 0x4000), 0x105),
            ((4096, 0x5000), 0x205),
            ((4096, 0x7000), 0x305),
            ((16384, 0x8000), 0x405),
        ]);
    }
    // A pinned root is not authority to walk or edit its other mappings.
    assert!(matches!(
        native.next_page(4096, 0x4000, 0x7000),
        Err(syscall::EFAULT)
    ));
    for (root, address) in [(4096, 0x4000), (4096, 0x7000), (16384, 0x8000)] {
        assert!(matches!(
            native.suspend(root, address),
            Err(syscall::EFAULT)
        ));
    }
    assert!(matches!(
        native.suspend(4096, u64::MAX - 4095),
        Err(syscall::EFAULT)
    ));
    assert_eq!(native.next_page(4096, 0x5000, 0x7000), Ok(Some(0x5000)));
    let page = native.suspend(4096, 0x5000).unwrap().unwrap();
    assert_eq!(state().lock().unwrap().entries[&(4096, 0x5000)], 0x204);
    native.restore(page);
    assert_eq!(state().lock().unwrap().entries[&(4096, 0x5000)], 0x205);
    drop(native);
    drop(targets);
    let mut destroyed = state().lock().unwrap().destroyed.clone();
    destroyed.sort_unstable();
    assert_eq!(destroyed, [4096, 8192, 12288]);
}

#[test]
fn target_capture_failure_never_edits_mappings_or_takes_root_ownership() {
    use mapping_targets::Targets;
    use task::process::{Process, ProcessTable};
    use vm_object::ObjectKey;
    let _test = TEST_LOCK.lock().unwrap();
    *state().lock().unwrap() = State {
        entries: BTreeMap::from([((4096, 0x4000), 0x105), ((8192, 0x8000), 0x205)]),
        ..Default::default()
    };
    let original = state().lock().unwrap().entries.clone();
    let identity = ObjectKey::Memory(13);
    let table = ProcessTable(vec![
        Process(4096, vec![region(identity, 0x4000, 4096, 0)]),
        Process(8192, vec![region(identity, 0x8000, 4096, 0)]),
    ]);
    root_lifetime_native::FAIL_ROOT.store(8192, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        Targets::capture(&table, identity, 0, 4096, 17),
        Err(syscall::ENOMEM)
    ));
    root_lifetime_native::FAIL_ROOT.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(state().lock().unwrap().entries, original);
    assert!(state().lock().unwrap().destroyed.is_empty());
    // Failure must drop the first acquired pin rather than strand a root.
    assert!(!root_lifetime::retire(4096));
    assert!(!root_lifetime::retire(8192));
    for (start, end) in [(1, 4096), (0, 4097), (8192, 4096)] {
        assert!(matches!(
            Targets::capture(&table, identity, start, end, 17),
            Err(syscall::EINVAL)
        ));
    }
    let duplicate = ProcessTable(vec![Process(
        4096,
        vec![
            region(identity, 0x4000, 8192, 0),
            region(identity, 0x5000, 4096, 0),
        ],
    )]);
    assert!(matches!(
        Targets::capture(&duplicate, identity, 0, 8192, 17),
        Err(syscall::EINVAL)
    ));
    assert!(!root_lifetime::retire(4096));
    assert_eq!(state().lock().unwrap().entries, original);
    // Source misalignment must not be hidden by aligned intersection endpoints
    // or an aligned boundary (which does not need suffix preservation).
    for invalid in [
        region(identity, 0x4001, 8191, 1),
        region(identity, 0x0000_7fff_ffff_f000, 8192, 0),
        region(identity, u64::MAX - 4095, 8192, 0),
    ] {
        let malformed = ProcessTable(vec![Process(4096, vec![invalid])]);
        assert!(matches!(
            Targets::capture(&malformed, identity, 4096, 8192, 0),
            Err(syscall::EINVAL)
        ));
        assert!(!root_lifetime::retire(4096));
    }
    let other = Targets::capture(&table, ObjectKey::Memory(14), 0, 4096, 17).unwrap();
    assert_eq!(other.ranges().count(), 0);
    assert!(!root_lifetime::retire(4096));
    let empty = Targets::capture(&table, identity, 4096, 4096, 17).unwrap();
    assert_eq!(empty.ranges().count(), 0);
    assert!(!empty.contains(4096, 0x4000, 0x5000));
}
