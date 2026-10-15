extern crate alloc;
#[path = "../../../core/src/mem/mapping_preservation_native.rs"]
mod mapping_preservation_native;
#[path = "../../../core/src/mem/mapping_revocation.rs"]
mod mapping_revocation;
#[path = "../../../core/src/mem/mapping_revocation_native.rs"]
mod mapping_revocation_native;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
static TEST_LOCK: Mutex<()> = Mutex::new(());

mod syscall {
    pub const EFAULT: u64 = (-14i64) as u64;
    pub const EIO: u64 = (-5i64) as u64;
    pub const EINVAL: u64 = (-22i64) as u64;
}
mod task {
    pub mod process {
        pub struct Process(pub u64);
        impl Process {
            pub fn page_table(&self) -> Option<u64> {
                Some(self.0)
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
}
fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(Default::default)
}
mod paging {
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

mod detached_roots {
    pub struct Root {
        pub table: u64,
        pub published: bool,
    }
    impl Root {
        pub fn table(&self) -> u64 {
            self.table
        }
        pub fn published(&self) -> bool {
            self.published
        }
    }
}

#[test]
fn native_local_commit_is_ordered_after_tlb_ack_before_frame_release_and_can_roll_back() {
    let _test = TEST_LOCK.lock().unwrap();
    use mapping_revocation::{revoke_with, Error};
    use mapping_revocation_native::Native;
    use task::process::{Process, ProcessTable};
    let table = ProcessTable(vec![Process(4096)]);
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
    let table = ProcessTable(vec![Process(4096)]);
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
    let process = task::process::Process(4096);
    let borrowed = unsafe { mapping_revocation_native::Native::for_process(&process, false) };
    assert!(mapping_preservation_native::Preserving::new(borrowed, &[]).is_err());
}

#[test]
fn actual_native_adapter_checks_owned_roots_restores_on_sync_failure_and_releases_only_after_ack() {
    let _test = TEST_LOCK.lock().unwrap();
    use mapping_revocation::{revoke, Backend, Error};
    use mapping_revocation_native::Native;
    use task::process::{Process, ProcessTable};
    let table = ProcessTable(vec![Process(4096), Process(8192)]);
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
        std::sync::Arc::new(detached_roots::Root {
            table: 12288,
            published: false,
        }),
        std::sync::Arc::new(detached_roots::Root {
            table: 16384,
            published: true,
        }),
    ];
    let mut staging = unsafe { Native::with_detached(&table, &roots) };
    assert!(matches!(staging.suspend(16384, 4096), Err(syscall::EFAULT)));
    state().lock().unwrap().entries.insert((12288, 4096), 0x105);
    revoke([(12288, 4096, 8192)], &mut staging).unwrap();
    assert_eq!(state().lock().unwrap().released, 3);
}
